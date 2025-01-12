// kxd is a key exchange daemon.
//
// It serves blobs of data (keys) over https, authenticating and authorizing
// the clients using SSL certificates, and notifying upon key accesses.
//
// It can be used to get keys remotely instead of using local storage.
// The main use case is to get keys to open dm-crypt devices automatically,
// without having to store them on the machine.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
)

var port = flag.Int(
	"port", 19840, "Port to listen on")
var ipAddr = flag.String(
	"ip_addr", "", "IP address to listen on")
var dataDir = flag.String(
	"data_dir", "/etc/kxd/data", "Data directory")
var certFile = flag.String(
	"cert", "/etc/kxd/cert.pem", "Certificate")
var keyFile = flag.String(
	"key", "/etc/kxd/key.pem", "Private key")
var smtpAddr = flag.String(
	"smtp_addr", "", "Address of the SMTP server to use to send emails")
var emailFrom = flag.String(
	"email_from", "", "Email address to send email from")
var logFile = flag.String(
	"logfile", "", "File to write logs to, use '-' for stdout")
var hookPath = flag.String(
	"hook", "/etc/kxd/hook",
	"Hook to run before authorizing keys (skipped if it doesn't exist)")

// Logger we will use to log entries.
var logging *log.Logger

// Request is our wrap around http.Request, so we can augment it with custom
// methods.
type Request struct {
	*http.Request
}

// Printf is a wrapper for fmt.Printf+logging.Output, which prefixes a string
// identifying this request.
func (req *Request) Printf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	msg = fmt.Sprintf("%s %s %s", req.RemoteAddr, req.URL.Path, msg)
	logging.Output(2, msg)
}

var (
	errInvalidVersion = errors.New("invalid version")
	errHasDotDot      = errors.New("path contains '..'")
)

// KeyPath returns the path to the requested key, extracting it from the URL.
func (req *Request) KeyPath() (string, error) {
	// Clean the path to remove any noise.
	kp := path.Clean(req.URL.Path)

	// Must start with "/v1/". Doing this after the Clean also ensures there
	// is something else after the version (because Clean removes trailing
	// slashes).
	kp, hasVersion := strings.CutPrefix(kp, "/v1/")
	if !hasVersion {
		return "", errInvalidVersion
	}

	// Be extra paranoid and reject keys with "..", even if they're valid
	// (e.g. "/v1/x..y" is valid, but will get rejected anyway).
	// Note requests like this shouldn't reach this stage anyway, due to the
	// http library processing and the path.Clean above.
	if strings.Contains(kp, "..") {
		return "", errHasDotDot
	}

	return kp, nil
}

func certToString(cert *x509.Certificate) string {
	return fmt.Sprintf(
		"(0x%.8s %s)",
		fmt.Sprintf("%x", cert.Signature),
		cert.Subject.ToRDNSequence())
}

// ChainToString makes a human-readable string out of the given certificate
// chain.
func ChainToString(chain []*x509.Certificate) (s string) {
	for i, cert := range chain {
		s += certToString(cert)
		if i < len(chain)-1 {
			s += " -> "
		}
	}
	return s
}

// HandlerV1 handles /v1/ key requests.
func HandlerV1(w http.ResponseWriter, httpreq *http.Request) {
	req := Request{httpreq}
	if len(req.TLS.PeerCertificates) <= 0 {
		req.Printf("Rejecting request without certificate")
		http.Error(w, "Client certificate not provided",
			http.StatusNotAcceptable)
		return
	}

	keyPath, err := req.KeyPath()
	if err != nil {
		req.Printf("Rejecting request with invalid key path: %s", err)
		http.Error(w, "Invalid key path", http.StatusNotAcceptable)
		return
	}

	realKeyPath := path.Join(*dataDir, keyPath)
	keyConf := NewKeyConfig(realKeyPath)

	exists, err := keyConf.Exists()
	if err != nil {
		req.Printf("Error checking key path %q: %s", keyPath, err)
		http.Error(w, "Error checking key",
			http.StatusInternalServerError)
		return
	}
	if !exists {
		req.Printf("Unknown key path %q", keyPath)
		http.Error(w, "Unknown key", http.StatusNotFound)
		return
	}

	if err = keyConf.LoadClientCerts(); err != nil {
		req.Printf("Error loading certs: %s", err)
		http.Error(w, "Error loading certs",
			http.StatusInternalServerError)
		return
	}

	if err = keyConf.LoadAllowedHosts(); err != nil {
		req.Printf("Error loading allowed hosts: %s", err)
		http.Error(w, "Error loading allowed hosts",
			http.StatusInternalServerError)
		return
	}

	err = keyConf.IsHostAllowed(req.RemoteAddr)
	if err != nil {
		req.Printf("Host not allowed: %s", err)
		http.Error(w, "Host not allowed", http.StatusForbidden)
		return
	}

	validChains, errs := keyConf.IsAnyCertAllowed(req.TLS.PeerCertificates)
	if validChains == nil {
		req.Printf("No allowed certificate found (checked %d certs)",
			len(errs))
		for i, e := range errs {
			req.Printf("  %d: %s %v", i, certToString(e.Cert), e.Err)
		}
		http.Error(w, "No allowed certificate found",
			http.StatusForbidden)
		return
	}

	keyData, err := keyConf.Key()
	if err != nil {
		req.Printf("Error getting key data: %s", err)
		http.Error(w, "Error getting key data",
			http.StatusInternalServerError)
		return
	}

	err = RunHook(keyConf, &req, validChains)
	if err != nil {
		req.Printf("Prevented by hook: %s", err)
		http.Error(w, "Prevented by hook", http.StatusForbidden)
		return
	}

	req.Printf("Allowing request to %s", certToString(validChains[0][0]))

	err = SendMail(keyConf, &req, validChains)
	if err != nil {
		req.Printf("Error sending notification: %s", err)
		http.Error(w, "Error sending notification",
			http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(keyData)
}

func initLog() {
	var err error
	var logfd io.Writer

	if *logFile == "-" {
		logfd = os.Stdout
	} else if *logFile != "" {
		logfd, err = os.OpenFile(*logFile,
			os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			log.Fatalf("Error opening log file %s: %s",
				*logFile, err)
		}
	} else {
		logfd, err = syslog.New(
			syslog.LOG_INFO|syslog.LOG_DAEMON, "kxd")
		if err != nil {
			log.Fatalf("Error opening syslog: %s", err)
		}
	}

	logging = log.New(logfd, "",
		log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
}

func signalHandler() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	for {
		switch sig := <-signals; sig {
		case syscall.SIGTERM, syscall.SIGINT:
			logging.Printf("Received signal %s, exiting", sig)
			os.Exit(0)
		default:
			logging.Printf("Received unexpected signal %s", sig)
		}
	}
}

func main() {
	flag.Parse()

	initLog()

	go signalHandler()

	if *smtpAddr == "" {
		logging.Print(
			"WARNING: No emails will be sent, use --smtp_addr")
	}

	if *emailFrom == "" {
		// Try to get a sane default if not provided, using
		// kxd@<smtp host>.
		*emailFrom = fmt.Sprintf("kxd@%s",
			strings.Split(*smtpAddr, ":")[0])
	}

	listenAddr := fmt.Sprintf("%s:%d", *ipAddr, *port)

	tlsConfig := tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}

	server := http.Server{
		Addr:      listenAddr,
		TLSConfig: &tlsConfig,
		ErrorLog:  logging,
	}

	http.HandleFunc("/v1/", HandlerV1)

	logging.Printf("Listening on %s", listenAddr)
	err := server.ListenAndServeTLS(*certFile, *keyFile)
	if err != nil {
		logging.Fatal(err)
	}
}
