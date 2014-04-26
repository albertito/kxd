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
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path"
	"strings"
)

var port = flag.Int(
	"port", 19840, "Port to listen on")
var ip_addr = flag.String(
	"ip_addr", "", "IP address to listen on")
var data_dir = flag.String(
	"data_dir", "/etc/kxd/data", "Data directory")
var certfile = flag.String(
	"cert", "/etc/kxd/cert.pem", "Certificate")
var keyfile = flag.String(
	"key", "/etc/kxd/key.pem", "Private key")
var smtp_addr = flag.String(
	"smtp_addr", "", "Address of the SMTP server to use to send emails")
var email_from = flag.String(
	"email_from", "", "Email address to send email from")
var logfile = flag.String(
	"logfile", "", "File to write logs to, use '-' for stdout")

// Logger we will use to log entries.
var logging *log.Logger

// Request is our wrap around http.Request, so we can augment it with custom
// methods.
type Request struct {
	*http.Request
}

func (req *Request) Printf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	msg = fmt.Sprintf("%s %s %s", req.RemoteAddr, req.URL.Path, msg)
	logging.Output(2, msg)
}

// KeyPath returns the path to the requested key, extracting it from the URL.
func (req *Request) KeyPath() (string, error) {
	s := strings.Split(req.URL.Path, "/")

	// We expect the path to be "/v1/path/to/key".
	if len(s) < 2 || !(s[0] == "" || s[1] == "v1") {
		return "", fmt.Errorf("Invalid path %q", s)
	}

	return strings.Join(s[2:], "/"), nil
}

func CertToString(cert *x509.Certificate) string {
	return fmt.Sprintf(
		"(0x%.8s ou:%s)",
		fmt.Sprintf("%x", cert.Signature),
		cert.Subject.OrganizationalUnit)
}

func ChainToString(chain []*x509.Certificate) (s string) {
	for i, cert := range chain {
		s += CertToString(cert)
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

	// Be extra paranoid and reject keys with "..", even if they're valid
	// (e.g. "/v1/x..y" is valid, but will get rejected anyway).
	if strings.Contains(keyPath, "..") {
		req.Printf("Rejecting because requested key %q contained '..'",
			keyPath)
		req.Printf("Full request: %+v", *req.Request)
		http.Error(w, "Invalid key path", http.StatusNotAcceptable)
		return
	}

	realKeyPath := path.Clean(*data_dir + "/" + keyPath)
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

	validChains := keyConf.IsAnyCertAllowed(req.TLS.PeerCertificates)
	if validChains == nil {
		req.Printf("No allowed certificate found")
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

	req.Printf("Allowing request to %s", CertToString(validChains[0][0]))

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

	if *logfile == "-" {
		logfd = os.Stdout
	} else if *logfile != "" {
		logfd, err = os.OpenFile(*logfile,
			os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			log.Fatalf("Error opening log file %s: %s",
				*logfile, err)
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

func main() {
	flag.Parse()

	initLog()

	if *smtp_addr == "" {
		logging.Print(
			"WARNING: No emails will be sent, use --smtp_addr")
	}

	if *email_from == "" {
		// Try to get a sane default if not provided, using
		// kxd@<smtp host>.
		*email_from = fmt.Sprintf("kxd@%s",
			strings.Split(*smtp_addr, ":")[0])
	}

	listenAddr := fmt.Sprintf("%s:%d", *ip_addr, *port)

	tlsConfig := tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}

	server := http.Server{
		Addr:      listenAddr,
		TLSConfig: &tlsConfig,
	}

	http.HandleFunc("/v1/", HandlerV1)

	logging.Printf("Listening on %s", listenAddr)
	err := server.ListenAndServeTLS(*certfile, *keyfile)
	if err != nil {
		logging.Fatal(err)
	}
}
