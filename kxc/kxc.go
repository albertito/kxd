// kxc is a client for the key exchange daemon kxd.
//
// It connects to the given server using the provided certificate,
// and authorizes the server against the given server certificate.
//
// If everything goes well, it prints the obtained key to standard output.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const defaultPort = 19840

var serverCert = flag.String(
	"server_cert", "", "File containing valid server certificate(s)")
var clientCert = flag.String(
	"client_cert", "", "File containing the client certificate")
var clientKey = flag.String(
	"client_key", "", "File containing the client private key")

func loadServerCerts() (*x509.CertPool, error) {
	pemData, err := ioutil.ReadFile(*serverCert)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("error appending certificates")
	}

	return pool, nil
}

// Check if the given network address has a port.
func hasPort(s string) bool {
	// Consider the IPv6 case (where the host part contains ':') by
	// checking if the last ':' comes after the ']' which closes the host.
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

func extractURL(rawurl string) (*url.URL, error) {
	serverURL, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// Make sure we're using https.
	switch serverURL.Scheme {
	case "https":
		// Nothing to do here.
	case "http", "kxd":
		serverURL.Scheme = "https"
	default:
		return nil, fmt.Errorf("unsupported URL schema (try kxd://)")
	}

	// The path must begin with /v1/, although we hide that from the user
	// for forward compatibility.
	if !strings.HasPrefix(serverURL.Path, "/v1/") {
		serverURL.Path = "/v1" + serverURL.Path
	}

	// Add the default port, if none was given.
	if !hasPort(serverURL.Host) {
		serverURL.Host += fmt.Sprintf(":%d", defaultPort)
	}

	return serverURL, nil
}

func makeTLSConf() *tls.Config {
	var err error

	tlsConf := &tls.Config{}
	tlsConf.Certificates = make([]tls.Certificate, 1)
	tlsConf.Certificates[0], err = tls.LoadX509KeyPair(
		*clientCert, *clientKey)
	if err != nil {
		log.Fatalf("Failed to load keys: %s", err)
	}

	// Compare against the server certificates.
	serverCerts, err := loadServerCerts()
	if err != nil {
		log.Fatalf("Failed to load server certs: %s", err)
	}
	tlsConf.RootCAs = serverCerts

	return tlsConf
}

func main() {
	var err error
	flag.Parse()

	tr := &http.Transport{
		TLSClientConfig: makeTLSConf(),
	}

	client := &http.Client{
		Transport: tr,
	}

	serverURL, err := extractURL(flag.Arg(0))
	if err != nil {
		log.Fatalf("Failed to extract the URL: %s", err)
	}

	resp, err := client.Get(serverURL.String())
	if err != nil {
		log.Fatalf("Failed to get key: %s", err)
	}

	content, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatalf("Error reading key body: %s", err)
	}

	if resp.StatusCode != 200 {
		log.Fatalf("HTTP error %q getting key: %s",
			resp.Status, content)
	}

	fmt.Printf("%s", content)
}
