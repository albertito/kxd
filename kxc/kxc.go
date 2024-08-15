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
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const defaultPort = 19840

var serverCert = flag.String(
	"server_cert", "", "File containing valid server certificate(s)")
var clientCert = flag.String(
	"client_cert", "", "File containing the client certificate")
var clientKey = flag.String(
	"client_key", "", "File containing the client private key")

func loadServerCerts() (*x509.CertPool, bool, error) {
	pemData, err := ioutil.ReadFile(*serverCert)
	if err != nil {
		return nil, false, err
	}

	// Old server certificates can use the deprecated '*' for the server name.
	// This is not supported by Go, but we still want to support them, so
	// we need to identify them at parsing time.
	hasWildcard := false
	{
		data := pemData[:]
		for {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, false, fmt.Errorf(
					"error parsing certificate: %s", err)
			}

			if strings.Contains(cert.Subject.CommonName, "*") {
				hasWildcard = true
				break
			}
			if slices.Contains(cert.DNSNames, "*") {
				hasWildcard = true
				break
			}
		}
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, false, fmt.Errorf("error appending certificates")
	}

	return pool, hasWildcard, nil
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

	serverCerts, hasWildcard, err := loadServerCerts()
	if err != nil {
		log.Fatalf("Failed to load server certs: %s", err)
	}

	if hasWildcard {
		// We want to do the standard verification, but ignoring the server name.
		// This is because old certificates might not have the server name, or use
		// '*' which was later deprecated and not supported by Go.
		// This also makes deployment much more practical on small networks where
		// the server name is not important.
		//
		// Unfortunately, there's no way to tell Go to ignore just that, so we need
		// to do it manually.
		// To do that, we need to set InsecureSkipVerify to true, and then provide
		// a custom VerifyConnection function that does the verification we want.
		// The verification is using the same logic Go does, and following the
		// official example at
		// https://pkg.go.dev/crypto/tls#example-Config-VerifyConnection.
		tlsConf.InsecureSkipVerify = true
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				// Explicitly not care about the server name.
				DNSName:       "",
				Intermediates: x509.NewCertPool(),

				// Compare against the server certificates.
				Roots: serverCerts,
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	} else {
		// If none of the server certificates use the deprecated '*', we can
		// use the standard verification.
		tlsConf.RootCAs = serverCerts
	}

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
