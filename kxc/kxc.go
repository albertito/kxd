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
	"net"
	"net/http"
	"net/url"
	"strings"
)

const defaultPort = 19840

var server_cert = flag.String(
	"server_cert", "", "File containing valid server certificate(s)")
var client_cert = flag.String(
	"client_cert", "", "File containing the client certificate")
var client_key = flag.String(
	"client_key", "", "File containing the client private key")

func LoadServerCerts() ([]*x509.Certificate, error) {
	pemData, err := ioutil.ReadFile(*server_cert)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return certs, nil
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// We can't ask the http client for the TLS connection, so we make it
// ourselves and save it here.
// It is hacky but it simplifies the code.
var tlsConn *tls.Conn

func OurDial(network, addr string) (net.Conn, error) {
	var err error

	tlsConf := &tls.Config{}
	tlsConf.Certificates = make([]tls.Certificate, 1)
	tlsConf.Certificates[0], err = tls.LoadX509KeyPair(
		*client_cert, *client_key)
	if err != nil {
		log.Fatalf("Failed to load keys: %s", err)
	}

	// We don't want the TLS stack to check the cert, as we will compare
	// it ourselves.
	tlsConf.InsecureSkipVerify = true

	tlsConn, err = tls.Dial(network, addr, tlsConf)
	return tlsConn, err
}

// Check if any cert from requestedCerts matches any cert in validCerts.
func AnyCertMatches(requestedCerts, validCerts []*x509.Certificate) bool {
	for _, cert := range requestedCerts {
		for _, validCert := range validCerts {
			if cert.Equal(validCert) {
				return true
			}
		}
	}

	return false
}

// Check if the given network address has a port.
func hasPort(s string) bool {
	// Consider the IPv6 case (where the host part contains ':') by
	// checking if the last ':' comes after the ']' which closes the host.
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

func ExtractURL(rawurl string) (*url.URL, error) {
	// Because we handle the transport ourselves, the http library has to
	// be told to use plain http; otherwise it will attempt to do its own
	// TLS on top of our TLS.
	serverURL, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// Fix up the scheme to use http.
	// Because we handle the transport ourselves, the http library has to
	// be told to use plain http; otherwise it will attempt to do its own
	// TLS on top of our TLS (and obviously fails, in this case with an
	// "local error: record overflow" error).
	switch serverURL.Scheme {
	case "http":
		// Nothing to do here.
	case "https", "kxd":
		serverURL.Scheme = "http"
	default:
		return nil, fmt.Errorf("Unsupported URL schema (try kxd://)")
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

func main() {
	var err error
	flag.Parse()

	serverCerts, err := LoadServerCerts()
	if err != nil {
		log.Fatalf("Failed to load server certs: %s", err)
	}

	tr := &http.Transport{
		Dial: OurDial,
	}

	client := &http.Client{
		Transport: tr,
	}

	serverURL, err := ExtractURL(flag.Arg(0))
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

	if !AnyCertMatches(
		tlsConn.ConnectionState().PeerCertificates, serverCerts) {
		log.Fatalf("No server certificate matches")
	}

	fmt.Printf("%s", content)
}
