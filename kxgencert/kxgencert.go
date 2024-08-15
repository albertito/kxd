// Utility to generate self-signed certificates.
// It generates a self-signed x509 certificate and key pair.
package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	host = flag.String("host", "localhost",
		"Hostnames/IPs to generate the certificate for (comma separated)")
	validFor = flag.Duration("validfor", 24*time.Hour*365*10,
		"How long will the certificate be valid for (default: 10y)")
	orgName = flag.String("organization", "",
		"Organization to use in the certificate, useful for debugging")

	certPath = flag.String("cert", "cert.pem",
		"Where to write the generated certificate")
	keyPath = flag.String("key", "key.pem",
		"Where to write the generated key")
)

func fatalf(f string, a ...interface{}) {
	fmt.Printf(f, a...)
	os.Exit(1)
}

func main() {
	flag.Parse()

	// Build the certificate template.
	serial, err := crand.Int(crand.Reader, big.NewInt(1<<62))
	if err != nil {
		fatalf("Error generating serial number: %v\n", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{*orgName}},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(*validFor),

		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	// Generate a private key (RSA 2048).
	privK, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		fatalf("Error generating key: %v\n", err)
	}

	// Write the certificate.
	{
		derBytes, err := x509.CreateCertificate(
			crand.Reader, &tmpl, &tmpl, &privK.PublicKey, privK)
		if err != nil {
			fatalf("Failed to create certificate: %v\n", err)
		}

		fullchain, err := os.Create(*certPath)
		if err != nil {
			fatalf("Failed to open %q: %v\n", *certPath, err)
		}
		pem.Encode(fullchain, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		fullchain.Close()
	}

	// Write the private key.
	{
		privkey, err := os.Create(*keyPath)
		if err != nil {
			fatalf("failed to open %q: %v\n", *keyPath, err)
		}
		block := &pem.Block{Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privK)}
		pem.Encode(privkey, block)
		privkey.Close()
	}
}
