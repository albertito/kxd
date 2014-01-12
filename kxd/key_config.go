package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

func FileStat(path string) (os.FileInfo, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return fd.Stat()
}

func IsDir(path string) (bool, error) {
	fi, err := FileStat(path)
	if err != nil {
		return false, err
	}

	return fi.IsDir(), nil
}

func IsRegular(path string) (bool, error) {
	fi, err := FileStat(path)
	if err != nil {
		return false, err
	}

	return fi.Mode().IsRegular(), nil
}

// KeyConfig holds the configuration data for a single key.
type KeyConfig struct {
	// Path to the configuration directory.
	ConfigPath string

	// Paths to the files themselves.
	keyPath            string
	allowedClientsPath string
	allowedHostsPath   string
	emailToPath        string

	// Allowed certificates.
	allowedClientCerts []*x509.Certificate

	// Allowed hosts.
	allowedHosts []string
}

func NewKeyConfig(configPath string) *KeyConfig {
	return &KeyConfig{
		ConfigPath:         configPath,
		keyPath:            configPath + "/key",
		allowedClientsPath: configPath + "/allowed_clients",
		allowedHostsPath:   configPath + "/allowed_hosts",
		emailToPath:        configPath + "/email_to",
	}
}

func (kc *KeyConfig) Exists() (bool, error) {
	isDir, err := IsDir(kc.ConfigPath)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if !isDir {
		return false, nil
	}

	isRegular, err := IsRegular(kc.keyPath)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return isRegular, nil
}

func (kc *KeyConfig) LoadClientCerts() error {
	rawContents, err := ioutil.ReadFile(kc.allowedClientsPath)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	for len(rawContents) > 0 {
		var block *pem.Block
		block, rawContents = pem.Decode(rawContents)
		if block == nil {
			return nil
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		kc.allowedClientCerts = append(kc.allowedClientCerts, cert)
	}

	return nil
}

func (kc *KeyConfig) LoadAllowedHosts() error {
	contents, err := ioutil.ReadFile(kc.allowedHostsPath)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	// If the file is there, we want our array to exist, even if it's
	// empty, to avoid authorizing everyone on an empty file (which means
	// authorize noone).
	kc.allowedHosts = make([]string, 1)
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if net.ParseIP(line) != nil {
			kc.allowedHosts = append(kc.allowedHosts, line)
		} else {
			names, err := net.LookupHost(line)
			if err != nil {
				continue
			}
			kc.allowedHosts = append(kc.allowedHosts, names...)
		}
	}

	return nil
}

func (kc *KeyConfig) IsAnyCertAllowed(
	certs []*x509.Certificate) *x509.Certificate {
	for _, cert := range certs {
		for _, allowedCert := range kc.allowedClientCerts {
			if cert.Equal(allowedCert) {
				return cert
			}
		}
	}
	return nil
}

func (kc *KeyConfig) IsHostAllowed(addr string) error {
	if kc.allowedHosts == nil {
		return nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	for _, allowedHost := range kc.allowedHosts {
		if allowedHost == host {
			return nil
		}
	}

	return fmt.Errorf("Host %q not allowed", host)
}

func (kc *KeyConfig) Key() (key []byte, err error) {
	return ioutil.ReadFile(kc.keyPath)
}

func (kc *KeyConfig) EmailTo() ([]string, error) {
	contents, err := ioutil.ReadFile(kc.emailToPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var emails []string
	for _, line := range strings.Split(string(contents), "\n") {
		email := strings.TrimSpace(line)
		if !strings.Contains(email, "@") {
			continue
		}
		emails = append(emails, email)
	}

	return emails, nil
}
