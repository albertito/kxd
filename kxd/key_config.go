package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

func fileStat(path string) (os.FileInfo, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return fd.Stat()
}

func isDir(path string) (bool, error) {
	fi, err := fileStat(path)
	if err != nil {
		return false, err
	}

	return fi.IsDir(), nil
}

func isRegular(path string) (bool, error) {
	fi, err := fileStat(path)
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
	allowedClientCerts *x509.CertPool

	// Allowed hosts.
	allowedHosts []string
}

// NewKeyConfig makes a new KeyConfig based on the given path. Note that there
// is no check about the key existing or being valid.
func NewKeyConfig(configPath string) *KeyConfig {
	return &KeyConfig{
		ConfigPath:         configPath,
		keyPath:            configPath + "/key",
		allowedClientsPath: configPath + "/allowed_clients",
		allowedHostsPath:   configPath + "/allowed_hosts",
		emailToPath:        configPath + "/email_to",
		allowedClientCerts: x509.NewCertPool(),
	}
}

// Exists checks if this key exists.
func (kc *KeyConfig) Exists() (bool, error) {
	isDir, err := isDir(kc.ConfigPath)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if !isDir {
		return false, nil
	}

	isRegular, err := isRegular(kc.keyPath)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return isRegular, nil
}

// LoadClientCerts loads the client certificates allowed for this key.
func (kc *KeyConfig) LoadClientCerts() error {
	rawContents, err := ioutil.ReadFile(kc.allowedClientsPath)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	if !kc.allowedClientCerts.AppendCertsFromPEM(rawContents) {
		return fmt.Errorf("Error parsing client certificate file")
	}

	return nil
}

// LoadAllowedHosts loads the hosts allowed for this key.
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

// IsAnyCertAllowed checks if any of the given certificates is allowed to
// access this key. If so, it returns the chain for each of them.
func (kc *KeyConfig) IsAnyCertAllowed(
	certs []*x509.Certificate) [][]*x509.Certificate {
	opts := x509.VerifyOptions{
		Roots: kc.allowedClientCerts,
	}
	for _, cert := range certs {
		chains, err := cert.Verify(opts)
		if err == nil && len(chains) > 0 {
			return chains
		}
	}
	return nil
}

// IsHostAllowed checks if the given host is allowed to access this key.
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

// Key returns the private key.
func (kc *KeyConfig) Key() (key []byte, err error) {
	return ioutil.ReadFile(kc.keyPath)
}

// EmailTo returns the list of addresses to email when this key is accessed.
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
