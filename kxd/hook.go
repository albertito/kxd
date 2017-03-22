package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RunHook runs the hook, returns an error if the request is not allowed (or
// there were problems with the hook; we don't make the distinction for now).
//
// Note that if the hook flag is not set, or points to a non-existing path,
// then we allow the request.
func RunHook(kc *KeyConfig, req *Request, chains [][]*x509.Certificate) error {
	if *hookPath == "" {
		return nil
	}

	if _, err := os.Stat(*hookPath); os.IsNotExist(err) {
		req.Printf("Hook not present, skipping")
		return nil
	}

	ctx, cancel := context.WithDeadline(context.Background(),
		time.Now().Add(1*time.Minute))
	defer cancel()
	cmd := exec.CommandContext(ctx, *hookPath)

	// Run the hook from the data directory.
	cmd.Dir = *dataDir

	// Prepare the environment, copying some common variables so the hook has
	// someting reasonable, and then setting the specific ones for this case.
	for _, v := range strings.Fields("USER PWD SHELL PATH") {
		cmd.Env = append(cmd.Env, v+"="+os.Getenv(v))
	}

	keyPath, err := req.KeyPath()
	if err != nil {
		return err
	}
	cmd.Env = append(cmd.Env, "KEY_PATH="+keyPath)

	cmd.Env = append(cmd.Env, "REMOTE_ADDR="+req.RemoteAddr)
	cmd.Env = append(cmd.Env, "MAIL_FROM="+*emailFrom)
	if emailTo, _ := kc.EmailTo(); emailTo != nil {
		cmd.Env = append(cmd.Env, "EMAIL_TO="+strings.Join(emailTo, " "))
	}

	clientCert := chains[0][0]
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("CLIENT_CERT_SIGNATURE=%x", clientCert.Signature))
	cmd.Env = append(cmd.Env,
		"CLIENT_CERT_SUBJECT="+NameToString(clientCert.Subject))

	for i, chain := range chains {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("CHAIN_%d=%s", i, ChainToString(chain)))
	}

	_, err = cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("exited with error: %v -- stderr: %q",
				ee.String(), ee.Stderr)
		}
		return err
	}

	return nil
}
