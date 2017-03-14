package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/smtp"
	"strings"
	"text/template"
	"time"
)

// EmailBody represents the body of an email message to sent.
type EmailBody struct {
	From       string
	To         string
	Key        string
	Time       time.Time
	TimeString string
	Req        *Request
	Cert       *x509.Certificate
	Chains     [][]*x509.Certificate
}

const emailTmplBody = (`Date: {{.TimeString}}
From: Key Exchange Daemon <{{.From}}>
To: {{.To}}
Subject: Access to key {{.Key}}

Key: {{.Key}}
Accessed by: {{.Req.RemoteAddr}}
On: {{.TimeString}}

Client certificate:
  Signature: {{printf "%.16s" (printf "%x" .Cert.Signature)}}...
  Subject: {{NameToString .Cert.Subject}}

Authorizing chains:
{{range .Chains}}  {{ChainToString .}}
{{end}}

`)

var emailTmpl = template.New("email")

func init() {
	emailTmpl.Funcs(map[string]interface{}{
		"NameToString":  NameToString,
		"ChainToString": ChainToString,
	})

	template.Must(emailTmpl.Parse(emailTmplBody))
}

// NameToString converts a pkix.Name from a certificate to a human-friendly
// string.
func NameToString(name pkix.Name) string {
	s := make([]string, 0)
	for _, c := range name.Country {
		s = append(s, fmt.Sprintf("C=%s", c))
	}
	for _, o := range name.Organization {
		s = append(s, fmt.Sprintf("O=%s", o))
	}
	for _, o := range name.OrganizationalUnit {
		s = append(s, fmt.Sprintf("OU=%s", o))
	}

	if name.CommonName != "" {
		s = append(s, fmt.Sprintf("N=%s", name.CommonName))
	}

	return strings.Join(s, " ")
}

// SendMail sends an email notifying of an access to the given key.
func SendMail(kc *KeyConfig, req *Request,
	chains [][]*x509.Certificate) error {
	if *smtpAddr == "" {
		req.Printf("Skipping notifications")
		return nil
	}

	emailTo, err := kc.EmailTo()
	if err != nil {
		return err
	}

	if emailTo == nil {
		return nil
	}

	keyPath, err := req.KeyPath()
	if err != nil {
		return err
	}

	now := time.Now()
	body := EmailBody{
		From:       *emailFrom,
		To:         strings.Join(emailTo, ", "),
		Key:        keyPath,
		Time:       now,
		TimeString: now.Format(time.RFC1123Z),
		Req:        req,
		Cert:       chains[0][0],
		Chains:     chains,
	}

	msg := new(bytes.Buffer)

	err = emailTmpl.Execute(msg, body)
	if err != nil {
		return err
	}

	return smtp.SendMail(*smtpAddr, nil, *emailFrom, emailTo,
		msg.Bytes())
}
