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

type EmailBody struct {
	From       string
	To         string
	Key        string
	Time       time.Time
	TimeString string
	Req        *Request
	Cert       *x509.Certificate
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
  Issuer: {{NameToString .Cert.Issuer}}
  Subject: {{NameToString .Cert.Subject}}

`)

var emailTmpl = template.New("email")

func init() {
	emailTmpl.Funcs(map[string]interface{}{
		"NameToString": NameToString,
	})

	template.Must(emailTmpl.Parse(emailTmplBody))
}

func NameToString(name pkix.Name) string {
	s := make([]string, 0)
	for _, c := range name.Country {
		s = append(s, fmt.Sprintf("C=%s", c))
	}
	for _, o := range name.Organization {
		s = append(s, fmt.Sprintf("O=%s", o))
	}

	if name.CommonName != "" {
		s = append(s, fmt.Sprintf("N=%s", name.CommonName))
	}

	return strings.Join(s, " ")
}

func SendMail(kc *KeyConfig, req *Request, cert *x509.Certificate) error {
	if *smtp_addr == "" {
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
		From:       *email_from,
		To:         strings.Join(emailTo, ", "),
		Key:        keyPath,
		Time:       now,
		TimeString: now.Format(time.RFC1123Z),
		Req:        req,
		Cert:       cert,
	}

	msg := new(bytes.Buffer)

	err = emailTmpl.Execute(msg, body)
	if err != nil {
		return err
	}

	return smtp.SendMail(*smtp_addr, nil, *email_from, emailTo,
		msg.Bytes())
}
