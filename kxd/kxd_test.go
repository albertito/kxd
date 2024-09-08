package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func init() {
	// Initialize the global logger. The testing framework will capture the
	// output and use it as needed.
	logging = log.Default()
}

func TestKeyPath(t *testing.T) {
	cases := []struct {
		url  string
		want string
		err  error
	}{
		{"/v1/key", "key", nil},
		{"/v1/path/to/key", "path/to/key", nil},
		{"/v1/path/to/key/", "path/to/key", nil},

		{"", "", errInvalidVersion},
		{"/", "", errInvalidVersion},
		{"/v1", "", errInvalidVersion},
		{"/v1/", "", errInvalidVersion},
		{"/v1//", "", errInvalidVersion},
		{"v1/path/to/key/", "", errInvalidVersion},
		{"/v2/path/to/key", "", errInvalidVersion},

		{"/v1/a..b", "", errHasDotDot},
	}

	for _, c := range cases {
		u, _ := url.Parse(c.url)
		req := Request{&http.Request{
			URL: u,
		}}
		got, err := req.KeyPath()
		if got != c.want {
			t.Errorf("%q KeyPath == %q, want %q", c.url, got, c.want)
		}
		if !errors.Is(err, c.err) {
			t.Errorf("%q KeyPath error == %v, want %v", c.url, err, c.err)
		}
	}
}

func TestHandlerWithoutCert(t *testing.T) {
	// Reject request without a client certificate.
	// Usually the http server doesn't let it get this far, so we have a
	// custom test for it.
	req := &http.Request{
		URL: &url.URL{},
		TLS: &tls.ConnectionState{},
	}
	w := httptest.NewRecorder()
	HandlerV1(w, req)
	if w.Code != http.StatusNotAcceptable {
		t.Errorf("HandlerV1(%v) == %d, want %d",
			req, w.Code, http.StatusNotAcceptable)
	}
}
