package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// TestSecurityHeadersSnapshot pins the exact header set. Any change here is a security
// review item (docs/security.md §3).
func TestSecurityHeadersSnapshot(t *testing.T) {
	h := SecurityHeaders(true)(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://oob.example/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	nonce := regexp.MustCompile(`'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(csp)
	if nonce == nil {
		t.Fatalf("CSP has no nonce: %q", csp)
	}
	want := map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'self' 'nonce-" + nonce[1] +
			"'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; " +
			"frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
		"Strict-Transport-Security":    "max-age=63072000; includeSubDomains",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Permissions-Policy":           "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s:\n got  %q\n want %q", k, got, v)
		}
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		tls     bool
		want    bool
	}{
		{"enabled+tls", true, true, true},
		{"enabled plain", true, false, false},
		{"disabled tls", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			rec := httptest.NewRecorder()
			SecurityHeaders(tc.enabled)(okHandler()).ServeHTTP(rec, req)
			if got := rec.Header().Get("Strict-Transport-Security") != ""; got != tc.want {
				t.Fatalf("HSTS present = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNonceIsPerRequestAndInContext(t *testing.T) {
	var seen []string
	h := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := Nonce(r.Context())
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "'nonce-"+n+"'") {
			t.Errorf("context nonce %q not in CSP", n)
		}
		seen = append(seen, n)
	}))
	for range 2 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	}
	if len(seen) != 2 || seen[0] == "" || seen[0] == seen[1] {
		t.Fatalf("nonces not unique per request: %q", seen)
	}
	if len(seen[0]) < 22 {
		t.Fatalf("nonce too short (%d chars), want >= 128 bits", len(seen[0]))
	}
}

func TestNonceMissingFromContext(t *testing.T) {
	if got := Nonce(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil).Context()); got != "" {
		t.Fatalf("Nonce without middleware = %q, want empty", got)
	}
}
