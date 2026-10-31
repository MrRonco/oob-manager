package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// nonceBytes gives a 128-bit CSP nonce.
const nonceBytes = 16

// hstsValue: two years, subdomains. No preload: the host name is LAN-only (decision 1).
const hstsValue = "max-age=63072000; includeSubDomains"

const permissionsPolicy = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), " +
	"magnetometer=(), microphone=(), payment=(), usb=()"

type nonceKey struct{}

// Nonce returns the CSP nonce for this request, or "" when SecurityHeaders did not run.
// Templates put it on every <script> element.
func Nonce(ctx context.Context) string {
	n, _ := ctx.Value(nonceKey{}).(string)
	return n
}

// SecurityHeaders sets the docs/security.md §3 header set on every response and stores a
// fresh nonce in the request context. HSTS is sent only when enabled and the request
// arrived over TLS.
func SecurityHeaders(hsts bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := newNonce()
			h := w.Header()
			h.Set("Content-Security-Policy", csp(nonce))
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Permissions-Policy", permissionsPolicy)
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Cache-Control", "no-store")
			if hsts && r.TLS != nil {
				h.Set("Strict-Transport-Security", hstsValue)
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nonceKey{}, nonce)))
		})
	}
}

func csp(nonce string) string {
	return "default-src 'none'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self'; " +
		"img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; " +
		"base-uri 'none'; form-action 'self'"
}

// newNonce uses crypto/rand.Read, which never returns an error (Go 1.24+): it aborts the
// process if the OS entropy source fails, so there is no weak fallback path.
func newNonce() string {
	b := make([]byte, nonceBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
