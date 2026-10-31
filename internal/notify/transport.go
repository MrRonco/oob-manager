package notify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"oob-manager/internal/egress"
)

// Error classes recorded in a target's status and in logs (never response text).
const (
	classBlocked     = "blocked"
	classDNS         = "dns"
	classTimeout     = "timeout"
	classTLS         = "tls"
	classNetwork     = "network"
	classRedirect    = "redirect"
	classHTTP4xx     = "http_4xx"
	classHTTP5xx     = "http_5xx"
	classRateLimited = "rate_limited"
	classSMTP        = "smtp"
	classSecrets     = "secrets"
	classDropped     = "dropped"
)

// Transport defaults.
const (
	DefaultTimeout     = 10 * time.Second
	defaultDialTimeout = egress.DefaultDialTimeout
	maxResponseBytes   = 4 << 10
	userAgent          = "oob-manager-notify/1"
)

// deliveryError carries a class and whether retrying can help.
type deliveryError struct {
	class string
	retry bool
	err   error
}

func (e *deliveryError) Error() string { return e.err.Error() }
func (e *deliveryError) Unwrap() error { return e.err }

func failed(class string, retry bool, format string, args ...any) error {
	return &deliveryError{class: class, retry: retry, err: fmt.Errorf(format, args...)}
}

// ErrorClass maps a delivery error to its class.
func ErrorClass(err error) string {
	var de *deliveryError
	var dns *egress.DNSError
	var ne net.Error
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var rh tls.RecordHeaderError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrBlocked), errors.Is(err, egress.ErrBadAddress):
		return classBlocked
	case errors.As(err, &de):
		return de.class
	case errors.As(err, &dns):
		return classDNS
	case errors.As(err, &cv), errors.As(err, &ua), errors.As(err, &hn), errors.As(err, &rh):
		return classTLS
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return classTimeout
	default:
		return classNetwork
	}
}

// retryable reports whether another attempt can succeed.
func retryable(err error) bool {
	var de *deliveryError
	if errors.As(err, &de) {
		return de.retry
	}
	switch ErrorClass(err) {
	case classBlocked, classTLS:
		return false
	default:
		return true
	}
}

// Transport sends over the network under the SSRF policy.
type Transport struct {
	Policy Policy
	// Dial opens TCP connections (default net.Dialer with a 5 s timeout). It is only
	// ever called with an IP literal the policy checked.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLS is the client TLS base (nil: system roots). Tests set RootCAs.
	TLS *tls.Config
	// Timeout bounds one attempt (default 10 s).
	Timeout time.Duration
}

func (t Transport) withDefaults() Transport {
	if t.Dial == nil {
		d := &net.Dialer{Timeout: defaultDialTimeout}
		t.Dial = d.DialContext
	}
	if t.Timeout <= 0 {
		t.Timeout = DefaultTimeout
	}
	return t
}

// tlsConfig is the base TLS config with a floor of TLS 1.2 and serverName set.
func (t Transport) tlsConfig(serverName string) *tls.Config {
	return egress.TLSConfig(t.TLS, serverName)
}

func (t Transport) dialer() egress.Dialer {
	return egress.Dialer{Policy: t.Policy.egress(), Dial: t.Dial}
}

// dialChecked resolves host under the policy and dials the checked address.
func (t Transport) dialChecked(ctx context.Context, addr string, plaintext bool) (net.Conn, error) {
	conn, err := t.dialer().DialContext(ctx, addr, plaintext)
	if errors.Is(err, egress.ErrBadAddress) {
		return nil, failed(classBlocked, false, "notify: bad address")
	}
	return conn, err
}

// client is a one-shot client (internal/egress): no proxy, no redirects, no
// keep-alive, bounded headers, and a dialer that only reaches policy-checked addresses.
func (t Transport) client(plaintext bool) *http.Client {
	return egress.NewClient(egress.ClientConfig{Dialer: t.dialer(), TLS: t.TLS, Timeout: t.Timeout, Plaintext: plaintext})
}

// do sends req and classifies the outcome. The response body is read up to a small
// cap and discarded: nothing a receiver says reaches logs, audit or the UI.
func (t Transport) do(req *http.Request) error {
	t = t.withDefaults()
	plaintext := req.URL.Scheme == "http"
	req.Header.Set("User-Agent", userAgent)
	cl := t.client(plaintext)
	defer cl.CloseIdleConnections()
	resp, err := cl.Do(req) //nolint:gosec // G704: the URL passed Validate and the dialer enforces the SSRF policy
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	return statusError(resp.StatusCode)
}

func statusError(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code >= 300 && code < 400:
		return failed(classRedirect, false, "notify: receiver answered with a redirect (%d); redirects are not followed", code)
	case code == http.StatusTooManyRequests:
		return failed(classRateLimited, true, "notify: receiver rate limited the request (429)")
	case code >= 400 && code < 500:
		return failed(classHTTP4xx, false, "notify: receiver refused the request (%d)", code)
	default:
		return failed(classHTTP5xx, true, "notify: receiver failed (%d)", code)
	}
}
