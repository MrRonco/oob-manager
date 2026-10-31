package redfish

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/tlspin"
)

const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 5 * time.Second
)

// SPKIPin returns the hex SHA-256 of a certificate's SubjectPublicKeyInfo, the value
// expected in Config.PinSHA256.
func SPKIPin(cert *x509.Certificate) string { return tlspin.Hex(cert) }

// pinnedTLSConfig trusts exactly one public key. Chain verification is replaced (BMC
// certificates are self-signed), never skipped: VerifyConnection runs on every full
// and resumed handshake and fails closed when no certificate matches the pin.
func pinnedTLSConfig(pin []byte) *tls.Config {
	return tlspin.Config(pin, tlspin.Leaf, bmc.ErrPinMismatch)
}

// guardTransport enforces the method allowlist and the response size cap.
type guardTransport struct {
	next    http.RoundTripper
	maxBody int64
	allow   func(method, path string) bool
}

func (g *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !g.allow(req.Method, req.URL.Path) || req.URL.RawQuery != "" || req.URL.Fragment != "" {
		return nil, fmt.Errorf("%w: %s", bmc.ErrMethodNotAllowed, req.Method)
	}
	resp, err := g.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &cappedBody{rc: resp.Body, left: g.maxBody}
	return resp, nil
}

// cappedBody fails with ErrResponseTooLarge instead of silently truncating.
type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, _ := c.rc.Read(one[:]); n > 0 {
			return 0, bmc.ErrResponseTooLarge
		}
		return c.rc.Read(p)
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.rc.Read(p)
	c.left -= int64(n)
	return n, err
}

func (c *cappedBody) Close() error { return c.rc.Close() }

// newHTTPClient builds the only HTTP client the driver uses: pinned TLS, no proxy,
// no redirects, the method allowlist, capped bodies and bounded timeouts.
func newHTTPClient(cfg Config, pin []byte, allow func(method, path string) bool) *http.Client {
	base := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSClientConfig:       pinnedTLSConfig(pin),
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: cfg.Timeout,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     false, // iDRAC8 speaks HTTP/1.1 only
	}
	return &http.Client{
		Transport: &guardTransport{next: base, maxBody: cfg.MaxBodyBytes, allow: allow},
		Timeout:   cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// allowRequest is the method allowlist: GET anywhere (paths are checked by checkURI),
// POST only to the sessions collection discovered from the service root (or to an action
// URI the driver's WithActionPolicy accepts; none by default), DELETE only
// to the URI of the session this driver created, PATCH only to the URI of a
// WithAttributePatch policy (none by default). Everything else is refused.
func (d *Driver) allowRequest(method, path string) bool {
	switch method {
	case http.MethodGet:
		return true
	case http.MethodPost:
		c := d.sessColl.Load()
		return (d.cfg.Auth == AuthSession && c != nil && path == *c) || d.actionAllowed(path)
	case http.MethodDelete:
		s := d.sess.Load()
		return d.cfg.Auth == AuthSession && s != nil && s.uri != "" && path == s.uri
	case http.MethodPatch:
		return checkURI(path) == nil && d.patchAllowed(path)
	default:
		return false
	}
}
