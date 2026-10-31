package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

// Defaults of a Dialer and a client.
const (
	DefaultDialTimeout    = 5 * time.Second
	DefaultMaxHeaderBytes = 16 << 10
)

// ErrBadAddress is a dial address that is not host:port.
var ErrBadAddress = errors.New("egress: bad address")

// Dialer opens TCP connections only to addresses the policy checked.
type Dialer struct {
	Policy Policy
	// Dial opens the TCP connection (nil: net.Dialer with DefaultDialTimeout). It is only
	// ever called with an IP literal the policy checked.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialContext resolves addr's host under the policy and dials the checked address.
func (d Dialer) DialContext(ctx context.Context, addr string, plaintext bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, ErrBadAddress
	}
	ip, err := d.Policy.Resolve(ctx, host, plaintext)
	if err != nil {
		return nil, err
	}
	dial := d.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: DefaultDialTimeout}).DialContext
	}
	return dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
}

// TLSConfig clones base (nil: system roots) with a floor of TLS 1.2 and serverName set.
func TLSConfig(base *tls.Config, serverName string) *tls.Config {
	var c *tls.Config
	if base != nil {
		c = base.Clone()
	} else {
		c = &tls.Config{} //nolint:gosec // G402: MinVersion is set just below
	}
	c.MinVersion = max(c.MinVersion, tls.VersionTLS12)
	c.ServerName = serverName
	return c
}

// ClientConfig shapes a one-shot client.
type ClientConfig struct {
	Dialer Dialer
	// TLS is the client TLS base (nil: system roots). Tests set RootCAs.
	TLS *tls.Config
	// Timeout bounds the whole request including the body read (0: none).
	Timeout time.Duration
	// HeaderTimeout bounds the wait for the response headers (0: Timeout).
	HeaderTimeout time.Duration
	// Plaintext permits http:// (the policy then allows only Allowed addresses).
	Plaintext bool
}

// NewClient is a one-shot client: no proxy, no redirects, no keep-alive, bounded
// headers, and a dialer that only reaches policy-checked addresses.
func NewClient(c ClientConfig) *http.Client {
	header := c.HeaderTimeout
	if header <= 0 {
		header = c.Timeout
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return c.Dialer.DialContext(ctx, addr, c.Plaintext)
		},
		TLSClientConfig:        TLSConfig(c.TLS, ""),
		TLSHandshakeTimeout:    DefaultDialTimeout,
		ResponseHeaderTimeout:  header,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: DefaultMaxHeaderBytes,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       c.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
