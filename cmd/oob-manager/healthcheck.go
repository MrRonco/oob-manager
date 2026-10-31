package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	// defaultHealthURL is the container's own listener. The Docker HEALTHCHECK runs
	// inside the container's network namespace, so loopback is the app itself.
	defaultHealthURL = "https://127.0.0.1:8443/healthz"
	healthTimeout    = 3 * time.Second
	maxHealthBody    = 4 << 10
)

// checkHealth performs one HTTPS GET against a loopback /healthz and returns nil only
// for a 200 response. It refuses any URL that is not https on a literal loopback IP,
// because the client below skips certificate verification.
func checkHealth(ctx context.Context, rawURL string, timeout time.Duration) error {
	if err := requireLoopbackHTTPS(rawURL); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("healthcheck: build request: %w", err)
	}
	resp, err := loopbackClient().Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHealthBody))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: unexpected status %d", resp.StatusCode)
	}
	return nil
}

func requireLoopbackHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("healthcheck: invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("healthcheck: url must use https")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return errors.New("healthcheck: url host must be a loopback IP literal")
	}
	return nil
}

// loopbackClient is used ONLY for the container's self-check against 127.0.0.1.
//
// Certificate verification is skipped because the serving certificate is issued for the
// public name (or is self-signed and pinned in the browser), never for 127.0.0.1, and the
// distroless image has no CA bundle for an internal CA. The connection never leaves the
// container's network namespace (requireLoopbackHTTPS enforces a loopback IP literal),
// no credentials are sent, redirects are not followed and proxies are ignored, so there
// is nothing for a man-in-the-middle to intercept or redirect.
func loopbackClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, //nolint:gosec // loopback self-check only; see comment above.
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
