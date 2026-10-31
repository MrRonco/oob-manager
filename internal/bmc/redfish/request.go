package redfish

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
)

// authFunc adds credentials to an outgoing request (nil: unauthenticated).
type authFunc func(*http.Request)

func (d *Driver) basicAuth() authFunc {
	c := d.creds.Load()
	return func(r *http.Request) { r.SetBasicAuth(c.username, c.password.Reveal()) }
}

func tokenAuth(s *session) authFunc {
	return func(r *http.Request) { r.Header.Set("X-Auth-Token", s.token.Reveal()) }
}

// send performs one request through the guarded client. uri is a validated
// service-relative path; the caller closes the response body.
func (d *Driver) send(ctx context.Context, method, uri string, body []byte, auth authFunc) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, d.cfg.Endpoint+uri, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("OData-Version", "4.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != nil {
		auth(req)
	}
	return d.httpClient.Do(req)
}

// fetch GETs uri and returns the body of a 2xx answer. Any other status becomes a
// statusError; its body is drained and dropped.
func (d *Driver) fetch(ctx context.Context, uri string, auth authFunc) ([]byte, error) {
	resp, err := d.send(ctx, http.MethodGet, uri, nil, auth)
	if err != nil {
		return nil, mapError(ctx, http.MethodGet, uri, err)
	}
	return readResponse(ctx, resp, http.MethodGet, uri)
}

func readResponse(ctx context.Context, resp *http.Response, method, uri string) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &statusError{method: method, uri: uri, code: resp.StatusCode}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, mapError(ctx, method, uri, err)
	}
	return body, nil
}

// endpointHost is the host[:port] of a validated endpoint URL.
func endpointHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Host
}
