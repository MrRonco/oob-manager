package redfish

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/secrets"
)

// session is one Redfish session this driver created. It is immutable: a new login
// publishes a new value.
type session struct {
	token secrets.Secret
	uri   string // OUR session resource (Location / @odata.id); "" if the BMC gave none
}

// getWithSession GETs uri with the session token. A 401 drops the session, waits
// reauthBackoff, logs in again and retries exactly once: a second 401 is returned.
func (d *Driver) getWithSession(ctx context.Context, uri string) ([]byte, error) {
	s, err := d.ensureSession(ctx)
	if err != nil {
		return nil, err
	}
	body, err := d.fetch(ctx, uri, tokenAuth(s))
	if !isStatus(err, http.StatusUnauthorized) {
		return body, err
	}
	d.sess.CompareAndSwap(s, nil) // the BMC no longer knows it; nothing to delete
	if werr := sleepCtx(ctx, d.opts.reauthBackoff); werr != nil {
		return nil, mapError(ctx, http.MethodGet, uri, werr)
	}
	if s, err = d.ensureSession(ctx); err != nil {
		return nil, err
	}
	return d.fetch(ctx, uri, tokenAuth(s))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ensureSession returns the live session, logging in when there is none. Concurrent
// callers wait for one login instead of each creating a session.
func (d *Driver) ensureSession(ctx context.Context) (*session, error) {
	if s := d.sess.Load(); s != nil {
		return s, nil
	}
	d.sessMu.Lock()
	defer d.sessMu.Unlock()
	if s := d.sess.Load(); s != nil {
		return s, nil
	}
	if d.closed.Load() {
		return nil, fmt.Errorf("%w: driver is closed", bmc.ErrInvalidConfig)
	}
	s, err := d.login(ctx)
	if err != nil {
		return nil, err
	}
	d.sess.Store(s)
	return s, nil
}

// login POSTs the credentials to the sessions collection named by the service root.
func (d *Driver) login(ctx context.Context) (*session, error) {
	coll, err := d.sessionsCollection(ctx)
	if err != nil {
		return nil, err
	}
	c := d.creds.Load()
	// The login body is the one place the password leaves the Secret; it is sent once
	// over the pinned TLS connection and never logged.
	body, err := json.Marshal(struct { //nolint:gosec // G117: intentional Redfish login body
		UserName string
		Password string
	}{c.username, c.password.Reveal()})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", bmc.ErrInvalidConfig)
	}
	resp, err := d.send(ctx, http.MethodPost, coll, body, nil)
	if err != nil {
		return nil, mapError(ctx, http.MethodPost, coll, err)
	}
	location, token := resp.Header.Get("Location"), resp.Header.Get("X-Auth-Token")
	doc, err := readResponse(ctx, resp, http.MethodPost, coll)
	if isStatus(err, http.StatusNotFound) || isStatus(err, http.StatusMethodNotAllowed) || isStatus(err, http.StatusNotImplemented) {
		return nil, noSessionService()
	}
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("POST %s: no X-Auth-Token: %w", coll, bmc.ErrDecode)
	}
	return &session{token: secrets.New(token), uri: sessionURIFrom(d.host, coll, location, doc)}, nil
}

func noSessionService() error {
	return fmt.Errorf("%w: BMC offers no Redfish SessionService (set bmc.auth: basic)", bmc.ErrUnsupported)
}

// sessionsCollection reads Links.Sessions from the (unauthenticated) service root and
// remembers it: it is the only URI the guard lets a POST go to.
func (d *Driver) sessionsCollection(ctx context.Context) (string, error) {
	if c := d.sessColl.Load(); c != nil {
		return *c, nil
	}
	body, err := d.fetch(ctx, serviceRoot, nil)
	if err != nil {
		return "", err
	}
	var root struct {
		Links struct {
			Sessions odataRef
		}
	}
	if err := decode(serviceRoot, body, &root); err != nil {
		return "", err
	}
	coll := strings.TrimSuffix(root.Links.Sessions.ID, "/")
	if coll == "" {
		return "", noSessionService()
	}
	if err := checkURI(coll); err != nil || coll == serviceRoot {
		return "", fmt.Errorf("service root Links.Sessions: %w", bmc.ErrDecode)
	}
	d.sessColl.Store(&coll)
	return coll, nil
}

// sessionURIFrom picks our session's URI from the Location header, else the body.
func sessionURIFrom(host, coll, location string, body []byte) string {
	if u := ownSessionURI(host, coll, location); u != "" {
		return u
	}
	var doc odataRef
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	return ownSessionURI(host, coll, doc.ID)
}

// ownSessionURI accepts only <coll>/<one segment> on this BMC, as a path; anything
// else ("" result) means the session is used but never DELETEd.
func ownSessionURI(host, coll, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return ""
	}
	if u.Host != "" && !sameHost(u.Host, host) {
		return ""
	}
	p := strings.TrimSuffix(u.Path, "/")
	id, ok := strings.CutPrefix(p, coll+"/")
	if !ok || id == "" || strings.Contains(id, "/") || checkURI(p) != nil {
		return ""
	}
	return p
}

func sameHost(a, b string) bool {
	return hostname(a) != "" && strings.EqualFold(hostname(a), hostname(b))
}

func hostname(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// Close deletes this driver's session (if any) and refuses every later request. A
// session the BMC has already dropped (401/404) is not an error.
func (d *Driver) Close(ctx context.Context) error {
	d.closed.Store(true)
	d.sessMu.Lock()
	defer d.sessMu.Unlock()
	return d.logoutLocked(ctx)
}

// SetCredentials replaces the login credentials. The current session (created with
// the old ones) is deleted first; the next request logs in with the new ones.
func (d *Driver) SetCredentials(ctx context.Context, username string, password secrets.Secret) error {
	if username == "" || password.IsZero() {
		return fmt.Errorf("%w: username and password are required", bmc.ErrInvalidConfig)
	}
	d.sessMu.Lock()
	defer d.sessMu.Unlock()
	err := d.logoutLocked(ctx)
	d.creds.Store(&credentials{username: username, password: password})
	return err
}

// logoutLocked DELETEs our session. The caller holds sessMu; the session stays
// published until the DELETE returns because the guard only lets a DELETE through to
// the URI of the current session.
func (d *Driver) logoutLocked(ctx context.Context) error {
	s := d.sess.Load()
	if s == nil {
		return nil
	}
	defer d.sess.CompareAndSwap(s, nil)
	if s.uri == "" {
		return nil
	}
	resp, err := d.send(ctx, http.MethodDelete, s.uri, nil, tokenAuth(s))
	if err != nil {
		return mapError(ctx, http.MethodDelete, s.uri, err)
	}
	_, err = readResponse(ctx, resp, http.MethodDelete, s.uri)
	if isStatus(err, http.StatusUnauthorized) || isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}
