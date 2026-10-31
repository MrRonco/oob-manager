package redfish

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"oob-manager/internal/bmc"
)

// WithActionPolicy lets the driver POST to the Redfish action URIs policy accepts.
// policy must be an exact-match check on a fixed URI shape (for example the Dell
// GetKVMSession action); a driver without this option can POST only its session login.
// Only the console launcher builds a driver with a policy; the pollers never do.
func WithActionPolicy(policy func(path string) bool) Option {
	return func(o *options) { o.actionPolicy = policy }
}

// actionAllowed is the guard's rule for action POSTs.
func (d *Driver) actionAllowed(path string) bool {
	return d.opts.actionPolicy != nil && checkURI(path) == nil && d.opts.actionPolicy(path)
}

// PostAction POSTs body (JSON) to the action at uri and decodes a 2xx answer into out
// (nil discards it). uri must come from config or a BMC response and must pass the
// driver's action policy; anything else is ErrMethodNotAllowed before a byte is sent.
// A 401 is not retried: actions are not idempotent.
func (d *Driver) PostAction(ctx context.Context, uri string, body, out any) error {
	if err := checkURI(uri); err != nil {
		return err
	}
	if !d.actionAllowed(uri) {
		return fmt.Errorf("POST %s: %w", uri, bmc.ErrMethodNotAllowed)
	}
	if d.closed.Load() {
		return fmt.Errorf("%w: driver is closed", bmc.ErrInvalidConfig)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("POST %s: %w", uri, bmc.ErrInvalidConfig)
	}
	auth, err := d.requestAuth(ctx)
	if err != nil {
		return err
	}
	resp, err := d.send(ctx, http.MethodPost, uri, payload, auth)
	if err != nil {
		return mapError(ctx, http.MethodPost, uri, err)
	}
	doc, err := readResponse(ctx, resp, http.MethodPost, uri)
	if err != nil || out == nil {
		return err
	}
	if err := json.Unmarshal(doc, out); err != nil {
		return fmt.Errorf("POST %s: %w", uri, bmc.ErrDecode)
	}
	return nil
}

// requestAuth returns the credentials for one request: the session token, logging in
// first if needed, or Basic auth.
func (d *Driver) requestAuth(ctx context.Context) (authFunc, error) {
	if d.cfg.Auth == AuthBasic {
		return d.basicAuth(), nil
	}
	s, err := d.ensureSession(ctx)
	if err != nil {
		return nil, err
	}
	return tokenAuth(s), nil
}
