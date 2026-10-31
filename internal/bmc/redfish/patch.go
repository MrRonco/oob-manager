package redfish

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"oob-manager/internal/bmc"
)

// attrPatch is the only PATCH a driver may send: one exact URI and a fixed set of
// integer attribute keys.
type attrPatch struct {
	uri  string
	keys []string
}

// WithAttributePatch lets the driver PATCH {"Attributes": {...}} to exactly uri, with
// attribute keys from keys only (for example Dell's
// ThermalSettings.1.MinimumFanSpeed). Only the fan floor applier builds a driver with
// this option; the pollers never do. An invalid uri or an empty key list makes New fail.
func WithAttributePatch(uri string, keys ...string) Option {
	return func(o *options) {
		o.attrPatch = &attrPatch{uri: uri, keys: append([]string(nil), keys...)}
	}
}

func (p *attrPatch) validate() error {
	if p == nil {
		return nil
	}
	if checkURI(p.uri) != nil || len(p.keys) == 0 || slices.Contains(p.keys, "") {
		return fmt.Errorf("%w: attribute PATCH policy needs a valid URI and keys", bmc.ErrInvalidConfig)
	}
	return nil
}

// patchAllowed is the transport guard's rule for PATCH: the policy URI, nothing else.
func (d *Driver) patchAllowed(path string) bool {
	p := d.opts.attrPatch
	return p != nil && path == p.uri
}

// PatchAttributes sends {"Attributes": attrs} to uri. Both must match the driver's
// WithAttributePatch policy (exact URI, every key allowed, at least one key); anything
// else is ErrMethodNotAllowed before a byte is sent. A 401 is not retried.
func (d *Driver) PatchAttributes(ctx context.Context, uri string, attrs map[string]int) error {
	if err := checkURI(uri); err != nil {
		return err
	}
	if !d.patchAllowed(uri) || !d.keysAllowed(attrs) {
		return fmt.Errorf("PATCH %s: %w", uri, bmc.ErrMethodNotAllowed)
	}
	if d.closed.Load() {
		return fmt.Errorf("%w: driver is closed", bmc.ErrInvalidConfig)
	}
	payload, err := json.Marshal(map[string]map[string]int{"Attributes": attrs})
	if err != nil {
		return fmt.Errorf("PATCH %s: %w", uri, bmc.ErrInvalidConfig)
	}
	auth, err := d.requestAuth(ctx)
	if err != nil {
		return err
	}
	resp, err := d.send(ctx, http.MethodPatch, uri, payload, auth)
	if err != nil {
		return mapError(ctx, http.MethodPatch, uri, err)
	}
	_, err = readResponse(ctx, resp, http.MethodPatch, uri)
	return err
}

func (d *Driver) keysAllowed(attrs map[string]int) bool {
	if len(attrs) == 0 {
		return false
	}
	for k := range attrs {
		if !slices.Contains(d.opts.attrPatch.keys, k) {
			return false
		}
	}
	return true
}
