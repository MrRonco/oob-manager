package redfish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/secrets"
)

const (
	serviceRoot = "/redfish/v1"
	maxURILen   = 512
	// defaultReauthBackoff is the pause before re-creating a session the BMC rejected
	// with 401, so a BMC that drops sessions cannot be hammered with logins.
	defaultReauthBackoff = 500 * time.Millisecond
)

// Option customises a Driver; OEM drivers use these to plug in vendor knowledge.
type Option func(*options)

type options struct {
	selFallbacks  func(managerURI string) []string
	fwParser      func(memberURIs []string) ([]bmc.FirmwareItem, bool)
	now           func() time.Time
	reauthBackoff time.Duration
	actionPolicy  func(path string) bool
	attrPatch     *attrPatch
}

// WithSELFallbacks adds SEL entry-collection URIs to try after the standard
// <manager>/LogServices/Sel/Entries (e.g. the iDRAC8 <manager>/Logs/Sel).
func WithSELFallbacks(f func(managerURI string) []string) Option {
	return func(o *options) { o.selFallbacks = f }
}

// WithFirmwareParser derives firmware items from collection member URIs without
// fetching each member. Returning ok=false falls back to per-member GETs.
func WithFirmwareParser(f func(memberURIs []string) ([]bmc.FirmwareItem, bool)) Option {
	return func(o *options) { o.fwParser = f }
}

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

// withReauthBackoff overrides the pause before a re-login after a 401 (tests).
func withReauthBackoff(d time.Duration) Option {
	return func(o *options) { o.reauthBackoff = d }
}

// credentials are swapped as a whole (SetCredentials); the password stays a Secret
// until the moment it is written into a login body or a Basic auth header.
type credentials struct {
	username string
	password secrets.Secret
}

// Driver is a generic, read-only Redfish driver. It is safe for concurrent use.
//
// In AuthSession mode it logs in once (POST to the service root's Links.Sessions),
// reuses the X-Auth-Token for every GET, logs in again once when the BMC answers 401,
// and deletes its session on Close or SetCredentials.
type Driver struct {
	cfg        Config
	opts       options
	host       string // endpoint host[:port], to validate session Locations
	httpClient *http.Client
	disc       atomic.Pointer[discovery]

	creds    atomic.Pointer[credentials]
	sess     atomic.Pointer[session] // our live session, nil when none
	sessColl atomic.Pointer[string]  // sessions collection from the service root
	sessMu   sync.Mutex              // serialises login and logout
	closed   atomic.Bool
}

// New validates cfg and builds a driver. It does not contact the BMC.
func New(cfg Config, opts ...Option) (*Driver, error) {
	norm, err := cfg.normalised()
	if err != nil {
		return nil, err
	}
	pin, _ := parsePin(norm.PinSHA256) // validated by normalised
	o := options{now: time.Now, reauthBackoff: defaultReauthBackoff}
	for _, fn := range opts {
		fn(&o)
	}
	if err := o.attrPatch.validate(); err != nil {
		return nil, err
	}
	d := &Driver{cfg: norm, opts: o, host: endpointHost(norm.Endpoint)}
	d.creds.Store(&credentials{username: norm.Username, password: secrets.New(norm.Password)})
	d.cfg.Password = "" // the only copy is the Secret above
	d.httpClient = newHTTPClient(norm, pin, d.allowRequest)
	return d, nil
}

// get fetches one resource and returns its body. Every attempt (login, GET, re-login,
// retried GET) has its own per-request timeout; the parent ctx bounds them all.
func (d *Driver) get(ctx context.Context, uri string) ([]byte, error) {
	if err := checkURI(uri); err != nil {
		return nil, err
	}
	if d.closed.Load() {
		return nil, fmt.Errorf("%w: driver is closed", bmc.ErrInvalidConfig)
	}
	if d.cfg.Auth == AuthBasic {
		return d.fetch(ctx, uri, d.basicAuth())
	}
	return d.getWithSession(ctx, uri)
}

// GetJSON fetches uri and decodes it into v. uri must be a service-relative path under
// /redfish/v1 taken from config constants or BMC responses, never from a user request.
func (d *Driver) GetJSON(ctx context.Context, uri string, v any) error {
	body, err := d.get(ctx, uri)
	if err != nil {
		return err
	}
	return decode(uri, body, v)
}

// ReadOptional is GetJSON for a resource the read-only account may not be allowed to
// read (the security checks): a 401 or 403 answer is returned as bmc.ErrAuth without
// dropping the session or logging in again. Some BMCs answer 401 rather than 403 for
// a privilege failure; treating that as an expired session would cost a new BMC
// session per refused resource and leak the old one until its timeout.
func (d *Driver) ReadOptional(ctx context.Context, uri string, v any) error {
	if err := checkURI(uri); err != nil {
		return err
	}
	if d.closed.Load() {
		return fmt.Errorf("%w: driver is closed", bmc.ErrInvalidConfig)
	}
	auth, err := d.requestAuth(ctx)
	if err != nil {
		return err
	}
	body, err := d.fetch(ctx, uri, auth)
	if err != nil {
		return err
	}
	return decode(uri, body, v)
}

// Members returns the member URIs of a collection.
func (d *Driver) Members(ctx context.Context, uri string) ([]string, error) {
	var col collectionDoc
	if err := d.GetJSON(ctx, uri, &col); err != nil {
		return nil, err
	}
	return col.uris(), nil
}

func decode(uri string, body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("GET %s: %w", uri, bmc.ErrDecode)
	}
	return nil
}

// checkURI keeps every request on the configured BMC under /redfish/v1.
func checkURI(uri string) error {
	bad := len(uri) > maxURILen ||
		(uri != serviceRoot && !strings.HasPrefix(uri, serviceRoot+"/")) ||
		strings.Contains(uri, "..") || strings.Contains(uri, "//") ||
		strings.ContainsFunc(uri, func(r rune) bool { return r <= ' ' || r == 0x7f || strings.ContainsRune(`\\%?#`, r) })
	if bad {
		return fmt.Errorf("%w: refusing BMC URI", bmc.ErrInvalidConfig)
	}
	return nil
}

// statusError is a non-2xx answer. It unwraps to the matching bmc sentinel; the
// response body is never kept, so BMC text cannot reach logs through error strings.
type statusError struct {
	method, uri string
	code        int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %v", e.method, e.uri, e.code, statusSentinel(e.code))
}

func (e *statusError) Unwrap() error { return statusSentinel(e.code) }

// isStatus reports whether err is an HTTP answer with the given status code.
func isStatus(err error, code int) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == code
}

// mapError converts transport errors into wrapped bmc sentinels.
func mapError(ctx context.Context, method, uri string, err error) error {
	var se *statusError
	var netErr net.Error
	switch {
	case errors.As(err, &se):
		return se
	case errors.Is(err, bmc.ErrPinMismatch):
		return fmt.Errorf("%s %s: %w", method, uri, bmc.ErrPinMismatch)
	case errors.Is(err, bmc.ErrResponseTooLarge), errors.Is(err, bmc.ErrMethodNotAllowed):
		return fmt.Errorf("%s %s: %w", method, uri, unwrapSentinel(err))
	case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("%s %s: %w", method, uri, bmc.ErrTimeout)
	case errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Errorf("%s %s: %w", method, uri, bmc.ErrTimeout)
	case errors.As(err, &netErr):
		return fmt.Errorf("%s %s: %w", method, uri, bmc.ErrUnreachable)
	default:
		return fmt.Errorf("%s %s: %w", method, uri, bmc.ErrDecode)
	}
}

func unwrapSentinel(err error) error {
	if errors.Is(err, bmc.ErrResponseTooLarge) {
		return bmc.ErrResponseTooLarge
	}
	return bmc.ErrMethodNotAllowed
}

func statusSentinel(code int) error {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return bmc.ErrAuth
	case http.StatusNotFound, http.StatusGone, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return bmc.ErrNotFound
	default:
		return bmc.ErrBMC
	}
}

// isAbsent reports whether err means "this BMC does not offer the resource".
func isAbsent(err error) bool { return errors.Is(err, bmc.ErrNotFound) }
