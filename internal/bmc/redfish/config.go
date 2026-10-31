package redfish

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// Defaults from docs/system_design.md §2.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultMaxBodyBytes = 4 << 20 // 4 MiB
	maxTimeout          = 2 * time.Minute
)

// AuthMode selects the Redfish authentication scheme.
type AuthMode string

// Supported auth modes.
const (
	AuthSession AuthMode = "session"
	AuthBasic   AuthMode = "basic"
)

// Config describes one BMC. Every field comes from the validated app config and the
// secrets store, never from a request.
type Config struct {
	// Endpoint is the BMC base URL: https://host[:port], nothing else.
	Endpoint string
	Username string
	Password string
	// PinSHA256 is the hex SHA-256 of the BMC certificate's SubjectPublicKeyInfo
	// (colons and case are ignored). Required: BMC certificates are self-signed.
	PinSHA256 string
	// Timeout bounds every single HTTP request (default 10 s).
	Timeout time.Duration
	// MaxBodyBytes caps every response body (default 4 MiB).
	MaxBodyBytes int64
	// Auth selects how requests authenticate: AuthSession (default) logs in once and
	// reuses the X-Auth-Token; AuthBasic sends the credentials on every request, for
	// BMCs without a SessionService.
	Auth AuthMode
}

// normalised validates c and returns a copy with defaults applied. Errors never
// include the password.
func (c Config) normalised() (Config, error) {
	if err := validateEndpoint(c.Endpoint); err != nil {
		return Config{}, err
	}
	if c.Username == "" || c.Password == "" {
		return Config{}, fmt.Errorf("%w: username and password are required", bmc.ErrInvalidConfig)
	}
	if _, err := parsePin(c.PinSHA256); err != nil {
		return Config{}, err
	}
	if c.Timeout < 0 || c.Timeout > maxTimeout {
		return Config{}, fmt.Errorf("%w: timeout must be between 0 and %s", bmc.ErrInvalidConfig, maxTimeout)
	}
	if c.MaxBodyBytes < 0 {
		return Config{}, fmt.Errorf("%w: max body bytes must not be negative", bmc.ErrInvalidConfig)
	}
	switch c.Auth {
	case "", AuthSession, AuthBasic:
	default:
		return Config{}, fmt.Errorf("%w: auth must be session or basic", bmc.ErrInvalidConfig)
	}
	out := c
	if out.Timeout == 0 {
		out.Timeout = DefaultTimeout
	}
	if out.MaxBodyBytes == 0 {
		out.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if out.Auth == "" {
		out.Auth = AuthSession
	}
	out.Endpoint = strings.TrimSuffix(out.Endpoint, "/")
	return out, nil
}

func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: endpoint is not a URL", bmc.ErrInvalidConfig)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%w: endpoint must use https", bmc.ErrInvalidConfig)
	case u.Host == "" || u.Hostname() == "":
		return fmt.Errorf("%w: endpoint has no host", bmc.ErrInvalidConfig)
	case u.User != nil:
		return fmt.Errorf("%w: endpoint must not carry credentials", bmc.ErrInvalidConfig)
	case (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return fmt.Errorf("%w: endpoint must be scheme://host[:port] only", bmc.ErrInvalidConfig)
	}
	return nil
}

// parsePin decodes a hex SHA-256 pin, tolerating colons and either case.
func parsePin(pin string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(pin), ":", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%w: tls pin must be a hex SHA-256 of the certificate SPKI", bmc.ErrInvalidConfig)
	}
	return b, nil
}
