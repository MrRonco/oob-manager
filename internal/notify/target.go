package notify

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"oob-manager/internal/secrets"
)

// Kind is a closed enum of target kinds.
type Kind string

// Target kinds.
const (
	KindNtfy     Kind = "ntfy"
	KindPushover Kind = "pushover"
	KindGotify   Kind = "gotify"
	KindWebhook  Kind = "webhook"
	KindEmail    Kind = "email"
)

// Kinds returns every kind in display order.
func Kinds() []Kind { return []Kind{KindNtfy, KindPushover, KindGotify, KindWebhook, KindEmail} }

// ParseKind validates a kind name exactly.
func ParseKind(s string) (Kind, error) {
	if k := Kind(s); slices.Contains(Kinds(), k) {
		return k, nil
	}
	return "", fmt.Errorf("%w: unknown target kind %q", ErrInvalid, s)
}

// Label is the kind as shown in the UI.
func (k Kind) Label() string {
	switch k {
	case KindNtfy:
		return "ntfy"
	case KindPushover:
		return "Pushover"
	case KindGotify:
		return "Gotify"
	case KindWebhook:
		return "Webhook (JSON)"
	case KindEmail:
		return "Email (SMTP)"
	default:
		return string(k)
	}
}

// EmailSecurity is how the SMTP connection is protected.
type EmailSecurity string

// SMTP transport security.
const (
	EmailSTARTTLS EmailSecurity = "starttls" // required STARTTLS (port 587)
	EmailTLS      EmailSecurity = "tls"      // implicit TLS (port 465)
	EmailNone     EmailSecurity = "none"     // plaintext, LAN relay only, no auth
)

// Source says where a target is defined.
type Source string

// Target sources.
const (
	SourceFile Source = "file" // config.yaml notifications.targets: read-only in the browser
	SourceDB   Source = "db"   // created in Settings → Notifications
)

// DefaultPushoverURL is the Pushover message API.
const DefaultPushoverURL = "https://api.pushover.net/1/messages.json"

// ErrInvalid marks a target that fails validation; the message is safe to show.
var ErrInvalid = errors.New("notify: invalid")

// Limits for target fields.
const (
	maxNameLen   = 64
	maxURLLen    = 512
	maxRecipient = 10
	maxSecretLen = 512
)

var targetIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Target is one destination. It is a value; the service publishes immutable copies.
// It holds no secret: those live in Secrets, sealed at rest.
type Target struct {
	ID      string
	Name    string
	Kind    Kind
	URL     string // ntfy topic URL, Pushover API, Gotify base, webhook URL, smtp://host:port
	Enabled bool
	// AllowPlaintext permits http (or SMTP without TLS) to a notifications.allowed_networks
	// address. Off by default; the policy refuses plaintext anywhere else.
	AllowPlaintext bool
	// IncludeDetail sends BMC-supplied event text (SEL messages). Off by default.
	IncludeDetail bool
	Classes       []Class
	MinSeverity   Severity
	// PushoverEmergency maps critical events to Pushover priority 2 (repeats until
	// acknowledged). Off by default.
	PushoverEmergency bool
	EmailFrom         string
	EmailTo           []string
	EmailSecurity     EmailSecurity

	Source        Source
	SecretVersion int // 0 = no secret stored
	UpdatedAt     time.Time
	UpdatedBy     string
}

// clone returns a copy that shares no slice with t.
func (t Target) clone() Target {
	t.Classes = slices.Clone(t.Classes)
	t.EmailTo = slices.Clone(t.EmailTo)
	return t
}

// Wants reports whether t takes e: enabled, subscribed to the class, at or above the
// minimum severity. A test event only ever goes to the target it was sent from.
func (t Target) Wants(e Event) bool {
	if !t.Enabled || e.Class == ClassTest || e.ExcludeTarget == t.ID {
		return false
	}
	if e.Severity < t.MinSeverity {
		return false
	}
	if e.Class == ClassMaintenance { // sent wherever the alerts it pauses would go
		return slices.ContainsFunc(t.Classes, Class.Mutable)
	}
	return slices.Contains(t.Classes, e.Class)
}

// Host is the destination host for display and audit (never the full URL: an ntfy
// topic or a webhook path can act as a credential).
func (t Target) Host() string {
	u, err := url.Parse(t.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Secrets are a target's credentials. Meaning per kind: ntfy Token (optional access
// token); Pushover Token (application token) and User (user key); Gotify Token (app
// token); webhook Token (HMAC signing secret, optional); email User and Password (optional
// SMTP AUTH, both or neither).
type Secrets struct {
	Token    secrets.Secret
	User     secrets.Secret
	Password secrets.Secret
}

// IsZero reports whether no secret is set.
func (s Secrets) IsZero() bool { return s.Token.IsZero() && s.User.IsZero() && s.Password.IsZero() }

// Validate checks t and the secrets it would be stored with. Messages name the field and
// the rule; they never echo a secret.
func Validate(t Target, sec Secrets) error {
	if err := validateIdentity(t); err != nil {
		return err
	}
	if err := validateDestination(t); err != nil {
		return err
	}
	if err := validateSubscription(t); err != nil {
		return err
	}
	if err := validateSecrets(t.Kind, sec); err != nil {
		return err
	}
	return validatePlaintextAuth(t, sec)
}

func validateIdentity(t Target) error {
	if !targetIDPattern.MatchString(t.ID) {
		return fmt.Errorf("%w: id must be 1-64 of a-z, 0-9, _ and -, starting with a letter or digit", ErrInvalid)
	}
	if t.Name == "" || len(t.Name) > maxNameLen || !printable(t.Name) {
		return fmt.Errorf("%w: name must be 1-%d printable characters", ErrInvalid, maxNameLen)
	}
	_, err := ParseKind(string(t.Kind))
	return err
}

func validateDestination(t Target) error {
	if t.Kind == KindEmail {
		return validateEmail(t)
	}
	if t.PushoverEmergency && t.Kind != KindPushover {
		return fmt.Errorf("%w: emergency priority applies to Pushover only", ErrInvalid)
	}
	_, err := checkHTTPURL(t.URL, t.AllowPlaintext)
	return err
}

// checkHTTPURL parses an http(s) destination: https (http only with allowPlaintext), a
// host, no user info and no fragment.
func checkHTTPURL(raw string, allowPlaintext bool) (*url.URL, error) {
	if raw == "" || len(raw) > maxURLLen || !printable(raw) || strings.ContainsAny(raw, " \\") {
		return nil, fmt.Errorf("%w: URL must be 1-%d characters without spaces", ErrInvalid, maxURLLen)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: URL must be an absolute https:// address", ErrInvalid)
	}
	switch {
	case u.User != nil:
		return nil, fmt.Errorf("%w: URL must not contain a user name or password (use the secret fields)", ErrInvalid)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%w: URL must not contain a fragment", ErrInvalid)
	case u.Scheme == "https":
	case u.Scheme == "http" && allowPlaintext:
	case u.Scheme == "http":
		return nil, fmt.Errorf("%w: http:// needs \"allow plaintext on the LAN\" and an address in notifications.allowed_networks", ErrInvalid)
	default:
		return nil, fmt.Errorf("%w: URL scheme must be https", ErrInvalid)
	}
	if err := checkPort(u.Port()); err != nil {
		return nil, err
	}
	return u, nil
}

func checkPort(p string) error {
	if p == "" {
		return nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: port must be 1-65535", ErrInvalid)
	}
	return nil
}

func validateEmail(t Target) error {
	if _, _, err := smtpHostPort(t.URL); err != nil {
		return err
	}
	switch t.EmailSecurity {
	case EmailSTARTTLS, EmailTLS:
	case EmailNone:
		if !t.AllowPlaintext {
			return fmt.Errorf("%w: plaintext SMTP needs \"allow plaintext on the LAN\"", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: email security must be starttls, tls or none", ErrInvalid)
	}
	if err := checkAddress(t.EmailFrom); err != nil {
		return fmt.Errorf("%w: from address: %v", ErrInvalid, err)
	}
	if len(t.EmailTo) == 0 || len(t.EmailTo) > maxRecipient {
		return fmt.Errorf("%w: email needs 1-%d recipients", ErrInvalid, maxRecipient)
	}
	for _, to := range t.EmailTo {
		if err := checkAddress(to); err != nil {
			return fmt.Errorf("%w: recipient: %v", ErrInvalid, err)
		}
	}
	return nil
}

// smtpHostPort parses smtp://host:port.
func smtpHostPort(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "smtp" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return "", "", fmt.Errorf("%w: SMTP server must be smtp://host:port", ErrInvalid)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" || port == "" {
		return "", "", fmt.Errorf("%w: SMTP server must be smtp://host:port", ErrInvalid)
	}
	if err := checkPort(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}

// checkAddress accepts one bare address (no display name, no CR/LF).
func checkAddress(s string) error {
	if s == "" || len(s) > 254 || strings.ContainsAny(s, "\r\n<>,; \"") {
		return errors.New("must be a single plain address like ops@example.org")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s {
		return errors.New("must be a single plain address like ops@example.org")
	}
	return nil
}

func validateSubscription(t Target) error {
	for _, c := range t.Classes {
		if _, err := ParseClass(string(c)); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	if !slices.Contains(Severities(), t.MinSeverity) {
		return fmt.Errorf("%w: minimum severity must be info, warning or critical", ErrInvalid)
	}
	return nil
}

func validateSecrets(k Kind, s Secrets) error {
	for _, v := range []secrets.Secret{s.Token, s.User, s.Password} {
		if b := v.Bytes(); len(b) > maxSecretLen || strings.ContainsAny(string(b), "\r\n") {
			return fmt.Errorf("%w: secrets must be at most %d characters on one line", ErrInvalid, maxSecretLen)
		}
	}
	switch k {
	case KindPushover:
		if s.Token.IsZero() || s.User.IsZero() {
			return fmt.Errorf("%w: Pushover needs an application token and a user key", ErrInvalid)
		}
	case KindGotify:
		if s.Token.IsZero() {
			return fmt.Errorf("%w: Gotify needs an application token", ErrInvalid)
		}
	case KindEmail:
		if s.User.IsZero() != s.Password.IsZero() {
			return fmt.Errorf("%w: SMTP authentication needs both a user name and a password, or neither", ErrInvalid)
		}
	}
	return nil
}

// validatePlaintextAuth refuses SMTP AUTH over a plaintext connection (passwords never
// leave in the clear).
func validatePlaintextAuth(t Target, s Secrets) error {
	if t.Kind == KindEmail && t.EmailSecurity == EmailNone && !s.User.IsZero() {
		return fmt.Errorf("%w: SMTP authentication needs TLS (starttls or tls)", ErrInvalid)
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
