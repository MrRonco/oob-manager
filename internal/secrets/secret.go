// Package secrets decrypts the age-encrypted credential file and hands out typed Secret
// values that refuse to print themselves (docs/security.md I1, I2).
package secrets

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
)

// Redacted is what every textual rendering of a Secret produces.
const Redacted = "[redacted]"

// Secret holds sensitive bytes. Every formatting, encoding and logging path prints
// Redacted; the only way to read the value is Reveal or Bytes, which are easy to grep.
// A Secret is immutable: constructors and Bytes copy.
type Secret struct {
	v []byte
}

// New wraps a string.
func New(s string) Secret { return Secret{v: []byte(s)} }

// FromBytes wraps a copy of b.
func FromBytes(b []byte) Secret { return Secret{v: append([]byte(nil), b...)} }

// Reveal returns the plaintext. Call it only at the point of use (BMC login, HMAC key).
func (s Secret) Reveal() string { return string(s.v) }

// Bytes returns a copy of the plaintext.
func (s Secret) Bytes() []byte { return append([]byte(nil), s.v...) }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return len(s.v) == 0 }

// Equal compares in constant time.
func (s Secret) Equal(o Secret) bool { return subtle.ConstantTimeCompare(s.v, o.v) == 1 }

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer (%#v).
func (Secret) GoString() string { return Redacted }

// Format implements fmt.Formatter so every verb (%x, %q, %d …) redacts.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler (YAML, XML, map keys).
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// Credential is one BMC account from the credential file.
type Credential struct {
	Username string
	Password Secret
}

// LogValue logs the username only.
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(slog.String("username", c.Username), slog.String("password", Redacted))
}

// HasLogin reports whether the entry has both a username and a password (a BMC login,
// as opposed to a password-only VNC entry).
func (c Credential) HasLogin() bool { return c.Username != "" && !c.Password.IsZero() }
