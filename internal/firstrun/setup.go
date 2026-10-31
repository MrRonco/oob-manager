package firstrun

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"strings"
	"sync"
	"time"
)

// SetupTTL is how long a first-run setup code is valid; a restart makes a new one.
const SetupTTL = 24 * time.Hour

const codeBytes = 20 // 160 bits, 32 base32 characters

// Setup is the one-time code that protects /setup while no account exists (plan 09 §4).
// Only the code's SHA-256 is kept.
type Setup struct {
	now     func() time.Time
	mu      sync.Mutex
	digest  [sha256.Size]byte
	expires time.Time
	claimed bool // a claim is in flight
	burned  bool
}

// NewSetup creates a setup code valid for ttl and returns it once, for the log.
func NewSetup(now func() time.Time, ttl time.Duration) (*Setup, string, error) {
	raw := make([]byte, codeBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	s := &Setup{now: now, digest: sha256.Sum256([]byte(code)), expires: now().Add(ttl)}
	return s, group(code), nil
}

// group writes the code in blocks of four for reading it off a log.
func group(code string) string {
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// normalise accepts the code in any case, with or without spaces and dashes.
func normalise(code string) string {
	return strings.NewReplacer("-", "", " ", "").Replace(strings.ToUpper(strings.TrimSpace(code)))
}

// ExpiresAt is when the code stops working.
func (s *Setup) ExpiresAt() time.Time { return s.expires }

// check reports whether code is the live code (constant-time on the digests).
func (s *Setup) check(code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validLocked(code)
}

func (s *Setup) validLocked(code string) bool {
	if s.burned || !s.now().Before(s.expires) {
		return false
	}
	d := sha256.Sum256([]byte(normalise(code)))
	return subtle.ConstantTimeCompare(d[:], s.digest[:]) == 1
}

// Claim checks code and reserves the setup for one caller: concurrent claims with the
// right code get true once. The winner calls Burn when the account exists, or Release
// when creating it failed (a weak password), so the administrator can try again.
func (s *Setup) Claim(code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimed || !s.validLocked(code) {
		return false
	}
	s.claimed = true
	return true
}

// Release ends a claim that did not create the account.
func (s *Setup) Release() {
	s.mu.Lock()
	s.claimed = false
	s.mu.Unlock()
}

// Burn ends the code for good (the first admin exists).
func (s *Setup) Burn() {
	s.mu.Lock()
	s.burned, s.claimed = true, false
	s.mu.Unlock()
}

// Live reports whether the code can still be used (not burned, not expired).
func (s *Setup) Live() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.burned && s.now().Before(s.expires)
}
