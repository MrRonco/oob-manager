package auth

import (
	"context"
	"errors"
	"regexp"
	"time"
)

// newUsernamePattern is the stricter rule for accounts created in the browser
// (settings_design.md §3): a letter first, 3-32 characters. Existing accounts keep the
// looser login pattern.
var newUsernamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)

// ValidateNewUsername checks a username for a new account.
func ValidateNewUsername(s string) error {
	if !newUsernamePattern.MatchString(s) {
		return errors.New("username must be 3-32 characters: a lowercase letter, then letters, digits, . _ or -")
	}
	return nil
}

// NewLinkToken returns a fresh 256-bit one-time link secret (base64url, safe in a URL
// path) and the SHA-256 to store. The raw value is shown once and never stored.
func NewLinkToken() (raw string, hash []byte) {
	raw = newOpaque()
	b, _ := decodeOpaque(raw)
	return raw, hashOpaque(b)
}

// HashLinkToken returns the storage hash of a link secret, or false when raw is not a
// well-formed link secret (so malformed input never reaches the database).
func HashLinkToken(raw string) ([]byte, bool) {
	b, ok := decodeOpaque(raw)
	if !ok {
		return nil, false
	}
	return hashOpaque(b), true
}

// StepUpExpires is when s's step-up window closes (zero when s never stepped up).
func (a *Authenticator) StepUpExpires(s Session) time.Time {
	if s.StepUpAt.IsZero() {
		return time.Time{}
	}
	return s.StepUpAt.Add(a.policy().StepUpWindow)
}

// PendingUsername returns the username of a pending (password accepted, TOTP
// outstanding) session, so the TOTP page can say who is signing in. Anything else,
// including an expired pending session, is ok=false.
func (a *Authenticator) PendingUsername(ctx context.Context, token string) (string, bool) {
	s, _, err := a.lookup(ctx, token)
	if err != nil || s.Level != LevelPending || a.cfg.Now().Sub(s.CreatedAt) > a.cfg.PendingTTL {
		return "", false
	}
	u, err := a.cfg.Users.GetByID(ctx, s.UserID)
	if err != nil || u.Disabled {
		return "", false
	}
	return u.Username, true
}
