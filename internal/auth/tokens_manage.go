package auth

import (
	"context"
	"fmt"
	"time"
)

// Token lifetime bounds for IssueExpiring (0 = never expires is also allowed).
const (
	MinTokenLifetime = time.Hour
	MaxTokenLifetime = 730 * 24 * time.Hour
)

// TokenStatus is the state of a token at a given time.
type TokenStatus string

// Token states. Revoked wins over expired.
const (
	TokenActive  TokenStatus = "active"
	TokenRevoked TokenStatus = "revoked"
	TokenExpired TokenStatus = "expired"
)

// StatusAt reports whether t is usable at now. The expiry instant itself is expired.
func (t APIToken) StatusAt(now time.Time) TokenStatus {
	switch {
	case !t.RevokedAt.IsZero():
		return TokenRevoked
	case !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt):
		return TokenExpired
	default:
		return TokenActive
	}
}

// List returns every token, oldest first, with the stored hash removed: listing never
// needs it, and nothing derived from it should reach output.
func (s *TokenService) List(ctx context.Context) ([]APIToken, error) {
	all, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list tokens: %w", err)
	}
	out := make([]APIToken, 0, len(all))
	for _, t := range all {
		t.Hash = nil
		out = append(out, t)
	}
	return out, nil
}

// ValidateTokenLifetime checks a lifetime for IssueExpiring (0 = never expires).
func ValidateTokenLifetime(ttl time.Duration) error {
	if ttl == 0 || (ttl >= MinTokenLifetime && ttl <= MaxTokenLifetime) {
		return nil
	}
	return fmt.Errorf("auth: token lifetime must be 0 (never) or between %s and %d days",
		MinTokenLifetime, int(MaxTokenLifetime.Hours()/24))
}
