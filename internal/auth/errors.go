package auth

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned to callers. Handlers map them to generic user messages; the
// distinction between "wrong password", "unknown user" and "disabled" is never exposed.
var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrLockedOut          = errors.New("auth: temporarily locked out")
	ErrSessionInvalid     = errors.New("auth: session invalid or expired")
	ErrInvalidToken       = errors.New("auth: invalid API token")
)

// LockedOutError carries how long to wait (for a Retry-After header). It matches
// ErrLockedOut with errors.Is.
type LockedOutError struct {
	RetryAfter time.Duration
}

func (e *LockedOutError) Error() string {
	return fmt.Sprintf("%v, retry after %s", ErrLockedOut, e.RetryAfter.Round(time.Second))
}

// Is makes errors.Is(err, ErrLockedOut) true.
func (e *LockedOutError) Is(target error) bool { return target == ErrLockedOut }
