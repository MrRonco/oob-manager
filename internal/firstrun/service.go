package firstrun

import (
	"context"
	"errors"

	"oob-manager/internal/auth"
)

// Errors of Service.Claim, mapped to messages by the UI.
var (
	// ErrSetupCode is a wrong, expired or already used setup code (or a claim in flight).
	ErrSetupCode = errors.New("firstrun: setup code not accepted")
	// ErrSetupClosed means an account exists: setup is over.
	ErrSetupClosed = errors.New("firstrun: setup is closed (an account exists)")
	// ErrInvalidInput is a username or password the account rules refuse.
	ErrInvalidInput = errors.New("firstrun: invalid username or password")
)

// Service is the first-run side the UI uses: the browser setup of the first admin and
// the backup notice of generated keys. Either part may be absent (nil Setup: an account
// existed at startup; nil Notice: the keys are mounted, not generated).
type Service struct {
	Setup  *Setup
	Notice *Notice
	// Users counts the accounts (store users).
	Users func(ctx context.Context) (int, error)
	// Bootstrap creates the first admin exactly like `bootstrap-admin`.
	Bootstrap func(ctx context.Context, username, password string) (auth.TOTPEnrollment, error)
}

// SetupOpen reports whether /setup is available: a live code and no account yet.
func (s *Service) SetupOpen(ctx context.Context) bool {
	if s == nil || s.Setup == nil || !s.Setup.Live() {
		return false
	}
	n, err := s.Users(ctx)
	if err != nil || n > 0 {
		if err == nil {
			s.Setup.Burn()
		}
		return false
	}
	return true
}

// Claim checks code and creates the first admin. On success the code is burned; when
// the account could not be created for a reason the administrator can fix, it stays usable.
func (s *Service) Claim(ctx context.Context, code, username, password string) (auth.TOTPEnrollment, error) {
	if !s.SetupOpen(ctx) {
		return auth.TOTPEnrollment{}, ErrSetupClosed
	}
	// Checked before the code is claimed, so a typo does not hold the claim.
	if !auth.ValidUsername(username) || auth.ValidatePassword(password) != nil {
		return auth.TOTPEnrollment{}, ErrInvalidInput
	}
	if !s.Setup.Claim(code) {
		return auth.TOTPEnrollment{}, ErrSetupCode
	}
	// Any way out that does not settle the claim (an error, or a panic the HTTP
	// middleware recovers) releases it, so /setup never stays wedged until a restart.
	// If the account was created before a panic, the next SetupOpen sees it and burns.
	settled := false
	defer func() {
		if !settled {
			s.Setup.Release()
		}
	}()
	enr, err := s.Bootstrap(ctx, username, password)
	switch {
	case errors.Is(err, auth.ErrUsersExist):
		s.Setup.Burn()
		settled = true
		return auth.TOTPEnrollment{}, ErrSetupClosed
	case err != nil:
		return auth.TOTPEnrollment{}, err
	}
	s.Setup.Burn()
	settled = true
	return enr, nil
}

// BackupPending reports the generated identity awaiting a backup acknowledgement.
func (s *Service) BackupPending() (identity string, pending bool) {
	if s == nil || s.Notice == nil || !s.Notice.Pending() {
		return "", false
	}
	return s.Notice.IdentityPath(), true
}

// DismissBackup acknowledges the backup (the notice disappears for everyone).
func (s *Service) DismissBackup() error {
	if s == nil || s.Notice == nil {
		return nil
	}
	return s.Notice.Dismiss()
}
