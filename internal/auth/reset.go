package auth

import (
	"context"
	"errors"
	"fmt"
)

// ResetTOTP replaces a user's TOTP secret with a fresh, unconfirmed one and deletes
// every session of that user. The old secret stops working at once; the account cannot
// log in until the new secret is confirmed (ConfirmTOTP: the enrolment page or the
// confirm-totp CLI). The returned enrollment is a secret: show it once, never log it.
//
// There is deliberately no web route to this method. It needs no password because it is
// meant for the operator's shell (`oob-manager reset-totp`), which is already trusted.
func (a *Authenticator) ResetTOTP(ctx context.Context, username string) (TOTPEnrollment, error) {
	if !validUsername(username) {
		return TOTPEnrollment{}, errors.New("auth: username must match " + usernamePattern.String())
	}
	u, err := a.cfg.Users.GetByUsername(ctx, username)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	enr, err := NewTOTPEnrollment(a.cfg.Issuer, u.Username)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	enc, err := a.sealer.Seal([]byte(enr.Secret), []byte(u.ID))
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("auth: seal TOTP secret: %w", err)
	}
	// Sessions are ended before and after the secret changes: a failure leaves either
	// nothing changed but sessions gone (safe), and a login racing the reset is ended too.
	if err := a.cfg.Sessions.DeleteForUser(ctx, u.ID); err != nil {
		return TOTPEnrollment{}, fmt.Errorf("auth: end sessions before TOTP reset: %w", err)
	}
	if err := a.cfg.Users.ReEnrollTOTP(ctx, u.ID, enc); err != nil {
		return TOTPEnrollment{}, fmt.Errorf("auth: reset TOTP: %w", err)
	}
	if err := a.cfg.Sessions.DeleteForUser(ctx, u.ID); err != nil {
		return TOTPEnrollment{}, fmt.Errorf("auth: end sessions after TOTP reset: %w", err)
	}
	a.log.Info("auth TOTP reset", "user_id", u.ID)
	return enr, nil
}
