package auth

import (
	"context"
	"errors"
	"fmt"

	"oob-manager/internal/authz"
)

// BootstrapAdmin creates the first account (role admin) when no user exists, and
// returns its TOTP enrollment to display once. The account cannot log in until
// ConfirmTOTP succeeds. It returns ErrUsersExist if any user already exists. The CLI
// wiring (P0 follow-up in cmd/) reads the password without echo and prints the URI.
func (a *Authenticator) BootstrapAdmin(ctx context.Context, username, password string) (TOTPEnrollment, error) {
	if !validUsername(username) {
		return TOTPEnrollment{}, errors.New("auth: username must match " + usernamePattern.String())
	}
	if err := ValidatePassword(password); err != nil {
		return TOTPEnrollment{}, err
	}
	hash, err := a.hasher.Hash(ctx, password)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	enr, err := NewTOTPEnrollment(a.cfg.Issuer, username)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	id := newID()
	enc, err := a.sealer.Seal([]byte(enr.Secret), []byte(id))
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("auth: seal TOTP secret: %w", err)
	}
	u := User{ID: id, Username: username, Role: authz.RoleAdmin, PasswordHash: hash,
		TOTPSecretEnc: enc, CreatedAt: a.cfg.Now()}
	if err := a.cfg.Users.CreateFirst(ctx, u); err != nil {
		return TOTPEnrollment{}, err
	}
	a.log.Info("auth first admin created", "user_id", id)
	return enr, nil
}

// ConfirmTOTP completes enrollment: the user proves both the password and a code from
// the newly scanned authenticator. Lockout applies as for login.
func (a *Authenticator) ConfirmTOTP(ctx context.Context, username, password, code, ip string) error {
	keys := []lockKey{a.ipKey(ip)}
	if validUsername(username) {
		keys = append(keys, a.accountKey(username))
	}
	if err := a.locks.check(ctx, keys...); err != nil {
		return err
	}
	u, ok, err := a.checkPassword(ctx, username, password)
	if err != nil {
		return err
	}
	if !ok || len(u.TOTPSecretEnc) == 0 {
		return a.fail(ctx, "enroll-password", ip, keys...)
	}
	if err := a.verifyTOTP(ctx, u, code); err != nil {
		return a.totpFailure(ctx, err, ip, keys...)
	}
	if err := a.cfg.Users.SetTOTP(ctx, u.ID, u.TOTPSecretEnc, true); err != nil {
		return fmt.Errorf("auth: confirm TOTP: %w", err)
	}
	a.log.Info("auth TOTP confirmed", "user_id", u.ID)
	return a.locks.reset(ctx, keys...)
}
