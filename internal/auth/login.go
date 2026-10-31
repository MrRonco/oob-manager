package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// usernamePattern: lowercase, 1-64 chars, no spaces or unicode look-alikes.
var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func validUsername(s string) bool { return usernamePattern.MatchString(s) }

// ValidUsername reports whether s is a well-formed account name (lowercase letters,
// digits, ".", "_" and "-", at most 64 characters, starting with a letter or digit).
func ValidUsername(s string) bool { return validUsername(s) }

// LoginRequest is the first login stage. Password is never logged or stored.
type LoginRequest struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
}

// BeginLogin checks the password and returns a pending-session token (put it in the
// session cookie). The pending session cannot be used for anything but CompleteLogin.
// All failures are ErrInvalidCredentials or a *LockedOutError, whatever the cause.
func (a *Authenticator) BeginLogin(ctx context.Context, r LoginRequest) (string, error) {
	keys := []lockKey{a.ipKey(r.IP)}
	if validUsername(r.Username) {
		keys = append(keys, a.accountKey(r.Username))
	}
	if err := a.locks.check(ctx, keys...); err != nil {
		return "", err
	}
	u, ok, err := a.checkPassword(ctx, r.Username, r.Password)
	if err != nil {
		return "", err
	}
	if !ok || !u.TOTPConfirmed {
		return "", a.fail(ctx, "password", r.IP, keys...)
	}
	now := a.cfg.Now()
	s := Session{UserID: u.ID, Level: LevelPending, CreatedAt: now, LastSeen: now, IP: r.IP, UserAgent: r.UserAgent}
	token, err := a.createSession(ctx, s)
	if err != nil {
		return "", err
	}
	a.log.Info("auth password accepted", "user_id", u.ID, "ip", r.IP)
	return token, nil
}

// CompleteLogin verifies the TOTP for a pending session and replaces it with a full
// session under a new ID (rotation on login). The login TOTP counts as a step-up.
func (a *Authenticator) CompleteLogin(ctx context.Context, pendingToken, code, ip, ua string) (string, Session, error) {
	pending, oldHash, err := a.lookup(ctx, pendingToken)
	if err != nil {
		return "", Session{}, err
	}
	now := a.cfg.Now()
	if pending.Level != LevelPending || now.Sub(pending.CreatedAt) > a.cfg.PendingTTL {
		return "", Session{}, a.invalidate(ctx, oldHash, pending.Level == LevelPending)
	}
	u, err := a.activeUser(ctx, pending.UserID)
	if err != nil {
		return "", Session{}, a.invalidate(ctx, oldHash, true)
	}
	keys := []lockKey{a.accountKey(u.Username), a.ipKey(ip)}
	if err = a.locks.check(ctx, keys...); err != nil {
		return "", Session{}, err
	}
	if err = a.verifyTOTP(ctx, u, code); err != nil {
		return "", Session{}, a.totpFailure(ctx, err, ip, keys...)
	}
	if err = a.locks.reset(ctx, keys...); err != nil {
		return "", Session{}, err
	}
	full := Session{UserID: u.ID, Level: LevelFull, CreatedAt: now, LastSeen: now, StepUpAt: now, IP: ip, UserAgent: ua}
	token, full, err := a.rotate(ctx, oldHash, full)
	if err == nil {
		a.log.Info("auth login complete", "user_id", u.ID, "ip", ip)
	}
	return token, full, err
}

// checkPassword verifies username/password. ok is false for unknown, disabled or
// wrong-password accounts alike, and unknown users cost one argon2 verify too.
func (a *Authenticator) checkPassword(ctx context.Context, username, pw string) (User, bool, error) {
	if !validUsername(username) || len(pw) > MaxPasswordLen {
		return User{}, false, nil
	}
	u, err := a.cfg.Users.GetByUsername(ctx, username)
	if errors.Is(err, ErrNotFound) {
		a.hasher.burn(ctx, pw)
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("auth: load user: %w", err)
	}
	ok, rehash, err := a.hasher.Verify(ctx, pw, u.PasswordHash)
	if err != nil {
		return User{}, false, fmt.Errorf("auth: verify password: %w", err)
	}
	if !ok || u.Disabled {
		return User{}, false, nil
	}
	if rehash {
		a.upgradeHash(ctx, u.ID, pw)
	}
	return u, true, nil
}

// upgradeHash re-hashes with current parameters. Failure is logged, never fatal.
func (a *Authenticator) upgradeHash(ctx context.Context, userID, pw string) {
	h, err := a.hasher.Hash(ctx, pw)
	if err == nil {
		err = a.cfg.Users.SetPasswordHash(ctx, userID, h)
	}
	if err != nil {
		a.log.Error("auth password rehash failed", "user_id", userID, "err", err)
	}
}

// verifyTOTP accepts code once: match a step after the last used one, then claim it
// with a compare-and-set so a concurrent request cannot reuse it.
func (a *Authenticator) verifyTOTP(ctx context.Context, u User, code string) error {
	secret, err := a.sealer.Open(u.TOTPSecretEnc, []byte(u.ID))
	if err != nil {
		return fmt.Errorf("auth: open TOTP secret: %w", err)
	}
	step, ok := matchTOTP(string(secret), code, a.cfg.Now(), u.TOTPLastStep)
	if !ok {
		return ErrInvalidCredentials
	}
	advanced, err := a.cfg.Users.AdvanceTOTPStep(ctx, u.ID, step)
	if err != nil {
		return fmt.Errorf("auth: record TOTP step: %w", err)
	}
	if !advanced {
		return ErrInvalidCredentials
	}
	return nil
}

// totpFailure records a lockout failure for a wrong code; other errors pass through.
func (a *Authenticator) totpFailure(ctx context.Context, err error, ip string, keys ...lockKey) error {
	if errors.Is(err, ErrInvalidCredentials) {
		return a.fail(ctx, "totp", ip, keys...)
	}
	return err
}

func (a *Authenticator) activeUser(ctx context.Context, id string) (User, error) {
	u, err := a.cfg.Users.GetByID(ctx, id)
	if err != nil {
		return User{}, err
	}
	if u.Disabled {
		return User{}, ErrSessionInvalid
	}
	return u, nil
}
