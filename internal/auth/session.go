package auth

import (
	"context"
	"errors"
	"fmt"
)

// Authenticate resolves a session cookie value to a full, unexpired session of an
// enabled user, and records activity. Anything else is ErrSessionInvalid; expired or
// orphaned sessions are deleted.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (Identity, error) {
	s, h, err := a.lookup(ctx, token)
	if err != nil {
		return Identity{}, err
	}
	if s.Level != LevelFull {
		return Identity{}, ErrSessionInvalid
	}
	now := a.cfg.Now()
	if p := a.policy(); now.Sub(s.LastSeen) > p.SessionIdle || now.Sub(s.CreatedAt) > p.SessionMax {
		return Identity{}, a.invalidate(ctx, h, true)
	}
	u, err := a.activeUser(ctx, s.UserID)
	if err != nil {
		return Identity{}, a.invalidate(ctx, h, true)
	}
	if err := a.cfg.Sessions.Touch(ctx, h, now); err != nil {
		return Identity{}, fmt.Errorf("auth: touch session: %w", err)
	}
	s.LastSeen = now
	return Identity{User: u, Session: s}, nil
}

// StepUp verifies a fresh TOTP for an authenticated session and rotates its ID. The
// absolute lifetime (CreatedAt) is kept, so step-ups cannot extend a session forever.
func (a *Authenticator) StepUp(ctx context.Context, token, code string) (string, Session, error) {
	id, err := a.Authenticate(ctx, token)
	if err != nil {
		return "", Session{}, err
	}
	keys := []lockKey{a.accountKey(id.User.Username)}
	if err = a.locks.check(ctx, keys...); err != nil {
		return "", Session{}, err
	}
	if err = a.verifyTOTP(ctx, id.User, code); err != nil {
		return "", Session{}, a.totpFailure(ctx, err, id.Session.IP, keys...)
	}
	if err = a.locks.reset(ctx, keys...); err != nil {
		return "", Session{}, err
	}
	next := id.Session
	next.StepUpAt = a.cfg.Now()
	tok, next, err := a.rotate(ctx, id.Session.IDHash, next)
	if err == nil {
		a.log.Info("auth step-up", "user_id", id.User.ID)
	}
	return tok, next, err
}

// Logout deletes the session. Unknown or malformed tokens are a no-op.
func (a *Authenticator) Logout(ctx context.Context, token string) error {
	raw, ok := decodeOpaque(token)
	if !ok {
		return nil
	}
	return a.cfg.Sessions.Delete(ctx, hashOpaque(raw))
}

// LogoutEverywhere deletes every session of a user (password change, disable).
func (a *Authenticator) LogoutEverywhere(ctx context.Context, userID string) error {
	return a.cfg.Sessions.DeleteForUser(ctx, userID)
}

// lookup decodes a cookie value and loads its session.
func (a *Authenticator) lookup(ctx context.Context, token string) (Session, []byte, error) {
	raw, ok := decodeOpaque(token)
	if !ok {
		return Session{}, nil, ErrSessionInvalid
	}
	h := hashOpaque(raw)
	s, err := a.cfg.Sessions.Get(ctx, h)
	if errors.Is(err, ErrNotFound) {
		return Session{}, nil, ErrSessionInvalid
	}
	if err != nil {
		return Session{}, nil, fmt.Errorf("auth: load session: %w", err)
	}
	if !sameHash(s.IDHash, h) {
		return Session{}, nil, ErrSessionInvalid
	}
	return s, h, nil
}

// invalidate optionally deletes the session and returns ErrSessionInvalid.
func (a *Authenticator) invalidate(ctx context.Context, h []byte, del bool) error {
	if !del {
		return ErrSessionInvalid
	}
	if err := a.cfg.Sessions.Delete(ctx, h); err != nil {
		return errors.Join(ErrSessionInvalid, err)
	}
	return ErrSessionInvalid
}

func (a *Authenticator) createSession(ctx context.Context, s Session) (string, error) {
	token := newOpaque()
	raw, _ := decodeOpaque(token)
	s.IDHash = hashOpaque(raw)
	if err := a.cfg.Sessions.Create(ctx, s); err != nil {
		return "", fmt.Errorf("auth: create session: %w", err)
	}
	return token, nil
}

// rotate gives s a new ID and atomically replaces oldHash with it.
func (a *Authenticator) rotate(ctx context.Context, oldHash []byte, s Session) (string, Session, error) {
	token := newOpaque()
	raw, _ := decodeOpaque(token)
	s.IDHash = hashOpaque(raw)
	err := a.cfg.Sessions.Replace(ctx, oldHash, s)
	if errors.Is(err, ErrNotFound) {
		return "", Session{}, ErrSessionInvalid
	}
	if err != nil {
		return "", Session{}, fmt.Errorf("auth: rotate session: %w", err)
	}
	return token, s, nil
}
