package authrepo

import (
	"context"
	"errors"
	"time"

	"oob-manager/internal/auth"
	"oob-manager/internal/store"
)

// Sessions adapts a store.SessionRepository.
func Sessions(r store.SessionRepository) auth.SessionRepo { return sessionRepo{r} }

type sessionRepo struct{ r store.SessionRepository }

func (s sessionRepo) Create(ctx context.Context, x auth.Session) error {
	return mapErr(s.r.Create(ctx, toStoreSession(x)))
}

func (s sessionRepo) Get(ctx context.Context, idHash []byte) (auth.Session, error) {
	x, err := s.r.Get(ctx, idHash)
	if err != nil {
		return auth.Session{}, mapErr(err)
	}
	return fromStoreSession(x), nil
}

func (s sessionRepo) Touch(ctx context.Context, idHash []byte, at time.Time) error {
	return mapErr(s.r.Touch(ctx, idHash, at))
}

func (s sessionRepo) Replace(ctx context.Context, oldIDHash []byte, x auth.Session) error {
	return mapErr(s.r.Replace(ctx, oldIDHash, toStoreSession(x)))
}

// Delete is a no-op when absent, as auth.SessionRepo requires.
func (s sessionRepo) Delete(ctx context.Context, idHash []byte) error {
	if err := s.r.Delete(ctx, idHash); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

func (s sessionRepo) DeleteForUser(ctx context.Context, userID string) error {
	_, err := s.r.DeleteForUser(ctx, userID)
	return err
}

// levelToStore maps auth levels explicitly; anything unknown is stored as pending.
func levelToStore(l auth.Level) store.SessionLevel {
	if l == auth.LevelFull {
		return store.SessionFull
	}
	return store.SessionPending
}

func levelFromStore(l store.SessionLevel) auth.Level {
	if l == store.SessionFull {
		return auth.LevelFull
	}
	return auth.LevelPending
}

func toStoreSession(s auth.Session) store.Session {
	return store.Session{
		IDHash: clone(s.IDHash), UserID: s.UserID, Level: levelToStore(s.Level),
		CreatedAt: s.CreatedAt, LastSeen: s.LastSeen, StepUpAt: s.StepUpAt, IP: s.IP, UA: s.UserAgent,
	}
}

func fromStoreSession(s store.Session) auth.Session {
	return auth.Session{
		IDHash: clone(s.IDHash), UserID: s.UserID, Level: levelFromStore(s.Level),
		CreatedAt: s.CreatedAt, LastSeen: s.LastSeen, StepUpAt: s.StepUpAt, IP: s.IP, UserAgent: s.UA,
	}
}

// Tokens adapts a store.TokenRepository.
func Tokens(r store.TokenRepository) auth.TokenRepo { return tokenRepo{r} }

type tokenRepo struct{ r store.TokenRepository }

func (t tokenRepo) Create(ctx context.Context, x auth.APIToken) error {
	return mapErr(t.r.Create(ctx, store.APIToken{
		ID: x.ID, Name: x.Name, TokenHash: clone(x.Hash), Scope: store.TokenScope(x.Scope),
		CreatedBy: x.CreatedBy, CreatedAt: x.CreatedAt, LastUsedAt: x.LastUsedAt, RevokedAt: x.RevokedAt,
		ExpiresAt: x.ExpiresAt,
	}))
}

func (t tokenRepo) GetByHash(ctx context.Context, hash []byte) (auth.APIToken, error) {
	x, err := t.r.ByHash(ctx, hash)
	if err != nil {
		return auth.APIToken{}, mapErr(err)
	}
	return fromStoreToken(x), nil
}

func (t tokenRepo) List(ctx context.Context) ([]auth.APIToken, error) {
	xs, err := t.r.List(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]auth.APIToken, 0, len(xs))
	for _, x := range xs {
		out = append(out, fromStoreToken(x))
	}
	return out, nil
}

func fromStoreToken(x store.APIToken) auth.APIToken {
	return auth.APIToken{
		ID: x.ID, Name: x.Name, Hash: clone(x.TokenHash), Scope: auth.Scope(x.Scope),
		CreatedBy: x.CreatedBy, CreatedAt: x.CreatedAt, LastUsedAt: x.LastUsedAt, RevokedAt: x.RevokedAt,
		ExpiresAt: x.ExpiresAt,
	}
}

func (t tokenRepo) MarkUsed(ctx context.Context, id string, at time.Time) error {
	return mapErr(t.r.Touch(ctx, id, at))
}

func (t tokenRepo) Revoke(ctx context.Context, id string, at time.Time) error {
	return mapErr(t.r.Revoke(ctx, id, at))
}
