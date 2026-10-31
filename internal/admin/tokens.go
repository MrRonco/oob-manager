package admin

import (
	"context"
	"errors"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/store"
	"oob-manager/internal/store/authrepo"
)

// TokenRow is one API token for the settings page: no hash, no secret.
type TokenRow struct {
	auth.APIToken
	Owner  string // username of CreatedBy
	Status auth.TokenStatus
}

// Tokens lists every token (oldest first) with its owner and status now.
func (s *Service) Tokens(ctx context.Context) ([]TokenRow, error) {
	list, err := s.cfg.Tokens.List(ctx)
	if err != nil {
		return nil, err
	}
	names, err := s.usernames(ctx)
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	out := make([]TokenRow, 0, len(list))
	for _, t := range list {
		out = append(out, TokenRow{APIToken: t, Owner: names[t.CreatedBy], Status: t.StatusAt(now)})
	}
	return out, nil
}

func (s *Service) usernames(ctx context.Context) (map[string]string, error) {
	users, err := s.cfg.DB.Users().List(ctx)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(users))
	for _, u := range users {
		m[u.ID] = u.Username
	}
	return m, nil
}

// CreateToken mints a read-only token owned by ownerID (the actor in the browser; the
// owner chosen on the CLI) and stores it with its audit row. The raw token is returned
// once and appears nowhere else.
func (s *Service) CreateToken(ctx context.Context, a Actor, ownerID, name string, ttl time.Duration) (string, auth.APIToken, error) {
	raw, tok, err := s.cfg.Tokens.Mint(name, ownerID, ttl)
	if err != nil {
		return "", auth.APIToken{}, invalidInput(err.Error())
	}
	params := map[string]any{"token_id": tok.ID, "name": tok.Name, "expires": fmtExpiry(tok.ExpiresAt)}
	err = s.change(ctx, func(tx *store.Tx) (audit.Entry, error) {
		owner, oerr := tx.Users().ByID(ctx, ownerID)
		if oerr != nil {
			return audit.Entry{}, invalidInput("unknown owner")
		}
		cerr := authrepo.Tokens(tx.Tokens()).Create(ctx, tok)
		return a.entry("token.create", with(params, "owner", owner.Username)), cerr
	})
	if err != nil {
		return "", auth.APIToken{}, err
	}
	tok.Hash = nil
	return raw, tok, nil
}

// RevokeToken permanently disables an active token (ErrNotFound if unknown or already
// revoked).
func (s *Service) RevokeToken(ctx context.Context, a Actor, id string) error {
	params := map[string]any{"token_id": id}
	err := s.change(ctx, func(tx *store.Tx) (audit.Entry, error) {
		name, err := tokenName(ctx, tx, id)
		if err != nil {
			return audit.Entry{}, err
		}
		err = tx.Tokens().Revoke(ctx, id, s.cfg.Now())
		return a.entry("token.revoke", with(params, "name", name)), err
	})
	err = mapStoreErr(err)
	if errors.Is(err, ErrNotFound) {
		s.auditDenied(ctx, a.entry("token.revoke", params), "not_found")
	}
	return err
}

func tokenName(ctx context.Context, tx *store.Tx, id string) (string, error) {
	list, err := tx.Tokens().List(ctx)
	if err != nil {
		return "", err
	}
	for _, t := range list {
		if t.ID == id {
			return t.Name, nil
		}
	}
	return "", store.ErrNotFound
}

// fmtExpiry is the audit form of an expiry (matches the CLI's).
func fmtExpiry(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
