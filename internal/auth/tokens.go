package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"oob-manager/internal/authz"
)

// TokenPrefix marks oob-manager API tokens (helps secret scanners and humans).
const TokenPrefix = "oobk_"

const maxTokenNameLen = 64

// TokenService issues and verifies read-only API bearer tokens.
type TokenService struct {
	repo TokenRepo
	now  func() time.Time
}

// NewTokenService returns a TokenService. A nil now means time.Now.
func NewTokenService(repo TokenRepo, now func() time.Time) (*TokenService, error) {
	if repo == nil {
		return nil, errors.New("auth: token repo is required")
	}
	if now == nil {
		now = time.Now
	}
	return &TokenService{repo: repo, now: now}, nil
}

// Issue creates a read-only token that never expires. The raw value is returned once
// and never stored.
func (s *TokenService) Issue(ctx context.Context, name, createdBy string) (string, APIToken, error) {
	return s.IssueExpiring(ctx, name, createdBy, 0)
}

// IssueExpiring creates a read-only token valid for ttl (0 = never expires) and stores
// it. The raw value is returned once and never stored.
func (s *TokenService) IssueExpiring(ctx context.Context, name, createdBy string, ttl time.Duration) (string, APIToken, error) {
	raw, t, err := s.Mint(name, createdBy, ttl)
	if err != nil {
		return "", APIToken{}, err
	}
	if err := s.repo.Create(ctx, t); err != nil {
		return "", APIToken{}, fmt.Errorf("auth: store token: %w", err)
	}
	return raw, t, nil
}

// Mint validates the request and generates a token without storing it, so a caller can
// store it in its own transaction together with the audit row (the settings UI and the
// CLI both do). The raw value is returned once; only t.Hash may be stored.
func (s *TokenService) Mint(name, createdBy string, ttl time.Duration) (string, APIToken, error) {
	if err := ValidateTokenLifetime(ttl); err != nil {
		return "", APIToken{}, err
	}
	if err := validTokenName(name); err != nil {
		return "", APIToken{}, err
	}
	if createdBy == "" {
		return "", APIToken{}, errors.New("auth: token creator is required")
	}
	opaque := newOpaque()
	raw, _ := decodeOpaque(opaque)
	t := APIToken{
		ID: newID(), Name: name, Hash: hashOpaque(raw), Scope: ScopeRead,
		CreatedBy: createdBy, CreatedAt: s.now(),
	}
	if ttl > 0 {
		t.ExpiresAt = t.CreatedAt.Add(ttl)
	}
	return TokenPrefix + opaque, t, nil
}

// Verify checks a raw bearer token and returns it with its principal. The principal is
// always a viewer-role token principal: no code path maps a token to anything more.
func (s *TokenService) Verify(ctx context.Context, rawToken string) (APIToken, authz.Principal, error) {
	opaque, ok := strings.CutPrefix(rawToken, TokenPrefix)
	if !ok {
		return APIToken{}, authz.Principal{}, ErrInvalidToken
	}
	raw, ok := decodeOpaque(opaque)
	if !ok {
		return APIToken{}, authz.Principal{}, ErrInvalidToken
	}
	h := hashOpaque(raw)
	t, err := s.repo.GetByHash(ctx, h)
	if err != nil {
		return APIToken{}, authz.Principal{}, ErrInvalidToken
	}
	now := s.now()
	if !sameHash(t.Hash, h) || t.StatusAt(now) != TokenActive || t.Scope != ScopeRead {
		return APIToken{}, authz.Principal{}, ErrInvalidToken
	}
	if err := s.repo.MarkUsed(ctx, t.ID, now); err != nil {
		return APIToken{}, authz.Principal{}, fmt.Errorf("auth: mark token used: %w", err)
	}
	t.LastUsedAt = now
	return t, authz.Principal{Kind: authz.KindToken, Role: authz.RoleViewer}, nil
}

// Revoke disables a token permanently.
func (s *TokenService) Revoke(ctx context.Context, id string) error {
	return s.repo.Revoke(ctx, id, s.now())
}

func validTokenName(name string) error {
	if name == "" || len(name) > maxTokenNameLen {
		return fmt.Errorf("auth: token name must be 1-%d bytes", maxTokenNameLen)
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return errors.New("auth: token name must be printable")
		}
	}
	return nil
}
