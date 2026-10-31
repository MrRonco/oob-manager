package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/authz"
)

func newTokenService(t *testing.T) (*TokenService, *fakeTokens, *fakeClock) {
	t.Helper()
	repo, clk := newFakeTokens(), newFakeClock()
	s, err := NewTokenService(repo, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	return s, repo, clk
}

func TestIssueAndVerifyToken(t *testing.T) {
	s, repo, clk := newTokenService(t)
	ctx := context.Background()
	raw, tok, err := s.Issue(ctx, "homepage", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, TokenPrefix) || len(raw) < len(TokenPrefix)+43 {
		t.Fatalf("raw token %q", raw)
	}
	stored := repo.m[tok.ID]
	if strings.Contains(string(stored.Hash), raw) || len(stored.Hash) != 32 {
		t.Fatal("token not stored as SHA-256 hash")
	}
	if stored.Scope != ScopeRead {
		t.Fatalf("scope = %q", stored.Scope)
	}
	clk.Advance(time.Minute)
	got, p, err := s.Verify(ctx, raw)
	if err != nil || got.ID != tok.ID {
		t.Fatalf("Verify = %+v, %v", got, err)
	}
	if p != (authz.Principal{Kind: authz.KindToken, Role: authz.RoleViewer}) {
		t.Fatalf("principal = %+v", p)
	}
	if !repo.m[tok.ID].LastUsedAt.Equal(clk.Now()) {
		t.Fatal("last_used_at not recorded")
	}
	if authz.Allowed(p, authz.PowerOn) {
		t.Fatal("token principal can act")
	}
}

func TestVerifyTokenRejects(t *testing.T) {
	s, repo, _ := newTokenService(t)
	ctx := context.Background()
	raw, tok, _ := s.Issue(ctx, "n8n", "user-1")

	bad := []string{"", "oobk_", "nope_" + raw[5:], raw + "x", raw[:len(raw)-1] + "!", TokenPrefix + strings.Repeat("A", 43)}
	for _, b := range bad {
		if _, _, err := s.Verify(ctx, b); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Verify(%q) err = %v", b, err)
		}
	}

	wrongScope := repo.m[tok.ID]
	wrongScope.Scope = Scope("admin")
	repo.m[tok.ID] = wrongScope
	if _, _, err := s.Verify(ctx, raw); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("non-read scope accepted: %v", err)
	}
	wrongScope.Scope = ScopeRead
	repo.m[tok.ID] = wrongScope

	if err := s.Revoke(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Verify(ctx, raw); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("revoked token accepted: %v", err)
	}
}

func TestIssueTokenValidatesName(t *testing.T) {
	s, _, _ := newTokenService(t)
	for _, n := range []string{"", strings.Repeat("a", 65), "bad\nname"} {
		if _, _, err := s.Issue(context.Background(), n, "u"); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	if _, _, err := s.Issue(context.Background(), "ok", ""); err == nil {
		t.Error("empty creator accepted")
	}
}

func TestNewTokenServiceValidates(t *testing.T) {
	if _, err := NewTokenService(nil, time.Now); err == nil {
		t.Fatal("nil repo accepted")
	}
	s, err := NewTokenService(newFakeTokens(), nil)
	if err != nil || s.now == nil {
		t.Fatal("nil clock should default to time.Now")
	}
}
