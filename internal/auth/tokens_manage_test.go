package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIssueExpiringTokenIsRejectedAfterExpiry(t *testing.T) {
	s, repo, clk := newTokenService(t)
	ctx := context.Background()
	raw, tok, err := s.IssueExpiring(ctx, "dashboard", "user-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if want := clk.Now().Add(24 * time.Hour); !tok.ExpiresAt.Equal(want) || !repo.m[tok.ID].ExpiresAt.Equal(want) {
		t.Fatalf("expiry = %v, stored %v", tok.ExpiresAt, repo.m[tok.ID].ExpiresAt)
	}
	clk.Advance(24*time.Hour - time.Second)
	if _, _, err := s.Verify(ctx, raw); err != nil {
		t.Fatalf("token rejected before expiry: %v", err)
	}
	clk.Advance(time.Second)
	if _, _, err := s.Verify(ctx, raw); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired token accepted: %v", err)
	}
}

func TestIssueExpiringValidatesLifetime(t *testing.T) {
	s, _, _ := newTokenService(t)
	cases := map[string]struct {
		ttl  time.Duration
		ok   bool
		zero bool
	}{
		"never":     {ttl: 0, ok: true, zero: true},
		"one hour":  {ttl: time.Hour, ok: true},
		"max":       {ttl: MaxTokenLifetime, ok: true},
		"negative":  {ttl: -time.Hour},
		"too long":  {ttl: MaxTokenLifetime + time.Hour},
		"too short": {ttl: time.Minute},
	}
	for name, c := range cases {
		_, tok, err := s.IssueExpiring(context.Background(), "n", "u", c.ttl)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", name, err)
			continue
		}
		if c.ok && tok.ExpiresAt.IsZero() != c.zero {
			t.Errorf("%s: ExpiresAt = %v", name, tok.ExpiresAt)
		}
	}
}

func TestListTokensNeverReturnsHashes(t *testing.T) {
	s, _, clk := newTokenService(t)
	ctx := context.Background()
	_, a, _ := s.Issue(ctx, "a", "u")
	clk.Advance(time.Second)
	_, b, _ := s.Issue(ctx, "b", "u")
	list, err := s.List(ctx)
	if err != nil || len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID {
		t.Fatalf("List = %+v, %v", list, err)
	}
	for _, tok := range list {
		if tok.Hash != nil {
			t.Fatalf("hash leaked for %s", tok.ID)
		}
	}
}

func TestTokenStatus(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := map[TokenStatus]APIToken{
		TokenActive:  {},
		TokenRevoked: {RevokedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)},
		TokenExpired: {ExpiresAt: now},
	}
	for want, tok := range cases {
		if got := tok.StatusAt(now); got != want {
			t.Errorf("StatusAt = %q, want %q", got, want)
		}
	}
}
