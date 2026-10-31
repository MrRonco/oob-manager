package auth

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestLinkTokenRoundTrip(t *testing.T) {
	raw, hash := NewLinkToken()
	if len(raw) != 43 || len(hash) != 32 {
		t.Fatalf("raw %q hash %d bytes", raw, len(hash))
	}
	got, ok := HashLinkToken(raw)
	if !ok || !bytes.Equal(got, hash) {
		t.Fatal("HashLinkToken does not reproduce the stored hash")
	}
	other, _ := NewLinkToken()
	if other == raw {
		t.Fatal("link tokens repeat")
	}
	for _, bad := range []string{"", "short", raw + "x", "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"} {
		if _, ok := HashLinkToken(bad); ok {
			t.Errorf("HashLinkToken(%q) accepted", bad)
		}
	}
}

func TestValidateNewUsername(t *testing.T) {
	for _, ok := range []string{"abc", "victor", "a.b-c_d", "a234567890123456789012345678901"} {
		if err := ValidateNewUsername(ok); err != nil {
			t.Errorf("ValidateNewUsername(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ab", "1abc", "Abc", "ab cd", "a23456789012345678901234567890123", "äbc"} {
		if err := ValidateNewUsername(bad); err == nil {
			t.Errorf("ValidateNewUsername(%q) accepted", bad)
		}
	}
}

func TestMintDoesNotStore(t *testing.T) {
	s, repo, _ := newTokenService(t)
	raw, tok, err := s.Mint("dash", "user-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.m) != 0 {
		t.Fatal("Mint stored the token")
	}
	if tok.ExpiresAt.Sub(tok.CreatedAt) != 24*time.Hour || len(tok.Hash) != 32 || raw == "" {
		t.Fatalf("minted %+v", tok)
	}
	if err := repo.Create(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Verify(context.Background(), raw); err != nil {
		t.Fatalf("minted token does not verify once stored: %v", err)
	}
	if _, _, err := s.Mint("", "user-1", 0); err == nil {
		t.Error("empty name accepted")
	}
	if _, _, err := s.Mint("x", "", 0); err == nil {
		t.Error("empty creator accepted")
	}
	if _, _, err := s.Mint("x", "u", time.Minute); err == nil {
		t.Error("too-short lifetime accepted")
	}
}

func TestConfirmTOTPWithoutSecretIsInvalidCredentials(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	u, _ := h.users.GetByUsername(ctx, "morgan")
	u.TOTPSecretEnc, u.TOTPConfirmed = nil, false
	h.users.byID[u.ID] = u
	err := h.a.ConfirmTOTP(ctx, "morgan", testPassword, "123456", "192.0.2.1")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
}

func TestStepUpExpires(t *testing.T) {
	h := enrolledHarness(t)
	now := h.clk.Now()
	if !h.a.StepUpExpires(Session{}).IsZero() {
		t.Fatal("no step-up must have no expiry")
	}
	if got := h.a.StepUpExpires(Session{StepUpAt: now}); !got.Equal(now.Add(DefaultStepUpWindow)) {
		t.Fatalf("expiry = %v", got)
	}
}

func TestPendingUsername(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	pending, err := h.a.BeginLogin(ctx, h.req(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := h.a.PendingUsername(ctx, pending); !ok || u != "morgan" {
		t.Fatalf("PendingUsername = %q, %v", u, ok)
	}
	if _, ok := h.a.PendingUsername(ctx, "garbage"); ok {
		t.Fatal("garbage token accepted")
	}
	full, _, err := h.a.CompleteLogin(ctx, pending, h.code(), "192.0.2.100", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.a.PendingUsername(ctx, full); ok {
		t.Fatal("full session reported as pending")
	}
	p2, _ := h.a.BeginLogin(ctx, h.req(testPassword))
	h.clk.Advance(DefaultPendingTTL + time.Second)
	if _, ok := h.a.PendingUsername(ctx, p2); ok {
		t.Fatal("expired pending session accepted")
	}
}
