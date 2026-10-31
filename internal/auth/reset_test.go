package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestResetTOTPReplacesSecretAndEndsSessions(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	tok := h.login(t)
	oldSecret := h.secret
	h.clk.Advance(30 * time.Second)

	enr, err := h.a.ResetTOTP(ctx, "morgan")
	if err != nil {
		t.Fatal(err)
	}
	if enr.Secret == "" || enr.Secret == oldSecret || enr.URL == "" {
		t.Fatalf("enrollment = %+v", enr)
	}
	if _, err := h.a.Authenticate(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("old session survived the reset: %v", err)
	}
	if h.sessions.count() != 0 {
		t.Fatalf("%d sessions left", h.sessions.count())
	}
	u, _ := h.users.GetByUsername(ctx, "morgan")
	if u.TOTPConfirmed || u.TOTPLastStep != 0 {
		t.Fatalf("reset account: confirmed %v last step %d", u.TOTPConfirmed, u.TOTPLastStep)
	}
	// Login is refused until the new secret is confirmed, even with a valid password.
	if _, err := h.a.BeginLogin(ctx, h.req(testPassword)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login before confirmation: %v", err)
	}
	// A code from the old secret no longer confirms anything.
	old, _ := codeFor(oldSecret, h.clk.Now())
	if err := h.a.ConfirmTOTP(ctx, "morgan", testPassword, old, "127.0.0.1"); err == nil {
		t.Fatal("old TOTP secret confirmed the reset")
	}
	h.secret = enr.Secret
	h.clk.Advance(30 * time.Second)
	if err := h.a.ConfirmTOTP(ctx, "morgan", testPassword, h.code(), "127.0.0.1"); err != nil {
		t.Fatalf("confirm with the new secret: %v", err)
	}
	h.clk.Advance(30 * time.Second)
	_ = h.login(t)
}

func TestResetTOTPErrors(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	if _, err := h.a.ResetTOTP(ctx, "Bad Name"); err == nil {
		t.Fatal("invalid username accepted")
	}
	if _, err := h.a.ResetTOTP(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestResetTOTPSessionDeleteFailure(t *testing.T) {
	h := enrolledHarness(t)
	h.sessions.failDeleteForUser = errors.New("disk on fire")
	before, _ := h.users.GetByUsername(context.Background(), "morgan")
	if _, err := h.a.ResetTOTP(context.Background(), "morgan"); err == nil {
		t.Fatal("session delete failure ignored")
	}
	after, _ := h.users.GetByUsername(context.Background(), "morgan")
	if !after.TOTPConfirmed || string(after.TOTPSecretEnc) != string(before.TOTPSecretEnc) {
		t.Fatal("secret changed although the sessions could not be ended")
	}
}
