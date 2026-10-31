package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"oob-manager/internal/authz"
)

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	tok := h.login(t)
	h.clk.Advance(DefaultSessionIdle - time.Minute)
	if _, err := h.a.Authenticate(ctx, tok); err != nil {
		t.Fatalf("active session rejected: %v", err)
	}
	h.clk.Advance(DefaultSessionIdle + time.Second)
	if _, err := h.a.Authenticate(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("idle session accepted: %v", err)
	}
	if h.sessions.count() != 0 {
		t.Fatal("expired session not deleted")
	}

	tok = h.login(t)
	for elapsed := time.Duration(0); elapsed < DefaultSessionMax; elapsed += 20 * time.Minute {
		h.clk.Advance(20 * time.Minute)
		_, _ = h.a.Authenticate(ctx, tok) // keep it non-idle
	}
	h.clk.Advance(time.Minute)
	if _, err := h.a.Authenticate(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session past absolute max accepted: %v", err)
	}
}

func TestDisabledUserSessionKilled(t *testing.T) {
	h := enrolledHarness(t)
	tok := h.login(t)
	u, _ := h.users.GetByUsername(context.Background(), "morgan")
	u.Disabled = true
	h.users.put(u)
	if _, err := h.a.Authenticate(context.Background(), tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("disabled user's session accepted: %v", err)
	}
}

func TestStepUp(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	tok := h.login(t)
	h.clk.Advance(DefaultStepUpWindow + time.Second)
	id, _ := h.a.Authenticate(ctx, tok)
	if h.a.StepUpFresh(id.Session) {
		t.Fatal("step-up still fresh after window")
	}
	if err := authz.Authorize(id.Principal(), authz.PowerForceOff, h.a.StepUpFresh(id.Session)); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Fatalf("dangerous action without fresh step-up: %v", err)
	}
	if _, _, err := h.a.StepUp(ctx, tok, "000000"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("bad step-up code: %v", err)
	}
	newTok, sess, err := h.a.StepUp(ctx, tok, h.code())
	if err != nil {
		t.Fatal(err)
	}
	if newTok == tok {
		t.Fatal("session not rotated on step-up")
	}
	if _, err := h.a.Authenticate(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("old session ID valid after step-up")
	}
	if !h.a.StepUpFresh(sess) {
		t.Fatal("step-up not fresh")
	}
	if !sess.CreatedAt.Equal(id.Session.CreatedAt) {
		t.Fatal("step-up must not extend the absolute session lifetime")
	}
	if _, _, err := h.a.StepUp(ctx, newTok, h.code()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("step-up TOTP replay accepted: %v", err)
	}
	if _, _, err := h.a.StepUp(ctx, "garbage", h.code()); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("step-up on bad session: %v", err)
	}
}

func TestLogout(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	tok := h.login(t)
	if err := h.a.Logout(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := h.a.Authenticate(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("session valid after logout")
	}
	if err := h.a.Logout(ctx, "garbage"); err != nil {
		t.Fatalf("logout of unknown token should be a no-op: %v", err)
	}
	h.clk.Advance(30 * time.Second) // a new TOTP step; the old code is spent
	h.login(t)
	u, _ := h.users.GetByUsername(ctx, "morgan")
	if err := h.a.LogoutEverywhere(ctx, u.ID); err != nil || h.sessions.count() != 0 {
		t.Fatalf("LogoutEverywhere: %v, %d left", err, h.sessions.count())
	}
}
