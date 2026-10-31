package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestLivePolicy: with Config.Policy set, session and step-up limits are read on every
// use, so an admin's change applies to existing sessions without a restart.
func TestLivePolicy(t *testing.T) {
	h := enrolledHarness(t)
	var p atomic.Pointer[Policy]
	p.Store(&Policy{SessionIdle: time.Hour, SessionMax: 12 * time.Hour, StepUpWindow: 5 * time.Minute})
	h.a.cfg.Policy = func() Policy { return *p.Load() }
	ctx := context.Background()
	tok := h.login(t)
	id, err := h.a.Authenticate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	h.clk.Advance(3 * time.Minute)
	if !h.a.StepUpFresh(id.Session) {
		t.Fatal("login step-up stale inside a 5 min window")
	}
	p.Store(&Policy{SessionIdle: 2 * time.Minute, SessionMax: 12 * time.Hour, StepUpWindow: time.Minute})
	if h.a.StepUpFresh(id.Session) {
		t.Fatal("shorter window not applied")
	}
	if got := h.a.StepUpExpires(id.Session); !got.Equal(id.Session.StepUpAt.Add(time.Minute)) {
		t.Fatalf("StepUpExpires = %v", got)
	}
	if c := h.a.SessionCookieFor(tok, id.Session); c.MaxAge <= 0 {
		t.Fatalf("cookie MaxAge %d", c.MaxAge)
	}
	if _, err := h.a.Authenticate(ctx, tok); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("idle 3 min under a 2 min idle limit: %v", err)
	}
}

func TestPolicyDefaultsToStaticConfig(t *testing.T) {
	h := newHarness(t)
	if got := h.a.policy(); got != (Policy{SessionIdle: DefaultSessionIdle, SessionMax: DefaultSessionMax,
		StepUpWindow: DefaultStepUpWindow}) {
		t.Fatalf("policy = %+v", got)
	}
}
