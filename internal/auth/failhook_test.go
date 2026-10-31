package auth

import (
	"context"
	"slices"
	"testing"
)

// OnFailure (the /metrics login failure counter) hears every failed stage, and
// nothing else.
func TestOnFailureHook(t *testing.T) {
	h := enrolledHarness(t)
	var stages []string
	h.a.cfg.OnFailure = func(stage string) { stages = append(stages, stage) }
	ctx := context.Background()
	if _, err := h.a.BeginLogin(ctx, h.req("wrong password entirely")); err == nil {
		t.Fatal("wrong password accepted")
	}
	pending, err := h.a.BeginLogin(ctx, h.req(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.a.CompleteLogin(ctx, pending, wrongCode(h.code()), "192.0.2.100", "test"); err == nil {
		t.Fatal("wrong code accepted")
	}
	h.login(t)
	if !slices.Equal(stages, []string{"password", "totp"}) {
		t.Fatalf("stages = %v", stages)
	}
}

func wrongCode(c string) string {
	b := []byte(c)
	b[0] = (b[0]-'0'+1)%10 + '0'
	return string(b)
}
