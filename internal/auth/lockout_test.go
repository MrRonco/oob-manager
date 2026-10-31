package auth

import (
	"testing"
	"time"
)

func TestLockoutPolicyDelay(t *testing.T) {
	p := LockoutPolicy{FreeAttempts: 3, BaseDelay: time.Second, MaxDelay: 10 * time.Second, ForgetAfter: time.Hour}
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, 0}, {2, 0}, {3, time.Second}, {4, 2 * time.Second}, {5, 4 * time.Second},
		{6, 8 * time.Second}, {7, 10 * time.Second}, {200, 10 * time.Second},
	}
	for _, tc := range cases {
		if got := p.delay(tc.failures); got != tc.want {
			t.Errorf("delay(%d) = %v, want %v", tc.failures, got, tc.want)
		}
	}
}

func TestLockoutPolicyRetryAfter(t *testing.T) {
	p := LockoutPolicy{FreeAttempts: 1, BaseDelay: time.Minute, MaxDelay: time.Hour, ForgetAfter: 24 * time.Hour}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := LockoutState{Failures: 2, LastFailure: t0} // delay 2m
	if got := p.retryAfter(st, t0.Add(30*time.Second)); got != 90*time.Second {
		t.Fatalf("retryAfter = %v", got)
	}
	if got := p.retryAfter(st, t0.Add(3*time.Minute)); got != 0 {
		t.Fatalf("retryAfter after delay = %v", got)
	}
	if !p.stale(st, t0.Add(25*time.Hour)) || p.stale(st, t0.Add(time.Hour)) {
		t.Fatal("stale() wrong")
	}
}

func TestDefaultLockoutPolicies(t *testing.T) {
	a, ip := DefaultAccountLockout(), DefaultIPLockout()
	if a.FreeAttempts > 5 || a.MaxDelay < 15*time.Minute {
		t.Fatalf("account policy too weak: %+v", a)
	}
	if ip.FreeAttempts > 20 || ip.MaxDelay < 15*time.Minute {
		t.Fatalf("ip policy too weak: %+v", ip)
	}
}
