package fleet

import (
	"testing"
	"time"
)

func TestBreakerLifecycle(t *testing.T) {
	b := breaker{threshold: 3, openFor: 2 * time.Minute}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var (
		n     int
		until time.Time
	)
	for i := 0; i < 2; i++ {
		n, until = b.afterFailure(n, until, now)
		if b.state(n, until, now) != BreakerClosed || !b.allow(n, until, now) {
			t.Fatalf("failure %d must keep the breaker closed", n)
		}
	}
	n, until = b.afterFailure(n, until, now)
	if b.state(n, until, now) != BreakerOpen || b.allow(n, until, now.Add(time.Minute)) {
		t.Fatal("third failure must open the breaker")
	}
	later := now.Add(2 * time.Minute)
	if b.state(n, until, later) != BreakerHalfOpen || !b.allow(n, until, later) {
		t.Fatal("after the open window the breaker is half-open")
	}
	n, until = b.afterFailure(n, until, later)
	if b.state(n, until, later.Add(time.Second)) != BreakerOpen || !until.Equal(later.Add(2*time.Minute)) {
		t.Fatal("a failed half-open probe re-opens the breaker")
	}
}
