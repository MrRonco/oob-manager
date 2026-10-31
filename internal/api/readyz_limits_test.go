package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// countingPinger counts database pings so the render cache can be observed.
type countingPinger struct{ n atomic.Int64 }

func (p *countingPinger) Ping(context.Context) error { p.n.Add(1); return nil }

type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time { return c.t }

func readyFrom(t *testing.T, a *API, ip string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil)
	r.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

// TestReadyzRenderCache: a flood of /readyz pings the database once per second, not
// once per request (plan 06 §3.1, security.md D1).
func TestReadyzRenderCache(t *testing.T) {
	clk := &stepClock{t: time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)}
	p := &countingPinger{}
	a := newTestAPI(t, Deps{DB: p, Now: clk.now})
	for i := range 5 {
		if w := readyFrom(t, a, "192.0.2."+strconv.Itoa(i+1)); w.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if got := p.n.Load(); got != 1 {
		t.Fatalf("pings within one second = %d, want 1", got)
	}
	clk.t = clk.t.Add(1100 * time.Millisecond)
	readyFrom(t, a, "192.0.2.1")
	if got := p.n.Load(); got != 2 {
		t.Fatalf("pings after the cache expired = %d, want 2", got)
	}
}

// ctxPinger fails when its context is already cancelled, like a real database ping.
type ctxPinger struct{ n atomic.Int64 }

func (p *ctxPinger) Ping(ctx context.Context) error { p.n.Add(1); return ctx.Err() }

// TestReadyzCancelledCallerDoesNotPoisonCache: the shared answer is computed without the
// first caller's cancellation, so a client that hung up early cannot make /readyz answer
// "unavailable" to everyone (Kuma included) for the next second (review M1).
func TestReadyzCancelledCallerDoesNotPoisonCache(t *testing.T) {
	clk := &stepClock{t: time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)}
	a := newTestAPI(t, Deps{DB: &ctxPinger{}, Now: clk.now})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/readyz", nil)
	a.ServeHTTP(httptest.NewRecorder(), r)
	if w := readyFrom(t, a, "192.0.2.9"); w.Code != http.StatusOK {
		t.Fatalf("second caller after a cancelled first caller: %d %s", w.Code, w.Body.String())
	}
}

// TestReadyzNeverRateLimited: monitors on the same host may share one source address, and
// Kuma reads 429 as down, so /readyz never answers 429; the cache bounds the database
// pings instead (review M2).
func TestReadyzNeverRateLimited(t *testing.T) {
	clk := &stepClock{t: time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)}
	p := &countingPinger{}
	a := newTestAPI(t, Deps{DB: p, Now: clk.now})
	for i := range 200 {
		if w := readyFrom(t, a, "192.0.2.7"); w.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if got := p.n.Load(); got != 1 {
		t.Fatalf("pings = %d, want 1 (cached)", got)
	}
}

// slowPinger advances the clock while it "pings", like a slow database.
type slowPinger struct {
	clk *stepClock
	n   atomic.Int64
}

func (p *slowPinger) Ping(context.Context) error {
	p.n.Add(1)
	p.clk.t = p.clk.t.Add(1500 * time.Millisecond)
	return nil
}

// TestReadyzCacheStampedAfterCompute: the cache age counts from when the answer was
// ready, so a slow ping does not leave the next caller with an already-expired answer
// (review L1).
func TestReadyzCacheStampedAfterCompute(t *testing.T) {
	clk := &stepClock{t: time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)}
	p := &slowPinger{clk: clk}
	a := newTestAPI(t, Deps{DB: p, Now: clk.now})
	readyFrom(t, a, "192.0.2.1")
	readyFrom(t, a, "192.0.2.2")
	if got := p.n.Load(); got != 1 {
		t.Fatalf("pings = %d, want 1: the answer expired before anyone could use it", got)
	}
}
