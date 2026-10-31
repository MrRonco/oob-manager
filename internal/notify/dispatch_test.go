package notify

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// startDispatcher runs d until the test ends.
func startDispatcher(t *testing.T, d *Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	t.Cleanup(func() { cancel(); d.Wait() })
}

func fastDispatcher(r *receiver, mod func(*DispatchConfig)) *Dispatcher {
	cfg := DispatchConfig{Transport: transportFor(r), Logger: quiet(), BackoffMin: time.Millisecond,
		BackoffMax: 4 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	return NewDispatcher(cfg)
}

func TestRetriesWithBackoffThenSuccess(t *testing.T) {
	r := newReceiver(t, true, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusOK)
	d := fastDispatcher(r, nil)
	startDispatcher(t, d)
	tg := target(KindWebhook, r.srv.URL+"/h")
	if !d.Enqueue(tg, Secrets{}, testEvent()) {
		t.Fatal("enqueue refused")
	}
	waitFor(t, "success", func() bool { return d.Status(tg.ID).Sent == 1 })
	if r.count() != 3 || d.Status(tg.ID).ConsecutiveFailures != 0 {
		t.Fatalf("attempts %d, status %+v", r.count(), d.Status(tg.ID))
	}
	reqs := r.requests()
	if reqs[0].Header.Get(HeaderDelivery) != reqs[2].Header.Get(HeaderDelivery) {
		t.Error("retries must carry the same delivery id")
	}
}

func TestBackoffDoublesUpToTheCap(t *testing.T) {
	r := newReceiver(t, true, http.StatusBadGateway)
	var mu sync.Mutex
	var at []time.Time
	r.hook = func(http.ResponseWriter) bool {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
		return false
	}
	d := fastDispatcher(r, func(c *DispatchConfig) {
		c.BackoffMin, c.BackoffMax, c.Attempts = 20*time.Millisecond, 40*time.Millisecond, 4
	})
	startDispatcher(t, d)
	tg := target(KindWebhook, r.srv.URL+"/h")
	d.Enqueue(tg, Secrets{}, testEvent())
	waitFor(t, "all attempts", func() bool { return d.Status(tg.ID).ConsecutiveFailures == 1 })
	mu.Lock()
	defer mu.Unlock()
	if len(at) != 4 {
		t.Fatalf("%d attempts", len(at))
	}
	gaps := []time.Duration{at[1].Sub(at[0]), at[2].Sub(at[1]), at[3].Sub(at[2])}
	if gaps[0] < 20*time.Millisecond || gaps[1] < 40*time.Millisecond || gaps[2] < 40*time.Millisecond ||
		gaps[2] > 400*time.Millisecond {
		t.Fatalf("gaps %v", gaps)
	}
}

func TestPermanentFailureIsNotRetried(t *testing.T) {
	r := newReceiver(t, true, http.StatusUnauthorized)
	d := fastDispatcher(r, nil)
	startDispatcher(t, d)
	tg := target(KindNtfy, r.srv.URL+"/t")
	d.Enqueue(tg, Secrets{}, testEvent())
	waitFor(t, "failure", func() bool { return d.Status(tg.ID).ConsecutiveFailures == 1 })
	if r.count() != 1 || d.Status(tg.ID).LastError != classHTTP4xx {
		t.Fatalf("attempts %d status %+v", r.count(), d.Status(tg.ID))
	}
}

func TestFailingAfterThresholdAndRecovery(t *testing.T) {
	r := newReceiver(t, true, 500, 500, 500, 200)
	var mu sync.Mutex
	var transitions []bool
	d := fastDispatcher(r, func(c *DispatchConfig) {
		c.Attempts = 1
		c.OnFailing = func(_ Target, failing bool) { mu.Lock(); transitions = append(transitions, failing); mu.Unlock() }
	})
	startDispatcher(t, d)
	tg := target(KindNtfy, r.srv.URL+"/t")
	for range 4 {
		d.Enqueue(tg, Secrets{}, testEvent())
	}
	waitFor(t, "recovery", func() bool { return d.Status(tg.ID).Sent == 1 })
	mu.Lock()
	defer mu.Unlock()
	if len(transitions) != 2 || !transitions[0] || transitions[1] {
		t.Fatalf("transitions %v", transitions)
	}
}

func TestRateLimitAndQueueBound(t *testing.T) {
	r := newReceiver(t, true)
	now := fixedNow
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	log, buf := logBuffer()
	d := fastDispatcher(r, func(c *DispatchConfig) { c.RateBurst, c.RateEvery, c.Now, c.Logger = 3, time.Minute, clock, log })
	startDispatcher(t, d)
	tg := target(KindNtfy, r.srv.URL+"/secret-topic-name")
	accepted := 0
	for range 5 {
		if d.Enqueue(tg, sec("tok-secret", "", ""), testEvent()) {
			accepted++
		}
	}
	if accepted != 3 || d.Status(tg.ID).Dropped != 2 {
		t.Fatalf("accepted %d, status %+v", accepted, d.Status(tg.ID))
	}
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	if !d.Enqueue(tg, Secrets{}, testEvent()) {
		t.Fatal("bucket did not refill")
	}
	waitFor(t, "deliveries", func() bool { return r.count() == 4 })
	if strings.Contains(buf.String(), "tok-secret") || strings.Contains(buf.String(), "secret-topic-name") {
		t.Fatal("secret or URL path in the log")
	}
}

func TestQueueFullDrops(t *testing.T) {
	r := newReceiver(t, true)
	block := make(chan struct{})
	r.hook = func(http.ResponseWriter) bool { <-block; return false }
	t.Cleanup(func() { close(block) })
	d := fastDispatcher(r, func(c *DispatchConfig) { c.QueueSize, c.RateBurst = 1, 100 })
	startDispatcher(t, d)
	tg := target(KindNtfy, r.srv.URL+"/t")
	d.Enqueue(tg, Secrets{}, testEvent())
	waitFor(t, "first in flight", func() bool { return r.count() == 1 })
	d.Enqueue(tg, Secrets{}, testEvent()) // fills the queue of 1
	if d.Enqueue(tg, Secrets{}, testEvent()) {
		t.Fatal("enqueue into a full queue")
	}
	if d.Status(tg.ID).Dropped != 1 {
		t.Fatalf("status %+v", d.Status(tg.ID))
	}
}

func TestEnqueueBeforeStartAndAfterWait(t *testing.T) {
	r := newReceiver(t, true)
	d := fastDispatcher(r, nil)
	tg := target(KindNtfy, r.srv.URL+"/t")
	if d.Enqueue(tg, Secrets{}, testEvent()) {
		t.Fatal("enqueue before start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	cancel()
	d.Wait()
	if d.Enqueue(tg, Secrets{}, testEvent()) {
		t.Fatal("enqueue after stop")
	}
	d.Forget(tg.ID)
}
