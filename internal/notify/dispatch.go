package notify

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Dispatcher defaults.
const (
	DefaultAttempts   = 4
	DefaultBackoffMin = 2 * time.Second
	DefaultBackoffMax = time.Minute
	DefaultQueueSize  = 64
	DefaultRateBurst  = 10
	DefaultRateEvery  = 30 * time.Second // one more message per 30 s after the burst
	DefaultFailAfter  = 3                // consecutive failed messages make a target "failing"
)

// DispatchConfig wires a Dispatcher. Zero values take the defaults above.
type DispatchConfig struct {
	Transport Transport
	// Instance is config ui.instance_name, sent in the webhook body; InstanceFn, when
	// set, is read at each send instead (the live Settings → General value).
	Instance   string
	InstanceFn func() string
	Now        func() time.Time
	Logger     *slog.Logger
	// Attempts per message (first try included), with exponential backoff between them.
	Attempts   int
	BackoffMin time.Duration
	BackoffMax time.Duration
	QueueSize  int
	RateBurst  int
	RateEvery  time.Duration
	FailAfter  int
	// OnFailing is called (from a worker) when a target becomes failing (true) or
	// delivers again after failing (false); the service turns it into a self-alert.
	OnFailing func(t Target, failing bool)
}

func (c DispatchConfig) withDefaults() DispatchConfig {
	c.Transport = c.Transport.withDefaults()
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	c.Attempts = orInt(c.Attempts, DefaultAttempts)
	c.BackoffMin = orDur(c.BackoffMin, DefaultBackoffMin)
	c.BackoffMax = orDur(c.BackoffMax, DefaultBackoffMax)
	c.QueueSize = orInt(c.QueueSize, DefaultQueueSize)
	c.RateBurst = orInt(c.RateBurst, DefaultRateBurst)
	c.RateEvery = orDur(c.RateEvery, DefaultRateEvery)
	c.FailAfter = orInt(c.FailAfter, DefaultFailAfter)
	if c.OnFailing == nil {
		c.OnFailing = func(Target, bool) {}
	}
	return c
}

// Status is a target's delivery state since start (kept in memory).
type Status struct {
	LastSuccess         time.Time
	LastFailure         time.Time
	LastError           string // error class, never receiver text
	ConsecutiveFailures int    // messages that failed after every retry, in a row
	Failing             bool
	Sent                uint64
	Dropped             uint64 // queue full or rate limited
}

type job struct {
	t   Target
	sec Secrets
	e   Event
}

// Dispatcher delivers events: one worker goroutine and one bounded queue per target,
// so a slow or dead receiver never delays the others and messages to one target keep
// their order. Enqueue never blocks.
type Dispatcher struct {
	cfg DispatchConfig

	mu      sync.Mutex
	ctx     context.Context
	workers map[string]chan job
	status  map[string]Status
	buckets map[string]bucket
	stopped bool
	wg      sync.WaitGroup
}

// NewDispatcher returns an idle dispatcher; call Start.
func NewDispatcher(cfg DispatchConfig) *Dispatcher {
	return &Dispatcher{cfg: cfg.withDefaults(), workers: map[string]chan job{}, status: map[string]Status{},
		buckets: map[string]bucket{}}
}

// Start lets workers run until ctx ends; Wait then returns once they stopped.
func (d *Dispatcher) Start(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ctx = ctx
}

// Wait blocks until every worker has returned (after the Start context ended). No
// worker starts after Wait was called.
func (d *Dispatcher) Wait() {
	d.mu.Lock()
	d.stopped = true
	d.mu.Unlock()
	d.wg.Wait()
}

// Enqueue queues e for t. It returns false when the dispatcher is not running, the
// target's queue is full or its rate limit is spent (counted as dropped).
func (d *Dispatcher) Enqueue(t Target, sec Secrets, e Event) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped || d.ctx == nil || d.ctx.Err() != nil {
		return false
	}
	if !d.take(t.ID) {
		d.drop(t, "rate limit")
		return false
	}
	ch, ok := d.workers[t.ID]
	if !ok {
		ch = make(chan job, d.cfg.QueueSize)
		d.workers[t.ID] = ch
		ctx := d.ctx
		d.wg.Go(func() { d.work(ctx, ch) })
	}
	select {
	case ch <- job{t: t, sec: sec, e: e}:
		return true
	default:
		d.drop(t, "queue full")
		return false
	}
}

// drop counts a dropped message; the caller holds mu.
func (d *Dispatcher) drop(t Target, why string) {
	st := d.status[t.ID]
	st.Dropped++
	d.status[t.ID] = st
	if st.Dropped == 1 || st.Dropped%100 == 0 {
		d.cfg.Logger.Warn("notify: message dropped", "target", t.ID, "reason", why, "dropped", st.Dropped)
	}
}

// Status returns the delivery state of target id.
func (d *Dispatcher) Status(id string) Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status[id]
}

// Forget drops the state of a deleted target.
func (d *Dispatcher) Forget(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.status, id)
	delete(d.buckets, id)
}

func (d *Dispatcher) work(ctx context.Context, ch chan job) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-ch:
			d.process(ctx, j)
		}
	}
}

// process delivers one job with bounded retries and exponential backoff.
func (d *Dispatcher) process(ctx context.Context, j job) {
	backoff := d.cfg.BackoffMin
	var err error
	for attempt := 1; attempt <= d.cfg.Attempts; attempt++ {
		if err = d.deliver(ctx, j.t, j.sec, j.e); err == nil {
			d.record(j.t, nil)
			return
		}
		if !retryable(err) || attempt == d.cfg.Attempts {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, d.cfg.BackoffMax)
	}
	d.cfg.Logger.Warn("notify: delivery failed", "target", j.t.ID, "kind", string(j.t.Kind),
		"class", ErrorClass(err), "event", string(j.e.Class))
	d.record(j.t, err)
}

// SendNow delivers e once, synchronously (Send test). It bypasses the queue and the
// rate limit (the UI limits tests itself) and updates the target's status.
func (d *Dispatcher) SendNow(ctx context.Context, t Target, sec Secrets, e Event) error {
	err := d.deliver(ctx, t, sec, e)
	d.record(t, err)
	return err
}

// record updates the status and reports failing/recovered transitions.
func (d *Dispatcher) record(t Target, err error) {
	d.mu.Lock()
	st := d.status[t.ID]
	now := d.cfg.Now()
	wasFailing := st.Failing
	if err == nil {
		st.LastSuccess, st.ConsecutiveFailures, st.Failing = now, 0, false
		st.Sent++
	} else {
		st.LastFailure, st.LastError = now, ErrorClass(err)
		st.ConsecutiveFailures++
		st.Failing = st.ConsecutiveFailures >= d.cfg.FailAfter
	}
	d.status[t.ID] = st
	d.mu.Unlock()
	if st.Failing != wasFailing {
		d.cfg.OnFailing(t, st.Failing)
	}
}

// deliver renders e for t's kind and sends it once.
func (d *Dispatcher) deliver(ctx context.Context, t Target, sec Secrets, e Event) error {
	e = e.withDetail(t.IncludeDetail)
	tr := d.cfg.Transport
	ctx, cancel := context.WithTimeout(ctx, tr.Timeout)
	defer cancel()
	if t.Kind == KindEmail {
		msg, err := buildEmail(t, e, d.cfg.Now())
		if err != nil {
			return err
		}
		return tr.sendEmail(ctx, t, sec, msg)
	}
	req, err := d.request(ctx, t, sec, e)
	if err != nil {
		return err
	}
	return tr.do(req)
}

func (d *Dispatcher) request(ctx context.Context, t Target, sec Secrets, e Event) (*http.Request, error) {
	if _, err := checkHTTPURL(t.URL, t.AllowPlaintext); err != nil {
		return nil, failed(classBlocked, false, "notify: URL not allowed")
	}
	switch t.Kind {
	case KindNtfy:
		return buildNtfy(ctx, t, sec, e)
	case KindPushover:
		return buildPushover(ctx, t, sec, e)
	case KindGotify:
		return buildGotify(ctx, t, sec, e)
	case KindWebhook:
		return buildWebhook(ctx, t, sec, e, d.instance(), d.cfg.Now())
	default:
		return nil, failed(classBlocked, false, "notify: unknown target kind")
	}
}

// bucket is a token bucket per target (rate limit).
type bucket struct {
	tokens float64
	at     time.Time
}

// take spends one token of id's bucket; the caller holds mu.
func (d *Dispatcher) take(id string) bool {
	now := d.cfg.Now()
	b, ok := d.buckets[id]
	if !ok {
		b = bucket{tokens: float64(d.cfg.RateBurst), at: now}
	}
	if el := now.Sub(b.at); el > 0 {
		b.tokens = min(float64(d.cfg.RateBurst), b.tokens+float64(el)/float64(d.cfg.RateEvery))
	}
	b.at = now
	if b.tokens < 1 {
		d.buckets[id] = b
		return false
	}
	b.tokens--
	d.buckets[id] = b
	return true
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// instance is the installation label sent in webhook bodies.
func (d *Dispatcher) instance() string {
	if d.cfg.InstanceFn != nil {
		return d.cfg.InstanceFn()
	}
	return d.cfg.Instance
}
