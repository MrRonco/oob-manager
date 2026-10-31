package fleet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"oob-manager/internal/bmc"
)

// poller owns one server. Only its run goroutine writes state; readers Load it.
type poller struct {
	cfg          Config
	brk          breaker
	target       Target
	interval     time.Duration // Config.Interval raised to cycleTimeout
	cycleTimeout time.Duration // budget of each tier in a cycle
	staleAfter   time.Duration
	state        atomic.Pointer[ServerState]
	// meta is the display name and tags; Apply updates it without a restart.
	meta atomic.Pointer[meta]
	// cancel and done are set by start (under Fleet.mu) and used by stop.
	cancel context.CancelFunc
	done   chan struct{}
	// postureReq is a pending RequestPosture; wake (one slot) ends the wait between
	// cycles so it runs at once.
	postureReq atomic.Bool
	// firmwareReq is a pending Refresh of the firmware tier.
	firmwareReq atomic.Bool
	wake        chan struct{}
	// restart is the open BMC restart window (restart.go); nil when none.
	restart atomic.Pointer[restartState]
	// behind: the last stored poll was older than samples already stored (the clock
	// moved back; samples.go); refusedLogged: the key cap was logged. Poller goroutine only.
	behind, refusedLogged, archivedLogged bool
}

type meta struct {
	name string
	tags []string
}

func (p *poller) setMeta(name string, tags []string) {
	p.meta.Store(&meta{name: name, tags: slices.Clone(tags)})
}

// start runs the poll loop in its own goroutine with a context derived from parent.
func (p *poller) start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	p.cancel, p.done = cancel, make(chan struct{})
	go func() {
		defer close(p.done)
		p.run(ctx)
	}()
}

// stop cancels the loop and waits for it to return (a no-op if it never started).
func (p *poller) stop() {
	if p.cancel == nil {
		return
	}
	p.cancel()
	<-p.done
}

// cadence is the run goroutine's private schedule for the slow tiers: when each is
// next due (zero = due now, e.g. at startup).
type cadence struct {
	events    time.Time
	inventory time.Time
	posture   time.Time
	firmware  time.Time
	// postureFails counts consecutive failed security check runs (the retry backoff).
	postureFails int
	// fwSig is the last good firmware scan's signature (firmware.go).
	fwSig string
	// holdFirmware defers the firmware tier to after a restart window ends (restart.go).
	holdFirmware bool
}

func newPoller(cfg Config, t Target) *poller {
	cycle := orValue(t.CycleTimeout, cfg.CycleTimeout)
	interval := max(orValue(t.Interval, cfg.Interval), cycle)
	p := &poller{
		cfg: cfg, brk: breaker{threshold: cfg.BreakerThreshold, openFor: cfg.BreakerOpenFor}, target: t,
		interval: interval, cycleTimeout: cycle, staleAfter: orValue(cfg.StaleAfter, 3*interval),
		wake: make(chan struct{}, 1),
	}
	initial := ServerState{ID: t.ID, Name: t.Name, Tags: append([]string(nil), t.Tags...),
		Interval: p.interval, StaleAfter: p.staleAfter, PostureEnabled: t.Posture != nil, PostureEvery: cfg.PostureEvery,
		FirmwareEvery: cfg.FirmwareEvery}
	initial.FirmwareEnabled = p.firmwareOn()
	p.state.Store(&initial)
	p.setMeta(t.Name, t.Tags)
	return p
}

// staleLimit is the fixed StaleAfter, else the live multiplier × the interval.
func (p *poller) staleLimit() time.Duration {
	if p.cfg.StaleAfter == 0 && p.cfg.StaleMultiplier != nil {
		if m := p.cfg.StaleMultiplier(); m > 0 {
			return time.Duration(m) * p.interval
		}
	}
	return p.staleAfter
}

func (p *poller) load() ServerState { return p.state.Load().clone() }

// publish stores s as the new state. The power fields are merged with whatever was
// published meanwhile (ObservePower runs on another goroutine): a verified power action
// newer than this poll's data keeps its state, the onset of the current state moves only
// when a poll sees a change, and a confirming poll keeps the cause.
func (p *poller) publish(s ServerState) {
	for {
		cur := p.state.Load()
		next := mergePower(*cur, s.clone())
		if p.state.CompareAndSwap(cur, &next) {
			return
		}
	}
}

// mergePower reconciles next's power state with the published cur.
func mergePower(cur, next ServerState) ServerState {
	switch {
	case !cur.HasSnapshot || !next.HasSnapshot:
		return next
	case cur.Snapshot.PowerAsOf().After(next.Snapshot.TakenAt()):
		// A verified power action is newer than this poll's data: keep it until a later poll.
		next.Snapshot = next.Snapshot.WithPowerState(cur.Snapshot.PowerState(), cur.Snapshot.PowerAsOf())
		next.PowerSince, next.PowerCause = cur.PowerSince, cur.PowerCause
	case next.Snapshot.PowerState() != cur.Snapshot.PowerState():
		next.PowerSince, next.PowerCause = next.LastSuccess, PowerCause{} // the poll saw a change
	default:
		next.PowerSince, next.PowerCause = cur.PowerSince, cur.PowerCause
	}
	return next
}

// observePower applies a verified power transition over the published state (see
// Fleet.ObservePower); only a newer observation is taken.
func (p *poller) observePower(o PowerObservation) bool {
	for {
		cur := p.state.Load()
		if !cur.HasSnapshot || !o.At.After(cur.Snapshot.PowerAsOf()) {
			return false
		}
		next := cur.clone()
		next.Snapshot = cur.Snapshot.WithPowerState(o.State, o.At)
		next.PowerCause = PowerCause{Action: o.Action, By: o.By, At: o.At}
		if o.State != cur.Snapshot.PowerState() {
			next.PowerSince = o.At
		}
		if p.state.CompareAndSwap(cur, &next) {
			return true
		}
	}
}

// view is the copy handed to readers, with the derived fields filled in.
func (p *poller) view(now time.Time) ServerState {
	s := p.load()
	m := p.meta.Load()
	s.Name, s.Tags = m.name, slices.Clone(m.tags)
	s.StaleAfter = p.staleLimit()
	s.Stale = !s.HasSnapshot || now.Sub(s.LastSuccess) > s.StaleAfter
	s.Breaker = p.brk.state(s.ConsecutiveFailures, s.BreakerOpenUntil, now)
	s.SELOverdue = p.overdue(s.HasSEL, s.SELAsOf, now, p.cfg.EventsEvery)
	s.LifecycleOverdue = p.overdue(s.HasLifecycle, s.LifecycleAsOf, now, p.cfg.EventsEvery)
	s.InventoryOverdue = p.overdue(s.HasInventory, s.InventoryAsOf, now, p.cfg.InventoryEvery)
	s.PostureOverdue = p.overdue(s.HasPosture, s.PostureAsOf, now, p.cfg.PostureEvery)
	s.PostureRequested = p.postureReq.Load()
	s.FirmwareRequested = p.firmwareReq.Load()
	if r := p.restart.Load(); r != nil && now.Before(r.w.Until) {
		s.Restarting, s.Restart = true, r.w
	}
	return s
}

// overdue: a kept value is older than its tier period plus two poll intervals (one for
// scheduling and jitter, one for a cycle that is still running).
func (p *poller) overdue(has bool, asOf, now time.Time, every time.Duration) bool {
	return has && now.Sub(asOf) > every+2*p.interval
}

func (p *poller) run(ctx context.Context) {
	var cad cadence
	for {
		cad = p.cycle(ctx, cad)
		if p.load().Paused {
			<-ctx.Done() // a changed certificate: wait for a confirmed new pin (Apply)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-p.cfg.Clock.After(p.nextDelay()):
		case <-p.wake:
		}
	}
}

// nextDelay is the interval ± Jitter, or the restart window's cadence while one is open.
func (p *poller) nextDelay() time.Duration {
	if r := p.restart.Load(); r != nil {
		return p.restartDelay(r, p.cfg.Clock.Now())
	}
	f := 1 + (2*p.cfg.Rand()-1)*p.cfg.Jitter
	return time.Duration(float64(p.interval) * f)
}

// cycle runs the fast tier and then any slow tier that is due, each under its own
// cycleTimeout budget, unless the breaker is open. Slow tiers wait for a good snapshot.
func (p *poller) cycle(ctx context.Context, cad cadence) cadence {
	now := p.cfg.Clock.Now()
	if r := p.restart.Load(); r != nil {
		return p.restartCycle(ctx, cad, r, now)
	}
	cur := p.load()
	if !p.brk.allow(cur.ConsecutiveFailures, cur.BreakerOpenUntil, now) {
		return cad
	}
	next, ok := p.pollSnapshot(ctx, cur, now)
	if ctx.Err() != nil {
		return cad // shutting down: a cancelled poll is not a BMC failure
	}
	p.publish(next)
	if !ok {
		return cad
	}
	next, cad = p.refreshSlowTiers(ctx, next, cad, now)
	if ctx.Err() == nil {
		p.publish(next)
	}
	return cad
}

func (p *poller) budget(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, p.cycleTimeout)
}

// pollSnapshot is the fast tier: health rollup, thermal, power and power state.
func (p *poller) pollSnapshot(ctx context.Context, cur ServerState, now time.Time) (ServerState, bool) {
	cctx, cancel := p.budget(ctx)
	defer cancel()
	next := cur
	next.LastAttempt = now
	started := time.Now()
	snap, err := p.target.Driver.Snapshot(cctx)
	next.LastPollDuration = time.Since(started)
	if err != nil {
		return p.recordFailure(next, budgetClass(ctx, cctx, err), now), false
	}
	p.logSuccess(cur, next.LastPollDuration, now)
	next.Previous, next.HasPrevious = cur.Snapshot, cur.HasSnapshot
	next.Snapshot, next.HasSnapshot, next.LastSuccess = snap, true, now
	next.LastError, next.ConsecutiveFailures = bmc.ClassNone, 0
	next.FailingSince, next.BreakerOpenUntil = time.Time{}, time.Time{}
	next.HistoryRefused += p.storeSamples(cctx, snap)
	return next, true
}

// budgetClass marks a failure as a timeout when the poll's own budget (cctx) ran
// out while the parent context did not: a response cut off at the deadline can
// surface as a decode error or a bare EOF, which would otherwise show as "protocol"
// or "other" for a BMC that simply hangs. Only those ambiguous errors are relabelled;
// errors with a definite cause (a pin mismatch, an HTTP status, an auth refusal, the
// local size cap or method guard) keep their class. A genuine decode fault returned
// in the last instant before the deadline is also reported as a timeout: the poll
// was out of budget either way. Every tier uses it (pollSnapshot, refreshPosture,
// refreshLogs, refreshInventory).
func budgetClass(parent, cctx context.Context, err error) error {
	if err == nil || parent.Err() != nil || !errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return err
	}
	if c := bmc.Classify(err); c == bmc.ClassOther || (c == bmc.ClassProtocol && errors.Is(err, bmc.ErrDecode)) {
		return fmt.Errorf("%w: %w", bmc.ErrTimeout, err)
	}
	return err
}

func (p *poller) recordFailure(next ServerState, err error, now time.Time) ServerState {
	if p.restart.Load() != nil && !errors.Is(err, bmc.ErrPinMismatch) {
		// An expected BMC restart: the silence is not a failure (restart.go).
		next.LastError = bmc.Classify(err)
		p.cfg.Logger.Debug("fleet: poll failed while the BMC restarts", "server", p.target.ID,
			"class", string(next.LastError))
		return next
	}
	if next.ConsecutiveFailures == 0 {
		next.FailingSince = now
	}
	next.ConsecutiveFailures, next.BreakerOpenUntil =
		p.brk.afterFailure(next.ConsecutiveFailures, next.BreakerOpenUntil, now)
	next.LastError = bmc.Classify(err)
	if errors.Is(err, bmc.ErrPinMismatch) {
		next.PinMismatch, next.Paused = true, true
		next.ConsecutiveFailures, next.BreakerOpenUntil = 1, time.Time{}
		p.cfg.Logger.Warn("fleet: BMC certificate does not match the pin; polling paused until a new fingerprint is confirmed",
			"server", p.target.ID)
		return next
	}
	p.cfg.Logger.Warn("fleet: poll failed", "server", p.target.ID,
		"class", string(next.LastError), "failures", next.ConsecutiveFailures,
		"duration", next.LastPollDuration.Round(time.Millisecond))
	return next
}

// logSuccess logs one INFO line when a server recovers after failures and a DEBUG
// line for every successful poll.
func (p *poller) logSuccess(prev ServerState, took time.Duration, now time.Time) {
	took = took.Round(time.Millisecond)
	if prev.ConsecutiveFailures > 0 {
		p.cfg.Logger.Info("fleet: poll recovered", "server", p.target.ID,
			"failures", prev.ConsecutiveFailures, "failing_for", now.Sub(prev.FailingSince), "duration", took)
	}
	p.cfg.Logger.Debug("fleet: poll ok", "server", p.target.ID, "duration", took)
}
