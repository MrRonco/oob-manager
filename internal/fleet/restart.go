package fleet

import (
	"context"
	"errors"
	"time"
)

// BMC restart window (tech_doc §37). While a server's BMC restarts on purpose, its
// poller does not treat the silence as a failure: it waits Config.RestartQuiet after the
// request, then polls every Config.RestartRetry until a snapshot succeeds or the window's
// deadline passes. Failures in the window do not count for the breaker and set no
// FailingSince; the slow tiers wait; Stale is still computed honestly.

// Defaults of the restart window cadence.
const (
	DefaultRestartQuiet = 60 * time.Second
	DefaultRestartRetry = 30 * time.Second
	// minRestartDelay keeps a window whose deadline is due from spinning.
	minRestartDelay = time.Second
	// MaxRestartWindow caps a window, so a stored or mistaken deadline can never hide a
	// real outage for long (migration 0013 has the same bound).
	MaxRestartWindow = 15 * time.Minute
)

// ErrRestarting is returned by ExpectRestart when a window is already open.
var ErrRestarting = errors.New("fleet: a BMC restart is already expected for this server")

// RestartWindow is an expected BMC restart: requested at Since by By, expected back by
// Until (the deadline).
type RestartWindow struct {
	Since, Until time.Time
	By           string
}

// RestartOutcome is how a restart window ended.
type RestartOutcome string

// Outcomes.
const (
	// RestartBack: a snapshot succeeded after the quiet period (the inventory tier ran
	// right after it, so State carries the new capabilities and firmware).
	RestartBack RestartOutcome = "back"
	// RestartTimeout: the deadline passed without a successful snapshot; normal failure
	// accounting starts with the next poll.
	RestartTimeout RestartOutcome = "timeout"
	// RestartConfigChanged: the server was rebuilt or removed (Apply) during the window.
	RestartConfigChanged RestartOutcome = "config_changed"
)

// RestartEnd reports the end of a window. State is the server as published at that
// moment (zero for RestartConfigChanged).
type RestartEnd struct {
	Outcome RestartOutcome
	At      time.Time
	State   ServerState
}

// restartState is one open window and its callback. It is immutable; the poller holds
// a pointer to it and whoever swaps it out calls done exactly once.
type restartState struct {
	w    RestartWindow
	done func(RestartEnd)
}

// ExpectRestart opens a restart window on server id. done is called exactly once when
// the window ends (back, timeout or config_changed), from the poller's goroutine or from
// Apply: it must not block. It is never called when CancelRestart closes the window or
// the fleet stops.
func (f *Fleet) ExpectRestart(id string, w RestartWindow, done func(RestartEnd)) error {
	p, ok := f.roster.Load().byID[id]
	switch {
	case !ok:
		return ErrUnknownServer
	case p.state.Load().Paused:
		return ErrPaused
	case !w.Until.After(w.Since) || w.Until.Sub(w.Since) > MaxRestartWindow:
		return errors.New("fleet: a restart window needs a deadline after its start, at most 15 minutes later")
	}
	if done == nil {
		done = func(RestartEnd) {}
	}
	st := &restartState{w: w, done: done}
	if !p.restart.CompareAndSwap(nil, st) {
		return ErrRestarting
	}
	if f.roster.Load().byID[id] != p {
		// A concurrent Apply retired this poller: its dropRestart either already ran
		// (and fired done) or never will, so take the window back and refuse.
		if p.restart.CompareAndSwap(st, nil) {
			return ErrUnknownServer
		}
		return nil // dropRestart took it and reported config_changed
	}
	select { // reschedule now: the quiet period counts from the request, not the next poll
	case p.wake <- struct{}{}:
	default: // a wake-up is already pending
	}
	return nil
}

// CancelRestart closes server id's window without calling its callback (the BMC
// refused the reset, so nothing restarts). It reports whether a window was open.
func (f *Fleet) CancelRestart(id string) bool {
	p, ok := f.roster.Load().byID[id]
	return ok && p.restart.Swap(nil) != nil
}

// endRestart closes r (if it is still the open window) and reports how it ended, with
// the state as published once the window is gone.
func (p *poller) endRestart(r *restartState, outcome RestartOutcome, now time.Time) {
	if p.restart.CompareAndSwap(r, nil) {
		r.done(RestartEnd{Outcome: outcome, At: now, State: p.view(now)})
	}
}

// dropRestart ends a window of a poller that Apply retires (rebuilt or removed server).
func (p *poller) dropRestart(at time.Time) {
	if r := p.restart.Swap(nil); r != nil {
		r.done(RestartEnd{Outcome: RestartConfigChanged, At: at})
	}
}

// restartDelay is the wait before the next cycle while a window is open: the rest of
// the quiet period, then RestartRetry, never past the deadline.
func (p *poller) restartDelay(r *restartState, now time.Time) time.Duration {
	if quietEnd := r.w.Since.Add(p.cfg.RestartQuiet); now.Before(quietEnd) {
		return max(quietEnd.Sub(now), minRestartDelay)
	}
	return max(min(p.cfg.RestartRetry, r.w.Until.Sub(now)), minRestartDelay)
}

// restartCycle runs one cycle inside an open window: no poll during the quiet period,
// then one poll. A good poll is the BMC back (also exactly at the deadline); a failed
// poll at or after the deadline ends the window as a timeout and counts as the first
// failure of the streak, so "unreachable since" is the deadline.
func (p *poller) restartCycle(ctx context.Context, cad cadence, r *restartState, now time.Time) cadence {
	if now.Before(r.w.Since.Add(p.cfg.RestartQuiet)) {
		return cad // the BMC is still going down or booting: do not poll
	}
	next, ok := p.pollSnapshot(ctx, p.load(), now)
	if ctx.Err() != nil {
		return cad
	}
	if !ok {
		p.restartFailed(r, next, now)
		return cad
	}
	p.publish(next)
	cad.inventory = time.Time{} // firmware and LastResetTime may have changed: re-read now
	cad.firmware = time.Time{}
	// The firmware scan (one document per changed component; slow on an iDRAC8) runs
	// after the window has ended, so the restart is reported back promptly (review C-L7).
	cad.holdFirmware = true
	next, cad = p.refreshSlowTiers(ctx, next, cad, now)
	cad.holdFirmware = false
	if ctx.Err() != nil {
		return cad
	}
	p.publish(next)
	p.cfg.Logger.Info("fleet: the BMC is back after its restart", "server", p.target.ID, "after", now.Sub(r.w.Since))
	p.endRestart(r, RestartBack, now)
	next, cad = p.runFirmwareIfDue(ctx, p.load(), cad, now)
	if ctx.Err() == nil {
		p.publish(next)
	}
	return cad
}

// restartFailed publishes a failed poll inside the window. Before the deadline it is
// not counted; at the deadline the window ends as a timeout and the failure starts the
// streak; a changed certificate (polling pauses) ends the window too.
func (p *poller) restartFailed(r *restartState, next ServerState, now time.Time) {
	switch {
	case next.Paused:
		p.publish(next)
		p.endRestart(r, RestartTimeout, now)
	case !now.Before(r.w.Until):
		next.ConsecutiveFailures, next.FailingSince = 0, now
		next.ConsecutiveFailures, next.BreakerOpenUntil = p.brk.afterFailure(0, time.Time{}, now)
		p.publish(next)
		p.endRestart(r, RestartTimeout, now)
		p.cfg.Logger.Warn("fleet: the BMC did not come back after its restart", "server", p.target.ID)
	default:
		p.publish(next)
	}
}
