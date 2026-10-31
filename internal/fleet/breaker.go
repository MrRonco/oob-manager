package fleet

import "time"

// BreakerState is the per-server circuit breaker position (system_design.md §2).
type BreakerState string

// Breaker states.
const (
	BreakerClosed   BreakerState = "closed"    // polling normally
	BreakerOpen     BreakerState = "open"      // too many failures: not polling until OpenUntil
	BreakerHalfOpen BreakerState = "half_open" // open window over: the next poll is a probe
)

// breaker holds the policy only; the counters live in the published ServerState, so
// the breaker itself has no mutable state.
type breaker struct {
	threshold int
	openFor   time.Duration
}

func (b breaker) state(failures int, openUntil, now time.Time) BreakerState {
	switch {
	case failures < b.threshold:
		return BreakerClosed
	case now.Before(openUntil):
		return BreakerOpen
	default:
		return BreakerHalfOpen
	}
}

// allow reports whether a poll may be sent now.
func (b breaker) allow(failures int, openUntil, now time.Time) bool {
	return b.state(failures, openUntil, now) != BreakerOpen
}

// afterFailure returns the new failure count and open-until time. Reaching the
// threshold (or failing the half-open probe) opens the breaker for openFor.
func (b breaker) afterFailure(failures int, openUntil, now time.Time) (int, time.Time) {
	failures++
	if failures >= b.threshold {
		return failures, now.Add(b.openFor)
	}
	return failures, openUntil
}
