package history

import "time"

// The janitor's retention clock (review MEDIUM-1). Samples carry the wall clock, and a
// wall clock stepped forward (a wrong RTC after a cold boot, a VM resumed with a stale
// offset) would make one pass delete every reading "older than 7 days". The janitor
// therefore prunes and rolls up by its own clock, persisted in history_meta: it follows
// the wall clock while the two agree, and otherwise advances at most twice the real
// time that passed (the monotonic clock while the process runs; the expected hourly
// cadence plus slack across a restart). A forward step or a long downtime is caught up
// gradually, never in one pass; a step back is followed at once (it deletes less).

// Clock tuning.
const (
	// restartAllowance is how far the retention clock may advance on the first pass
	// after a start, when the real time since the last pass is unknown: the hourly
	// cadence plus two hours of slack.
	restartAllowance = 3 * time.Hour
	// monoSlack is how much the wall clock may run ahead of the monotonic clock between
	// two passes before it counts as a forward step.
	monoSlack = 5 * time.Minute
	// lagNotice is the lag behind the wall clock from which the History tab explains
	// that retention is catching up.
	lagNotice = 2 * time.Hour
)

// clockStep is one pass's retention clock.
type clockStep struct {
	Clock time.Time
	// Jumped: the wall clock ran ahead of real time (a forward step while running, or
	// more than restartAllowance since the last pass across a restart).
	Jumped bool
}

// advanceClock returns the retention clock for a pass at wall. prevWall and prevClock
// are the last pass's wall time and retention clock (zero: no pass yet); mono is the
// monotonic time since that pass when this process ran it (monoKnown).
func advanceClock(prevWall, prevClock, wall time.Time, mono time.Duration, monoKnown bool) clockStep {
	if prevWall.IsZero() || prevClock.IsZero() {
		return clockStep{Clock: wall}
	}
	if !wall.After(prevClock) { // the wall clock is behind the retention clock: follow it
		return clockStep{Clock: wall}
	}
	allowed := restartAllowance
	jumped := wall.Sub(prevWall) > restartAllowance
	if monoKnown {
		allowed = 2 * max(mono, 0)
		jumped = wall.Sub(prevWall) > mono+monoSlack
	}
	if lag := wall.Sub(prevClock); lag <= allowed {
		return clockStep{Clock: wall, Jumped: jumped}
	}
	return clockStep{Clock: prevClock.Add(allowed), Jumped: jumped}
}

// Lagging reports how far the retention clock of st is behind now, when that is more
// than lagNotice (the History tab then says retention is catching up).
func Lagging(st Status, now time.Time) (time.Duration, bool) {
	if st.Clock.IsZero() {
		return 0, false
	}
	lag := now.Sub(st.Clock)
	return lag, lag > lagNotice
}
