package ui

import (
	"fmt"
	"time"
)

// fmtPollDuration renders a poll duration for "poll took …": 850 ms, 4.2 s.
func fmtPollDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.1f s", d.Seconds())
	}
}

// overdueNote is the per-section staleness line, shown only when a slow poll tier
// (logs every few minutes, inventory every few hours) missed its refresh.
func (s *server) overdueNote(section string, overdue bool, asOf time.Time, tf timeFmt) string {
	if !overdue || asOf.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s last read at %s (%s ago); its refresh is overdue, so it may be out of date.",
		section, tf.full(asOf), fmtAge(s.d.Now().Sub(asOf)))
}

func (s *server) logOverdueNote(v ServerView, kind LogKind, tf timeFmt) string {
	if kind == LogLifecycle {
		return s.overdueNote("Lifecycle log", v.LifecycleOverdue, v.LifecycleAsOf, tf)
	}
	return s.overdueNote("System Event Log", v.SELOverdue, v.SELAsOf, tf)
}
