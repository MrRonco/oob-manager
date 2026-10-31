package history

import (
	"testing"
	"time"
)

func TestAdvanceClock(t *testing.T) {
	t0 := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		prevWall, prevClock, wall time.Time
		mono                      time.Duration
		monoKnown                 bool
		want                      time.Time
		jumped                    bool
	}{
		"first pass":                 {time.Time{}, time.Time{}, t0, 0, false, t0, false},
		"hourly pass":                {t0, t0, t0.Add(time.Hour), time.Hour, true, t0.Add(time.Hour), false},
		"restart after 2 h":          {t0, t0, t0.Add(2 * time.Hour), 0, false, t0.Add(2 * time.Hour), false},
		"restart after 3 days":       {t0, t0, t0.Add(72 * time.Hour), 0, false, t0.Add(3 * time.Hour), true},
		"forward step while running": {t0, t0, t0.Add(60 * 24 * time.Hour), time.Hour, true, t0.Add(2 * time.Hour), true},
		"catching up, wall honest":   {t0.Add(50 * time.Hour), t0, t0.Add(51 * time.Hour), time.Hour, true, t0.Add(2 * time.Hour), false},
		"caught up":                  {t0.Add(3 * time.Hour), t0.Add(2 * time.Hour), t0.Add(4 * time.Hour), time.Hour, true, t0.Add(4 * time.Hour), false},
		"step back":                  {t0, t0, t0.Add(-5 * time.Hour), time.Hour, true, t0.Add(-5 * time.Hour), false},
	} {
		got := advanceClock(tc.prevWall, tc.prevClock, tc.wall, tc.mono, tc.monoKnown)
		if !got.Clock.Equal(tc.want) || got.Jumped != tc.jumped {
			t.Errorf("%s: %+v, want %v jumped=%v", name, got, tc.want, tc.jumped)
		}
	}
}
