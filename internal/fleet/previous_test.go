package fleet

import (
	"testing"
	"time"
)

// TestPreviousSnapshotIsKept: the value-change cue (plan 04 §11 item 5) compares each
// reading with the poll before; a failed poll moves neither snapshot.
func TestPreviousSnapshotIsKept(t *testing.T) {
	d := &countingDriver{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute, BreakerThreshold: 100})
	waitFor(t, "first poll", func() bool { return h.state(t, "x").HasSnapshot })
	if s := h.state(t, "x"); s.HasPrevious {
		t.Fatalf("the first poll has nothing before it: %+v", s.Previous)
	}
	h.tick(t, 1, time.Minute)
	waitFor(t, "second poll", func() bool { return h.state(t, "x").LastSuccess.Equal(t0.Add(time.Minute)) })
	if s := h.state(t, "x"); !s.HasPrevious || !s.Previous.TakenAt().Equal(s.Snapshot.TakenAt()) {
		t.Fatalf("after two polls the first is kept as Previous: has=%v", s.HasPrevious)
	}
	d.setFail(true)
	h.tick(t, 1, time.Minute)
	waitFor(t, "failure", func() bool { return h.state(t, "x").ConsecutiveFailures == 1 })
	if s := h.state(t, "x"); !s.HasPrevious || !s.HasSnapshot {
		t.Fatalf("a failed poll keeps both snapshots: %+v", s)
	}
}
