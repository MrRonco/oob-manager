package svg

import (
	"strings"
	"testing"
	"time"

	"oob-manager/internal/store"
)

func TestRecorderRowLineAreaAndGaps(t *testing.T) {
	step := 30 * time.Minute
	from, to := t0, t0.Add(48*step)
	// Buckets 0-9 and 20-47: one gap of 10 steps in the middle.
	var bs []store.Bucket
	for i := 0; i < 48; i++ {
		if i >= 10 && i < 20 {
			continue
		}
		bs = append(bs, store.Bucket{Start: from.Add(time.Duration(i) * step), Avg: float64(40 + i%5), N: 6})
	}
	r := RecorderRow(bs, from, to, step)
	if r.ViewBox != "0 0 720 40" || r.Points != 38 {
		t.Fatalf("viewBox %q points %d", r.ViewBox, r.Points)
	}
	if n := strings.Count(r.Line, "M"); n != 2 {
		t.Errorf("line has %d subpaths, want 2 (broken at the gap): %s", n, r.Line)
	}
	if n := strings.Count(r.Area, "Z"); n != 2 {
		t.Errorf("area has %d closed runs, want 2: %s", n, r.Area)
	}
	if len(r.Gaps) != 1 || r.Gaps[0].X != "150.0" || r.Gaps[0].W != "150.0" || r.Gaps[0].H != "40.0" {
		t.Errorf("gaps %+v, want one from x 150, 150 wide", r.Gaps)
	}
}

func TestRecorderRowEmptyAndFlat(t *testing.T) {
	step := 30 * time.Minute
	from, to := t0, t0.Add(4*step)
	r := RecorderRow(nil, from, to, step)
	if r.Line != "" || r.Area != "" || len(r.Gaps) != 1 || r.Gaps[0].W != "720.0" {
		t.Fatalf("empty row %+v", r)
	}
	flat := RecorderRow(buckets(step, 30, 30, 30, 30), from, to, step)
	if len(flat.Gaps) != 0 || !strings.Contains(flat.Line, " 20") {
		t.Fatalf("a flat row sits in the middle with no gaps: %+v", flat)
	}
	if got := gaps(nil, to, from, step, timeScale{}); got != nil {
		t.Errorf("an inverted window has no gaps: %+v", got)
	}
	single := RecorderRow(buckets(step, 30), from, to, step)
	if single.Area != "" || !strings.Contains(single.Line, "h0.1") {
		t.Errorf("a lone point is a dot with no area: %+v", single)
	}
}

func TestAxisTicksAreHoursInTheViewersZone(t *testing.T) {
	from := time.Date(2026, 10, 22, 10, 30, 0, 0, time.UTC)
	ticks := AxisTicks(from, from.Add(24*time.Hour), nil)
	if len(ticks) != 4 {
		t.Fatalf("%d ticks", len(ticks))
	}
	for i, tk := range ticks {
		if tk.At.Minute() != 0 || tk.At.Hour()%6 != 0 || tk.Pct < 0 || tk.Pct > 100 {
			t.Errorf("tick %d: %v at %d %%", i, tk.At, tk.Pct)
		}
	}
	if ticks[0].At != time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC) || ticks[0].Pct != 6 {
		t.Errorf("first tick %v at %d %%", ticks[0].At, ticks[0].Pct)
	}
	tokyo := time.FixedZone("JST", 9*3600)
	if got := AxisTicks(from, from.Add(24*time.Hour), tokyo)[0].At; got.In(tokyo).Hour()%6 != 0 {
		t.Errorf("ticks follow the viewer's zone: %v", got.In(tokyo))
	}
}

// TestAxisTicksStayOnTheHourAcrossDST (review L6): New York falls back on 2026-11-01.
func TestAxisTicksStayOnTheHourAcrossDST(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no zoneinfo:", err)
	}
	from := time.Date(2026, 10, 31, 22, 0, 0, 0, ny)
	ticks := AxisTicks(from, from.Add(24*time.Hour), ny)
	if len(ticks) == 0 {
		t.Fatal("no ticks")
	}
	for _, tk := range ticks {
		if l := tk.At.In(ny); l.Hour()%6 != 0 || l.Minute() != 0 {
			t.Errorf("tick at %v, want 00, 06, 12 or 18 local", l)
		}
	}
}
