package svg

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)

func buckets(step time.Duration, vals ...float64) []store.Bucket {
	out := make([]store.Bucket, 0, len(vals))
	for i, v := range vals {
		out = append(out, store.Bucket{Start: t0.Add(time.Duration(i) * step), Min: v - 1, Avg: v, Max: v + 1, N: 10})
	}
	return out
}

var cmdRE = regexp.MustCompile(`[ML]`)

func TestPathHasOnePointPerBucketAndBreaksAtGaps(t *testing.T) {
	step := 10 * time.Minute
	bs := buckets(step, 40, 41, 42, 43)
	bs = append(bs[:2], append([]store.Bucket{{Start: t0.Add(9 * step), Avg: 50, Min: 49, Max: 51, N: 1}},
		store.Bucket{Start: t0.Add(30 * step), Avg: 45, Min: 45, Max: 45, N: 1})...)
	in := Input{From: t0, To: t0.Add(36 * step), Series: []Series{{Buckets: bs, Step: step, Focus: true, Title: "CPU"}}}
	c := Build(in)
	if c.Empty || len(c.Lines) != 1 || !c.Lines[0].Focus || c.Lines[0].Title != "CPU" {
		t.Fatalf("chart = %+v", c)
	}
	d := c.Lines[0].D
	if got := len(cmdRE.FindAllString(d, -1)); got != len(bs) {
		t.Errorf("path %q has %d points, want %d", d, got, len(bs))
	}
	if strings.Count(d, "M") != 3 || strings.Count(d, "h0.1") != 2 {
		t.Errorf("path %q: want 3 runs, two of them lone points", d)
	}
	if !strings.HasSuffix(c.Envelope, "Z") || strings.Count(c.Envelope, "M") != 1 {
		t.Errorf("envelope %q: only the run of two buckets has an area", c.Envelope)
	}
	if !reflect.DeepEqual(c, Build(in)) {
		t.Error("Build is not deterministic")
	}
	if c.ViewBox != "0 0 600 140" || c.Plot.X != "56.0" || c.Plot.W != "536.0" {
		t.Errorf("frame %s %+v", c.ViewBox, c.Plot)
	}
}

func TestBandsOnlyNearTheData(t *testing.T) {
	step := time.Hour
	bs := buckets(step, 40, 50, 60) // values 39..61
	near := Build(Input{From: t0, To: t0.Add(3 * step), Series: []Series{{Buckets: bs, Step: step, Focus: true}},
		Bands: Bands{Warn: 62, HasWarn: true, Crit: 90, HasCrit: true}})
	if len(near.Bands) != 1 || near.Bands[0].Crit {
		t.Errorf("warn just above the data: bands %+v (critical too far to draw)", near.Bands)
	}
	inside := Build(Input{From: t0, To: t0.Add(3 * step), Series: []Series{{Buckets: bs, Step: step}},
		Bands: Bands{Warn: 45, HasWarn: true, Crit: 55, HasCrit: true}})
	if len(inside.Bands) != 2 || !inside.Bands[0].Crit || inside.Bands[1].Crit {
		t.Errorf("both inside: %+v", inside.Bands)
	}
	far := Build(Input{From: t0, To: t0.Add(3 * step), Series: []Series{{Buckets: bs, Step: step}},
		Bands: Bands{Warn: 85, HasWarn: true}})
	if len(far.Bands) != 0 {
		t.Errorf("a far threshold is not drawn: %+v", far.Bands)
	}
}

func TestTicksMarksAndSpans(t *testing.T) {
	step := 10 * time.Minute
	from, to := t0, t0.Add(24*time.Hour)
	c := Build(Input{From: from, To: to, Series: []Series{{Buckets: buckets(step, 20, 21, 25), Step: step}},
		Marks:  []Mark{{At: t0.Add(6 * time.Hour), Critical: true, Title: "PSU"}},
		Spans:  []Span{{From: t0.Add(time.Hour), To: t0.Add(2 * time.Hour), Title: "Maintenance"}},
		Format: func(v float64) string { return strings.TrimSuffix(strings.TrimSuffix(trim(v), "0"), ".") + "°" },
		XLabel: func(t time.Time, daily bool) string { return t.Format("15h") }})
	if len(c.XTicks) != 6 || c.XTicks[0].Label != "00h" || c.XTicks[1].Label != "04h" {
		t.Errorf("x ticks = %+v", c.XTicks)
	}
	if n := len(c.YTicks); n < 3 || n > 7 || !strings.HasSuffix(c.YTicks[0].Label, "°") {
		t.Errorf("y ticks = %+v", c.YTicks)
	}
	if len(c.Marks) != 1 || c.Marks[0].X != "190.0" || !c.Marks[0].Critical || c.Marks[0].Title != "PSU" {
		t.Errorf("marks = %+v", c.Marks)
	}
	if len(c.Spans) != 1 || c.Spans[0].Title != "Maintenance" || c.Spans[0].X != "78.3" {
		t.Errorf("spans = %+v", c.Spans)
	}
	week := Build(Input{From: t0, To: t0.Add(7 * 24 * time.Hour), Series: []Series{{Buckets: buckets(time.Hour, 1), Step: time.Hour}},
		Loc: time.FixedZone("EDT", -4*3600)})
	if len(week.XTicks) < 3 || len(week.XTicks) > 6 || week.XTicks[0].Label != "00:00" {
		t.Errorf("7 d ticks = %+v (local midnights)", week.XTicks)
	}
}

func trim(v float64) string { return strings.TrimRight(strings.TrimRight(num(v), "0"), ".") }

func TestEmptyAndFlat(t *testing.T) {
	if c := Build(Input{From: t0, To: t0.Add(time.Hour)}); !c.Empty || len(c.Lines) != 0 {
		t.Errorf("empty chart = %+v", c)
	}
	flat := Build(Input{From: t0, To: t0.Add(2 * time.Hour), Series: []Series{{Buckets: []store.Bucket{
		{Start: t0, Min: 5, Avg: 5, Max: 5, N: 1}, {Start: t0.Add(time.Hour), Min: 5, Avg: 5, Max: 5, N: 1}}, Step: time.Hour}}})
	if flat.Empty || len(flat.YTicks) == 0 {
		t.Errorf("flat chart = %+v", flat)
	}
	sp := Sparkline(buckets(sparkStep, 3, 3, 3), t0, t0.Add(3*sparkStep), sparkStep)
	if sp.Points != 3 || !strings.Contains(sp.D, " 12.0") || sp.ViewBox != "0 0 120 24" {
		t.Errorf("flat sparkline = %+v (middle line)", sp)
	}
	if e := Sparkline(nil, t0, t0.Add(time.Hour), time.Minute); e.D != "" || e.Points != 0 {
		t.Errorf("empty sparkline = %+v", e)
	}
	up := Sparkline(buckets(sparkStep, 1, 2, 3), t0, t0.Add(3*sparkStep), sparkStep)
	if !strings.HasPrefix(up.D, "M") || !strings.HasSuffix(up.D, " 1.0") {
		t.Errorf("rising sparkline ends at the top: %q", up.D)
	}
}

const sparkStep = 30 * time.Minute

func TestScales(t *testing.T) {
	if num(0.04) != "0" || num(-0) != "0" || num(12.345) != "12.3" {
		t.Error("num")
	}
	if lo, hi := domain(5, 3); lo != 0 || hi != 1 {
		t.Error("inverted domain")
	}
	if s := niceStep(0, 4); s != 1 {
		t.Error("niceStep of nothing")
	}
	if s := niceStep(97, 4); s != 25 {
		t.Errorf("niceStep(97) = %v", s)
	}
	if x := (timeScale{from: t0, to: t0, x0: 3, x1: 9}).x(t0); x != 3 {
		t.Error("empty time scale")
	}
	if ticks, _ := timeTicks(t0, t0.Add(400*24*time.Hour), time.UTC); len(ticks) == 0 || len(ticks) > 8 {
		t.Errorf("a long span still gets ticks: %d", len(ticks))
	}
}

func TestDayTicksStayOnMidnightAcrossDST(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no zoneinfo")
	}
	from := time.Date(2026, 10, 25, 0, 0, 0, 0, ny)
	ticks, _ := timeTicks(from, from.AddDate(0, 0, 30), ny)
	for _, tk := range ticks {
		if l := tk.In(ny); l.Hour() != 0 {
			t.Errorf("tick %v is not on local midnight", l)
		}
	}
}

// TestCoarseBucketsSitAtTheirOwnMiddle (review L4/L5): in a 3-hour chart, daily rows are
// drawn at noon and joined to each other (a day apart is no gap for a daily row), while
// a hole between 3-hour buckets still breaks the line.
func TestCoarseBucketsSitAtTheirOwnMiddle(t *testing.T) {
	step := 3 * time.Hour
	day := 24 * time.Hour
	bs := []store.Bucket{{Start: t0, Avg: 1}, {Start: t0.Add(day), Avg: 2}, {Start: t0.Add(2 * day), Avg: 3},
		{Start: t0.Add(2*day + 9*time.Hour), Avg: 4}}
	width := func(b store.Bucket) time.Duration {
		if b.Start.Before(t0.Add(2 * day)) {
			return day
		}
		return step
	}
	ts := timeScale{from: t0, to: t0.Add(3 * day), x0: 0, x1: 72}
	vs := valueScale{lo: 0, hi: 5, y0: 0, y1: 10}
	d := path(Series{Buckets: bs, Step: step, Width: width}, ts, vs)
	if !strings.HasPrefix(d, "M12.0 ") {
		t.Errorf("the first daily row is drawn at noon: %q", d)
	}
	if strings.Count(d, "M") != 2 {
		t.Errorf("daily rows join, the 9-hour hole between 3-hour buckets breaks: %q", d)
	}
}
