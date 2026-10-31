package svg

import (
	"math"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/store"
)

// RecorderW and RecorderH are a flight-recorder row's viewBox (round-2 slice C, the
// Overview's fleet view): every server is one row on the same 24 h axis, stretched to the
// row's width by CSS (preserveAspectRatio="none" with non-scaling strokes), so the rows
// line up and a time is at the same x in every row.
const (
	RecorderW = 720
	RecorderH = 40
)

// Recorder is one row's geometry: the averages as a line and the area under them, and
// the stretches of the window without readings.
type Recorder struct {
	ViewBox    string
	Line, Area string
	// Gaps are the stretches with no bucket (the server was not polled, or the history
	// starts later), full height, in viewBox units.
	Gaps   []Rect
	Points int
}

// RecorderRow draws buckets of step over [from, to). The value axis fits the row's own
// minimum and maximum (a flat series sits in the middle); a gap of more than 2.5 steps
// breaks the line, and every step without a bucket is part of a gap.
func RecorderRow(bs []store.Bucket, from, to time.Time, step time.Duration) Recorder {
	r := Recorder{ViewBox: "0 0 " + strconv.Itoa(RecorderW) + " " + strconv.Itoa(RecorderH), Points: len(bs)}
	ts := timeScale{from: from, to: to, x0: 0, x1: RecorderW}
	r.Gaps = gaps(bs, from, to, step, ts)
	if len(bs) == 0 {
		return r
	}
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, b := range bs {
		lo, hi = math.Min(lo, b.Avg), math.Max(hi, b.Avg)
	}
	vs := valueScale{lo: lo, hi: hi, y0: 4, y1: RecorderH - 4}
	s := Series{Buckets: bs, Step: step}
	r.Line = path(s, ts, vs)
	r.Area = under(s, ts, vs)
	return r
}

// under is the closed area between each contiguous run of the line and the bottom edge.
func under(s Series, ts timeScale, vs valueScale) string {
	var parts []string
	start := 0
	for i := 1; i <= len(s.Buckets); i++ {
		if i < len(s.Buckets) && !s.broken(s.Buckets[i-1], s.Buckets[i]) {
			continue
		}
		run := s.Buckets[start:i]
		if len(run) > 1 {
			var b strings.Builder
			for j, bk := range run {
				cmd := " L"
				if j == 0 {
					cmd = "M"
				}
				b.WriteString(cmd + num(ts.x(mid(bk, s))) + " " + num(vs.y(bk.Avg)))
			}
			b.WriteString(" L" + num(ts.x(mid(run[len(run)-1], s))) + " " + num(RecorderH) +
				" L" + num(ts.x(mid(run[0], s))) + " " + num(RecorderH) + " Z")
			parts = append(parts, b.String())
		}
		start = i
	}
	return strings.Join(parts, " ")
}

// gaps merges the steps of [from, to) that hold no bucket into rectangles.
func gaps(bs []store.Bucket, from, to time.Time, step time.Duration, ts timeScale) []Rect {
	if step <= 0 || !from.Before(to) {
		return nil
	}
	have := make(map[int64]bool, len(bs))
	for _, b := range bs {
		have[b.Start.Sub(from).Milliseconds()/step.Milliseconds()] = true
	}
	var out []Rect
	open := time.Time{}
	n := int64(to.Sub(from) / step)
	for i := int64(0); i <= n; i++ {
		t := from.Add(time.Duration(i) * step)
		empty := i < n && !have[i]
		switch {
		case empty && open.IsZero():
			open = t
		case !empty && !open.IsZero():
			x0, x1 := ts.x(open), ts.x(t)
			out = append(out, Rect{X: num(x0), Y: "0", W: num(x1 - x0), H: num(RecorderH)})
			open = time.Time{}
		}
	}
	return out
}

// AxisTick is a time label of the shared axis at Pct percent of the row's width.
type AxisTick struct {
	At  time.Time
	Pct int
}

// AxisTicks label every sixth hour of [from, to) in loc (the viewer's zone): four labels
// on a day, as in the mockup. They are percentages so the axis can be laid out by
// position classes under the CSP.
func AxisTicks(from, to time.Time, loc *time.Location) []AxisTick {
	if loc == nil {
		loc = time.UTC
	}
	l := from.In(loc)
	t := time.Date(l.Year(), l.Month(), l.Day(), l.Hour()-l.Hour()%6, 0, 0, 0, loc)
	ts := timeScale{from: from, to: to, x0: 0, x1: 100}
	var out []AxisTick
	// Wall-clock steps (time.Date normalises the hour), so a DST change keeps the labels on
	// 00, 06, 12 and 18 instead of shifting them by an hour.
	for ; t.Before(to) && len(out) < 8; t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+6, 0, 0, 0, loc) {
		if !t.Before(from) {
			out = append(out, AxisTick{At: t, Pct: int(math.Round(ts.x(t)))})
		}
	}
	return out
}
