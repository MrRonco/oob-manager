package svg

import (
	"math"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/store"
)

// Series is one line of a chart: the buckets' averages at the middle of each bucket,
// drawn muted or as the focus (accented, with its min/max envelope). A bucket is Step
// wide unless Width says otherwise (a row of a coarser tier: an hour or a day); two
// buckets further apart than 2.5 widths (the wider of the two) break the line: no data
// there.
type Series struct {
	Buckets []store.Bucket
	Step    time.Duration
	Width   func(store.Bucket) time.Duration
	Focus   bool
	Title   string
}

func (s Series) width(b store.Bucket) time.Duration {
	if s.Width != nil {
		if w := s.Width(b); w > 0 {
			return w
		}
	}
	return s.Step
}

// broken reports whether the line breaks between buckets a and b.
func (s Series) broken(a, b store.Bucket) bool {
	return b.Start.Sub(a.Start) > max(s.width(a), s.width(b))*5/2
}

// Bands are the focused series' thresholds (temperatures): from Warn up, and from Crit up.
type Bands struct {
	Warn, Crit       float64
	HasWarn, HasCrit bool
}

// Mark is an event drawn as a vertical line.
type Mark struct {
	At       time.Time
	Critical bool
	Title    string
}

// Span is a shaded period (a maintenance window).
type Span struct {
	From, To time.Time
	Title    string
}

// Input is everything a chart shows. Values are already in display units; Format
// writes a y tick label and XLabel an x tick (daily: the step is a day or more).
type Input struct {
	From, To time.Time
	Series   []Series
	Bands    Bands
	Marks    []Mark
	Spans    []Span
	Loc      *time.Location
	Format   func(v float64) string
	XLabel   func(t time.Time, daily bool) string
}

// Line is a series' path.
type Line struct {
	D, Title string
	Focus    bool
}

// Rect is a rectangle (band, span, plot frame).
type Rect struct {
	X, Y, W, H string
	Title      string
	Crit       bool
}

// Tick is an axis label at (X, Y), with its grid line position.
type Tick struct {
	X, Y, Label string
}

// MarkLine is an event marker from Y1 to Y2 at X.
type MarkLine struct {
	X, Y1, Y2, Title string
	Critical         bool
}

// Chart is the geometry of one chart.
type Chart struct {
	ViewBox string
	Plot    Rect
	// GridFrom and GridTo are the x ends of the horizontal grid lines (the plot's edges).
	GridFrom, GridTo string
	Lines            []Line
	Envelope         string // the focused series' min/max area ("" when none)
	Bands            []Rect
	Spans            []Rect
	Marks            []MarkLine
	XTicks           []Tick
	YTicks           []Tick
	// Empty: no series has a bucket (the template says "No history yet").
	Empty bool
}

// Build computes a chart.
func Build(in Input) Chart {
	box := chartBox()
	c := Chart{ViewBox: "0 0 " + strconv.Itoa(ChartW) + " " + strconv.Itoa(ChartH),
		Plot:     Rect{X: num(box.x0), Y: num(box.y0), W: num(box.x1 - box.x0), H: num(box.y1 - box.y0)},
		GridFrom: num(box.x0), GridTo: num(box.x1)}
	lo, hi, ok := extent(in.Series)
	if !ok {
		c.Empty = true
		return c
	}
	lo, hi = domain(lo, hi)
	lo, hi = withBands(lo, hi, in.Bands)
	ts := timeScale{from: in.From, to: in.To, x0: box.x0, x1: box.x1}
	vs := valueScale{lo: lo, hi: hi, y0: box.y0, y1: box.y1}
	c.Bands = bandRects(in.Bands, ts, vs, lo, hi)
	for _, sp := range in.Spans {
		x0, x1 := ts.x(sp.From), ts.x(sp.To)
		c.Spans = append(c.Spans, Rect{X: num(x0), Y: num(box.y0), W: num(math.Max(x1-x0, 1)), H: num(box.y1 - box.y0), Title: sp.Title})
	}
	for _, s := range in.Series {
		if s.Focus {
			c.Envelope = envelope(s, ts, vs)
		}
		c.Lines = append(c.Lines, Line{D: path(s, ts, vs), Title: s.Title, Focus: s.Focus})
	}
	for _, m := range in.Marks {
		c.Marks = append(c.Marks, MarkLine{X: num(ts.x(m.At)), Y1: num(box.y0), Y2: num(box.y1), Title: m.Title, Critical: m.Critical})
	}
	c.YTicks = yTicks(lo, hi, vs, in.Format)
	c.XTicks = xTicks(in, ts)
	return c
}

// extent is the smallest min and the largest max over every bucket.
func extent(series []Series) (float64, float64, bool) {
	lo, hi, ok := math.Inf(1), math.Inf(-1), false
	for _, s := range series {
		for _, b := range s.Buckets {
			lo, hi, ok = math.Min(lo, b.Min), math.Max(hi, b.Max), true
		}
	}
	return lo, hi, ok
}

// withBands extends the domain to a threshold that lies within 10 % of the span above
// it, so a value close to its warning level shows the band; farther thresholds are not
// drawn (they would squash the series).
func withBands(lo, hi float64, b Bands) (float64, float64) {
	reach := hi + (hi-lo)*0.1
	for _, t := range []struct {
		v  float64
		on bool
	}{{b.Warn, b.HasWarn}, {b.Crit, b.HasCrit}} {
		if t.on && t.v > hi && t.v <= reach {
			hi = t.v + (hi-lo)*0.02
		}
	}
	return lo, hi
}

func bandRects(b Bands, ts timeScale, vs valueScale, lo, hi float64) []Rect {
	var out []Rect
	add := func(from, to float64, crit bool) {
		from, to = math.Max(from, lo), math.Min(to, hi)
		if from >= to {
			return
		}
		y0, y1 := vs.y(to), vs.y(from)
		out = append(out, Rect{X: num(ts.x0), Y: num(y0), W: num(ts.x1 - ts.x0), H: num(y1 - y0), Crit: crit})
	}
	top := hi
	if b.HasCrit {
		add(b.Crit, hi, true)
		top = b.Crit
	}
	if b.HasWarn {
		add(b.Warn, top, false)
	}
	return out
}

// path is the series' averages, one point per bucket at its middle; a gap longer than
// the series' Gap starts a new subpath, and a lone point is a short dash (round caps
// in CSS make it a dot).
func path(s Series, ts timeScale, vs valueScale) string {
	var b strings.Builder
	for i, bk := range s.Buckets {
		x, y := ts.x(mid(bk, s)), vs.y(bk.Avg)
		if i == 0 || s.broken(s.Buckets[i-1], bk) {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString("M" + num(x) + " " + num(y))
			if i+1 == len(s.Buckets) || s.broken(bk, s.Buckets[i+1]) {
				b.WriteString(" h0.1")
			}
		} else {
			b.WriteString(" L" + num(x) + " " + num(y))
		}
	}
	return b.String()
}

// mid is the middle of a bucket: of its own width, so a daily row in a 3-hour chart sits
// at noon, not at 01:30.
func mid(b store.Bucket, s Series) time.Time { return b.Start.Add(s.width(b) / 2) }

// envelope is the closed area between the focused series' maxima (left to right) and
// minima (right to left), for contiguous runs of buckets.
func envelope(s Series, ts timeScale, vs valueScale) string {
	var parts []string
	run := []store.Bucket{}
	flush := func() {
		if len(run) > 1 {
			parts = append(parts, area(run, s, ts, vs))
		}
		run = run[:0]
	}
	for i, b := range s.Buckets {
		if i > 0 && s.broken(s.Buckets[i-1], b) {
			flush()
		}
		run = append(run, b)
	}
	flush()
	return strings.Join(parts, " ")
}

func area(run []store.Bucket, s Series, ts timeScale, vs valueScale) string {
	var b strings.Builder
	for i, bk := range run {
		cmd := " L"
		if i == 0 {
			cmd = "M"
		}
		b.WriteString(cmd + num(ts.x(mid(bk, s))) + " " + num(vs.y(bk.Max)))
	}
	for i := len(run) - 1; i >= 0; i-- {
		b.WriteString(" L" + num(ts.x(mid(run[i], s))) + " " + num(vs.y(run[i].Min)))
	}
	return b.String() + " Z"
}

func yTicks(lo, hi float64, vs valueScale, format func(float64) string) []Tick {
	if format == nil {
		format = func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
	}
	var out []Tick
	for _, v := range valueTicks(lo, hi) {
		out = append(out, Tick{X: num(padLeft - 4), Y: num(vs.y(v)), Label: format(v)})
	}
	return out
}

func xTicks(in Input, ts timeScale) []Tick {
	loc := in.Loc
	if loc == nil {
		loc = time.UTC
	}
	times, step := timeTicks(in.From, in.To, loc)
	var out []Tick
	for _, t := range times {
		label := t.In(loc).Format("15:04")
		if in.XLabel != nil {
			label = in.XLabel(t, step >= 24*time.Hour)
		}
		out = append(out, Tick{X: num(ts.x(t)), Y: num(ChartH - 4), Label: label})
	}
	return out
}
