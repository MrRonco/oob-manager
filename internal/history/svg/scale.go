// Package svg computes the geometry of the history charts and sparklines (tech_doc
// §39): path data, rectangles and tick positions as fixed-precision strings in a fixed
// viewBox, scaled by CSS. It writes no markup: the UI's templates draw the elements
// (html/template escapes every attribute and text), colours come from CSS classes mapped
// to the design tokens, and nothing here needs a script or a style attribute.
//
// Output is deterministic: the same input always gives the same strings.
package svg

import (
	"math"
	"strconv"
	"time"
)

// Chart and sparkline geometry (viewBox units).
const (
	ChartW = 600
	ChartH = 140
	SparkW = 120
	SparkH = 24

	padLeft   = 56 // y tick labels (room for "12000" at the phone font size)
	padRight  = 8
	padTop    = 6
	padBottom = 18 // x tick labels
)

// plotBox is the plot area inside the chart's viewBox.
type plotBox struct{ x0, y0, x1, y1 float64 }

func chartBox() plotBox {
	return plotBox{x0: padLeft, y0: padTop, x1: ChartW - padRight, y1: ChartH - padBottom}
}

// num formats a coordinate with one decimal (deterministic, locale-free).
func num(v float64) string {
	if v == 0 || math.Abs(v) < 0.05 {
		return "0"
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// timeScale maps [from, to) onto [x0, x1].
type timeScale struct {
	from, to time.Time
	x0, x1   float64
}

func (s timeScale) x(t time.Time) float64 {
	span := s.to.Sub(s.from)
	if span <= 0 {
		return s.x0
	}
	f := float64(t.Sub(s.from)) / float64(span)
	return s.x0 + math.Max(0, math.Min(1, f))*(s.x1-s.x0)
}

// valueScale maps [lo, hi] onto [y1, y0] (up is larger).
type valueScale struct {
	lo, hi float64
	y0, y1 float64
}

func (s valueScale) y(v float64) float64 {
	if s.hi <= s.lo {
		return (s.y0 + s.y1) / 2
	}
	f := (v - s.lo) / (s.hi - s.lo)
	return s.y1 - math.Max(0, math.Min(1, f))*(s.y1-s.y0)
}

// domain widens [lo, hi] by 5 % on each side; a flat series gets a unit-wide domain
// around its value.
func domain(lo, hi float64) (float64, float64) {
	if hi < lo {
		return 0, 1
	}
	span := hi - lo
	if span == 0 {
		span = math.Max(math.Abs(hi)*0.1, 1)
		return lo - span/2, hi + span/2
	}
	return lo - span*0.05, hi + span*0.05
}

// niceStep is the tick step for about n ticks over span: 1, 2, 2.5 or 5 × 10^k.
func niceStep(span float64, n int) float64 {
	if span <= 0 || n < 1 {
		return 1
	}
	raw := span / float64(n)
	mag := math.Pow(10, math.Floor(math.Log10(raw)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if raw <= m*mag {
			return m * mag
		}
	}
	return 10 * mag
}

// valueTicks are the tick values inside [lo, hi] at a nice step (4 to 6 of them).
func valueTicks(lo, hi float64) []float64 {
	step := niceStep(hi-lo, 4)
	var out []float64
	for v := math.Ceil(lo/step) * step; v <= hi+step*1e-9 && len(out) < 8; v += step {
		out = append(out, math.Round(v/step)*step)
	}
	return out
}

// timeSteps are the candidate x tick steps, smallest first.
func timeSteps() []time.Duration {
	h, d := time.Hour, 24*time.Hour
	return []time.Duration{h, 2 * h, 3 * h, 4 * h, 6 * h, 12 * h, d, 2 * d, 7 * d, 14 * d, 30 * d, 61 * d, 91 * d}
}

// timeTicks are 4 to 6 tick times in [from, to), aligned to midnight (steps of a day or
// more) or to the hour in loc, the viewer's time zone.
func timeTicks(from, to time.Time, loc *time.Location) ([]time.Time, time.Duration) {
	span := to.Sub(from)
	step := timeSteps()[len(timeSteps())-1]
	for _, s := range timeSteps() {
		if span/s <= 6 {
			step = s
			break
		}
	}
	l := from.In(loc)
	first := time.Date(l.Year(), l.Month(), l.Day(), 0, 0, 0, 0, loc)
	if step < 24*time.Hour {
		first = time.Date(l.Year(), l.Month(), l.Day(), l.Hour()-l.Hour()%int(step/time.Hour), 0, 0, 0, loc)
	}
	var out []time.Time
	next := func(t time.Time) time.Time { return t.Add(step) }
	if step >= 24*time.Hour { // calendar days, so a DST change keeps the ticks on midnight
		next = func(t time.Time) time.Time { return t.AddDate(0, 0, int(step/(24*time.Hour))) }
	}
	for t := first; t.Before(to) && len(out) < 8; t = next(t) {
		if !t.Before(from) {
			out = append(out, t)
		}
	}
	return out, step
}
