package history

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"oob-manager/internal/store"
)

// Range is one of the chart ranges the UI offers (a closed set).
type Range string

// Ranges.
const (
	Range24h Range = "24h"
	Range7d  Range = "7d"
	Range30d Range = "30d"
	Range1y  Range = "1y"
)

// Ranges returns every range in picker order (a fresh slice).
func Ranges() []Range { return []Range{Range24h, Range7d, Range30d, Range1y} }

// ParseRange reads a range; "" is the default (24 h).
func ParseRange(s string) (Range, bool) {
	if s == "" {
		return Range24h, true
	}
	for _, r := range Ranges() {
		if string(r) == s {
			return r, true
		}
	}
	return "", false
}

// Duration is the length of the range.
func (r Range) Duration() time.Duration {
	switch r {
	case Range7d:
		return 7 * day
	case Range30d:
		return 30 * day
	case Range1y:
		return 365 * day
	default:
		return day
	}
}

// Label is the range as the picker shows it.
func (r Range) Label() string {
	switch r {
	case Range7d:
		return "7 days"
	case Range30d:
		return "30 days"
	case Range1y:
		return "1 year"
	default:
		return "24 hours"
	}
}

const day = 24 * time.Hour

// Limits of a request.
const (
	// MaxPoints is the API's point budget (plan 02 decision): the step is raised to fit.
	MaxPoints = 2000
	// MaxSpan is the longest range one request may cover.
	MaxSpan = 2 * 365 * day
	// SparkStep is the sparklines' bucket (24 h in 48 points).
	SparkStep = 30 * time.Minute
)

// Plan is how a chart, a series or an export is served: buckets of Step in [From, To)
// (both multiples of Step since the epoch), preferably from Tier.
type Plan struct {
	From, To time.Time
	Step     time.Duration
	Tier     store.Tier
	Range    Range // "" for a custom request
	// Asked is a custom request's own window before alignment (zero for a range): a raw
	// export covers exactly it.
	AskedFrom, AskedTo time.Time
}

// rawWindow is what a raw export covers: the asked window, else the plan's.
func (p Plan) rawWindow() (time.Time, time.Time) {
	if p.AskedFrom.IsZero() {
		return p.From, p.To
	}
	return p.AskedFrom, p.AskedTo
}

// Points is the number of buckets the plan can hold.
func (p Plan) Points() int { return int(p.To.Sub(p.From) / p.Step) }

// PlanFor is the plan of a range ending now. The served tier per range: raw for 24 h
// (10-minute buckets), hourly for 7 d (1 h buckets: an hourly row is exactly one
// bucket) and 30 d (3 h), daily for 1 y (1 d). Recent hours not rolled up yet come from
// the raw rows, older periods beyond a tier's retention from the next coarser tier
// (Segments).
func PlanFor(r Range, now time.Time) Plan {
	step, tier := 10*time.Minute, store.TierRaw
	switch r {
	case Range7d:
		step, tier = time.Hour, store.TierHourly
	case Range30d:
		step, tier = 3*time.Hour, store.TierHourly
	case Range1y:
		step, tier = day, store.TierDaily
	}
	return window(now, r.Duration(), step, tier, r)
}

// SparkPlan is the 24 h sparkline: 48 buckets of 30 minutes from the raw rows.
func SparkPlan(now time.Time) Plan { return window(now, day, SparkStep, store.TierRaw, Range24h) }

// window ends at the end of the bucket holding now, so the current bucket is drawn.
func window(now time.Time, span, step time.Duration, tier store.Tier, r Range) Plan {
	to := ceilTo(now, step)
	return Plan{From: to.Add(-span), To: to, Step: step, Tier: tier, Range: r}
}

// ceilTo rounds t up to a multiple of step since the epoch (UTC buckets).
func ceilTo(t time.Time, step time.Duration) time.Time {
	ms, s := t.UnixMilli(), step.Milliseconds()
	if r := ms % s; r != 0 {
		ms += s - r
	}
	return time.UnixMilli(ms).UTC()
}

func floorTo(t time.Time, step time.Duration) time.Time {
	ms, s := t.UnixMilli(), step.Milliseconds()
	return time.UnixMilli(ms - ms%s).UTC()
}

// ErrBadQuery is a request the history cannot serve (unknown range, bad times or step).
var ErrBadQuery = errors.New("history: bad query")

func badQuery(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadQuery, fmt.Sprintf(format, a...))
}

// ParsePlan reads range=… (a closed set), or from=…&to=… (RFC 3339) with an optional
// step=… in seconds. A custom request may cover at most MaxSpan; its step is raised to
// fit MaxPoints and rounded up to the granularity of the tier that serves it (1 minute
// raw, 1 hour hourly, 1 day daily).
func ParsePlan(q url.Values, now time.Time) (Plan, error) {
	if q.Has("from") || q.Has("to") || q.Has("step") {
		if q.Has("range") {
			return Plan{}, badQuery("use range or from/to, not both")
		}
		return customPlan(q.Get("from"), q.Get("to"), q.Get("step"), now)
	}
	r, ok := ParseRange(q.Get("range"))
	if !ok {
		return Plan{}, badQuery("range must be one of 24h, 7d, 30d, 1y")
	}
	return PlanFor(r, now), nil
}

func customPlan(fromS, toS, stepS string, now time.Time) (Plan, error) {
	from, ferr := time.Parse(time.RFC3339, fromS)
	to, terr := time.Parse(time.RFC3339, toS)
	if ferr != nil || terr != nil {
		return Plan{}, badQuery("from and to must be RFC 3339 times")
	}
	switch {
	case !to.After(from):
		return Plan{}, badQuery("to must be after from")
	case to.Sub(from) > MaxSpan:
		return Plan{}, badQuery("a request covers at most 2 years")
	case to.After(now.Add(day)) || from.Before(time.Unix(0, 0)):
		return Plan{}, badQuery("from and to must lie between 1970 and tomorrow")
	}
	step := time.Minute
	if stepS != "" {
		n, err := strconv.ParseInt(stepS, 10, 64)
		if err != nil || n < 1 || n > int64(MaxSpan/time.Second) {
			return Plan{}, badQuery("step must be a whole number of seconds")
		}
		step = time.Duration(n) * time.Second
	}
	step = fitStep(to.Sub(from), step)
	f, t := floorTo(from, step), ceilTo(to, step)
	for int(t.Sub(f)/step) > MaxPoints { // alignment added a bucket at either end
		step = fitStep(to.Sub(from), step+granule(step))
		f, t = floorTo(from, step), ceilTo(to, step)
	}
	return Plan{From: f, To: t, Step: step, Tier: tierForStep(step), AskedFrom: from.UTC(), AskedTo: to.UTC()}, nil
}

// fitStep raises step to fit MaxPoints over span and rounds it to its granule.
func fitStep(span, step time.Duration) time.Duration {
	if least := (span + MaxPoints - 1) / MaxPoints; step < least {
		step = least
	}
	g := granule(step)
	return (step + g - 1) / g * g
}

// granule is the rounding unit of a step: the bucket of the tier that serves it.
func granule(step time.Duration) time.Duration {
	switch tierForStep(step) {
	case store.TierDaily:
		return day
	case store.TierHourly:
		return time.Hour
	default:
		return time.Minute
	}
}

// tierForStep serves steps under an hour from raw rows, under a day from hourly rows.
func tierForStep(step time.Duration) store.Tier {
	switch {
	case step < time.Hour:
		return store.TierRaw
	case step < day:
		return store.TierHourly
	default:
		return store.TierDaily
	}
}
