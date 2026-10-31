package history

import (
	"slices"
	"time"

	"oob-manager/internal/store"
)

// Coverage is what one tier holds for one key: rows from First (Has: any at all) up to
// Done, the tier's rollup watermark (the raw tier is never "done": zero Done).
type Coverage struct {
	Has   bool
	First time.Time
	Done  time.Time
}

// Segment is a part of a plan served from one tier.
type Segment struct {
	Tier     store.Tier
	From, To time.Time
}

// tierOrder is finest first.
func tierOrder() [3]store.Tier {
	return [3]store.Tier{store.TierRaw, store.TierHourly, store.TierDaily}
}

func tierIndex(t store.Tier) int {
	order := tierOrder()
	return slices.Index(order[:], t)
}

// end is where a tier's rows stop: its watermark, or the plan's end for raw rows.
func (c Coverage) end(t store.Tier, p Plan) time.Time {
	if t == store.TierRaw {
		return p.To
	}
	return c.Done
}

// bucketOf is the bucket size of a rollup tier (raw rows have none).
func bucketOf(t store.Tier) time.Duration {
	switch t {
	case store.TierDaily:
		return day
	case store.TierHourly:
		return time.Hour
	default:
		return time.Millisecond
	}
}

// Segments splits a plan between the tiers: the plan's tier where it has rows; after its
// watermark the finer tiers (hourly, then raw: hours not rolled up yet); before its
// first row the coarser tiers (older periods beyond its retention). A coarser tier
// ends at its bucket boundary before the finer tier's first row, so no sample is
// counted twice; the janitor prunes on those boundaries (raw rows by the hour, hourly
// rows by the day), so a finer tier that starts mid-bucket started there, and nothing
// is lost. Segments do not overlap and are ordered oldest first.
func Segments(p Plan, cov map[store.Tier]Coverage) []Segment {
	si := tierIndex(p.Tier)
	if si < 0 {
		return nil
	}
	clamp := func(t time.Time) time.Time { return maxTime(p.From, minTime(p.To, t)) }
	s := cov[p.Tier]
	lo := clamp(s.end(p.Tier, p))
	hi := lo
	if s.Has {
		lo = clamp(s.First)
	}
	order := tierOrder()
	var out []Segment
	cursor := lo
	for i := si + 1; i < len(order); i++ { // coarser tiers, before the plan's tier
		t := order[i]
		c := cov[t]
		if !c.Has {
			continue
		}
		from, to := clamp(c.First), minTime(clamp(floorTo(cursor, bucketOf(t))), clamp(c.end(t, p)))
		if from.Before(cursor) && from.Before(to) { // only rows from before the finer tier's first
			out = append(out, Segment{Tier: t, From: from, To: to})
			cursor = from
		}
	}
	slices.Reverse(out)
	if lo.Before(hi) {
		out = append(out, Segment{Tier: p.Tier, From: lo, To: hi})
	}
	cursor = hi
	for i := si - 1; i >= 0; i-- { // finer tiers, after the plan's tier
		t := order[i]
		c := cov[t]
		if !c.Has {
			continue
		}
		from, to := maxTime(cursor, clamp(c.First)), clamp(c.end(t, p))
		if from.Before(to) {
			out = append(out, Segment{Tier: t, From: from, To: to})
			cursor = to
		}
	}
	return disjoint(out)
}

// disjoint starts each segment where the one before it ended and drops empty ones.
func disjoint(segs []Segment) []Segment {
	out := make([]Segment, 0, len(segs))
	for _, sg := range segs {
		if n := len(out); n > 0 {
			sg.From = maxTime(sg.From, out[n-1].To)
		}
		if sg.From.Before(sg.To) {
			out = append(out, sg)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Merge combines bucket lists from several segments into one, oldest first. Buckets of
// the same start (a segment edge inside a bucket) become one: min of mins, max of
// maxes, the count-weighted average.
func Merge(parts ...[]store.Bucket) []store.Bucket {
	var all []store.Bucket
	for _, p := range parts {
		all = append(all, p...)
	}
	slices.SortStableFunc(all, func(a, b store.Bucket) int { return a.Start.Compare(b.Start) })
	out := make([]store.Bucket, 0, len(all))
	for _, b := range all {
		if n := len(out); n > 0 && out[n-1].Start.Equal(b.Start) {
			out[n-1] = combine(out[n-1], b)
			continue
		}
		out = append(out, b)
	}
	return out
}

func combine(a, b store.Bucket) store.Bucket {
	n := a.N + b.N
	if n <= 0 {
		return a
	}
	return store.Bucket{Start: a.Start, Min: min(a.Min, b.Min), Max: max(a.Max, b.Max), N: n,
		Avg: (a.Avg*float64(a.N) + b.Avg*float64(b.N)) / float64(n)}
}

// Summary is the minimum, the count-weighted average and the maximum of a series.
type Summary struct {
	Min, Avg, Max float64
	N             int64
}

// Has reports whether any sample went into the summary.
func (s Summary) Has() bool { return s.N > 0 }

// Summarize folds the buckets of a series.
func Summarize(bs []store.Bucket) Summary {
	if len(bs) == 0 {
		return Summary{}
	}
	acc := bs[0]
	for _, b := range bs[1:] {
		acc = combine(acc, b)
	}
	return Summary{Min: acc.Min, Avg: acc.Avg, Max: acc.Max, N: acc.N}
}
