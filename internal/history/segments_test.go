package history

import (
	"reflect"
	"testing"
	"time"

	"oob-manager/internal/store"
)

func at(h int) time.Time {
	return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC).Add(time.Duration(h) * time.Hour)
}

func seg(t store.Tier, from, to int) Segment { return Segment{Tier: t, From: at(from), To: at(to)} }

func TestSegments(t *testing.T) {
	p := Plan{From: at(-72), To: at(14), Step: time.Hour, Tier: store.TierHourly}
	for name, tc := range map[string]struct {
		plan Plan
		cov  map[store.Tier]Coverage
		want []Segment
	}{
		"hourly, raw after the watermark": {p, map[store.Tier]Coverage{
			store.TierHourly: {Has: true, First: at(-100), Done: at(12)},
			store.TierRaw:    {Has: true, First: at(-48)},
		}, []Segment{seg(store.TierHourly, -72, 12), seg(store.TierRaw, 12, 14)}},
		"daily before the hourly retention": {p, map[store.Tier]Coverage{
			store.TierHourly: {Has: true, First: at(-24), Done: at(12)},
			store.TierDaily:  {Has: true, First: at(-240), Done: at(0)},
			store.TierRaw:    {Has: true, First: at(-30)},
		}, []Segment{seg(store.TierDaily, -72, -24), seg(store.TierHourly, -24, 12), seg(store.TierRaw, 12, 14)}},
		"nothing rolled up yet": {p, map[store.Tier]Coverage{
			store.TierRaw: {Has: true, First: at(-5)},
		}, []Segment{seg(store.TierRaw, -5, 14)}},
		"raw plan, hourly before the raw retention": {Plan{From: at(-72), To: at(14), Step: time.Hour, Tier: store.TierRaw},
			map[store.Tier]Coverage{
				store.TierRaw:    {Has: true, First: at(-24)},
				store.TierHourly: {Has: true, First: at(-200), Done: at(13)},
			}, []Segment{seg(store.TierHourly, -72, -24), seg(store.TierRaw, -24, 14)}},
		"daily plan, hourly then raw for today": {Plan{From: at(-240), To: at(24), Step: 24 * time.Hour, Tier: store.TierDaily},
			map[store.Tier]Coverage{
				store.TierDaily:  {Has: true, First: at(-480), Done: at(0)},
				store.TierHourly: {Has: true, First: at(-100), Done: at(13)},
				store.TierRaw:    {Has: true, First: at(-30)},
			}, []Segment{seg(store.TierDaily, -240, 0), seg(store.TierHourly, 0, 13), seg(store.TierRaw, 13, 24)}},
		"no data at all": {p, map[store.Tier]Coverage{}, nil},
		"raw covers the whole range: no coarser tier": {Plan{From: at(0), To: at(24), Step: 10 * time.Minute, Tier: store.TierRaw},
			map[store.Tier]Coverage{
				store.TierRaw:    {Has: true, First: at(-24)},
				store.TierHourly: {Has: true, First: at(-24), Done: at(23)},
				store.TierDaily:  {Has: true, First: at(-24), Done: at(0)},
			}, []Segment{seg(store.TierRaw, 0, 24)}},
		// The hourly rows start mid-day: the daily row of that day overlaps them, so the
		// daily tier stops at the midnight before (prunes are bucket aligned: a mid-day
		// start is where the data started).
		"daily ends at its own bucket edge": {p, map[store.Tier]Coverage{
			store.TierHourly: {Has: true, First: at(-36), Done: at(12)},
			store.TierDaily:  {Has: true, First: at(-240), Done: at(0)},
		}, []Segment{seg(store.TierDaily, -72, -48), seg(store.TierHourly, -36, 12)}},
		"hourly ends at the hour before the first raw row": {
			Plan{From: at(0), To: at(10), Step: 10 * time.Minute, Tier: store.TierRaw},
			map[store.Tier]Coverage{
				store.TierRaw:    {Has: true, First: at(2).Add(37 * time.Minute)},
				store.TierHourly: {Has: true, First: at(-5), Done: at(9)},
			}, []Segment{seg(store.TierHourly, 0, 2), {Tier: store.TierRaw, From: at(2).Add(37 * time.Minute), To: at(10)}}},
		"unknown tier": {Plan{From: at(0), To: at(1), Step: time.Hour, Tier: "weekly"}, nil, nil},
	} {
		if got := Segments(tc.plan, tc.cov); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, tc.want)
		}
	}
}

func TestMergeAndSummarize(t *testing.T) {
	a := []store.Bucket{{Start: at(0), Min: 1, Avg: 2, Max: 3, N: 2}, {Start: at(1), Min: 5, Avg: 5, Max: 5, N: 1}}
	b := []store.Bucket{{Start: at(1), Min: 0, Avg: 8, Max: 9, N: 3}, {Start: at(2), Min: 4, Avg: 4, Max: 4, N: 1}}
	m := Merge(b, a)
	if len(m) != 3 || m[1].Min != 0 || m[1].Max != 9 || m[1].N != 4 || m[1].Avg != 7.25 || !m[0].Start.Equal(at(0)) {
		t.Fatalf("Merge = %+v", m)
	}
	s := Summarize(m)
	if !s.Has() || s.Min != 0 || s.Max != 9 || s.N != 7 || s.Avg != (4+29+4)/7.0 {
		t.Errorf("Summarize = %+v", s)
	}
	if Summarize(nil).Has() {
		t.Error("empty series has a summary")
	}
	if c := combine(store.Bucket{Start: at(0), Avg: 1}, store.Bucket{Start: at(0), Avg: 2}); c.Avg != 1 {
		t.Errorf("zero counts keep the first bucket: %+v", c)
	}
}

func TestBucketEndFollowsTheServingTier(t *testing.T) {
	p := Plan{From: at(-72), To: at(0), Step: 3 * time.Hour, Tier: store.TierHourly}
	sr := Series{Segments: []Segment{seg(store.TierDaily, -72, -24), seg(store.TierHourly, -24, -1), seg(store.TierRaw, -1, 0)}}
	if end := sr.BucketEnd(store.Bucket{Start: at(-48)}, p); !end.Equal(at(-24)) {
		t.Errorf("a daily row ends a day later: %v", end)
	}
	if end := sr.BucketEnd(store.Bucket{Start: at(-12)}, p); !end.Equal(at(-9)) {
		t.Errorf("an hourly bucket ends one step later: %v", end)
	}
}
