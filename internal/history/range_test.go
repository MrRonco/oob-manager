package history

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"oob-manager/internal/store"
)

var now = time.Date(2026, 10, 23, 14, 37, 12, 0, time.UTC)

func TestParseRange(t *testing.T) {
	for in, want := range map[string]Range{"": Range24h, "24h": Range24h, "7d": Range7d, "30d": Range30d, "1y": Range1y} {
		if r, ok := ParseRange(in); !ok || r != want {
			t.Errorf("ParseRange(%q) = %v %v", in, r, ok)
		}
	}
	for _, bad := range []string{"1d", "24H", "all", "7d "} {
		if _, ok := ParseRange(bad); ok {
			t.Errorf("ParseRange(%q) accepted", bad)
		}
	}
	for _, r := range Ranges() {
		if r.Label() == "" || r.Duration() <= 0 {
			t.Errorf("%s: label %q duration %v", r, r.Label(), r.Duration())
		}
	}
}

// TestPlanFor: the point budgets of plan §6 (144, 168, 240, 365), the served tier per
// range, and windows that end at the end of the bucket holding now (UTC aligned).
func TestPlanFor(t *testing.T) {
	for _, tc := range []struct {
		r      Range
		step   time.Duration
		tier   store.Tier
		points int
		to     time.Time
	}{
		{Range24h, 10 * time.Minute, store.TierRaw, 144, time.Date(2026, 10, 23, 14, 40, 0, 0, time.UTC)},
		{Range7d, time.Hour, store.TierHourly, 168, time.Date(2026, 10, 23, 15, 0, 0, 0, time.UTC)},
		{Range30d, 3 * time.Hour, store.TierHourly, 240, time.Date(2026, 10, 23, 15, 0, 0, 0, time.UTC)},
		{Range1y, 24 * time.Hour, store.TierDaily, 365, time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)},
	} {
		p := PlanFor(tc.r, now)
		if p.Step != tc.step || p.Tier != tc.tier || p.Points() != tc.points || !p.To.Equal(tc.to) || p.Range != tc.r {
			t.Errorf("%s: %+v (points %d)", tc.r, p, p.Points())
		}
	}
	s := SparkPlan(now)
	if s.Points() != 48 || s.Tier != store.TierRaw || s.Step != SparkStep {
		t.Errorf("spark = %+v", s)
	}
	exact := time.Date(2026, 10, 23, 14, 40, 0, 0, time.UTC)
	if p := PlanFor(Range24h, exact); !p.To.Equal(exact) {
		t.Errorf("an aligned now is the end: %v", p.To)
	}
}

func q(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func TestParsePlanCustom(t *testing.T) {
	from := now.Add(-24 * time.Hour).Format(time.RFC3339)
	to := now.Format(time.RFC3339)
	p, err := ParsePlan(q("from", from, "to", to, "step", "30"), now)
	if err != nil || p.Step != time.Minute || p.Tier != store.TierRaw || p.Points() > MaxPoints {
		t.Fatalf("1 day at 30 s = %+v, %v; want the step raised to 1 min", p, err)
	}
	p, err = ParsePlan(q("from", now.Add(-30*24*time.Hour).Format(time.RFC3339), "to", to), now)
	if err != nil || p.Step != 22*time.Minute || p.Tier != store.TierRaw || p.Points() > MaxPoints {
		t.Fatalf("30 days at the default step = %+v (points %d), %v; want 22 min (30 d / 2000, whole minutes)", p, p.Points(), err)
	}
	p, err = ParsePlan(q("from", now.Add(-MaxSpan).Format(time.RFC3339), "to", to, "step", "86400"), now)
	if err != nil || p.Step != 24*time.Hour || p.Tier != store.TierDaily || p.Points() > MaxPoints {
		t.Fatalf("2 years = %+v, %v", p, err)
	}
	p, err = ParsePlan(q("from", now.Add(-24*time.Hour).Format(time.RFC3339), "to", to, "step", "5400"), now)
	if err != nil || p.Step != 2*time.Hour || p.Tier != store.TierHourly {
		t.Fatalf("90 min rounds up to whole hours: %+v, %v", p, err)
	}
	if p.From.UnixMilli()%p.Step.Milliseconds() != 0 || p.To.UnixMilli()%p.Step.Milliseconds() != 0 {
		t.Errorf("custom plan not aligned: %+v", p)
	}
	if f, to2 := p.rawWindow(); !f.Equal(now.Add(-24*time.Hour).Truncate(time.Second)) || !to2.Equal(now) {
		t.Errorf("a raw export covers the asked window: %v %v", f, to2)
	}
	if f, _ := PlanFor(Range24h, now).rawWindow(); !f.Equal(PlanFor(Range24h, now).From) {
		t.Error("a range's raw window is the plan")
	}
}

func TestParsePlanRejects(t *testing.T) {
	to := now.Format(time.RFC3339)
	for name, v := range map[string]url.Values{
		"unknown range":    q("range", "5y"),
		"range and from":   q("range", "7d", "from", to),
		"bad from":         q("from", "yesterday", "to", to),
		"backwards":        q("from", to, "to", now.Add(-time.Hour).Format(time.RFC3339)),
		"too long":         q("from", now.Add(-MaxSpan-time.Hour).Format(time.RFC3339), "to", to),
		"future":           q("from", to, "to", now.Add(72*time.Hour).Format(time.RFC3339)),
		"before 1970":      q("from", "1969-12-31T00:00:00Z", "to", "1970-01-02T00:00:00Z"),
		"step not a count": q("from", now.Add(-time.Hour).Format(time.RFC3339), "to", to, "step", "5m"),
		"step zero":        q("from", now.Add(-time.Hour).Format(time.RFC3339), "to", to, "step", "0"),
		"only a step":      q("step", "60"),
	} {
		if _, err := ParsePlan(v, now); !errors.Is(err, ErrBadQuery) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if p, err := ParsePlan(url.Values{}, now); err != nil || p.Range != Range24h {
		t.Errorf("default = %+v, %v", p, err)
	}
}
