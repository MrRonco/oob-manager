package fan

import (
	"errors"
	"testing"
	"time"

	"oob-manager/internal/config"
)

func hostPolicy() Policy {
	return Policy{ServerID: "node-a", Mode: config.FanHostLease, SafeMin: 30, MaxLease: 2 * time.Hour}
}

func TestParseRequestValid(t *testing.T) {
	p := hostPolicy()
	cases := []struct {
		pct, minutes string
		want         Request
	}{
		{"55", "30", Request{Pct: 55, Duration: 30 * time.Minute}},
		{"100", "120", Request{Pct: 100, Duration: 2 * time.Hour}},
		{"30", "5", Request{Pct: 30, Duration: 5 * time.Minute}},
		// Below the safe minimum is clamped up, never down (rule 3).
		{"0", "15", Request{Pct: 30, Duration: 15 * time.Minute}},
		{"7", "15", Request{Pct: 30, Duration: 15 * time.Minute}},
		{"055", "015", Request{Pct: 55, Duration: 15 * time.Minute}},
	}
	for _, c := range cases {
		got, err := ParseRequest(c.pct, c.minutes, p)
		if err != nil || got != c.want {
			t.Errorf("ParseRequest(%q, %q) = %+v, %v; want %+v", c.pct, c.minutes, got, err, c.want)
		}
	}
}

func TestParseRequestHostile(t *testing.T) {
	p := hostPolicy()
	bad := []struct{ pct, minutes string }{
		{"", "30"}, {"55", ""}, {"-1", "30"}, {"101", "30"}, {"1000", "30"}, {"55.5", "30"}, {"5e1", "30"},
		{" 55", "30"}, {"55 ", "30"}, {"+55", "30"}, {"0x37", "30"}, {"５５", "30"}, {"55\n", "30"},
		{"55", "4"}, {"55", "121"}, {"55", "0"}, {"55", "-30"}, {"55", "30m"}, {"55", "99999999999999999999"},
		{"99999999999999999999", "30"}, {"55", "1e2"},
	}
	for _, c := range bad {
		if _, err := ParseRequest(c.pct, c.minutes, p); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseRequest(%q, %q) err = %v, want ErrInvalid", c.pct, c.minutes, err)
		}
	}
	none := Policy{ServerID: "x", Mode: config.FanNone}
	if _, err := ParseRequest("55", "30", none); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("mode none: %v", err)
	}
}

func TestParseRequestShortMaxLease(t *testing.T) {
	p := hostPolicy()
	p.MaxLease = 10 * time.Minute
	if _, err := ParseRequest("55", "15", p); !errors.Is(err, ErrInvalid) {
		t.Errorf("duration above max_lease: %v", err)
	}
	if r, err := ParseRequest("55", "10", p); err != nil || r.Duration != 10*time.Minute {
		t.Errorf("at max_lease: %+v %v", r, err)
	}
}

func TestDurationChoices(t *testing.T) {
	p := hostPolicy()
	got := p.DurationChoices()
	want := []int{15, 30, 60, 120}
	if len(got) != len(want) {
		t.Fatalf("choices = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("choices = %v", got)
		}
	}
	p.MaxLease = 45 * time.Minute
	if got := p.DurationChoices(); len(got) != 3 || got[2] != 45 {
		t.Fatalf("short max: %v", got)
	}
	p.MaxLease = 5 * time.Minute
	if got := p.DurationChoices(); len(got) != 1 || got[0] != 5 {
		t.Fatalf("tiny max: %v", got)
	}
	if !p.Enabled() || (Policy{Mode: config.FanNone}).Enabled() {
		t.Error("Enabled")
	}
}
