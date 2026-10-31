package bmc

import (
	"testing"
	"time"
)

func TestParseHealth(t *testing.T) {
	cases := map[string]Health{
		"OK":       HealthOK,
		"ok":       HealthOK,
		"Warning":  HealthWarning,
		"Critical": HealthCritical,
		"":         HealthUnknown,
		"bogus":    HealthUnknown,
	}
	for in, want := range cases {
		if got := ParseHealth(in); got != want {
			t.Errorf("ParseHealth(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWorstHealth(t *testing.T) {
	cases := []struct {
		in   []Health
		want Health
	}{
		{nil, HealthUnknown},
		{[]Health{HealthOK}, HealthOK},
		{[]Health{HealthOK, HealthUnknown}, HealthOK},
		{[]Health{HealthOK, HealthWarning}, HealthWarning},
		{[]Health{HealthCritical, HealthWarning, HealthOK}, HealthCritical},
		{[]Health{HealthUnknown, HealthUnknown}, HealthUnknown},
	}
	for _, c := range cases {
		if got := WorstHealth(c.in...); got != c.want {
			t.Errorf("WorstHealth(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParsePowerState(t *testing.T) {
	cases := map[string]PowerState{
		"On":          PowerOn,
		"Off":         PowerOff,
		"PoweringOn":  PowerPoweringOn,
		"PoweringOff": PowerPoweringOff,
		"Paused":      PowerUnknown,
		"":            PowerUnknown,
	}
	for in, want := range cases {
		if got := ParsePowerState(in); got != want {
			t.Errorf("ParsePowerState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReading(t *testing.T) {
	if r := NoReading(); r.Valid {
		t.Fatal("NoReading must be invalid")
	}
	if r := ReadingOf(42.5); !r.Valid || r.Value != 42.5 {
		t.Fatalf("ReadingOf: %+v", r)
	}
	v := 7.0
	if r := ReadingFrom(&v); !r.Valid || r.Value != 7 {
		t.Fatalf("ReadingFrom ptr: %+v", r)
	}
	if r := ReadingFrom[float64](nil); r.Valid {
		t.Fatal("ReadingFrom(nil) must be invalid")
	}
	i := 9000
	if r := ReadingFrom(&i); r.Value != 9000 {
		t.Fatalf("ReadingFrom int: %+v", r)
	}
	f32 := float32(1.5)
	if r := ReadingFrom(&f32); r.Value != 1.5 {
		t.Fatalf("ReadingFrom float32: %+v", r)
	}
}

func TestSnapshotCopiesInputsAndOutputs(t *testing.T) {
	temps := []Temperature{{ID: "t1", Name: "CPU1 Temp", Celsius: ReadingOf(45)}}
	fans := []Fan{{ID: "f1", Name: "Fan1", Speed: ReadingOf(9000), Units: FanRPM}}
	psus := []PSU{{ID: "p1", Name: "PS1"}}
	taken := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	s := NewSnapshot(SnapshotParams{
		TakenAt:      taken,
		PowerState:   PowerOn,
		Health:       HealthOK,
		Temperatures: temps,
		Fans:         fans,
		PSUs:         psus,
		Power:        PowerDraw{ConsumedWatts: ReadingOf(263)},
		Problems:     []string{"thermal: x"},
	})

	temps[0].Name = "mutated"
	fans[0].Name = "mutated"
	psus[0].Name = "mutated"

	if s.Temperatures()[0].Name != "CPU1 Temp" || s.Fans()[0].Name != "Fan1" || s.PSUs()[0].Name != "PS1" {
		t.Fatal("snapshot shares input slices")
	}
	out := s.Temperatures()
	out[0].Name = "mutated"
	if s.Temperatures()[0].Name != "CPU1 Temp" {
		t.Fatal("snapshot leaks internal slice")
	}
	p := s.Problems()
	p[0] = "mutated"
	if s.Problems()[0] != "thermal: x" {
		t.Fatal("problems slice leaks")
	}
	if !s.TakenAt().Equal(taken) || s.PowerState() != PowerOn || s.Health() != HealthOK {
		t.Fatalf("scalar accessors wrong: %v %v %v", s.TakenAt(), s.PowerState(), s.Health())
	}
	if s.Power().ConsumedWatts.Value != 263 {
		t.Fatalf("power: %+v", s.Power())
	}
	if !s.Degraded() {
		t.Fatal("snapshot with problems must be degraded")
	}
	if NewSnapshot(SnapshotParams{}).Degraded() {
		t.Fatal("empty snapshot must not be degraded")
	}
}

func TestZeroSnapshotIsSafe(t *testing.T) {
	var s Snapshot
	if len(s.Temperatures()) != 0 || len(s.Fans()) != 0 || len(s.PSUs()) != 0 {
		t.Fatal("zero snapshot should have empty sensors")
	}
	if s.Health() != "" && s.Health() != HealthUnknown {
		t.Fatalf("zero health: %q", s.Health())
	}
}
