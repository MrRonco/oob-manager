package ui

import (
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/display"
)

func TestTimeFmtVariants(t *testing.T) {
	t.Parallel()
	loc, err := display.LoadZone("America/New_York")
	must(t, err)
	at := time.Date(2026, 10, 21, 18, 5, 9, 0, time.UTC)
	now := at.Add(time.Hour)
	cases := []struct {
		date             display.DateFormat
		clock            display.ClockFormat
		full, clk, short string
	}{
		{display.DateISO, display.Clock24, "2026-10-21 14:05:09 EDT", "14:05:09 EDT", "14:05"},
		{display.DateUS, display.Clock12, "10/21/2026 2:05:09 PM EDT", "2:05:09 PM EDT", "2:05 PM"},
		{display.DateUS, display.Clock24, "10/21/2026 14:05:09 EDT", "14:05:09 EDT", "14:05"},
	}
	for _, c := range cases {
		f := fmtFor(display.View{Loc: loc, Date: c.date, Clock: c.clock})
		if got := f.full(at); got != c.full {
			t.Errorf("full = %q, want %q", got, c.full)
		}
		if got := f.clockOf(at); got != c.clk {
			t.Errorf("clock = %q, want %q", got, c.clk)
		}
		if got := f.short(at, now); got != c.short {
			t.Errorf("short = %q, want %q", got, c.short)
		}
	}
	winter := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	if got := fmtFor(display.View{Loc: loc}).full(winter); got != "2026-12-01 07:00:00 EST" {
		t.Errorf("winter = %q", got)
	}
	if got := fmtFor(display.View{}).full(winter); got != "2026-12-01 12:00:00 UTC" {
		t.Errorf("nil location = %q", got)
	}
	if got := fmtFor(display.View{Loc: loc, Clock: display.Clock12}).short(at.Add(-48*time.Hour), now); got != "Oct 19 2:05 PM" {
		t.Errorf("short other day = %q", got)
	}
}

func TestTempUnitConversion(t *testing.T) {
	t.Parallel()
	f := unitOf(display.Fahrenheit)
	ts := f.convert([]bmc.Temperature{{Name: "CPU1", Celsius: bmc.ReadingOf(40), WarnAbove: bmc.ReadingOf(87), CritAbove: bmc.NoReading()}})
	if ts[0].Celsius.Value != 104 || ts[0].WarnAbove.Value != 188.6 || ts[0].CritAbove.Valid {
		t.Fatalf("converted = %+v", ts[0])
	}
	// "Close to warning" is 5 °C = 9 °F: 180 °F against a 188.6 °F warning is close.
	m := headroomIn(f, bmc.ReadingOf(180), bmc.ReadingOf(188.6), bmc.NoReading())
	if !m.Close || m.Unit != "°F" || m.Text != "Close: 9 °F below warning" {
		t.Fatalf("meter = %+v", m)
	}
	if c := unitOf(display.Celsius); c.convert([]bmc.Temperature{{Celsius: bmc.ReadingOf(40)}})[0].Celsius.Value != 40 {
		t.Fatal("Celsius must not convert")
	}
	if trimUnit("87 °F") != "87" || trimUnit("87 °C") != "87" {
		t.Fatal("trimUnit")
	}
}
