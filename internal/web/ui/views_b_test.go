package ui

import (
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func TestAgeChipStates(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	chip := func(age time.Duration, has bool) chipView {
		v := ServerView{HasSnapshot: has, LastSuccess: now.Add(-age)}
		if !has {
			v.LastSuccess = time.Time{}
		}
		return freshnessOf(v, now, 3*time.Minute, fmtIn(time.UTC)).Chip
	}
	cases := []struct {
		name  string
		got   chipView
		class string
		text  string
	}{
		{"live", chip(15*time.Second, true), "", "Live 15 s"},
		{"aging past half the threshold", chip(2*time.Minute, true), "chip-aging", "Aging 2 min"},
		{"stale", chip(14*time.Minute, true), "chip-stale", "Stale 14 min"},
		{"never polled", chip(0, false), "chip-stale", "No data"},
	}
	for _, c := range cases {
		if c.got.Class != c.class || c.got.Text != c.text {
			t.Errorf("%s: chip = %+v, want class %q text %q", c.name, c.got, c.class, c.text)
		}
	}
}

func TestShortAndRelativeTimes(t *testing.T) {
	loc := time.FixedZone("EDT", -4*3600)
	now := time.Date(2026, 10, 21, 14, 44, 0, 0, time.UTC)
	if got := fmtShort(now.Add(-13*time.Minute), now, loc); got != "10:31" {
		t.Errorf("same day = %q", got)
	}
	if got := fmtShort(now.Add(-30*time.Hour), now, loc); got != "Oct 20 04:44" {
		t.Errorf("other day = %q", got)
	}
	if got := fmtShort(time.Time{}, now, loc); got != "" {
		t.Errorf("zero = %q", got)
	}
	for d, want := range map[time.Duration]string{
		30 * time.Second: "just now", 13 * time.Minute: "13 min ago", 2 * time.Hour: "2 h ago",
		26 * time.Hour: "yesterday", 76 * time.Hour: "3 days ago", -5 * time.Minute: "just now",
	} {
		if got := fmtRel(now, now.Add(-d)); got != want {
			t.Errorf("fmtRel(-%s) = %q, want %q", d, got, want)
		}
	}
	if got := fmtClock(now, loc); got != "10:44:00 EDT" {
		t.Errorf("clock = %q", got)
	}
	if got := dayLabel(now, now, loc); got != "Today, Oct 21" {
		t.Errorf("today = %q", got)
	}
	if got := dayLabel(now.Add(-24*time.Hour), now, loc); got != "Yesterday, Oct 20" {
		t.Errorf("yesterday = %q", got)
	}
	if got := dayLabel(now.Add(-96*time.Hour), now, loc); got != "Sat, Oct 17" {
		t.Errorf("older = %q", got)
	}
	if got := dayLabel(time.Time{}, now, loc); got != "No time recorded" {
		t.Errorf("zero = %q", got)
	}
}

func TestHeadroomMeter(t *testing.T) {
	r := bmc.ReadingOf
	cases := []struct {
		name                string
		reading, warn, crit bmc.Reading
		fill, wTick, cTick  int
		class, text         string
		close, has          bool
	}{
		{"far below", r(61), r(87), r(92), 60, 86, 91, "ok", "26 °C below warning", false, true},
		{"close", r(40), r(42), r(47), 77, 81, 91, "near", "Close: 2 °C below warning", true, true},
		{"above warning", r(44), r(42), r(47), 85, 81, 91, "warn", "2 °C above warning", false, true},
		{"at critical", r(50), r(42), r(47), 97, 81, 91, "crit", "At or above critical (47 °C)", false, true},
		{"warning only", r(48), r(85), bmc.NoReading(), 49, 86, -1, "ok", "37 °C below warning", false, true},
		{"critical only", r(48), bmc.NoReading(), r(90), 48, -1, 91, "ok", "42 °C below critical", false, true},
		{"no thresholds", r(51), bmc.NoReading(), bmc.NoReading(), 0, -1, -1, "", "No threshold reported", false, false},
		{"no reading", bmc.NoReading(), r(42), r(47), 0, -1, -1, "", "", false, false},
	}
	for _, c := range cases {
		m := headroom(c.reading, c.warn, c.crit)
		if m.Has != c.has || m.Class != c.class || m.Text != c.text || m.Close != c.close {
			t.Errorf("%s: meter = %+v", c.name, m)
			continue
		}
		if c.has && (m.Fill != c.fill || m.WarnAt != c.wTick || m.CritAt != c.cTick) {
			t.Errorf("%s: fill %d warn %d crit %d, want %d %d %d", c.name, m.Fill, m.WarnAt, m.CritAt, c.fill, c.wTick, c.cTick)
		}
	}
}

func TestTempRowsProblemsFirstWithDisplayNames(t *testing.T) {
	r := bmc.ReadingOf
	rows := tempRows([]bmc.Temperature{
		{Name: "System Board Exhaust Temp", Context: "Exhaust", Celsius: r(30), WarnAbove: r(70), CritAbove: r(75), Health: bmc.HealthOK},
		{Name: "CPU1 Temp", Context: "CPU", Celsius: r(61), WarnAbove: r(87), CritAbove: r(92), Health: bmc.HealthOK},
		{Name: "System Board Inlet Temp", Context: "Intake", Celsius: r(40), WarnAbove: r(42), CritAbove: r(47), Health: bmc.HealthOK},
		{Name: "CPU2 Temp", Context: "CPU", Celsius: r(90), WarnAbove: r(87), CritAbove: r(92), Health: bmc.HealthWarning},
	}, celsius())
	want := []string{"CPU2", "Inlet", "CPU1", "Exhaust"}
	for i, w := range want {
		if rows[i].Name != w {
			t.Fatalf("order = %v, want %v", names(rows), want)
		}
	}
	if rows[1].FullName != "System Board Inlet Temp" || !rows[0].Alert || !rows[1].Meter.Close {
		t.Fatalf("rows = %+v", rows[:2])
	}
}

func names(rows []tempRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
}

func TestVoltagesSplitPowerGood(t *testing.T) {
	vs := []bmc.Voltage{
		{Name: "System Board 3.3V PG", Volts: bmc.ReadingOf(1), Health: bmc.HealthOK},
		{Name: "CPU1 VCORE PG", Volts: bmc.NoReading(), Health: bmc.HealthOK},
		{Name: "PS1 Voltage 1", Volts: bmc.ReadingOf(118), Health: bmc.HealthOK},
		{Name: "System Board PS1 PG Fail", Volts: bmc.NoReading(), Health: bmc.HealthCritical},
	}
	v := splitVoltages(vs)
	if len(v.Analog) != 1 || v.Analog[0].Name != "PS1 Voltage 1" || v.Analog[0].Reading != "118.00 V" {
		t.Fatalf("analog = %+v", v.Analog)
	}
	if v.PGTotal != 3 || v.PGGood != 2 || !v.PGOpen || len(v.PG) != 3 {
		t.Fatalf("power-good = %+v", v)
	}
	if v.PG[0].State != "Fault" || v.PG[0].Name != "PS1 PG Fail" {
		t.Fatalf("faults first, with display names: %+v", v.PG)
	}
	for _, p := range v.PG {
		if p.State != "Good" && p.State != "Fault" {
			t.Fatalf("power-good shown as %q (never volts)", p.State)
		}
	}
	if ok := splitVoltages(vs[:2]); ok.PGOpen || ok.PGGood != 2 {
		t.Fatalf("healthy power-good must stay collapsed: %+v", ok)
	}
}

func TestZoneLabel(t *testing.T) {
	now := time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC)
	for loc, want := range map[*time.Location]string{time.UTC: "UTC", time.FixedZone("EDT", -4*3600): "EDT (UTC−4)",
		time.FixedZone("IST", 5*3600+1800): "IST (UTC+5:30)"} {
		if got := zoneLabel(now, loc); got != want {
			t.Errorf("zoneLabel = %q, want %q", got, want)
		}
	}
}

func TestFirmwareRowsGroupAndHideEmptyColumns(t *testing.T) {
	rows, cols := firmwareRows([]bmc.FirmwareItem{
		{Name: "Component 101068", Version: "3.35", State: "Installed"},
		{Name: "BIOS", Version: "2.18", State: "Previous", ComponentID: "159"},
		{Name: "BIOS", Version: "2.19", State: "Installed", ComponentID: "159"},
		{Name: "BIOS", Version: "2.20", State: "Available", ComponentID: "159"},
	})
	got := []string{rows[0].Version, rows[1].Version, rows[2].Version, rows[3].Name}
	want := []string{"2.19", "2.20", "2.18", "Unnamed component (ID 101068)"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rows = %v, want %v", got, want)
		}
	}
	if !cols.ComponentID || cols.FQDD {
		t.Fatalf("columns = %+v", cols)
	}
}
