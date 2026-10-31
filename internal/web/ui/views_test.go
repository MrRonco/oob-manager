package ui

import (
	"math"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func TestFmtAge(t *testing.T) {
	cases := map[time.Duration]string{
		-time.Second:                   "0 s",
		42 * time.Second:               "42 s",
		3*time.Minute + 10*time.Second: "3 min",
		2*time.Hour + 5*time.Minute:    "2 h 5 min",
		2 * time.Hour:                  "2 h",
		76 * time.Hour:                 "3 d 4 h",
	}
	for d, want := range cases {
		if got := fmtAge(d); got != want {
			t.Errorf("fmtAge(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestFreshness(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	v := ServerView{HasSnapshot: true, LastSuccess: now.Add(-3 * time.Minute)}
	if f := freshnessOf(v, now, 3*time.Minute, fmtIn(time.UTC)); f.Stale {
		t.Fatal("exactly at the threshold must not be stale")
	}
	v.LastSuccess = now.Add(-3*time.Minute - time.Second)
	if f := freshnessOf(v, now, 3*time.Minute, fmtIn(time.UTC)); !f.Stale || f.Age != "3 min" || f.ISO != "2026-10-20T11:56:59Z" {
		t.Fatalf("freshness = %+v", f)
	}
	if f := freshnessOf(ServerView{HasSnapshot: true}, now, time.Minute, fmtIn(time.UTC)); !f.NoData {
		t.Fatal("zero LastSuccess must be no-data")
	}
}

func TestSummaries(t *testing.T) {
	pct := []bmc.Fan{{Speed: bmc.ReadingOf(30), Units: bmc.FanPercent, Health: bmc.HealthOK},
		{Speed: bmc.ReadingOf(40), Units: bmc.FanPercent, Health: bmc.HealthOK},
		{Speed: bmc.ReadingOf(9000), Units: bmc.FanRPM, Health: bmc.HealthCritical}, {Speed: bmc.NoReading()}}
	if got := fanSummary(pct); got != "2/4 OK · 30–40 %" {
		t.Errorf("fanSummary percent = %q", got)
	}
	if got := fanSummary(nil); got != dash {
		t.Errorf("fanSummary(nil) = %q", got)
	}
	if s, hv := psuSummary(nil); s != dash || hv.Class != "unknown" {
		t.Errorf("psuSummary(nil) = %q %+v", s, hv)
	}
	in, cpu := keyTemps([]bmc.Temperature{{Name: "Inlet", Celsius: bmc.ReadingOf(20)}, {Name: "cpu0", Celsius: bmc.NoReading()}})
	if in != "20 °C" || cpu != dash {
		t.Errorf("keyTemps = %q %q", in, cpu)
	}
	if got := fmtReading(bmc.ReadingOf(math.NaN()), "W"); got != dash {
		t.Errorf("NaN rendered as %q", got)
	}
}

func TestErrorClassText(t *testing.T) {
	for c, want := range map[bmc.ErrorClass]string{bmc.ClassTimeout: "timed out", bmc.ClassAuth: "credentials rejected",
		bmc.ClassTLS: "certificate does not match the pin", bmc.ClassUnreachable: "BMC unreachable", "": "",
		bmc.ClassOther: "unexpected error"} {
		if got := errorText(c); got != want {
			t.Errorf("errorText(%q) = %q, want %q", c, got, want)
		}
	}
}

func TestStaleHealth(t *testing.T) {
	if h := staleOf(healthOf(bmc.HealthOK), false); h.Label != "Stale (last: OK)" || h.Class != "stale" {
		t.Fatalf("stale OK = %+v", h)
	}
	if h := staleOf(healthOf(bmc.HealthUnknown), true); h.Label != "No data" {
		t.Fatalf("no data = %+v", h)
	}
}

func TestEnumLabels(t *testing.T) {
	for h, want := range map[bmc.Health]string{bmc.HealthOK: "ok", bmc.HealthWarning: "warn",
		bmc.HealthCritical: "crit", bmc.HealthUnknown: "unknown", "weird": "unknown"} {
		if got := healthOf(h).Class; got != want {
			t.Errorf("healthOf(%q) = %q", h, got)
		}
	}
	for s, want := range map[bmc.Severity]string{bmc.SeverityOK: "ok", bmc.SeverityWarning: "warn",
		bmc.SeverityCritical: "crit", bmc.SeverityUnknown: "unknown"} {
		if got := severityOf(s).Class; got != want {
			t.Errorf("severityOf(%q) = %q", s, got)
		}
	}
	for p, want := range map[bmc.PowerState]string{bmc.PowerOn: "On", bmc.PowerOff: "Off",
		bmc.PowerPoweringOn: "Powering on", bmc.PowerPoweringOff: "Powering off", bmc.PowerUnknown: "Unknown"} {
		if got := powerLabel(p); got != want {
			t.Errorf("powerLabel(%q) = %q", p, got)
		}
	}
}

func TestDetailRows(t *testing.T) {
	rows := tempRows([]bmc.Temperature{{Name: "hot", Celsius: bmc.ReadingOf(50), WarnAbove: bmc.ReadingOf(45)}}, celsius())
	if !rows[0].Alert {
		t.Fatal("reading above warning not flagged")
	}
	if f := fanRows([]bmc.Fan{{Speed: bmc.ReadingOf(40), Units: bmc.FanPercent}}); f[0].Speed != "40 %" {
		t.Errorf("fan percent row = %q", f[0].Speed)
	}
	info := infoRows(bmc.InventoryInfo{})
	for _, r := range info {
		if r.Value != dash {
			t.Errorf("empty inventory %s = %q", r.Key, r.Value)
		}
	}
	if l := licenseRows(bmc.License{Tier: bmc.LicenseUnknown}); l[0].Value != "" {
		t.Errorf("empty licence tier = %q", l[0].Value)
	}
}

func TestPaging(t *testing.T) {
	cases := []struct{ page, size, n, wantPage, wantPages, lo, hi int }{
		{1, 50, 0, 1, 1, 0, 0},
		{1, 50, 120, 1, 3, 0, 50},
		{3, 50, 120, 3, 3, 100, 120},
		{9, 50, 120, 3, 3, 100, 120},
		{0, 50, 10, 1, 1, 0, 10},
	}
	for _, c := range cases {
		p, ps, lo, hi := pageBounds(c.page, c.size, c.n)
		if p != c.wantPage || ps != c.wantPages || lo != c.lo || hi != c.hi {
			t.Errorf("pageBounds(%d,%d,%d) = %d %d %d %d", c.page, c.size, c.n, p, ps, lo, hi)
		}
	}
	if _, ok := parseLogKind("lifecycle"); !ok {
		t.Error("lifecycle rejected")
	}
	if k, ok := parseLogKind(""); !ok || k != LogSEL {
		t.Error("default log is not SEL")
	}
}
