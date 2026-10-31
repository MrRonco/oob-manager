package ui

import (
	"fmt"
	"math"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// View models: everything is pre-formatted here so templates stay logic-free. All
// BMC-supplied strings pass through html/template escaping; none is marked safe.
//
// One "no data" vocabulary (UI review F-10): a value the BMC did not report is the empty
// string, which templates render as "Not reported" (partial "v"). "Unknown" is reserved
// for health; "Not monitored by this server" for telemetry the hardware cannot provide.

type healthView struct {
	Label string
	Class string // CSS modifier: ok, warn, crit, info, unknown, stale
}

func healthOf(h bmc.Health) healthView {
	switch h {
	case bmc.HealthOK:
		return healthView{Label: "OK", Class: "ok"}
	case bmc.HealthWarning:
		return healthView{Label: "Warning", Class: "warn"}
	case bmc.HealthCritical:
		return healthView{Label: "Critical", Class: "crit"}
	default:
		return healthView{Label: "Unknown", Class: "unknown"}
	}
}

// staleOf replaces a health badge on data that is not current (UI review F-02): a stale
// server must never show a plain "OK".
func staleOf(h healthView, noData bool) healthView {
	if noData {
		return healthView{Label: "No data", Class: "stale"}
	}
	return healthView{Label: "Stale (last: " + h.Label + ")", Class: "stale"}
}

func severityOf(s bmc.Severity) healthView {
	switch s {
	case bmc.SeverityOK:
		return healthOf(bmc.HealthOK)
	case bmc.SeverityWarning:
		return healthOf(bmc.HealthWarning)
	case bmc.SeverityCritical:
		return healthOf(bmc.HealthCritical)
	default:
		return healthOf(bmc.HealthUnknown)
	}
}

func powerLabel(p bmc.PowerState) string {
	switch p {
	case bmc.PowerOn:
		return "On"
	case bmc.PowerOff:
		return "Off"
	case bmc.PowerPoweringOn:
		return "Powering on"
	case bmc.PowerPoweringOff:
		return "Powering off"
	default:
		return "Unknown"
	}
}

// errorText is the human form of an error class (UI review F-20). No BMC text is shown.
func errorText(c bmc.ErrorClass) string {
	switch c {
	case bmc.ClassNone:
		return ""
	case bmc.ClassTimeout:
		return "timed out"
	case bmc.ClassTLS:
		return "certificate does not match the pin"
	case bmc.ClassAuth:
		return "credentials rejected"
	case bmc.ClassUnreachable:
		return "BMC unreachable"
	case bmc.ClassNotFound, bmc.ClassUnsupported:
		return "not offered by this BMC"
	case bmc.ClassBMC, bmc.ClassProtocol:
		return "BMC returned an unexpected answer"
	case bmc.ClassConfig:
		return "configuration error"
	default:
		return "unexpected error"
	}
}

// freshness says how old a server's data is. Stale data is labelled on every page
// that shows it (FR-6: never display a cached value as current). The absolute time is
// the primary text, so a page left open is self-evidently old (UI review F-03).
type freshness struct {
	Stale  bool
	NoData bool
	Age    string // age when the page was generated: "42s"
	At     string // absolute time of the last successful poll
	ISO    string // the same, RFC 3339, for <time datetime>
	Error  string // human text of the last failure class, "" when the last poll worked
	Chip   chipView
	// Restarting: the app restarted the BMC and waits for it (tech_doc §37); the banner
	// and chip say so instead of "stale". Restart is "requested 01:12 by alice · expected
	// back by 01:17".
	Restarting bool
	Restart    string
}

// chipView is the age chip (brief C-02): Live, Aging (past half the stale threshold) or
// Stale, with the age.
type chipView struct {
	Class, Text string
}

func ageChip(f freshness, age, staleAfter time.Duration) chipView {
	switch {
	case f.NoData:
		return chipView{Class: "chip-stale", Text: "No data"}
	case f.Stale:
		return chipView{Class: "chip-stale", Text: "Stale " + f.Age}
	case age > staleAfter/2:
		return chipView{Class: "chip-aging", Text: "Aging " + f.Age}
	default:
		return chipView{Text: "Live " + f.Age}
	}
}

func freshnessOf(v ServerView, now time.Time, staleAfter time.Duration, tf timeFmt) freshness {
	f := freshnessAt(v, now, staleAfter, tf)
	if v.Restarting {
		f.Restarting, f.Restart = true, restartText(v.Restart, tf)
		f.Chip = chipView{Class: "chip-stale", Text: "BMC restarting"}
	}
	return f
}

// restartText is the one line that describes an open BMC restart window.
func restartText(w RestartWindow, tf timeFmt) string {
	return "requested " + tf.full(w.Since) + " by " + w.By + " · expected back by " + tf.full(w.Until)
}

func freshnessAt(v ServerView, now time.Time, staleAfter time.Duration, tf timeFmt) freshness {
	f := freshness{Error: errorText(v.ErrorClass)}
	if !v.HasSnapshot || v.LastSuccess.IsZero() {
		f.NoData, f.Stale = true, true
		f.Chip = ageChip(f, 0, staleAfter)
		return f
	}
	age := now.Sub(v.LastSuccess)
	f.Age, f.At, f.ISO = fmtAge(age), tf.full(v.LastSuccess), v.LastSuccess.UTC().Format(time.RFC3339)
	f.Stale = age > staleAfter
	f.Chip = ageChip(f, age, staleAfter)
	return f
}

// dash is the empty value: templates render it as "Not reported".
const dash = ""

func validReading(r bmc.Reading) bool {
	return r.Valid && !math.IsNaN(r.Value) && !math.IsInf(r.Value, 0)
}

func fmtReading(r bmc.Reading, unit string) string {
	if !validReading(r) {
		return dash
	}
	return fmt.Sprintf("%.0f %s", r.Value, unit)
}

func fmtTemp(r bmc.Reading) string { return fmtReading(r, "°C") }

func fmtWatts(r bmc.Reading) string { return fmtReading(r, "W") }

// fmtVolts keeps two decimals: rails such as 0.18 V or 12.06 V need them.
func fmtVolts(r bmc.Reading) string {
	if !validReading(r) {
		return dash
	}
	return fmt.Sprintf("%.2f V", r.Value)
}

// notMonitored is shown instead of PSU and power values the server cannot report.
const notMonitored = "Not monitored by this server"

func matches(t bmc.Temperature, context, word string) bool {
	return strings.EqualFold(t.Context, context) || strings.Contains(strings.ToLower(t.Name), word)
}

// keyTemps returns the inlet temperature and the hottest CPU temperature.
func keyTemps(ts []bmc.Temperature) (inlet, cpu string) {
	inlet, cpu = dash, dash
	hottest := bmc.NoReading()
	for _, t := range ts {
		if inlet == dash && t.Celsius.Valid && matches(t, "Intake", "inlet") {
			inlet = fmtTemp(t.Celsius)
		}
		if t.Celsius.Valid && matches(t, "CPU", "cpu") && (!hottest.Valid || t.Celsius.Value > hottest.Value) {
			hottest = t.Celsius
		}
	}
	if hottest.Valid {
		cpu = fmtTemp(hottest)
	}
	return inlet, cpu
}

// fanSummary is "6/6 OK · 7440–9000 RPM": a count, so one failed fan is visible, and
// the range rather than an average that would hide it (UI review F-12). Percent is
// preferred when a BMC reports both units.
func fanSummary(fs []bmc.Fan) string {
	if len(fs) == 0 {
		return dash
	}
	ok := 0
	var pct, rpm []float64
	for _, f := range fs {
		if f.Health == bmc.HealthOK {
			ok++
		}
		switch {
		case !validReading(f.Speed):
		case f.Units == bmc.FanPercent:
			pct = append(pct, f.Speed.Value)
		default:
			rpm = append(rpm, f.Speed.Value)
		}
	}
	text := fmt.Sprintf("%d/%d OK", ok, len(fs))
	switch {
	case len(pct) > 0:
		return text + " · " + span(pct, "%")
	case len(rpm) > 0:
		return text + " · " + span(rpm, "RPM")
	default:
		return text
	}
}

func span(xs []float64, unit string) string {
	lo, hi := xs[0], xs[0]
	for _, x := range xs {
		lo, hi = min(lo, x), max(hi, x)
	}
	if lo == hi {
		return fmt.Sprintf("%.0f %s", lo, unit)
	}
	return fmt.Sprintf("%.0f–%.0f %s", lo, hi, unit)
}

func psuSummary(ps []bmc.PSU) (string, healthView) {
	if len(ps) == 0 {
		return dash, healthOf(bmc.HealthUnknown)
	}
	ok := 0
	hs := make([]bmc.Health, 0, len(ps))
	for _, p := range ps {
		hs = append(hs, p.Health)
		if p.Health == bmc.HealthOK {
			ok++
		}
	}
	return fmt.Sprintf("%d/%d OK", ok, len(ps)), healthOf(bmc.WorstHealth(hs...))
}
