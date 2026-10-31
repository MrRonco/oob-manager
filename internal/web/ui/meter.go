package ui

import (
	"fmt"
	"math"
	"strings"

	"oob-manager/internal/bmc"
)

// meterView is a headroom meter (brief C-03): a CSS bar on a scale that puts the
// critical threshold at about 91 %, ticks at the warning and critical thresholds, and
// a text equivalent ("26 °C below warning") so the meter itself can be aria-hidden.
// Widths and positions are class names (.wNN, .tNN): CSP forbids inline styles.
type meterView struct {
	Has    bool   // a bar can be drawn (a reading and at least one threshold)
	Value  string // "61" (unit in the column header)
	Fill   int    // 0..100
	WarnAt int    // tick position, -1 = no warning threshold
	CritAt int    // tick position, -1 = no critical threshold
	Class  string // ok, near, warn, crit
	Text   string
	Close  bool   // within nearBand below the warning threshold
	Unit   string // "°C" or "°F"
}

// nearBand is how close to the warning threshold a reading counts as "close".
const nearBand = 5.0

// headroom builds the meter for one Celsius temperature against its thresholds.
func headroom(reading, warn, crit bmc.Reading) meterView {
	return headroomIn(celsius(), reading, warn, crit)
}

// headroomIn builds the meter for values already converted to unit u.
func headroomIn(u tempUnit, reading, warn, crit bmc.Reading) meterView {
	m := meterView{WarnAt: -1, CritAt: -1, Unit: u.Symbol}
	if !validReading(reading) {
		return m
	}
	r := reading.Value
	m.Value = fmt.Sprintf("%.0f", r)
	scale := 0.0
	switch {
	case validReading(crit) && crit.Value > 0:
		scale = crit.Value * 1.1
	case validReading(warn) && warn.Value > 0:
		scale = warn.Value * 1.16
	default:
		m.Text = "No threshold reported"
		return m
	}
	m.Has, m.Fill = true, pct(r, scale)
	if validReading(warn) {
		m.WarnAt = pct(warn.Value, scale)
	}
	if validReading(crit) {
		m.CritAt = pct(crit.Value, scale)
	}
	m.Class, m.Text, m.Close = headroomText(u, r, warn, crit)
	return m
}

func headroomText(u tempUnit, r float64, warn, crit bmc.Reading) (class, text string, isClose bool) {
	deg := func(x float64) string { return fmt.Sprintf("%.0f %s", math.Abs(x), u.Symbol) }
	switch {
	case validReading(crit) && r >= crit.Value:
		return "crit", "At or above critical (" + deg(crit.Value) + ")", false
	case validReading(warn) && r >= warn.Value:
		return "warn", deg(r-warn.Value) + " above warning", false
	case validReading(warn) && warn.Value-r <= u.band:
		return "near", "Close: " + deg(warn.Value-r) + " below warning", true
	case validReading(warn):
		return "ok", deg(warn.Value-r) + " below warning", false
	default:
		return "ok", deg(crit.Value-r) + " below critical", false
	}
}

func pct(x, scale float64) int {
	return int(math.Round(min(max(x/scale*100, 0), 100)))
}

// displayName drops BMC naming noise (UX-23): the "System Board " prefix and a trailing
// " RPM". The full name stays available as FullName (title attribute).
func displayName(name string) string {
	n := strings.TrimPrefix(name, "System Board ")
	for _, suffix := range []string{" RPM", " Temp", " Status"} {
		n = strings.TrimSuffix(n, suffix)
	}
	if n == "" {
		return name
	}
	return n
}
