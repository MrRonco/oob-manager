package ui

import (
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/display"
	"oob-manager/internal/store"
)

// histUnit is how one stored unit is shown to a viewer: the symbol, the conversion
// (°C to °F for a viewer who prefers it; storage and CSV stay in °C) and the decimals.
type histUnit struct {
	Symbol   string
	f        bool // convert Celsius to Fahrenheit
	decimals int
}

func histUnitOf(u store.SensorUnit, t display.TempUnit) histUnit {
	switch u {
	case store.UnitCelsius:
		tu := unitOf(t)
		return histUnit{Symbol: tu.Symbol, f: tu.f, decimals: 1}
	case store.UnitRPM:
		return histUnit{Symbol: "RPM"}
	case store.UnitPercent:
		return histUnit{Symbol: "%"}
	case store.UnitWatts:
		return histUnit{Symbol: "W"}
	default: // volts
		return histUnit{Symbol: "V", decimals: 2}
	}
}

func (u histUnit) conv(v float64) float64 {
	if u.f {
		return v*9/5 + 32
	}
	return v
}

// num is a converted value without the unit ("41.5", "7440").
func (u histUnit) num(v float64) string { return strconv.FormatFloat(u.conv(v), 'f', u.decimals, 64) }

// text is a converted value with its unit ("41.5 °C", "7440 RPM", "41 %").
func (u histUnit) text(v float64) string { return u.num(v) + " " + u.Symbol }

// tick is an axis label: a value already converted, trailing zeros dropped.
func (u histUnit) tick(v float64) string {
	s := strconv.FormatFloat(v, 'f', u.decimals, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

// buckets returns converted copies (the chart draws display units).
func (u histUnit) buckets(bs []store.Bucket) []store.Bucket {
	if !u.f {
		return bs
	}
	out := make([]store.Bucket, len(bs))
	for i, b := range bs {
		b.Min, b.Avg, b.Max = u.conv(b.Min), u.conv(b.Avg), u.conv(b.Max)
		out[i] = b
	}
	return out
}

// bucketTime is a bucket's start as the data table shows it: the time of day for
// steps under a day ("Oct 20 14:30" off today), the UTC date for daily buckets (they
// are UTC days: a viewer's local date would name the wrong day west of Greenwich).
func (f timeFmt) bucketTime(t time.Time, step time.Duration, now time.Time) string {
	if step >= 24*time.Hour {
		if f.date == display.DateUS {
			return t.UTC().Format("01/02/2006") + " UTC"
		}
		return t.UTC().Format("2006-01-02") + " UTC"
	}
	return f.short(t, now)
}

// axisLabel is an x tick: the time of day, or the day ("Oct 20") for steps of a day or more.
func (f timeFmt) axisLabel(t time.Time, daily bool) string {
	lt := t.In(f.loc)
	if daily {
		return lt.Format("Jan 2")
	}
	if lt.Hour() == 0 && lt.Minute() == 0 {
		return lt.Format("Jan 2")
	}
	return lt.Format(f.hm())
}
