package ui

import (
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/display"
)

// tempUnit is the viewer's temperature unit. BMCs report Celsius; readings and
// thresholds are converted before any meter is built, so meters, "close to warning"
// and sorting work the same in both units.
type tempUnit struct {
	Symbol string  // "°C" or "°F"
	band   float64 // "close to warning" band in this unit (5 °C = 9 °F)
	f      bool
}

func unitOf(u display.TempUnit) tempUnit {
	if u == display.Fahrenheit {
		return tempUnit{Symbol: "°F", band: nearBand * 9 / 5, f: true}
	}
	return tempUnit{Symbol: "°C", band: nearBand}
}

// celsius is the default unit (tests and code paths without a viewer).
func celsius() tempUnit { return unitOf(display.Celsius) }

func (u tempUnit) reading(r bmc.Reading) bmc.Reading {
	if !u.f || !r.Valid {
		return r
	}
	return bmc.ReadingOf(r.Value*9/5 + 32)
}

// convert returns copies of ts in this unit.
func (u tempUnit) convert(ts []bmc.Temperature) []bmc.Temperature {
	out := make([]bmc.Temperature, len(ts))
	for i, t := range ts {
		t.Celsius, t.WarnAbove, t.CritAbove = u.reading(t.Celsius), u.reading(t.WarnAbove), u.reading(t.CritAbove)
		out[i] = t
	}
	return out
}

// trimUnit drops the unit from "87 °C" or "190 °F" for columns whose header carries it.
func trimUnit(s string) string {
	return strings.TrimSuffix(strings.TrimSuffix(s, " °C"), " °F")
}
