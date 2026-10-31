package ui

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"

	"oob-manager/internal/bmc"
)

type kv struct {
	Key   string
	Value string
}

type tempRow struct {
	Name, FullName, Context, Reading, Warn, Crit string
	Health                                       healthView
	Alert                                        bool // at or above the warning threshold
	Meter                                        meterView
	Change                                       string // "up", "down" or "" (valuechange.go)
}

type fanRow struct {
	Name, FullName, Speed, Value, Unit string
	Health                             healthView
	Change                             string // "up", "down" or "" (valuechange.go)
}

// psuRow: Rating is the rated output (and rated input when the BMC reports one);
// Input and Output are live measurements only (UI review F-11).
type psuRow struct {
	Name, FullName, Model, Firmware, Rating, Input, Output, Volts string
	Health                                                        healthView
}

// psuColumns hides PSU columns no supply reports (UX-19).
type psuColumns struct{ Rating, Input, Output, Volts, Model, Firmware bool }

type voltageRow struct {
	Name, FullName, Context, Reading string
	Health                           healthView
}

// tempRows puts problems first (UX-03): critical, then at or above warning, then close to
// warning; within a rank by location then name, so CPU1 comes before CPU2 (F-17).
func tempRows(ts []bmc.Temperature, u tempUnit) []tempRow {
	out := make([]tempRow, 0, len(ts))
	for _, t := range ts {
		alert := t.Celsius.Valid && t.WarnAbove.Valid && t.Celsius.Value >= t.WarnAbove.Value
		out = append(out, tempRow{Name: displayName(t.Name), FullName: t.Name, Context: t.Context,
			Reading: fmtReading(t.Celsius, u.Symbol), Warn: fmtReading(t.WarnAbove, u.Symbol), Crit: fmtReading(t.CritAbove, u.Symbol),
			Health: healthOf(t.Health), Alert: alert, Meter: headroomIn(u, t.Celsius, t.WarnAbove, t.CritAbove)})
	}
	slices.SortStableFunc(out, func(a, b tempRow) int {
		return cmp.Or(cmp.Compare(tempRank(a), tempRank(b)), cmp.Compare(a.Context, b.Context), cmp.Compare(a.Name, b.Name))
	})
	return out
}

func tempRank(r tempRow) int {
	switch {
	case r.Meter.Class == "crit" || r.Health.Class == "crit":
		return 0
	case r.Alert || r.Health.Class == "warn":
		return 1
	case r.Meter.Close:
		return 2
	default:
		return 3
	}
}

// fanRows lists fans problems first, with short names (the full name is in title).
func fanRows(fs []bmc.Fan) []fanRow {
	out := make([]fanRow, 0, len(fs))
	for _, f := range fs {
		unit := "RPM"
		if f.Units == bmc.FanPercent {
			unit = "%"
		}
		r := fanRow{Name: displayName(f.Name), FullName: f.Name, Speed: fmtReading(f.Speed, unit), Unit: unit,
			Health: healthOf(f.Health)}
		if validReading(f.Speed) {
			r.Value = fmt.Sprintf("%.0f", f.Speed.Value)
		}
		out = append(out, r)
	}
	slices.SortStableFunc(out, func(a, b fanRow) int { return cmp.Compare(healthRank(a.Health), healthRank(b.Health)) })
	return out
}

func psuRows(ps []bmc.PSU) ([]psuRow, psuColumns) {
	out := make([]psuRow, 0, len(ps))
	var cols psuColumns
	for _, p := range ps {
		r := psuRow{Name: displayName(p.Name), FullName: p.Name, Model: p.Model, Firmware: p.Firmware,
			Rating: psuRating(p), Input: fmtWatts(p.InputWatts), Output: fmtWatts(p.OutputWatts),
			Volts: fmtReading(p.LineInputVolts, "V"), Health: healthOf(p.Health)}
		cols = psuColumns{Rating: cols.Rating || r.Rating != "", Input: cols.Input || r.Input != "",
			Output: cols.Output || r.Output != "", Volts: cols.Volts || r.Volts != "",
			Model: cols.Model || r.Model != "", Firmware: cols.Firmware || r.Firmware != ""}
		out = append(out, r)
	}
	slices.SortStableFunc(out, func(a, b psuRow) int { return cmp.Compare(healthRank(a.Health), healthRank(b.Health)) })
	return out, cols
}

func psuRating(p bmc.PSU) string {
	out, in := fmtWatts(p.CapacityWatts), fmtWatts(p.RatedInputWatts)
	switch {
	case out != "" && in != "":
		return out + " out · " + in + " in"
	case out != "":
		return out + " out"
	case in != "":
		return in + " in"
	default:
		return dash
	}
}

func powerRows(p bmc.PowerDraw) []kv {
	return []kv{
		{"Consumed now", fmtWatts(p.ConsumedWatts)},
		{"Average", fmtWatts(p.AverageWatts)},
		{"Minimum", fmtWatts(p.MinWatts)},
		{"Peak", fmtWatts(p.MaxWatts)},
		{"Capacity", fmtWatts(p.CapacityWatts)},
	}
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// pageBounds clamps page (1-based) and returns the slice bounds for n items.
func pageBounds(page, size, n int) (clamped, pages, lo, hi int) {
	pages = max(1, (n+size-1)/size)
	clamped = min(max(page, 1), pages)
	lo = min((clamped-1)*size, n)
	hi = min(lo+size, n)
	return clamped, pages, lo, hi
}

func pageHref(id string, kind LogKind, page int) string {
	return "/servers/" + id + "/events?log=" + string(kind) + "&page=" + strconv.Itoa(page)
}
