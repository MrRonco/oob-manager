package ui

import (
	"fmt"

	"oob-manager/internal/bmc"
)

// The value-change cue (plan 04 §11 item 5, UX audit C5): a reading that shows another
// value than at the previous poll is marked "up" or "down", and the Sensors tab tints it
// briefly (only under prefers-reduced-motion: no-preference; motion.css). Nothing is
// marked for a sensor that is new, gone or unread in either poll, or that changed below
// the shown precision.

// readingChange compares two readings at the precision fmtReading shows.
func readingChange(cur, prev bmc.Reading) string {
	if !validReading(cur) || !validReading(prev) {
		return ""
	}
	if fmt.Sprintf("%.0f", cur.Value) == fmt.Sprintf("%.0f", prev.Value) {
		return ""
	}
	if cur.Value > prev.Value {
		return "up"
	}
	return "down"
}

func tempKey(name, context string) string { return name + "\x00" + context }

// withTempChanges returns a copy of rows with Change set from the readings in cur and
// prev (same unit as the rows), matched by sensor name and context.
func withTempChanges(rows []tempRow, cur, prev []bmc.Temperature) []tempRow {
	now := make(map[string]bmc.Reading, len(cur))
	for _, t := range cur {
		now[tempKey(t.Name, t.Context)] = t.Celsius
	}
	before := make(map[string]bmc.Reading, len(prev))
	for _, t := range prev {
		before[tempKey(t.Name, t.Context)] = t.Celsius
	}
	out := make([]tempRow, len(rows))
	for i, r := range rows {
		k := tempKey(r.FullName, r.Context)
		if p, ok := before[k]; ok {
			r.Change = readingChange(now[k], p)
		}
		out[i] = r
	}
	return out
}

// withFanChanges returns a copy of rows with Change set, matched by fan name.
func withFanChanges(rows []fanRow, cur, prev []bmc.Fan) []fanRow {
	now := make(map[string]bmc.Reading, len(cur))
	for _, f := range cur {
		now[f.Name] = f.Speed
	}
	before := make(map[string]bmc.Reading, len(prev))
	for _, f := range prev {
		before[f.Name] = f.Speed
	}
	out := make([]fanRow, len(rows))
	for i, r := range rows {
		if p, ok := before[r.FullName]; ok {
			r.Change = readingChange(now[r.FullName], p)
		}
		out[i] = r
	}
	return out
}
