package ui

import (
	"cmp"
	"slices"

	"oob-manager/internal/bmc"
)

// pgRow is one power-good signal: Good, Fault or Unknown, never volts.
type pgRow struct {
	Name, FullName, State string
	Health                healthView
}

// voltagesView splits analog rails from power-good signals. The signals are summarized
// as "N of M good" and their list is open only when one has failed.
type voltagesView struct {
	Analog    []voltageRow
	PG        []pgRow
	PGTotal   int
	PGGood    int
	PGUnknown int
	PGOpen    bool
}

func splitVoltages(vs []bmc.Voltage) voltagesView {
	var v voltagesView
	for _, x := range vs {
		if !x.IsPowerGood() {
			v.Analog = append(v.Analog, voltageRow{Name: displayName(x.Name), FullName: x.Name, Context: x.Context,
				Reading: fmtVolts(x.Volts), Health: healthOf(x.Health)})
			continue
		}
		row := pgRow{Name: displayName(x.Name), FullName: x.Name, Health: healthOf(x.Health)}
		switch x.Health {
		case bmc.HealthOK:
			row.State = "Good"
			v.PGGood++
		case bmc.HealthWarning, bmc.HealthCritical:
			row.State, v.PGOpen = "Fault", true
		default:
			row.State = "Unknown"
			v.PGUnknown++
		}
		v.PG = append(v.PG, row)
	}
	v.PGTotal = len(v.PG)
	slices.SortStableFunc(v.PG, func(a, b pgRow) int { return cmp.Compare(pgRank(a.State), pgRank(b.State)) })
	slices.SortStableFunc(v.Analog, func(a, b voltageRow) int { return cmp.Compare(healthRank(a.Health), healthRank(b.Health)) })
	return v
}

func pgRank(state string) int {
	switch state {
	case "Fault":
		return 0
	case "Unknown":
		return 1
	default:
		return 2
	}
}

// healthRank orders problems first: critical, powered off, warning, stale/no data,
// unknown, OK (the §32 precedence: critical > off > warning > OK).
func healthRank(h healthView) int {
	switch h.Class {
	case "crit":
		return 0
	case "off":
		return 1
	case "warn":
		return 2
	case "stale":
		return 3
	case "unknown":
		return 4
	default:
		return 5
	}
}
