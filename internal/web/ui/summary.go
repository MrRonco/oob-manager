package ui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/display"
	"oob-manager/internal/fleet"
)

// summaryRow is one server on the overview's fleet table, the sidebar and the header
// of its pages.
type summaryRow struct {
	ID, Name string
	Tags     []string
	Critical bool // tagged "critical" in config
	Health   healthView
	Power    string
	// Inlet and CPU (hottest CPU) against their thresholds; Hottest is the hottest
	// sensor of any kind (server Status panel).
	Inlet, CPU, Hottest             meterView
	InletName, CPUName, HottestName string
	// InletKey and HottestKey are those sensors' history keys (the server page's sparklines).
	InletKey, HottestKey string
	Fans                 string // "6/6 OK · 7440–9000 RPM"
	FanCount             string // "6/6"
	PSUs                 string // "2/2 OK"
	PSUCount             string // "2/2"
	PSUHealth            healthView
	Watts                string // "241 W"
	DrawW                string // "241" (unit in the column header)
	PeakW                string // "390 W"
	Fresh                freshness
	// PowerUnmonitored: the BMC reports neither PSUs nor power draw (a property of the
	// server, shown as "Not monitored by this server", not as Unknown).
	PowerUnmonitored bool
	Issue            string   // the first problem, as a sentence; "" when none
	unit             tempUnit // the viewer's temperature unit
	RowClass         string   // r-crit, r-warn, r-stale or ""
	// Maint is the active maintenance window: the server's problems are shown but not
	// counted in the fleet verdict or Needs attention.
	Maint *maintBadge
	// Security is the BMC security check cell of the fleet table (nil: not wired).
	Security *secCell
	// PowerItem is the attention item of a host that is not running (nil: it is on);
	// PowerNote is its short form for the Status panel; HostDown: off or powering off.
	PowerItem *attentionItem
	PowerNote string
	HostDown  bool
	raw       ServerView // for the attention list; never rendered directly
}

func (s *server) summarize(v ServerView, vw display.View) summaryRow {
	row := summaryRow{ID: v.ID, Name: v.Name, Tags: v.Tags, Critical: slices.Contains(v.Tags, "critical"),
		Health: healthOf(bmc.HealthUnknown), Power: dash, PSUHealth: healthOf(bmc.HealthUnknown),
		unit:  unitOf(vw.Temp),
		Fresh: freshnessOf(v, s.d.Now(), cmp.Or(v.StaleAfter, s.d.StaleAfter), fmtFor(vw)), raw: v,
		Inlet: meterView{WarnAt: -1, CritAt: -1}, CPU: meterView{WarnAt: -1, CritAt: -1}}
	if v.HasSnapshot {
		row = withSnapshot(row, v.Snapshot, unitOf(vw.Temp))
		row = s.withPowerState(row, v, fmtFor(vw))
	}
	if row.Fresh.Stale {
		row.Health = staleOf(row.Health, row.Fresh.NoData)
		row.PSUHealth = staleOf(row.PSUHealth, row.Fresh.NoData)
	}
	if row.Fresh.Restarting { // an expected BMC restart, not an outage (tech_doc §37)
		row.Health = healthView{Label: "BMC restarting", Class: "stale"}
	}
	if items := attentionFor(row); len(items) > 0 {
		row.Issue = items[0].Text
	}
	row.Maint = s.activeBadge(v.ID, fmtFor(vw))
	row.Security = s.secCellFor(v.ID, fmtFor(vw))
	row.RowClass = rowClass(row)
	return row
}

func withSnapshot(row summaryRow, snap bmc.Snapshot, u tempUnit) summaryRow {
	row.Health = healthOf(snap.Health())
	row.Power = powerLabel(snap.PowerState())
	ts := u.convert(snap.Temperatures())
	row.InletName, row.Inlet, row.InletKey = keyMeter(ts, func(t bmc.Temperature) bool { return matches(t, "Intake", "inlet") }, false, u)
	row.CPUName, row.CPU, _ = keyMeter(ts, func(t bmc.Temperature) bool { return matches(t, "CPU", "cpu") }, true, u)
	row.HottestName, row.Hottest, row.HottestKey = keyMeter(ts, func(bmc.Temperature) bool { return true }, true, u)
	row.Fans, row.FanCount = fanSummary(snap.Fans()), fanCount(snap.Fans())
	row.PSUs, row.PSUHealth = psuSummary(snap.PSUs())
	row.PSUCount = strings.TrimSuffix(row.PSUs, " OK")
	p := snap.Power()
	row.Watts, row.PeakW = fmtWatts(p.ConsumedWatts), fmtWatts(p.MaxWatts)
	if validReading(p.ConsumedWatts) {
		row.DrawW = fmt.Sprintf("%.0f", p.ConsumedWatts.Value)
	}
	if snap.PowerTelemetry() == bmc.PowerTelemetryUnavailable {
		row.PowerUnmonitored, row.PSUs, row.Watts, row.PSUCount, row.DrawW = true, notMonitored, notMonitored, "", ""
	}
	return row
}

// withPowerState applies the power-state semantics of power_state.go: a host that is
// not running gets an attention item, the Status panel note and the power badge. A host
// that is down takes the badge unless the sensor rollup is critical; powering on or an
// unknown power state replaces only an OK badge, so a sensor warning stays visible as
// it does in the metrics and notifications.
func (s *server) withPowerState(row summaryRow, v ServerView, tf timeFmt) summaryRow {
	p := v.Snapshot.PowerState()
	ctx := s.powerContextFor(v)
	row.PowerNote = powerNote(p, v.PowerSince, ctx, tf)
	badge, ok := hostBadge(p, row.Critical, ctx.planned())
	if !ok {
		return row
	}
	row.PowerItem = powerAttention(row.Name, "/servers/"+row.ID, p, row.Critical, v.PowerSince, ctx, tf)
	row.HostDown = hostDown(p)
	if (row.HostDown && row.Health.Class != "crit") || row.Health.Class == "ok" {
		row.Health = badge
	}
	return row
}

// keyMeter picks the first matching sensor (or, with hottest, the one with the highest
// reading) and returns its display name, headroom meter and history key.
func keyMeter(ts []bmc.Temperature, match func(bmc.Temperature) bool, hottest bool, u tempUnit) (string, meterView, string) {
	var best *bmc.Temperature
	for i := range ts {
		t := &ts[i]
		if !validReading(t.Celsius) || !match(*t) {
			continue
		}
		if best == nil || (hottest && t.Celsius.Value > best.Celsius.Value) {
			best = t
		}
		if !hottest {
			break
		}
	}
	if best == nil {
		return "", meterView{WarnAt: -1, CritAt: -1}, ""
	}
	return displayName(best.Name), headroomIn(u, best.Celsius, best.WarnAbove, best.CritAbove),
		fleet.SampleKey(fleet.KeyTemperature, best.ID, best.Name)
}

func fanCount(fs []bmc.Fan) string {
	if len(fs) == 0 {
		return dash
	}
	ok := 0
	for _, f := range fs {
		if f.Health == bmc.HealthOK {
			ok++
		}
	}
	return fmt.Sprintf("%d/%d", ok, len(fs))
}

func rowClass(row summaryRow) string {
	switch {
	case row.Fresh.Stale, row.Fresh.Restarting:
		return "r-stale"
	case row.Health.Class == "crit":
		return "r-crit"
	case row.Health.Class == "warn", row.Health.Class == "off" && row.PowerItem != nil && row.PowerItem.Health.Class == "warn":
		return "r-warn"
	case row.Health.Class == "off":
		return "r-off"
	default:
		return ""
	}
}

// rowRank sorts servers in maintenance after every counted problem, before OK servers.
func rowRank(r summaryRow) int {
	maint := healthRank(healthView{Class: "unknown"}) + 1
	switch rank := healthRank(r.Health); {
	case r.Maint != nil:
		return maint
	case rank >= maint:
		return rank + 1 // OK
	default:
		return rank
	}
}

// bySeverity orders fleet rows problems first (critical, off, warning, stale, unknown,
// maintenance, OK), keeping config order within a rank.
func bySeverity(rows []summaryRow) []summaryRow {
	out := slices.Clone(rows)
	slices.SortStableFunc(out, func(a, b summaryRow) int { return cmp.Compare(rowRank(a), rowRank(b)) })
	return out
}
