package ui

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// TestOffSortsBetweenCriticalAndWarning (§32 precedence: critical > off > warning > OK):
// a powered-off server is listed after critical servers and before warnings, never
// among the OK ones; maintenance still sorts after every counted problem.
func TestOffSortsBetweenCriticalAndWarning(t *testing.T) {
	t.Parallel()
	rows := []summaryRow{
		{ID: "ok", Health: healthView{Class: "ok"}},
		{ID: "maint", Health: healthView{Class: "crit"}, Maint: &maintBadge{}},
		{ID: "unknown", Health: healthView{Class: "unknown"}},
		{ID: "stale", Health: healthView{Class: "stale"}},
		{ID: "warn", Health: healthView{Class: "warn"}},
		{ID: "off", Health: healthView{Class: "off"}},
		{ID: "crit", Health: healthView{Class: "crit"}},
	}
	var got []string
	for _, r := range bySeverity(rows) {
		got = append(got, r.ID)
	}
	if want := []string{"crit", "off", "warn", "stale", "unknown", "maint", "ok"}; !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

// TestStalePillIsNotHiddenByOff: stale data outranks a powered-off server in the pill,
// so "1 stale · 1 off" carries the stale class.
func TestStalePillIsNotHiddenByOff(t *testing.T) {
	t.Parallel()
	p := pillOf(fleetCounts{Total: 2, Off: 1, Stale: 1})
	if p.Class != "gp-stale" || p.Text != "1 stale · 1 off" {
		t.Fatalf("pill %+v", p)
	}
}

// warnHostAt is hostAt with a sensor warning (CPU above its warning threshold).
func warnHostAt(now time.Time, id, name string, st bmc.PowerState) ServerView {
	snap := bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: now, PowerState: st, Health: bmc.HealthWarning,
		Temperatures: []bmc.Temperature{{ID: "0", Name: "CPU1 Temp", Context: "CPU", Celsius: bmc.ReadingOf(90),
			WarnAbove: bmc.ReadingOf(85), Health: bmc.HealthWarning}}})
	return ServerView{ID: id, Name: name, Snapshot: snap, HasSnapshot: true, LastSuccess: now}
}

// TestPowerUnknownKeepsASensorWarning (R3): an unknown or powering-on power state only
// replaces an OK badge. A sensor warning keeps its badge, count and row tint (as metrics
// and notifications do); the attention item still says what the power state is.
func TestPowerUnknownKeepsASensorWarning(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	now := h.clock.Now()
	h.fleet.servers = []ServerView{warnHostAt(now, "q", "Quiet", bmc.PowerUnknown), warnHostAt(now, "up", "Booting", bmc.PowerPoweringOn)}
	ov := result(c.get("/")).status(t, http.StatusOK)
	ov.contains(t, "2 warning", "Power state not reported by the BMC.", "Powering on.").lacks(t, "1 off", "1 unknown")
	table := fleetTable(c)
	for _, id := range []string{"q", "up"} {
		row := between(table, `href="/servers/`+id+`"`, "</tr>")
		if !strings.Contains(row, "b-warn") || strings.Contains(row, "Power unknown") || strings.Contains(row, "b-off") ||
			strings.Contains(row, "Power state not reported") || strings.Contains(row, "Powering on.") {
			t.Fatalf("%s: the warning badge was replaced:\n%s", id, row)
		}
	}
	if strings.Count(table, `class="r-warn"`) != 2 {
		t.Fatalf("rows not tinted as warnings:\n%s", table)
	}
}
