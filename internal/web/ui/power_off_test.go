package ui

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/power"
)

// hostAt is a fresh, sensor-healthy server whose host is in power state st; since is
// when that state was first seen (zero: unknown).
func hostAt(now time.Time, id, name string, tags []string, st bmc.PowerState, since time.Time) ServerView {
	snap := bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: now, PowerState: st, Health: bmc.HealthOK,
		Temperatures: []bmc.Temperature{{ID: "0", Name: "CPU1 Temp", Context: "CPU", Celsius: bmc.ReadingOf(30),
			WarnAbove: bmc.ReadingOf(85), Health: bmc.HealthOK}}})
	return ServerView{ID: id, Name: name, Tags: tags, Snapshot: snap, HasSnapshot: true, LastSuccess: now, PowerSince: since}
}

// TestPoweredOffServerIsNotHealthy (audit R2-01): a powered-off server is its own
// non-OK state on the Overview, the fleet row, the pill, the sidebar and its verdict.
func TestPoweredOffServerIsNotHealthy(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	now := h.clock.Now()
	h.fleet.servers = []ServerView{
		hostAt(now, "a", "Node A", nil, bmc.PowerOn, time.Time{}),
		hostAt(now, "b", "Node B", nil, bmc.PowerOff, now.Add(-7*time.Minute)),
	}
	since := fmtIn(time.UTC).full(now.Add(-7 * time.Minute))
	ov := result(c.get("/")).status(t, http.StatusOK)
	ov.contains(t, "<span>1 off</span>", "Powered off since "+since, `gp-off`, "1 OK · 1 off",
		`class="sdot s-off"`, `<span class="sv">Powered off</span>`).
		lacks(t, "All 2 servers healthy")
	body := ov.rec.Body.String()
	attn := between(body, `id="verdict"`, `id="fleet-h"`)
	if !strings.Contains(attn, "Node B") || !strings.Contains(attn, "b-warn") {
		t.Fatalf("Needs attention lacks the powered-off warning:\n%s", attn)
	}
	row := between(fleetTable(c), `href="/servers/b"`, "</tr>")
	if !strings.Contains(row, "Powered off") || !strings.Contains(row, "b-off") || strings.Contains(row, "b-ok") {
		t.Fatalf("fleet row of an off server:\n%s", row)
	}
	if !strings.Contains(fleetTable(c), `class="r-warn"`) {
		t.Fatal("the off row is not tinted as a warning")
	}
	srv := result(c.get("/servers/b")).status(t, http.StatusOK)
	srv.contains(t, "Powered off since "+since, `class="panel p-warn" id="problems"`, "<dt>Power</dt><dd>Off <span class=\"meta\">since "+since).
		lacks(t, "All reported sensors are within their limits.")
	result(c.get("/servers/b")).contains(t, "Power: Off")
}

func TestPoweredOffCriticalServerIsCritical(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	now := h.clock.Now()
	h.fleet.servers = []ServerView{
		hostAt(now, "a", "Node A", nil, bmc.PowerOn, time.Time{}),
		hostAt(now, "gw", "Gateway", []string{"critical"}, bmc.PowerOff, time.Time{}),
	}
	ov := result(c.get("/")).status(t, http.StatusOK)
	ov.contains(t, `gp-crit`, "</svg> 1 critical<span", "<span>1 critical</span>", "Powered off.").lacks(t, "Powered off since")
	attn := between(ov.rec.Body.String(), `id="verdict"`, `id="fleet-h"`)
	if !strings.Contains(attn, "Gateway") || !strings.Contains(attn, "b-crit") {
		t.Fatalf("a powered-off critical server must be a critical attention item:\n%s", attn)
	}
	row := between(fleetTable(c), `href="/servers/gw"`, "</tr>")
	if !strings.Contains(row, "b-crit") || !strings.Contains(row, "Powered off") {
		t.Fatalf("fleet row:\n%s", row)
	}
	result(c.get("/servers/gw")).contains(t, `class="panel p-crit" id="problems"`, "Powered off.")
}

// A graceful shutdown this app ran for a user reads calmly: who, when, and that it was
// asked for; it is still counted as off, never as healthy.
func TestPlannedShutdownReadsCalmly(t *testing.T) {
	t.Parallel()
	fp := &fakePower{last: map[string]power.Operation{}, info: map[string]power.Info{"b": {Configured: true, Operator: true}}}
	h, c := signedIn(t, func(d *Deps) { d.Power = fp })
	now := h.clock.Now()
	done := now.Add(-8 * time.Minute)
	fp.last["b"] = power.Operation{Action: power.GracefulShutdown, By: "alice", RequestedAt: done.Add(-time.Minute),
		FinishedAt: done, Phase: power.PhaseDone, State: bmc.PowerOff}
	h.fleet.servers = []ServerView{
		hostAt(now, "a", "Node A", nil, bmc.PowerOn, time.Time{}),
		hostAt(now, "b", "Node B", []string{"critical"}, bmc.PowerOff, done.Add(time.Minute)),
	}
	at, since := fmtIn(time.UTC).full(done), fmtIn(time.UTC).full(done.Add(time.Minute))
	ov := result(c.get("/")).status(t, http.StatusOK)
	ov.contains(t, "Powered off (by alice, "+at+"): graceful shutdown.", "1 OK · 1 off", "gp-off").
		lacks(t, "gp-crit", "gp-warn", "All 2 servers healthy")
	attn := between(ov.rec.Body.String(), `id="verdict"`, `id="fleet-h"`)
	if !strings.Contains(attn, "b-info") || strings.Contains(attn, "b-warn") || strings.Contains(attn, "b-crit") {
		t.Fatalf("a planned shutdown must not alarm:\n%s", attn)
	}
	result(c.get("/servers/b")).contains(t, `class="panel" id="problems"`, "Powered off (by alice")

	// A forced power-off by a user is named, and still an alarm (critical here: the
	// server is tagged critical).
	fp.last["b"] = power.Operation{Action: power.ForceOff, By: "admin", FinishedAt: done, Phase: power.PhaseDone, State: bmc.PowerOff}
	result(c.get("/")).contains(t, "Powered off since "+since+" (forced off by admin).", "b-crit", "gp-crit")

	// An old operation does not explain a newer power-down.
	fp.last["b"] = power.Operation{Action: power.GracefulShutdown, By: "alice", FinishedAt: now.Add(-3 * time.Hour),
		Phase: power.PhaseDone, State: bmc.PowerOff}
	result(c.get("/")).contains(t, "Powered off since "+since+".").lacks(t, "by alice")
}

func TestTransitionalAndUnknownPowerStates(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	now := h.clock.Now()
	h.fleet.servers = []ServerView{
		hostAt(now, "up", "Booting", nil, bmc.PowerPoweringOn, now),
		hostAt(now, "q", "Quiet", nil, bmc.PowerUnknown, time.Time{}),
	}
	ov := result(c.get("/")).status(t, http.StatusOK)
	ov.contains(t, "Powering on", "Power state not reported by the BMC.", "1 off · 1 unknown", " Power unknown</span>").
		lacks(t, "All 2 servers healthy", "b-ok")
}

func TestOffPill(t *testing.T) {
	t.Parallel()
	if p := pillOf(fleetCounts{Total: 3, OK: 2, Off: 1}); p.Class != "gp-off" || p.Text != "2 OK · 1 off" {
		t.Fatalf("pill %+v", p)
	}
	if p := pillOf(fleetCounts{Total: 3, Warning: 1, Off: 1, OK: 1}); p.Class != "gp-warn" || p.Text != "1 warning · 1 off" {
		t.Fatalf("pill %+v", p)
	}
	if p := pillOf(fleetCounts{Total: 2, Off: 1, Maintenance: 1}); p.Class != "gp-off" || p.Text != "1 off · 1 in maintenance" {
		t.Fatalf("pill %+v", p)
	}
}

// TestVerifiedPowerStateIsShownEverywhere (audit R2-08): once the fleet carries a
// verified transition that is newer than the last poll, the header, the fleet row, the
// Status panel and the Operations tab all show that state, with its source.
func TestVerifiedPowerStateIsShownEverywhere(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	now := h.clock.Now()
	polled, verified := now.Add(-2*time.Minute), now.Add(-time.Minute)
	v := hostAt(polled, "b", "Node B", nil, bmc.PowerOn, time.Time{})
	v.Snapshot = v.Snapshot.WithPowerState(bmc.PowerOff, verified)
	v.PowerSince, v.PowerCause = verified, PowerCause{Action: "force-off", By: "admin", At: verified}
	h.fleet.servers = []ServerView{hostAt(now, "a", "Node A", nil, bmc.PowerOn, time.Time{}), v}
	at := fmtIn(time.UTC).full(verified)
	ov := result(c.get("/")).status(t, http.StatusOK)
	ov.contains(t, "Powered off since "+at+" (forced off by admin).", "1 OK · 1 off")
	row := between(fleetTable(c), `href="/servers/b"`, "</tr>")
	if !strings.Contains(row, "Powered off") {
		t.Fatalf("fleet row still shows the polled state:\n%s", row)
	}
	result(c.get("/servers/b")).status(t, http.StatusOK).
		contains(t, "<dt>Power</dt><dd>Off <span class=\"meta\">verified "+at+" (force off by admin)</span>")
	result(c.get("/servers/b")).contains(t, "Power: Off", "verified "+at+" (force off by admin)")
}
