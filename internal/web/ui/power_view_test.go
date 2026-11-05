package ui

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// noPSUServer models a BMC without PSU telemetry (a cabled, non-PMBus PSU): no PSUs,
// no draw, but voltage sensors.
func noPSUServer(now time.Time) ServerView {
	snap := bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: now, PowerState: bmc.PowerOn, Health: bmc.HealthOK,
		PowerTelemetry: bmc.PowerTelemetryUnavailable,
		Voltages: []bmc.Voltage{
			{ID: "0", Name: "System Board 1.8V SW PG", Context: "SystemBoard", Volts: bmc.NoReading(), Health: bmc.HealthOK},
			{ID: "13", Name: "CPU1 VCORE VR", Context: "CPU", Volts: bmc.ReadingOf(0.18), Health: bmc.HealthOK},
			{ID: "14", Name: "<b>PS rail</b>", Volts: bmc.ReadingOf(12.06), Health: bmc.HealthCritical},
		}})
	return ServerView{ID: "edge", Name: "Edge node", Snapshot: snap, HasSnapshot: true, LastSuccess: now}
}

func TestNoPSUTelemetryOverview(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.servers = []ServerView{noPSUServer(h.clock.Now())}
	r := result(c.get("/servers")).status(t, http.StatusOK)
	r.contains(t, "Not monitored")
	body := r.rec.Body.String()
	if strings.Count(fleetTable(c), ">Not monitored<") != 2 {
		t.Fatalf("want PSUs and power draw both marked not monitored:\n%s", body)
	}
	if strings.Contains(between(body, `data-label="PSUs"`, "</td>"), "b-unknown") {
		t.Fatal("a server without PSU telemetry must not show an Unknown PSU badge")
	}
}

func TestNoPSUTelemetryServerPageShowsVoltages(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.servers = []ServerView{noPSUServer(h.clock.Now())}
	r := result(c.get("/servers/edge/sensors")).status(t, http.StatusOK)
	r.contains(t, "Not monitored by this server", "Voltage rails", "CPU1 VCORE VR", "0.18 V", "12.06 V",
		`title="System Board 1.8V SW PG"`, "Power-good signals", "&lt;b&gt;PS rail&lt;/b&gt;", "b-crit")
	r.lacks(t, "No power supplies reported.", "Chassis power", "<b>PS rail</b>")
}

func TestServerPageVoltagesWithPSUs(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	v := h.fleet.servers[0]
	p := bmc.SnapshotParams{TakenAt: h.clock.Now(), PowerState: bmc.PowerOn, Health: bmc.HealthOK,
		PSUs:           []bmc.PSU{{ID: "p1", Name: "PS1", Health: bmc.HealthOK}},
		Power:          bmc.PowerDraw{ConsumedWatts: bmc.ReadingOf(200)},
		PowerTelemetry: bmc.PowerTelemetryAvailable}
	v.Snapshot = bmc.NewSnapshot(p)
	h.fleet.servers = []ServerView{v}
	result(c.get("/servers/"+v.ID+"/sensors")).status(t, http.StatusOK).
		contains(t, "PS1", "Chassis power", "200 W", "No voltage sensors reported.").
		lacks(t, "Not monitored by this server")
}

func TestFmtVolts(t *testing.T) {
	t.Parallel()
	if fmtVolts(bmc.NoReading()) != dash || fmtVolts(bmc.ReadingOf(3.3)) != "3.30 V" {
		t.Fatal("fmtVolts")
	}
}
