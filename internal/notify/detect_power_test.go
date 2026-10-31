package notify

import (
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

func withPower(st bmc.PowerState) stateOpt {
	return func(s *fleet.ServerState) {
		s.Snapshot = bmc.NewSnapshot(bmc.SnapshotParams{Health: bmc.HealthOK, PowerState: st,
			PowerTelemetry: bmc.PowerTelemetryAvailable, PSUs: s.Snapshot.PSUs()})
	}
}

func tagged(tags ...string) stateOpt {
	return func(s *fleet.ServerState) { s.Tags = tags }
}

// TestPoweredOffIsAHealthEvent (audit R2-01): a host that is powered off is reported on
// the health class after the debounce, as a warning (critical for a critical-tagged
// server), and its return is a recovery.
func TestPoweredOffIsAHealthEvent(t *testing.T) {
	d := NewDetector(time.Minute)
	t0 := fixedNow
	on, off := healthy(t0, withPower(bmc.PowerOn)), healthy(t0, withPower(bmc.PowerOff))
	if evs := run(d, on, off, on); len(evs) != 0 {
		t.Fatalf("a one-poll blip was reported: %+v", evs)
	}
	d = NewDetector(time.Minute)
	evs := run(d, on, off, off, off, off)
	if len(evs) != 1 || evs[0].Class != ClassHealth || evs[0].Severity != SeverityWarning || evs[0].Recovery ||
		!strings.Contains(evs[0].Title, "powered off") {
		t.Fatalf("powered off: %+v", evs)
	}
	evs = run(d, on, on, on)
	if len(evs) != 1 || !evs[0].Recovery || evs[0].Severity != SeverityWarning || !strings.Contains(evs[0].Title, "powered on again") {
		t.Fatalf("recovery: %+v", evs)
	}

	crit := NewDetector(time.Minute)
	gw := healthy(t0, withPower(bmc.PowerOff), tagged("critical"))
	evs = run(crit, gw, gw, gw, gw)
	if len(evs) != 1 || evs[0].Severity != SeverityCritical {
		t.Fatalf("critical-tagged server off: %+v", evs)
	}

	// Powering on is not "off"; an unknown power state leaves the sensor verdict in charge.
	for _, st := range []bmc.PowerState{bmc.PowerPoweringOn, bmc.PowerUnknown} {
		s := healthy(t0, withPower(st))
		if evs := run(NewDetector(time.Second), s, s, s); len(evs) != 0 {
			t.Fatalf("%s reported: %+v", st, evs)
		}
	}
}

func plannedOff(by string) stateOpt {
	return func(s *fleet.ServerState) {
		s.PowerCause = fleet.PowerCause{Action: "graceful-shutdown", By: by, At: fixedNow}
	}
}

// TestPlannedShutdownIsInformational (audit R2-01/R2-08): a graceful shutdown this app
// ran for a user is reported as information, not an alarm, and so is its return.
func TestPlannedShutdownIsInformational(t *testing.T) {
	d := NewDetector(time.Minute)
	on := healthy(fixedNow, withPower(bmc.PowerOn), tagged("critical"))
	off := healthy(fixedNow, withPower(bmc.PowerOff), tagged("critical"), plannedOff("alice"))
	evs := run(d, on, off, off, off, off)
	if len(evs) != 1 || evs[0].Severity != SeverityInfo || evs[0].Recovery || !strings.Contains(evs[0].Title, "powered off") ||
		!strings.Contains(evs[0].Message, "graceful shutdown by alice") {
		t.Fatalf("planned shutdown: %+v", evs)
	}
	evs = run(d, on, on, on)
	if len(evs) != 1 || !evs[0].Recovery || evs[0].Severity != SeverityInfo {
		t.Fatalf("return from a planned shutdown: %+v", evs)
	}
}
