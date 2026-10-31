package redfish

import (
	"math"
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

func TestR240HasNoPowerTelemetryButVoltages(t *testing.T) {
	s := mockFor(t, idrac9)
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if snap.PowerTelemetry() != bmc.PowerTelemetryUnavailable {
		t.Fatalf("telemetry = %q", snap.PowerTelemetry())
	}
	vs := snap.Voltages()
	if len(vs) != 14 {
		t.Fatalf("want the 14 captured voltages, got %d", len(vs))
	}
	var vr bmc.Voltage
	for _, v := range vs {
		if v.Name == "CPU1 VCORE VR" {
			vr = v
		}
	}
	if !vr.Volts.Valid || math.Abs(vr.Volts.Value-0.18) > 1e-6 || vr.Health != bmc.HealthOK || vr.Context != "CPU" {
		t.Fatalf("CPU1 VCORE VR = %+v", vr)
	}
	if pg := vs[0]; pg.Volts.Valid || pg.Health != bmc.HealthOK || pg.Name != "System Board 1.8V SW PG" {
		t.Fatalf("power-good sensor = %+v", pg)
	}
	if snap.Degraded() {
		t.Fatalf("problems %v", snap.Problems())
	}
}

func TestIDRAC8PowerTelemetryAvailable(t *testing.T) {
	snap, err := driverFor(t, mockFor(t, idrac8)).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if snap.PowerTelemetry() != bmc.PowerTelemetryAvailable || len(snap.Voltages()) != 33 {
		t.Fatalf("telemetry %q, %d voltages", snap.PowerTelemetry(), len(snap.Voltages()))
	}
}

// SYNTHETIC: an all-zero PowerControl with no PSUs (what an iDRAC9 reports on
// hardware with a non-PMBus PSU) must read as "not monitored", with no 0 W draw.
func TestAllZeroPowerControlIsNotMonitored(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithOverlay(powerURI, `{"PowerControl": [{"MemberId": "0",
		"PowerConsumedWatts": 0, "PowerCapacityWatts": 0,
		"PowerMetrics": {"AverageConsumedWatts": 0, "MinConsumedWatts": 0, "MaxConsumedWatts": 0}}],
		"PowerSupplies": [], "Voltages": [{"MemberId": "0", "Name": "PS1 Voltage", "ReadingVolts": 12.1,
		"Status": {"Health": "OK"}}, {"MemberId": "1"}]}`))
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if snap.PowerTelemetry() != bmc.PowerTelemetryUnavailable || snap.Power() != (bmc.PowerDraw{}) {
		t.Fatalf("telemetry %q draw %+v", snap.PowerTelemetry(), snap.Power())
	}
	if vs := snap.Voltages(); len(vs) != 1 || vs[0].Volts.Value < 12 {
		t.Fatalf("voltages %+v", vs)
	}
}

func TestPowerReadFailureIsUnknown(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithStatus(powerURI, 503))
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if snap.PowerTelemetry() != bmc.PowerTelemetryUnknown || !snap.Degraded() {
		t.Fatalf("telemetry %q problems %v", snap.PowerTelemetry(), snap.Problems())
	}
}

func TestVoltagesAreBounded(t *testing.T) {
	var b []byte
	// gofish's Power decoder needs PowerControl present (every real BMC sends it).
	b = append(b, `{"PowerControl": [], "Voltages": [`...)
	for i := range maxVoltages + 5 {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"Name": "V", "ReadingVolts": 1}`...)
	}
	b = append(b, `]}`...)
	s := mockFor(t, idrac8, redfishmock.WithOverlay(powerURI, string(b)))
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(snap.Voltages()); n != maxVoltages {
		t.Fatalf("%d voltages kept", n)
	}
}

// SYNTHETIC: legacy Power is empty (voltages only) and the PowerSubsystem fallback
// fails. The voltages survive; telemetry is unknown, not "not monitored".
func TestSubsystemFailureKeepsLegacyVoltages(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithStatus("/redfish/v1/Chassis/System.Embedded.1/PowerSubsystem", 503))
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if snap.PowerTelemetry() != bmc.PowerTelemetryUnknown || len(snap.Voltages()) != 14 || !snap.Degraded() {
		t.Fatalf("telemetry %q, %d voltages, problems %v", snap.PowerTelemetry(), len(snap.Voltages()), snap.Problems())
	}
}
