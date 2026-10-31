package redfish

import (
	"errors"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

const (
	thermalURI = "/redfish/v1/Chassis/System.Embedded.1/Thermal"
	powerURI   = "/redfish/v1/Chassis/System.Embedded.1/Power"
)

func TestSnapshotIDRAC8(t *testing.T) {
	s := mockFor(t, idrac8)
	fixed := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	d := driverFor(t, s, WithClock(func() time.Time { return fixed }))
	snap, err := d.Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if !snap.TakenAt().Equal(fixed) || snap.PowerState() != bmc.PowerOn || snap.Health() != bmc.HealthOK {
		t.Fatalf("header: %v %v %v", snap.TakenAt(), snap.PowerState(), snap.Health())
	}
	temps := snap.Temperatures()
	if len(temps) != 4 {
		t.Fatalf("want 4 temperatures (null entry skipped), got %d: %+v", len(temps), temps)
	}
	inlet := findTemp(t, temps, "System Board Inlet Temp")
	if inlet.Celsius.Value != 25 || inlet.WarnAbove.Value != 42 || inlet.CritAbove.Value != 47 || inlet.Health != bmc.HealthOK {
		t.Fatalf("inlet %+v", inlet)
	}
	if cpu := findTemp(t, temps, "CPU1 Temp"); cpu.Celsius.Value != 45 {
		t.Fatalf("cpu1 %+v", cpu)
	}
	fans := snap.Fans()
	if len(fans) != 6 || fans[2].Speed.Value != 8880 || fans[2].Units != bmc.FanRPM || fans[2].Name != "System Board Fan3 RPM" {
		t.Fatalf("fans %+v", fans)
	}
	psus := snap.PSUs()
	if len(psus) != 2 {
		t.Fatalf("psus %+v", psus)
	}
	p := psus[0]
	if p.ID != "PSU.Slot.1" || p.Model != "PWR SPLY,750W,RDNT,DELTA" || p.Firmware != "00.24.7A" ||
		p.LineInputVolts.Value != 118 || p.CapacityWatts.Value != 750 || p.Health != bmc.HealthOK {
		t.Fatalf("psu %+v", p)
	}
	pw := snap.Power()
	if pw.ConsumedWatts.Value != 263 || pw.AverageWatts.Value != 263 || pw.MinWatts.Value != 250 ||
		pw.MaxWatts.Value != 280 || pw.CapacityWatts.Value != 1792 {
		t.Fatalf("power %+v", pw)
	}
	if snap.Degraded() {
		t.Fatalf("unexpected problems: %v", snap.Problems())
	}
	assertNoWrites(t, s)
}

func TestSnapshotIDRAC9(t *testing.T) {
	s := mockFor(t, idrac9)
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	temps := snap.Temperatures()
	if len(temps) != 2 {
		t.Fatalf("temps %+v", temps)
	}
	cpu := findTemp(t, temps, "CPU1 Temp")
	if cpu.Celsius.Value != 40 || cpu.CritAbove.Value != 100 || cpu.WarnAbove.Valid {
		t.Fatalf("cpu %+v", cpu)
	}
	if fans := snap.Fans(); len(fans) != 4 || fans[0].Speed.Value != 7920 {
		t.Fatalf("fans %+v", fans)
	}
	// The R240 reports empty PowerControl/PowerSupplies, and its PowerSubsystem
	// PowerSupplies collection is absent: degrade to "no PSU data", not an error.
	if len(snap.PSUs()) != 0 || snap.Power().ConsumedWatts.Valid {
		t.Fatalf("power: %+v %+v", snap.PSUs(), snap.Power())
	}
	if snap.Degraded() || snap.PowerState() != bmc.PowerOn || snap.Health() != bmc.HealthOK {
		t.Fatalf("problems %v state %v health %v", snap.Problems(), snap.PowerState(), snap.Health())
	}
	assertNoWrites(t, s)
}

func TestSnapshotMissingThermalAndPowerDegrade(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithMissing(thermalURI), redfishmock.WithMissing(powerURI))
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatalf("missing sections must not fail the snapshot: %v", err)
	}
	if len(snap.Temperatures())+len(snap.Fans())+len(snap.PSUs()) != 0 || snap.Degraded() {
		t.Fatalf("expected empty, non-degraded snapshot: %v", snap.Problems())
	}
	if snap.PowerState() != bmc.PowerOn {
		t.Fatal("system data lost")
	}
}

func TestSnapshotSectionErrorsAreRecorded(t *testing.T) {
	s := mockFor(t, idrac8,
		redfishmock.WithStatus(thermalURI, 503),
		redfishmock.WithOverlay(powerURI, `{"PowerControl": "not-an-array"}`),
	)
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	probs := strings.Join(snap.Problems(), "|")
	if !strings.Contains(probs, "thermal") || !strings.Contains(probs, "power") || !snap.Degraded() {
		t.Fatalf("problems %q", probs)
	}
}

func TestSnapshotSlowSectionTimesOutIndividually(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithDelay(thermalURI, 3*time.Second))
	cfg := configFor(s)
	cfg.Timeout = 300 * time.Millisecond
	d, _ := New(cfg)
	ctx := testCtx(t)
	if _, err := d.Resources(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := d.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(snap.Problems(), "|"), "timeout") || len(snap.PSUs()) != 2 {
		t.Fatalf("problems %v psus %d", snap.Problems(), len(snap.PSUs()))
	}
}

func TestSnapshotSystemFailureIsAnError(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithStatus("/redfish/v1/Systems/System.Embedded.1", 500))
	if _, err := driverFor(t, s).Snapshot(testCtx(t)); !errors.Is(err, bmc.ErrBMC) {
		t.Fatalf("want ErrBMC, got %v", err)
	}
}

func TestSnapshotSubsystemFromFixtures(t *testing.T) {
	// Real R240 captures with the legacy resources hidden: ThermalSubsystem/Fans lists four
	// fans (only Fan.Embedded.1 was captured), ThermalMetrics has two readings and the
	// PowerSubsystem PowerSupplies collection is empty.
	s := mockFor(t, idrac9, redfishmock.WithMissing(thermalURI), redfishmock.WithMissing(powerURI))
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	fans := snap.Fans()
	if len(fans) != 1 || fans[0].ID != "Fan.Embedded.1" || fans[0].Speed.Value != 7920 || fans[0].Units != bmc.FanRPM {
		t.Fatalf("fans %+v", fans)
	}
	temps := snap.Temperatures()
	if len(temps) != 2 || findTemp(t, temps, "Internal").Celsius.Value != 36 || findTemp(t, temps, "Intake").Celsius.Value != 28 {
		t.Fatalf("temps %+v", temps)
	}
	if len(snap.PSUs()) != 0 || snap.Degraded() {
		t.Fatalf("psus %+v problems %v", snap.PSUs(), snap.Problems())
	}
	assertNoWrites(t, s)
}

// TestSnapshotSubsystemOnly keeps SYNTHETIC overlays for shapes the captures lack
// (percent-only fan readings, a populated PowerSupplies collection).
func TestSnapshotSubsystemOnly(t *testing.T) {
	s := mockFor(t, idrac9, subsystemOnlyOverlays()...)
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	fans := snap.Fans()
	if len(fans) != 2 || fans[0].Units != bmc.FanRPM || fans[0].Speed.Value != 7920 ||
		fans[1].Units != bmc.FanPercent || fans[1].Speed.Value != 40 {
		t.Fatalf("fans %+v", fans)
	}
	temps := snap.Temperatures()
	if len(temps) != 2 || temps[0].Name != "CPU1 Temp" || temps[0].Celsius.Value != 41 {
		t.Fatalf("temps %+v", temps)
	}
	psus := snap.PSUs()
	if len(psus) != 1 || psus[0].Model != "PWR SPLY,250W" || psus[0].CapacityWatts.Value != 250 || psus[0].Health != bmc.HealthOK {
		t.Fatalf("psus %+v", psus)
	}
	if snap.Degraded() {
		t.Fatalf("problems %v", snap.Problems())
	}
}

func findTemp(t *testing.T, ts []bmc.Temperature, name string) bmc.Temperature {
	t.Helper()
	for _, x := range ts {
		if x.Name == name {
			return x
		}
	}
	t.Fatalf("temperature %q not found in %+v", name, ts)
	return bmc.Temperature{}
}

// subsystemOnlyOverlays is SYNTHETIC data (modelled on DMTF ThermalSubsystem/PowerSubsystem
// schemas, not captured from hardware): an iDRAC9 whose chassis offers only the new schemas.
func subsystemOnlyOverlays() []redfishmock.Option {
	const ch = "/redfish/v1/Chassis/System.Embedded.1"
	return []redfishmock.Option{
		redfishmock.WithOverlay(ch, `{"@odata.id":"`+ch+`","Status":{"Health":"OK","HealthRollup":"OK"},
			"ThermalSubsystem":{"@odata.id":"`+ch+`/ThermalSubsystem"},
			"PowerSubsystem":{"@odata.id":"`+ch+`/PowerSubsystem"}}`),
		redfishmock.WithOverlay(ch+"/ThermalSubsystem/Fans", collection(ch+"/ThermalSubsystem/Fans/Fan.1", ch+"/ThermalSubsystem/Fans/Fan.2")),
		redfishmock.WithOverlay(ch+"/ThermalSubsystem/Fans/Fan.1", `{"Id":"Fan.1","Name":"System Board Fan1",
			"SpeedPercent":{"SpeedRPM":7920},"Status":{"Health":"OK"}}`),
		redfishmock.WithOverlay(ch+"/ThermalSubsystem/Fans/Fan.2", `{"Id":"Fan.2","Name":"System Board Fan2",
			"SpeedPercent":{"Reading":40},"Status":{"Health":"Warning"}}`),
		redfishmock.WithOverlay(ch+"/ThermalSubsystem/ThermalMetrics", `{"TemperatureReadingsCelsius":[
			{"DataSourceUri":"/redfish/v1/Chassis/System.Embedded.1/Sensors/CPU1Temp","DeviceName":"CPU1 Temp","Reading":41},
			{"DeviceName":"System Board Inlet Temp","Reading":27}]}`),
		redfishmock.WithOverlay(ch+"/PowerSubsystem/PowerSupplies", collection(ch+"/PowerSubsystem/PowerSupplies/PSU.Slot.1")),
		redfishmock.WithOverlay(ch+"/PowerSubsystem/PowerSupplies/PSU.Slot.1", `{"Id":"PSU.Slot.1","Name":"PS1",
			"Model":"PWR SPLY,250W","FirmwareVersion":"1.0","PowerCapacityWatts":250,"Status":{"Health":"OK"}}`),
	}
}

func TestConcurrentUseIsRaceFree(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	ctx := testCtx(t)
	errs := make(chan error, 16)
	for i := 0; i < 8; i++ {
		go func() {
			_, err := d.Snapshot(ctx)
			errs <- err
		}()
		go func() {
			_, err := d.Probe(ctx)
			errs <- err
		}()
	}
	for i := 0; i < 16; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	assertNoWrites(t, s)
}
