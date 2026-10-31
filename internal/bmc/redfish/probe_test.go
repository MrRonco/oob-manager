package redfish

import (
	"slices"
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

func TestProbeIDRAC8(t *testing.T) {
	s := mockFor(t, idrac8)
	d := driverFor(t, s, WithSELFallbacks(dellSEL))
	caps, err := d.Probe(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	f := caps.Flags()
	want := bmc.CapabilityFlags{
		RedfishVersion:    "1.4.0",
		Product:           "Integrated Dell Remote Access Controller",
		BMCModel:          "13G Monolithic",
		BMCFirmware:       "2.86.86.86",
		LegacyThermal:     true,
		LegacyPower:       true,
		SEL:               true,
		SELSource:         "/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Sel",
		FirmwareInventory: true,
		GraphicalConsole:  true,
		SSH:               true,
		ManagerReset:      true, // iDRAC8 offers GracefulRestart but reports no LastResetTime
		ProbedAt:          f.ProbedAt,
	}
	if f != want {
		t.Fatalf("flags\n got %+v\nwant %+v", f, want)
	}
	if f.ProbedAt.IsZero() {
		t.Fatal("ProbedAt not set")
	}
	if !slices.Equal(caps.ResetTypes(), []string{"On", "ForceOff", "ForceRestart", "GracefulShutdown", "PushPowerButton", "Nmi"}) {
		t.Fatalf("reset types %v", caps.ResetTypes())
	}
	assertNoWrites(t, s)
}

func TestProbeIDRAC9(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	caps, err := d.Probe(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	f := caps.Flags()
	if f.RedfishVersion != "1.17.0" || f.BMCFirmware != "7.00.00.182" || f.BMCModel != "14G Monolithic" {
		t.Fatalf("identity: %+v", f)
	}
	if !f.LegacyThermal || !f.ThermalSubsystem || !f.LegacyPower || !f.PowerSubsystem {
		t.Fatalf("schemas: %+v", f)
	}
	if !f.SEL || f.SELSource != "/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries" {
		t.Fatalf("sel: %+v", f)
	}
	if !f.LicenseService || !f.FirmwareInventory || !f.GraphicalConsole || !f.SSH || f.SerialConsole {
		t.Fatalf("features: %+v", f)
	}
	if len(caps.ResetTypes()) != 8 {
		t.Fatalf("reset types %v", caps.ResetTypes())
	}
	assertNoWrites(t, s)
}

func TestProbeWithoutDellFallbackHasNoSELOnIDRAC8(t *testing.T) {
	s := mockFor(t, idrac8)
	caps, err := driverFor(t, s).Probe(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if caps.Flags().SEL || caps.Flags().SELSource != "" {
		t.Fatalf("generic driver should not find the iDRAC8 legacy SEL: %+v", caps.Flags())
	}
}

func TestProbeMissingEndpointsDegrade(t *testing.T) {
	s := mockFor(t, idrac9,
		redfishmock.WithMissing("/redfish/v1/Managers/iDRAC.Embedded.1/LogServices"),
		redfishmock.WithMissing("/redfish/v1/UpdateService/FirmwareInventory"),
		redfishmock.WithMissing("/redfish/v1/Managers/iDRAC.Embedded.1"),
	)
	caps, err := driverFor(t, s).Probe(testCtx(t))
	if err != nil {
		t.Fatalf("missing optional endpoints must not fail the probe: %v", err)
	}
	f := caps.Flags()
	if f.SEL || f.FirmwareInventory || f.GraphicalConsole || f.BMCFirmware != "" {
		t.Fatalf("capabilities should be off: %+v", f)
	}
	if !f.LegacyThermal {
		t.Fatal("chassis capabilities lost")
	}
}

func TestProbeFallsBackToCollectionsWithoutSystemLinks(t *testing.T) {
	sys := `{"@odata.id":"/redfish/v1/Systems/System.Embedded.1","PowerState":"On",
		"Status":{"Health":"OK"},"Links":{}}`
	s := mockFor(t, idrac9,
		redfishmock.WithOverlay("/redfish/v1/Systems/System.Embedded.1", sys),
	)
	d := driverFor(t, s)
	res, err := d.Resources(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Chassis != "/redfish/v1/Chassis/System.Embedded.1" || res.Manager != "/redfish/v1/Managers/iDRAC.Embedded.1" {
		t.Fatalf("resources %+v", res)
	}
	if len(res.LogServices()) != 3 {
		t.Fatalf("log services %v", res.LogServices())
	}
}

func TestProbeWithoutSystemsFails(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithOverlay("/redfish/v1/Systems", collection()))
	_, err := driverFor(t, s).Probe(testCtx(t))
	if err == nil {
		t.Fatal("a service with no ComputerSystem must fail the probe")
	}
}

func TestResourcesAreCachedAndReprobed(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	ctx := testCtx(t)
	if _, err := d.Resources(ctx); err != nil {
		t.Fatal(err)
	}
	n := len(s.Requests())
	if _, err := d.Resources(ctx); err != nil {
		t.Fatal(err)
	}
	if len(s.Requests()) != n {
		t.Fatal("Resources re-probed although a probe result was cached")
	}
	if _, err := d.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	if len(s.Requests()) == n {
		t.Fatal("Probe must refresh the cached discovery")
	}
}

func collection(members ...string) string {
	out := `{"Members":[`
	for i, m := range members {
		if i > 0 {
			out += ","
		}
		out += `{"@odata.id":"` + m + `"}`
	}
	return out + `]}`
}

func TestCapabilitiesUsesCache(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	ctx := testCtx(t)
	caps, err := d.Capabilities(ctx)
	if err != nil || !caps.Flags().LicenseService {
		t.Fatalf("caps %+v err %v", caps.Flags(), err)
	}
	n := len(s.Requests())
	if _, err := d.Capabilities(ctx); err != nil || len(s.Requests()) != n {
		t.Fatalf("second call must use the cache (err %v)", err)
	}
	bad := mockFor(t, idrac9, redfishmock.WithStatus("/redfish/v1/Systems", 500))
	if _, err := driverFor(t, bad).Capabilities(ctx); err == nil {
		t.Fatal("probe failure must surface")
	}
	if _, err := driverFor(t, bad).Resources(ctx); err == nil {
		t.Fatal("probe failure must surface from Resources")
	}
}
