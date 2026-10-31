package redfish

import (
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

func TestInventoryIDRAC8(t *testing.T) {
	s := mockFor(t, idrac8)
	inv, err := driverFor(t, s).Inventory(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	want := bmc.InventoryInfo{
		Manufacturer: "Dell Inc.", Model: "PowerEdge R730xd", SerialNumber: "REDACTED", SKU: "REDACTED",
		BIOSVersion: "2.19.0", BMCModel: "13G Monolithic", BMCFirmware: "2.86.86.86",
		MemoryGiB: 160, ProcessorCount: 2, LogicalProcessors: 56,
		ProcessorModel: "Intel(R) Xeon(R) CPU E5-2660 v4 @ 2.00GHz",
	}
	if inv.Info() != want {
		t.Fatalf("info\n got %+v\nwant %+v", inv.Info(), want)
	}
	// 21 members are listed; only three member resources were captured. The generic
	// driver GETs each member and skips the ones that 404.
	if fw := inv.Firmware(); len(fw) != 3 || fw[2].Name != "PERC H730 Mini" || fw[2].Version != "25.5.9.0001" {
		t.Fatalf("firmware %+v", fw)
	}
	if inv.License().Tier != "" {
		t.Fatalf("generic driver must not invent a licence: %+v", inv.License())
	}
	assertNoWrites(t, s)
}

func TestInventoryIDRAC9TrimsBlankStrings(t *testing.T) {
	s := mockFor(t, idrac9)
	inv, err := driverFor(t, s).Inventory(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	i := inv.Info()
	if i.Model != "" || i.Manufacturer != "" || i.BIOSVersion != "2.20.0" || i.MemoryGiB != 32 ||
		i.ProcessorCount != 1 || i.LogicalProcessors != 12 || i.BMCFirmware != "7.00.00.182" || i.SystemID != "088F" {
		t.Fatalf("info %+v", i)
	}
}

func TestInventoryFetchesFirmwareMembers(t *testing.T) {
	s := mockFor(t, idrac9)
	inv, err := driverFor(t, s).Inventory(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	fw := inv.Firmware()
	if len(fw) != 3 {
		t.Fatalf("want the 3 captured members, got %+v", fw)
	}
	for _, f := range fw {
		if f.ID == "" || f.Name == "" || f.Version == "" {
			t.Fatalf("firmware %+v", f)
		}
	}
}

func TestInventoryFirmwareMemberErrorPropagates(t *testing.T) {
	const m = "/redfish/v1/UpdateService/FirmwareInventory/Current-101555-25.5.9.0001"
	s := mockFor(t, idrac8, redfishmock.WithStatus(m, 500))
	if _, err := driverFor(t, s).Inventory(testCtx(t)); err == nil {
		t.Fatal("want error for a failing firmware member")
	}
}

func TestInventoryUsesFirmwareParserOption(t *testing.T) {
	s := mockFor(t, idrac9)
	var seen int
	parser := func(members []string) ([]bmc.FirmwareItem, bool) {
		seen = len(members)
		return []bmc.FirmwareItem{{Name: "parsed"}}, true
	}
	inv, err := driverFor(t, s, WithFirmwareParser(parser)).Inventory(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if seen != 25 || len(inv.Firmware()) != 1 || inv.Firmware()[0].Name != "parsed" {
		t.Fatalf("seen %d fw %+v", seen, inv.Firmware())
	}
	for _, r := range s.Requests() {
		if len(r.Path) > len("/redfish/v1/UpdateService/FirmwareInventory/") &&
			r.Path[:len("/redfish/v1/UpdateService/FirmwareInventory/")] == "/redfish/v1/UpdateService/FirmwareInventory/" {
			t.Fatalf("parser path must not GET members: %s", r.Path)
		}
	}
}

func TestInventoryWithoutFirmwareInventory(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithMissing("/redfish/v1/UpdateService/FirmwareInventory"))
	inv, err := driverFor(t, s).Inventory(testCtx(t))
	if err != nil || len(inv.Firmware()) != 0 {
		t.Fatalf("err %v fw %+v", err, inv.Firmware())
	}
}

func TestMembersHelper(t *testing.T) {
	s := mockFor(t, idrac9)
	ms, err := driverFor(t, s).Members(testCtx(t), "/redfish/v1/LicenseService/Licenses")
	if err != nil || len(ms) != 2 {
		t.Fatalf("err %v members %v", err, ms)
	}
}

func TestDellSystemID(t *testing.T) {
	cases := map[string]string{
		`{"Dell":{"DellSystem":{"SystemID":2191}}}`: "088F", `{"Dell":{"DellSystem":{"SystemID":0}}}`: "",
		`{"Dell":{"DellSystem":{"SystemID":70000}}}`: "", `{"Dell":{"DellSystem":{"SystemID":"x"}}}`: "",
		`{"Other":{}}`: "", `not json`: "", ``: "",
	}
	for in, want := range cases {
		if got := dellSystemID([]byte(in)); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}
