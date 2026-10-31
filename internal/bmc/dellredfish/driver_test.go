package dellredfish

import (
	"context"
	"errors"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/secrets"
)

const (
	idrac8 = "idrac8-r730xd"
	idrac9 = "idrac9-r240"

	licenses   = "/redfish/v1/LicenseService/Licenses"
	licMember1 = licenses + "/EvaluationLicense"
	licMember2 = licenses + "/ProductionLicense"
	lcLog9     = "/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Lclog/Entries"
	lcLog8     = "/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Lclog"
)

var _ bmc.Driver = (*Driver)(nil)

func newDriver(t *testing.T, fixture string, opts ...redfishmock.Option) (*Driver, *redfishmock.Server) {
	t.Helper()
	s := redfishmock.New(t, redfishmock.FixtureDir(t, fixture), opts...)
	d, err := New(redfish.Config{
		Endpoint: s.URL(), Username: redfishmock.User, Password: redfishmock.Password,
		PinSHA256: s.PinSHA256(), Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, s
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(redfish.Config{Endpoint: "http://x"}); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestIDRAC8SELViaLegacyPath(t *testing.T) {
	d, s := newDriver(t, idrac8)
	caps, err := d.Probe(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if f := caps.Flags(); !f.SEL || f.SELSource != "/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Sel" {
		t.Fatalf("sel flags %+v", f)
	}
	log, err := d.EventLog(ctx(t), time.Time{})
	if err != nil || log.Len() != 15 {
		t.Fatalf("err %v len %d", err, log.Len())
	}
	snap, err := d.Snapshot(ctx(t))
	if err != nil || len(snap.Temperatures()) != 4 || len(snap.Fans()) != 6 || len(snap.PSUs()) != 2 {
		t.Fatalf("snapshot err %v", err)
	}
	if s.OtherWrites() != 0 {
		t.Fatalf("writes sent: %+v", s.Requests())
	}
}

func TestIDRAC9SELUsesStandardPath(t *testing.T) {
	d, _ := newDriver(t, idrac9)
	log, err := d.EventLog(ctx(t), time.Time{})
	if err != nil || log.Len() != 1 || log.Source() != "/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries" {
		t.Fatalf("err %v len %d src %s", err, log.Len(), log.Source())
	}
}

func TestLicenseIDRAC8IsUnknownWithGraphicalConsoleHint(t *testing.T) {
	d, _ := newDriver(t, idrac8)
	lic, err := d.License(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	want := bmc.License{Tier: bmc.LicenseUnknown, Source: SourceUnavailable, GraphicalConsole: true}
	if lic != want {
		t.Fatalf("got %+v want %+v", lic, want)
	}
}

func TestLicenseIDRAC9EnterpriseFromFixtures(t *testing.T) {
	// Real captures: an expired "Enterprise Evaluation" trial and the perpetual
	// "Enterprise" production licence. Equal tiers: the production licence wins.
	d, _ := newDriver(t, idrac9)
	inv, err := d.Inventory(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	lic := inv.License()
	want := bmc.License{Tier: bmc.LicenseEnterprise, Source: SourceLicenseService,
		Description: "iDRAC9 Enterprise License", GraphicalConsole: true}
	if lic != want {
		t.Fatalf("licence\n got %+v\nwant %+v", lic, want)
	}
}

func TestLicenseTrialOnlyStillReportsTier(t *testing.T) {
	d, _ := newDriver(t, idrac9, redfishmock.WithMissing(licMember2))
	lic, err := d.License(ctx(t))
	if err != nil || lic.Tier != bmc.LicenseEnterprise || lic.Description != "iDRAC9 Enterprise Evaluation License" {
		t.Fatalf("err %v lic %+v", err, lic)
	}
}

func TestLicenseMembersMissingIsUnknown(t *testing.T) {
	d, _ := newDriver(t, idrac9, redfishmock.WithMissing(licMember1), redfishmock.WithMissing(licMember2))
	lic, err := d.License(ctx(t))
	if err != nil || lic.Tier != bmc.LicenseUnknown || lic.Source != SourceLicenseService || !lic.GraphicalConsole {
		t.Fatalf("err %v lic %+v", err, lic)
	}
}

func TestLicenseUsesLicenseServiceLink(t *testing.T) {
	const alt = "/redfish/v1/LicenseService/AltLicenses"
	d, _ := newDriver(t, idrac9,
		redfishmock.WithOverlay("/redfish/v1/LicenseService", `{"Licenses":{"@odata.id":"`+alt+`"}}`),
		redfishmock.WithOverlay(alt, `{"Members":[{"@odata.id":"`+alt+`/1"}]}`),
		redfishmock.WithOverlay(alt+"/1", `{"Name":"iDRAC9 Datacenter License"}`),
	)
	lic, err := d.License(ctx(t))
	if err != nil || lic.Tier != bmc.LicenseDatacenter {
		t.Fatalf("err %v lic %+v", err, lic)
	}
}

func TestLicenseErrorsPropagate(t *testing.T) {
	d, _ := newDriver(t, idrac9, redfishmock.WithStatus(licMember1, 500))
	if _, err := d.License(ctx(t)); !errors.Is(err, bmc.ErrBMC) {
		t.Fatalf("want ErrBMC, got %v", err)
	}
	if _, err := d.Inventory(ctx(t)); !errors.Is(err, bmc.ErrBMC) {
		t.Fatalf("inventory: want ErrBMC, got %v", err)
	}
}

func TestLicenseCollectionMissing(t *testing.T) {
	d, _ := newDriver(t, idrac9, redfishmock.WithMissing(licenses))
	lic, err := d.License(ctx(t))
	if err != nil || lic.Tier != bmc.LicenseUnknown || lic.Source != SourceLicenseService {
		t.Fatalf("err %v lic %+v", err, lic)
	}
}

func TestInventoryFirmwareFromMemberIDs(t *testing.T) {
	d, s := newDriver(t, idrac8)
	inv, err := d.Inventory(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	fw := inv.Firmware()
	if len(fw) != 21 {
		t.Fatalf("want 21 firmware items, got %d", len(fw))
	}
	idrac := findFW(t, fw, "Installed", "25227")
	if idrac.Name != "iDRAC" || idrac.Version != "2.86.86.86" {
		t.Fatalf("idrac %+v", idrac)
	}
	if bios := findFW(t, fw, "Installed", "159"); bios.Name != "BIOS" || bios.Version != "2.19.0" {
		t.Fatalf("bios %+v", bios)
	}
	if prev := findFW(t, fw, "Previous", "25227"); prev.Version != "2.85.85.85" {
		t.Fatalf("previous idrac %+v", prev)
	}
	if inv.Info().BMCFirmware != "2.86.86.86" || inv.License().Source != SourceUnavailable {
		t.Fatalf("info %+v lic %+v", inv.Info(), inv.License())
	}
	for _, r := range s.Requests() {
		if len(r.Path) > len(fwPrefix) && r.Path[:len(fwPrefix)] == fwPrefix {
			t.Fatalf("Dell inventory must not GET firmware members: %s", r.Path)
		}
	}
}

const fwPrefix = "/redfish/v1/UpdateService/FirmwareInventory/"

func TestInventoryFirmwareIDRAC9FQDDs(t *testing.T) {
	d, _ := newDriver(t, idrac9)
	inv, err := d.Inventory(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	fw := inv.Firmware()
	if len(fw) != 25 {
		t.Fatalf("want 25, got %d", len(fw))
	}
	idrac := findFW(t, fw, "Installed", "25227")
	if idrac.Version != "7.00.00.182" || idrac.FQDD != "iDRAC.Embedded.1-1" || idrac.Name != "iDRAC" {
		t.Fatalf("idrac %+v", idrac)
	}
	nic := findFW(t, fw, "Installed", "102301")
	if nic.Name != "NIC.Slot.2-1-1" || nic.Version != "23.0.8" {
		t.Fatalf("nic %+v", nic)
	}
	disk := findFW(t, fw, "Installed", "106864")
	if disk.FQDD != "Disk.Direct.0-0:AHCI.Slot.1-1" || disk.Version != "E013" {
		t.Fatalf("disk %+v", disk)
	}
}

func TestLifecycleLogIDRAC9(t *testing.T) {
	d, _ := newDriver(t, idrac9)
	log, err := d.LifecycleLog(ctx(t), time.Time{})
	if err != nil || log.Len() != 15 || log.Source() != lcLog9 {
		t.Fatalf("err %v len %d src %s", err, log.Len(), log.Source())
	}
	// Members@odata.count is 2090 but only the first page was captured.
	if log.Complete() {
		t.Fatal("a truncated capture must be reported incomplete")
	}
	if e := log.Entries()[0]; e.MessageID == "" || e.Message == "" {
		t.Fatalf("entry %+v", e)
	}
}

func TestLifecycleLogIDRAC8LegacyPath(t *testing.T) {
	d, _ := newDriver(t, idrac8)
	log, err := d.LifecycleLog(ctx(t), time.Time{})
	if err != nil || log.Len() != 15 || log.Source() != lcLog8 {
		t.Fatalf("err %v len %d src %s", err, log.Len(), log.Source())
	}
}

func TestLifecycleLogMissingIsUnsupported(t *testing.T) {
	d, _ := newDriver(t, idrac9, redfishmock.WithMissing(lcLog9),
		redfishmock.WithMissing("/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Lclog"))
	if _, err := d.LifecycleLog(ctx(t), time.Time{}); !errors.Is(err, bmc.ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
}

func TestLifecycleLogServerErrorPropagates(t *testing.T) {
	d, _ := newDriver(t, idrac9, redfishmock.WithStatus(lcLog9, 503))
	if _, err := d.LifecycleLog(ctx(t), time.Time{}); !errors.Is(err, bmc.ErrBMC) {
		t.Fatalf("want ErrBMC, got %v", err)
	}
}

func TestProbeFailurePropagates(t *testing.T) {
	d, _ := newDriver(t, idrac9, redfishmock.WithStatus("/redfish/v1/Systems", 500))
	if _, err := d.License(ctx(t)); err == nil {
		t.Fatal("License: want error")
	}
	if _, err := d.LifecycleLog(ctx(t), time.Time{}); err == nil {
		t.Fatal("LifecycleLog: want error")
	}
	if _, err := d.Inventory(ctx(t)); err == nil {
		t.Fatal("Inventory: want error")
	}
}

func findFW(t *testing.T, fw []bmc.FirmwareItem, state, comp string) bmc.FirmwareItem {
	t.Helper()
	for _, f := range fw {
		if f.State == state && f.ComponentID == comp {
			return f
		}
	}
	t.Fatalf("firmware %s-%s not found", state, comp)
	return bmc.FirmwareItem{}
}

func TestCloseAndCredentialChangeDelegate(t *testing.T) {
	d, s := newDriver(t, idrac9)
	if _, err := d.Probe(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if err := d.SetCredentials(ctx(t), redfishmock.User, secrets.New(redfishmock.Password)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Probe(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if st := s.SessionStats(); st.Created != 2 || st.Deleted != 2 || s.LiveSessions() != 0 {
		t.Fatalf("stats %+v", st)
	}
}
