package dellredfish

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/firmware"
)

const fwInv = "/redfish/v1/UpdateService/FirmwareInventory"

func synthetic(t *testing.T, fixture string) redfishmock.Option {
	t.Helper()
	return redfishmock.WithExtraFixtures(redfishmock.FixtureDir(t, filepath.Join("synthetic-firmware", fixture)))
}

func memberGETs(s *redfishmock.Server) []string {
	var out []string
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Path, fwInv+"/") {
			out = append(out, strings.TrimPrefix(r.Path, fwInv+"/"))
		}
	}
	return out
}

func components(t *testing.T, scan bmc.FirmwareScan) map[firmware.Key]firmware.Component {
	t.Helper()
	out := map[firmware.Key]firmware.Component{}
	for _, c := range firmware.Merge(scan.Items()) {
		out[c.Key] = c
	}
	return out
}

func TestScanFirmwareIDRAC8(t *testing.T) {
	d, s := newDriver(t, idrac8, synthetic(t, idrac8))
	scan, err := d.ScanFirmware(ctx(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Items()) != 21 || scan.Listed() != 21 || !scan.Complete() || scan.DocsFailed() != 0 {
		t.Fatalf("items %d listed %d complete %v failed %d", len(scan.Items()), scan.Listed(), scan.Complete(), scan.DocsFailed())
	}
	// One document per component (15 of them), from the running state's member: no
	// Previous- member is read.
	gets := memberGETs(s)
	if len(gets) != 15 || scan.DocsRead() != 15 {
		t.Fatalf("member GETs %d (%v), read %d", len(gets), gets, scan.DocsRead())
	}
	for _, g := range gets {
		if !strings.HasPrefix(g, "Installed-") {
			t.Errorf("read %s: the running state's document is enough", g)
		}
	}
	cs := components(t, scan)
	cases := []struct {
		id   string
		name string
		kind bmc.FirmwareKind
	}{
		{"101434", "Backplane 0", bmc.FirmwareEnclosure},
		{"101068", "BP13G+EXP 0:1", bmc.FirmwareEnclosure},
		{"101555", "PERC H730 Mini", bmc.FirmwareStorage},
		{"159", "BIOS", bmc.FirmwareBIOS},
		{"25227", "Integrated Dell Remote Access Controller", bmc.FirmwareBMC},
		{"28897", "Lifecycle Controller", bmc.FirmwareLC},
		{"101095", "Disk 0 in Backplane 0 of Integrated RAID Controller 1", bmc.FirmwareDrive},
		{"102302", "Intel(R) Ethernet 10G 2P X520 Adapter - 00:00:5E:00:53:10", bmc.FirmwareNIC},
		{"103710", "Power Supply.Slot.1", bmc.FirmwarePSU},
	}
	for _, c := range cases {
		got := cs[firmware.Key{ComponentID: c.id}]
		if got.Name != c.name || !got.Named || got.Kind != c.kind {
			t.Errorf("%s: %+v", c.id, got)
		}
	}
	bp := cs[firmware.Key{ComponentID: "101434"}]
	if bp.Running != "2.23" || bp.Stored != "2.25" || !bp.NotApplied() || !bp.ReleaseDate.IsZero() {
		t.Errorf("iDRAC8 backplane runs 2.23 and holds 2.25, no release dates: %+v", bp)
	}
	if bios := cs[firmware.Key{ComponentID: "159"}]; bios.Running != "2.19.0" || bios.Previous != "2.18.1" {
		t.Errorf("bios %+v", bios)
	}
	assertOnlyGETs(t, s)
}

func TestScanFirmwareIDRAC9(t *testing.T) {
	d, s := newDriver(t, idrac9, synthetic(t, idrac9))
	scan, err := d.ScanFirmware(ctx(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := components(t, scan)
	nic := cs[firmware.Key{ComponentID: "105897", FQDD: "NIC.Embedded.1-1-1"}]
	if nic.Name != "Broadcom Gigabit Ethernet BCM5720 - 00:00:5E:00:53:00" || nic.Kind != bmc.FirmwareNIC ||
		!nic.ReleaseDate.Equal(time.Date(2025, 9, 27, 0, 0, 0, 0, time.UTC)) || nic.Identity != "DCIM:firmware:14E4:165F:1028:088F" {
		t.Errorf("nic %+v", nic)
	}
	if n2 := cs[firmware.Key{ComponentID: "105897", FQDD: "NIC.Embedded.2-1-1"}]; n2.Running != "23.31.1" || !n2.Named {
		t.Errorf("second embedded NIC %+v", n2)
	}
	// Members whose FQDD holds ":" have no document in the fixtures: the scan keeps their
	// ID-derived version, the known name and the FQDD's kind.
	diag := cs[firmware.Key{ComponentID: "25806", FQDD: "Diagnostics.Embedded.1:LC.Embedded.1"}]
	if diag.Named || diag.Name != "Diagnostics" || diag.Kind != bmc.FirmwareLC || diag.Running != "4301A73" {
		t.Errorf("diagnostics %+v", diag)
	}
	disk := cs[firmware.Key{ComponentID: "106864", FQDD: "Disk.Direct.0-0:AHCI.Slot.1-1"}]
	if disk.Kind != bmc.FirmwareDrive || disk.Running != "E013" {
		t.Errorf("disk %+v", disk)
	}
	if boss := cs[firmware.Key{ComponentID: "106883", FQDD: "AHCI.Slot.1-1"}]; boss.Kind != bmc.FirmwareStorage || boss.Name != "BOSS-S1 Adapter" {
		t.Errorf("boss %+v", boss)
	}
	if pm := cs[firmware.Key{ComponentID: "105048", FQDD: "PM.Embedded.1"}]; pm.Kind != bmc.FirmwareOther || pm.Name != "PM.Embedded.1" {
		t.Errorf("an unknown FQDD is other, named by its FQDD: %+v", pm)
	}
	idrac := cs[firmware.Key{ComponentID: "25227", FQDD: "iDRAC.Embedded.1-1"}]
	if idrac.Kind != bmc.FirmwareBMC || idrac.Running != "7.00.00.182" || idrac.Previous != "3.34.34.34" || idrac.ReleaseDate.IsZero() {
		t.Errorf("idrac %+v", idrac)
	}
	if scan.DocsFailed() != 0 || !scan.Complete() || scan.Listed() != 25 {
		t.Errorf("failed %d complete %v listed %d", scan.DocsFailed(), scan.Complete(), scan.Listed())
	}
	assertOnlyGETs(t, s)
}

func TestScanFirmwareReadsOnlyWhatIsNeeded(t *testing.T) {
	d, s := newDriver(t, idrac8, synthetic(t, idrac8))
	var asked []bmc.FirmwareItem
	scan, err := d.ScanFirmware(ctx(t), func(it bmc.FirmwareItem) bool {
		asked = append(asked, it)
		return it.ComponentID == "159"
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 21 || asked[0].ComponentID == "" {
		t.Fatalf("need sees every ID-derived item: %d", len(asked))
	}
	if gets := memberGETs(s); len(gets) != 1 || gets[0] != "Installed-159-2.19.0" || scan.DocsRead() != 1 {
		t.Fatalf("GETs %v", gets)
	}
	before := len(s.Requests())
	if _, err := d.ScanFirmware(ctx(t), func(bmc.FirmwareItem) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if extra := memberGETs(s)[1:]; len(extra) != 0 || len(s.Requests())-before != 1 {
		t.Fatalf("a scan with every name known is one GET (the collection): %v", s.Requests()[before:])
	}
}

func TestScanFirmwareSyntheticOverlays(t *testing.T) {
	const avail = fwInv + "/Available-159-2.21.0"
	members := `{"Members":[{"@odata.id":"` + fwInv + `/Current-159-2.19.0"},{"@odata.id":"` + avail + `"},` +
		`{"@odata.id":"` + fwInv + `/Current-999-1.0"},{"@odata.id":"` + fwInv + `/Current-998-1.0"}],"Members@odata.count":4}`
	d, _ := newDriver(t, idrac8,
		redfishmock.WithOverlay(fwInv, members),
		redfishmock.WithOverlay(fwInv+"/Current-999-1.0", `{"Id":"Current-999-1.0","Version":"1.0","Updateable":true}`), // no Name
		redfishmock.WithStatus(fwInv+"/Current-998-1.0", 500),
		redfishmock.WithOverlay(fwInv+"/Current-159-2.19.0", `{"Id":"x","Name":7}`), // undecodable
	)
	scan, err := d.ScanFirmware(ctx(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := components(t, scan)
	bios := cs[firmware.Key{ComponentID: "159"}]
	if bios.Running != "2.19.0" || bios.Staged != "2.21.0" || bios.Named || bios.Name != "BIOS" || bios.Kind != bmc.FirmwareBIOS {
		t.Errorf("staged image and an undecodable document: %+v", bios)
	}
	if u := cs[firmware.Key{ComponentID: "999"}]; u.Named || u.Name != "Component 999" || !u.Updateable {
		t.Errorf("document without a name: %+v", u)
	}
	if scan.DocsFailed() != 2 || len(scan.Items()) != 4 || !scan.Complete() {
		t.Errorf("failed %d items %d complete %v", scan.DocsFailed(), len(scan.Items()), scan.Complete())
	}
}

func TestScanFirmwareUnknownIDFormatFallsBack(t *testing.T) {
	members := `{"Members":[{"@odata.id":"` + fwInv + `/Odd"}],"Members@odata.count":1}`
	d, _ := newDriver(t, idrac9, redfishmock.WithOverlay(fwInv, members),
		redfishmock.WithOverlay(fwInv+"/Odd", `{"Id":"Odd","Name":"Odd thing","Version":"1"}`))
	scan, err := d.ScanFirmware(ctx(t), nil)
	if err != nil || len(scan.Items()) != 1 || scan.Items()[0].Name != "Odd thing" {
		t.Fatalf("generic fallback: %+v %v", scan.Items(), err)
	}
}

func TestDellKind(t *testing.T) {
	cases := []struct {
		comp, fqdd, ctype, name string
		want                    bmc.FirmwareKind
	}{
		{"1", "iDRAC.Embedded.1-1", "", "", bmc.FirmwareBMC},
		{"1", "BIOS.Setup.1-1", "", "", bmc.FirmwareBIOS},
		{"1", "CPLD.Embedded.1", "", "", bmc.FirmwareCPLD},
		{"1", "NIC.Slot.2-1-1", "", "", bmc.FirmwareNIC},
		{"1", "RAID.Integrated.1-1", "", "", bmc.FirmwareStorage},
		{"1", "NonRAID.Slot.3-1", "", "", bmc.FirmwareStorage},
		{"1", "Disk.Bay.0:Enclosure.Internal.0-1:RAID.Integrated.1-1", "", "", bmc.FirmwareDrive},
		{"1", "Enclosure.Internal.0-1:RAID.Integrated.1-1", "", "", bmc.FirmwareEnclosure},
		{"1", "PSU.Slot.1", "", "", bmc.FirmwarePSU},
		{"1", "USC.Embedded.1:LC.Embedded.1", "", "", bmc.FirmwareLC},
		{"1", "ServiceModule.Embedded.1", "", "", bmc.FirmwareLC},
		{"159", "", "", "", bmc.FirmwareBIOS},
		{"25227", "", "", "", bmc.FirmwareBMC},
		{"28897", "", "", "", bmc.FirmwareLC},
		{"27763", "", "", "", bmc.FirmwareCPLD},
		{"104684", "", "", "", bmc.FirmwareLC},
		{"1", "", "BIOS", "", bmc.FirmwareBIOS},
		{"1", "", "APAC", "", bmc.FirmwareLC},
		{"1", "", "FRMW", "PERC H330", bmc.FirmwareStorage},
		{"1", "", "", "Dell HBA330 Mini", bmc.FirmwareStorage},
		{"1", "", "", "BP14G+ 0:1", bmc.FirmwareEnclosure},
		{"1", "", "", "iDRAC Service Module", bmc.FirmwareBMC},
		{"1", "", "", "Lifecycle Controller", bmc.FirmwareLC},
		{"1", "", "", "Broadcom NetXtreme", ""},
		{"1", "", "", "Broadcom Gigabit Ethernet", bmc.FirmwareNIC},
	}
	for _, c := range cases {
		if got := dellKind(c.comp, c.fqdd, c.ctype, c.name); got != c.want {
			t.Errorf("dellKind(%q, %q, %q, %q) = %q, want %q", c.comp, c.fqdd, c.ctype, c.name, got, c.want)
		}
	}
}

func assertOnlyGETs(t *testing.T, s *redfishmock.Server) {
	t.Helper()
	if n := s.OtherWrites(); n != 0 {
		t.Fatalf("writes sent: %+v", s.Requests())
	}
	for _, r := range s.Requests() {
		if strings.Contains(r.Path, "UpdateService") && r.Method != "GET" {
			t.Fatalf("non-GET firmware request %+v", r)
		}
	}
}
