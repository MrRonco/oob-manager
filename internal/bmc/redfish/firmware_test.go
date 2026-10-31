package redfish

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

const fwInventory = "/redfish/v1/UpdateService/FirmwareInventory"

func TestScanFirmwareGeneric(t *testing.T) {
	s := mockFor(t, idrac9)
	called := 0
	scan, err := driverFor(t, s).ScanFirmware(testCtx(t), func(bmc.FirmwareItem) bool { called++; return false })
	if err != nil {
		t.Fatal(err)
	}
	// 25 members are listed; three member documents exist, the others answer 404 and
	// are left out, so the scan cannot claim to be complete.
	items := scan.Items()
	if len(items) != 3 || scan.Listed() != 25 || scan.Complete() || scan.DocsRead() != 3 || scan.DocsFailed() != 0 {
		t.Fatalf("scan %d items listed %d complete %v read %d failed %d", len(items), scan.Listed(), scan.Complete(),
			scan.DocsRead(), scan.DocsFailed())
	}
	if called != 0 {
		t.Fatal("the generic driver reads every document: need is not consulted")
	}
	var nic bmc.FirmwareItem
	for _, it := range items {
		if strings.HasPrefix(it.ID, "Current-105897") {
			nic = it
		}
	}
	want := time.Date(2025, 9, 27, 0, 0, 0, 0, time.UTC)
	if nic.Name != "Broadcom Gigabit Ethernet BCM5720 - 00:00:5E:00:53:00" || !nic.Named || !nic.Detailed ||
		nic.Version != "23.31.1" || !nic.ReleaseDate.Equal(want) || !nic.Updateable || nic.Kind != bmc.FirmwareNIC {
		t.Fatalf("nic %+v", nic)
	}
	assertOnlyGETs(t, s)
}

func TestScanFirmwareGenericDocuments(t *testing.T) {
	members := `{"Members":[{"@odata.id":"` + fwInventory + `/bmc"},{"@odata.id":"` + fwInventory + `/bad"},` +
		`{"@odata.id":"` + fwInventory + `/odd"}],"Members@odata.count":3}`
	s := mockFor(t, idrac9,
		redfishmock.WithOverlay(fwInventory, members),
		redfishmock.WithOverlay(fwInventory+"/bmc", `{"Id":"bmc","Name":"  Main\u202e BMC ","Version":"1.2.3",
			"ReleaseDate":"not a date","Updateable":false,"RelatedItem":[{"@odata.id":"/redfish/v1/Managers/1"}]}`),
		redfishmock.WithOverlay(fwInventory+"/bad", `{"Id":"bad","Version":7}`),
		redfishmock.WithOverlay(fwInventory+"/odd", `{"Id":"odd","Name":"","Version":"`+strings.Repeat("9", 100)+`"}`),
	)
	scan, err := driverFor(t, s).ScanFirmware(testCtx(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	items := scan.Items()
	if len(items) != 2 || scan.Complete() || scan.DocsFailed() != 1 || scan.Listed() != 3 {
		t.Fatalf("scan %+v complete %v failed %d", items, scan.Complete(), scan.DocsFailed())
	}
	b := items[0]
	if b.Name != "Main BMC" || b.Kind != bmc.FirmwareBMC || !b.ReleaseDate.IsZero() || b.Updateable {
		t.Fatalf("bmc item %+v (BMC text is cleaned, a bad date is unknown)", b)
	}
	if o := items[1]; o.Named || len(o.Version) != maxVersionLen || o.Kind != "" {
		t.Fatalf("odd item %+v", o)
	}
}

func TestScanFirmwareAbsentAndCapped(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithMissing(fwInventory))
	scan, err := driverFor(t, s).ScanFirmware(testCtx(t), nil)
	if err != nil || len(scan.Items()) != 0 || !scan.Complete() {
		t.Fatalf("absent inventory: %+v %v", scan, err)
	}
	var b strings.Builder
	b.WriteString(`{"Members":[`)
	for i := range 70 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"@odata.id":"%s/m%d"}`, fwInventory, i)
	}
	b.WriteString(`],"Members@odata.count":70}`)
	s = mockFor(t, idrac9, redfishmock.WithOverlay(fwInventory, b.String()))
	scan, err = driverFor(t, s).ScanFirmware(testCtx(t), nil)
	if err != nil || scan.Listed() != 70 || scan.Complete() {
		t.Fatalf("capped scan listed %d complete %v err %v", scan.Listed(), scan.Complete(), err)
	}
	gets := 0
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Path, fwInventory+"/m") {
			gets++
		}
	}
	if gets != MaxFirmwareMembers {
		t.Fatalf("%d member GETs, want the cap %d", gets, MaxFirmwareMembers)
	}
}

func TestScanFirmwareBudget(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithDelay(fwInventory+"/Current-102302-23.0.8__NIC.Slot.2-2-1", 2*time.Second))
	d := driverFor(t, s)
	if _, err := d.Probe(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	scan, err := d.ScanFirmware(ctx, nil)
	if err != nil {
		t.Fatalf("a scan cut by its budget keeps what it read: %v", err)
	}
	if scan.Complete() || len(scan.Items()) == 0 {
		t.Fatalf("scan %+v complete %v", scan.Items(), scan.Complete())
	}
}

func TestScanFirmwareListFailure(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithStatus(fwInventory, 500))
	if _, err := driverFor(t, s).ScanFirmware(testCtx(t), nil); err == nil {
		t.Fatal("a collection that cannot be read is an error")
	}
}

// assertOnlyGETs: the firmware scan reads; besides the session login and logout it
// sends nothing but GET (rule 11: it never updates firmware).
func assertOnlyGETs(t *testing.T, s *redfishmock.Server) {
	t.Helper()
	assertNoWrites(t, s)
	for _, r := range s.Requests() {
		if strings.Contains(r.Path, "UpdateService") && r.Method != "GET" {
			t.Fatalf("non-GET firmware request %+v", r)
		}
	}
}
