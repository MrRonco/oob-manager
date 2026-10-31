package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func fwComp(server, id, running string, at time.Time) FirmwareComponentRow {
	return FirmwareComponentRow{ServerID: server, ComponentID: id, Kind: "bios", Name: "BIOS", Named: true, Running: running,
		FirstSeen: at, LastSeen: at}
}

func TestFirmwareReplaceAndRead(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Firmware()
	rel := t0.Add(-400 * 24 * time.Hour)
	a := fwComp("srv-a", "159", "2.19.0", t0)
	a.Previous, a.Staged, a.Stored, a.ReleaseDate, a.Updateable, a.Identity, a.DocReadAt =
		"2.18.1", "2.20.0", "2.18.9", rel, true, "DCIM:x", t0
	nic := fwComp("srv-a", "105897", "23.31.1", t0)
	nic.FQDD, nic.Kind, nic.Named = "NIC.Embedded.1-1-1", "nic", false
	scan := FirmwareScanRow{ServerID: "srv-a", ScannedAt: t0, Listed: 21, Components: 2, Complete: true, DocsRead: 2, DocsFailed: 1,
		Model: "PowerEdge R730xd", SystemID: "0627"}
	if err := r.ReplaceServer(ctx, scan, []FirmwareComponentRow{a, nic}, nil); err != nil {
		t.Fatal(err)
	}
	b := fwComp("srv-b", "25227", "7.00.00.182", t0)
	b.Kind = "bmc"
	if err := r.ReplaceServer(ctx, FirmwareScanRow{ServerID: "srv-b", ScannedAt: t0, Listed: 1, Components: 1},
		[]FirmwareComponentRow{b}, nil); err != nil {
		t.Fatal(err)
	}
	comps, err := r.Components(ctx)
	if err != nil || len(comps) != 3 {
		t.Fatalf("components %+v %v", comps, err)
	}
	if got := comps[1]; got != a {
		t.Fatalf("round trip\n got %+v\nwant %+v", got, a)
	}
	if got := comps[0]; got != nic || !got.ReleaseDate.IsZero() || !got.DocReadAt.IsZero() {
		t.Fatalf("nic %+v", got)
	}
	// A second scan replaces the server's rows and appends its changes.
	next := a
	next.Running, next.Previous, next.LastSeen = "2.20.0", "2.19.0", t0.Add(time.Hour)
	ch := []FirmwareChangeRow{
		{ServerID: "srv-a", ComponentID: "159", Name: "BIOS", Field: "running", Before: "2.19.0", After: "2.20.0", SeenAt: t0.Add(time.Hour)},
		{ServerID: "srv-a", ComponentID: "159", Name: "BIOS", Field: "previous", Before: "2.18.1", After: "2.19.0", SeenAt: t0.Add(time.Hour)},
		{ServerID: "srv-a", ComponentID: "105897", FQDD: "NIC.Embedded.1-1-1", Field: "running", Before: "23.31.1", After: "", SeenAt: t0.Add(time.Hour)},
	}
	scan.ScannedAt, scan.Components = t0.Add(time.Hour), 1
	if err = r.ReplaceServer(ctx, scan, []FirmwareComponentRow{next}, ch); err != nil {
		t.Fatal(err)
	}
	comps, _ = r.Components(ctx)
	if len(comps) != 2 || comps[0].Running != "2.20.0" || comps[1].ServerID != "srv-b" {
		t.Fatalf("after replace %+v", comps)
	}
	scans, err := r.Scans(ctx)
	if err != nil || len(scans) != 2 || scans[0].Components != 1 || !scans[0].ScannedAt.Equal(t0.Add(time.Hour)) ||
		!scans[0].Complete || scans[0].DocsFailed != 1 || scans[1].Complete || scans[0].Model != "PowerEdge R730xd" ||
		scans[0].SystemID != "0627" || scans[1].SystemID != "" {
		t.Fatalf("scans %+v %v", scans, err)
	}
	got, err := r.Changes(ctx, "srv-a", 2)
	if err != nil || len(got) != 2 || got[0].ComponentID != "105897" || got[0].After != "" || got[1].Field != "previous" {
		t.Fatalf("changes %+v %v", got, err)
	}
	if _, err := r.Changes(ctx, "srv-a", 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("limit 0: %v", err)
	}
	if n, err := r.PruneChanges(ctx, t0.Add(2*time.Hour)); err != nil || n != 3 {
		t.Fatalf("prune %d %v", n, err)
	}
	if err := r.DeleteServer(ctx, "srv-a"); err != nil {
		t.Fatal(err)
	}
	comps, _ = r.Components(ctx)
	scans, _ = r.Scans(ctx)
	if len(comps) != 1 || len(scans) != 1 || comps[0].ServerID != "srv-b" {
		t.Fatalf("after delete %+v %+v", comps, scans)
	}
}

func TestFirmwareReplaceRefusesForeignRows(t *testing.T) {
	db := newTestDB(t)
	r := db.Firmware()
	ctx := context.Background()
	scan := FirmwareScanRow{ServerID: "srv-a", ScannedAt: t0}
	if err := r.ReplaceServer(ctx, scan, []FirmwareComponentRow{fwComp("srv-b", "1", "1", t0)}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign component: %v", err)
	}
	if err := r.ReplaceServer(ctx, scan, nil, []FirmwareChangeRow{{ServerID: "srv-b", ComponentID: "1", Field: "running",
		After: "1", SeenAt: t0}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign change: %v", err)
	}
}

func TestFirmwareSchemaChecks(t *testing.T) {
	db := newTestDB(t)
	r := db.Firmware()
	ctx := context.Background()
	scan := FirmwareScanRow{ServerID: "srv-a", ScannedAt: t0}
	bad := []FirmwareComponentRow{
		func() FirmwareComponentRow { c := fwComp("srv-a", "1", "1", t0); c.Kind = "cpu"; return c }(),
		func() FirmwareComponentRow { c := fwComp("srv-a", "1", strings.Repeat("9", 65), t0); return c }(),
		func() FirmwareComponentRow { c := fwComp("srv-a", "", "1", t0); return c }(),
		func() FirmwareComponentRow {
			c := fwComp("srv-a", "1", "1", t0)
			c.LastSeen = t0.Add(-time.Second)
			return c
		}(),
	}
	for i, c := range bad {
		if err := r.ReplaceServer(ctx, scan, []FirmwareComponentRow{c}, nil); err == nil {
			t.Errorf("bad row %d accepted", i)
		}
	}
	same := FirmwareChangeRow{ServerID: "srv-a", ComponentID: "1", Field: "running", Before: "1", After: "1", SeenAt: t0}
	if err := r.ReplaceServer(ctx, scan, nil, []FirmwareChangeRow{same}); err == nil {
		t.Error("a change that changes nothing was accepted")
	}
	if comps, _ := r.Components(ctx); len(comps) != 0 {
		t.Fatalf("a refused replace left rows: %+v", comps)
	}
}

func TestFirmwareInTx(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.Firmware().ReplaceServer(ctx, FirmwareScanRow{ServerID: "srv-a", ScannedAt: t0},
			[]FirmwareComponentRow{fwComp("srv-a", "1", "1", t0)}, nil); err != nil {
			return err
		}
		return errors.New("roll back")
	})
	if err == nil {
		t.Fatal("expected the callback error")
	}
	if comps, _ := db.Firmware().Components(ctx); len(comps) != 0 {
		t.Fatalf("rolled-back rows stayed: %+v", comps)
	}
}
