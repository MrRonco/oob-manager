package fwinventory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/firmware"
	"oob-manager/internal/notify"
)

func fresh(prefix string, n int) []bmc.FirmwareItem {
	out := make([]bmc.FirmwareItem, 0, n)
	for i := range n {
		out = append(out, it("Current", fmt.Sprintf("%s%d", prefix, i), "1.0", ""))
	}
	return out
}

// TestIncompleteScansAreBounded (review S-M1): five incomplete scans of 64 new IDs each
// must not grow a server's rows without bound.
func TestIncompleteScansAreBounded(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	for i := range 5 {
		e.now = t0.Add(time.Duration(i) * time.Hour)
		scan := bmc.NewFirmwareScan(fresh(fmt.Sprintf("s%d-", i), bmc.MaxFirmwareMembers), 200, false)
		if err := e.svc.Record(ctx, "r240", scan, e.now); err != nil {
			t.Fatal(err)
		}
	}
	v, _ := e.svc.Server(ctx, "r240")
	if len(v.Rows) != MaxRowsPerServer {
		t.Fatalf("%d rows, want the cap %d", len(v.Rows), MaxRowsPerServer)
	}
	for _, r := range v.Rows {
		if strings.HasPrefix(r.ComponentID, "s0-") || strings.HasPrefix(r.ComponentID, "s1-") || strings.HasPrefix(r.ComponentID, "s2-") {
			t.Fatalf("an older unlisted row was kept over a newer one: %s", r.ComponentID)
		}
	}
	// Unlisted rows older than UnlistedExpiry go even on an incomplete scan.
	e.now = t0.Add(UnlistedExpiry + 5*time.Hour)
	if err := e.svc.Record(ctx, "r240", bmc.NewFirmwareScan(fresh("late-", 1), 200, false), e.now); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.svc.Server(ctx, "r240"); len(v.Rows) != 1 {
		t.Fatalf("%d rows after the expiry", len(v.Rows))
	}
}

// TestManyChangesAreCappedAndAggregated (reviews S-M2, S-M3): 64 changed components
// make 16 change rows, 16 audit rows and one summary, and one notification.
func TestManyChangesAreCappedAndAggregated(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r240", bmc.NewFirmwareScan(fresh("c", 64), 64, true), t0); err != nil {
		t.Fatal(err)
	}
	next := fresh("c", 64)
	for i := range next {
		next[i].Version = "2.0"
	}
	e.now = t0.Add(time.Hour)
	if err := e.svc.Record(ctx, "r240", bmc.NewFirmwareScan(next, 64, true), e.now); err != nil {
		t.Fatal(err)
	}
	v, _ := e.svc.Server(ctx, "r240")
	if len(v.Changes) != MaxChangesPerScan {
		t.Fatalf("changes listed %d", len(v.Changes))
	}
	stored, _ := e.db.Firmware().Changes(ctx, "r240", 1000)
	rows := e.auditRows(ActionChanged)
	if len(stored) != MaxChangesPerScan || len(rows) != MaxChangesPerScan+1 {
		t.Fatalf("%d change rows, %d audit rows", len(stored), len(rows))
	}
	if !strings.Contains(rows[0].ParamsJSON, `"changes":64`) || !strings.Contains(rows[0].ParamsJSON, `"summary":true`) {
		t.Fatalf("summary row %s", rows[0].ParamsJSON)
	}
	if c, _ := e.svc.Counts(context.Background(), "r240"); c.Changes != 64 {
		t.Fatalf("the metric counts every change: %d", c.Changes)
	}
	if len(e.events) != 1 {
		t.Fatalf("%d notifications, want one per scan", len(e.events))
	}
	ev := e.events[0]
	if ev.Class != notify.ClassSecurity || ev.Severity != notify.SeverityWarning || !strings.Contains(ev.Title, "64 components") ||
		ev.Count != 64 || strings.Contains(ev.Title+ev.Message, "c1") || len(ev.Detail) == 0 || len(ev.Detail) > 17 {
		t.Fatalf("event %+v", ev)
	}
}

// TestRollbackChangesAloneDoNotNotify: a scan that only changes rollback copies raises
// no notification (the running change it follows already did).
func TestRollbackChangesAloneDoNotNotify(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	scan := func(prev string) bmc.FirmwareScan {
		return bmc.NewFirmwareScan([]bmc.FirmwareItem{it("Current", "159", "2.0", ""), it("Previous", "159", prev, "")}, 2, true)
	}
	if err := e.svc.Record(ctx, "r240", scan("1.0"), t0); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Record(ctx, "r240", scan("1.5"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(e.events) != 0 {
		t.Fatalf("events %+v", e.events)
	}
}

// TestNearIdenticalFQDDs (review S-L1): two FQDDs that differ only by a zero-width space
// are one component after cleaning, and the scan is stored.
func TestNearIdenticalFQDDs(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	items := []bmc.FirmwareItem{it("Current", "102301", "23.0.8", "NIC.Slot.2-1-1"), it("Current", "102301", "23.0.9", "NIC.Slot.2\u200b-1-1")}
	if err := e.svc.Record(context.Background(), "r240", bmc.NewFirmwareScan(items, 2, true), t0); err != nil {
		t.Fatalf("the scan must store: %v", err)
	}
	if v, _ := e.svc.Server(context.Background(), "r240"); len(v.Rows) != 1 || v.Rows[0].FQDD != "NIC.Slot.2-1-1" {
		t.Fatalf("rows %+v", v.Rows)
	}
}

// TestClockStepBack (review S-L5): a scan stamped before a component's first sighting
// (the clock stepped back) still stores, with last seen not before first seen.
func TestClockStepBack(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0.Add(-time.Hour)); err != nil {
		t.Fatalf("a clock step back failed the scan: %v", err)
	}
	v, _ := e.svc.Server(ctx, "r730xd")
	for _, r := range v.Rows {
		if r.LastSeen.Before(r.FirstSeen) {
			t.Fatalf("row %+v", r)
		}
	}
}

// TestIncompleteScanWithoutOneDellMember (review C-M1): the iDRAC8 backplane runs 2.23
// (Installed) and the BMC holds a 2.25 image it never installed (Current). An incomplete
// scan that listed only the Current member is not an upgrade, and one that listed only
// the Installed member has not lost the stored image: both keep the stored row.
func TestIncompleteScanWithoutOneDellMember(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	for i, items := range [][]bmc.FirmwareItem{
		{it("Current", "101434", "2.25", ""), it("Installed", "159", "2.19.0", "")},
		{it("Installed", "101434", "2.23", ""), it("Installed", "159", "2.19.0", "")},
	} {
		if err := e.svc.Record(ctx, "r730xd", bmc.NewFirmwareScan(items, 21, false), t0.Add(time.Duration(i+1)*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if rows := e.auditRows(ActionChanged); len(rows) != 0 {
			t.Fatalf("scan %d: false change: %s", i, rows[0].ParamsJSON)
		}
		v, _ := e.svc.Server(ctx, "r730xd")
		if bp := find(t, v.Rows, "101434"); bp.Running != "2.23" || bp.Stored != "2.25" || bp.Primary() != firmware.FlagNotApplied {
			t.Fatalf("scan %d: backplane %+v", i, bp)
		}
	}
}

// TestIncompleteScanStoredImageChanges (review of the states fix, M1): an incomplete scan
// that lists both Dell members at the same version reports the stored image gone, and
// one that lists only a new Current- member reports a new stored image, never a running
// version change.
func TestIncompleteScanStoredImageChanges(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	newImage := bmc.NewFirmwareScan([]bmc.FirmwareItem{it("Current", "101434", "2.30", "")}, 21, false)
	if err := e.svc.Record(ctx, "r730xd", newImage, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rows := e.auditRows(ActionChanged); len(rows) != 0 {
		t.Fatalf("a new stored image is not a running change: %s", rows[0].ParamsJSON)
	}
	v, _ := e.svc.Server(ctx, "r730xd")
	if bp := find(t, v.Rows, "101434"); bp.Running != "2.23" || bp.Stored != "2.30" || bp.Primary() != firmware.FlagNotApplied {
		t.Fatalf("new stored image: %+v", bp)
	}
	purged := bmc.NewFirmwareScan([]bmc.FirmwareItem{it("Current", "101434", "2.23", ""), it("Installed", "101434", "2.23", "")}, 21, false)
	if err := e.svc.Record(ctx, "r730xd", purged, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	v, _ = e.svc.Server(ctx, "r730xd")
	if bp := find(t, v.Rows, "101434"); bp.Running != "2.23" || bp.Stored != "" || bp.Primary() != firmware.FlagNone {
		t.Fatalf("both members at one version: no stored image: %+v", bp)
	}
}

// TestRescanCooldownAndFailClosedAudit (reviews S-M4, S-L2).
func TestRescanCooldownAndFailClosedAudit(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	a := admin.Actor{Username: "olga", Role: "operator", Method: "local"}
	e.auditDown = true
	if err := e.svc.Rescan(ctx, a, "r240"); err == nil || len(e.refreshd) != 0 {
		t.Fatalf("no started row, no re-scan: %v %v", err, e.refreshd)
	}
	e.auditDown = false
	if err := e.svc.Rescan(ctx, a, "r240"); err != nil {
		t.Fatal(err)
	}
	var cd *CooldownError
	if err := e.svc.Rescan(ctx, a, "r240"); !errors.As(err, &cd) || cd.Left <= 0 || cd.Left > RescanCooldown {
		t.Fatalf("second re-scan within the cooldown: %v", err)
	}
	if err := e.svc.Rescan(ctx, a, "r730xd"); err != nil {
		t.Fatalf("the cooldown is per server: %v", err)
	}
	rows := e.auditRows(ActionRescan)
	if rows[2].Result != audit.ResultDenied || rows[2].ErrorClass != "cooldown" || rows[2].ServerID != "r240" {
		t.Fatalf("cooldown not audited: %+v", rows)
	}
	e.now = e.now.Add(RescanCooldown)
	if err := e.svc.Rescan(ctx, a, "r240"); err != nil {
		t.Fatalf("after the cooldown: %v", err)
	}
	if len(e.refreshd) != 3 {
		t.Fatalf("refreshes %v", e.refreshd)
	}
}

// TestWarnCountIsCached (review S-L4): the sidebar count is not rebuilt on every page.
func TestWarnCountIsCached(t *testing.T) {
	p := firmware.NewPolicy(firmware.PolicyParams{Rules: []firmware.Rule{{BMCKind: "idrac8", Kind: "bios", Version: "2.20.0"}}})
	e := newEnv(t, p)
	ctx := context.Background()
	if n := e.svc.WarnCount(ctx); n != 0 {
		t.Fatalf("empty %d", n)
	}
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	if n := e.svc.WarnCount(ctx); n != 1 {
		t.Fatalf("a recorded scan refreshes the count: %d", n)
	}
	e.fl.mu.Lock()
	saved := e.fl.states
	e.fl.states = nil
	e.fl.mu.Unlock()
	if n := e.svc.WarnCount(ctx); n != 1 {
		t.Fatalf("served from the cache: %d", n)
	}
	e.now = e.now.Add(warnCacheFor + time.Second)
	if n := e.svc.WarnCount(ctx); n != 0 {
		t.Fatalf("recomputed after the cache time: %d", n)
	}
	e.fl.mu.Lock()
	e.fl.states = saved
	e.fl.mu.Unlock()
}

// TestModelIsKeptWithTheScan (review C-L3): model rules keep matching while the fleet has
// not read the inventory yet (after a restart).
func TestModelIsKeptWithTheScan(t *testing.T) {
	p := firmware.NewPolicy(firmware.PolicyParams{Rules: []firmware.Rule{{Model: "PowerEdge R730xd", Kind: "bios", Version: "2.20.0"}}})
	e := newEnv(t, p)
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	e.fl.mu.Lock()
	e.fl.states[0].HasInventory = false
	e.fl.mu.Unlock()
	again := e.open(p)
	v, _ := again.Server(ctx, "r730xd")
	if v.Info.Model != "PowerEdge R730xd" || find(t, v.Rows, "159").Primary() != firmware.FlagBelowMinimum {
		t.Fatalf("model %q rows %+v", v.Info.Model, v.Rows)
	}
}

// TestFloodKeepsThePlatformFirmware (review N1): incomplete scans full of junk IDs evict
// other components first; the BMC, BIOS and CPLD rows (and their "before" versions) stay.
func TestFloodKeepsThePlatformFirmware(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		e.now = t0.Add(time.Duration(i+1) * time.Hour)
		scan := bmc.NewFirmwareScan(fresh(fmt.Sprintf("j%d-", i), bmc.MaxFirmwareMembers), 300, false)
		if err := e.svc.Record(ctx, "r730xd", scan, e.now); err != nil {
			t.Fatal(err)
		}
	}
	v, _ := e.svc.Server(ctx, "r730xd")
	if len(v.Rows) != MaxRowsPerServer {
		t.Fatalf("%d rows", len(v.Rows))
	}
	if b := find(t, v.Rows, "159"); b.Running != "2.19.0" {
		t.Fatalf("bios %+v", b)
	}
	find(t, v.Rows, "25227")
}

// TestChangeCapKeepsThePlatformFirmware (review N2): when more than MaxChangesPerScan
// components change, the BMC, BIOS and CPLD running changes are the ones recorded.
func TestChangeCapKeepsThePlatformFirmware(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	scan := func(v string) bmc.FirmwareScan {
		items := fresh("000", 30) // component IDs that sort before "159"
		for i := range items {
			items[i].Version = v
		}
		b := named(it("Current", "159", v, ""), "BIOS")
		b.Kind = bmc.FirmwareBIOS
		return bmc.NewFirmwareScan(append(items, b), 31, true)
	}
	if err := e.svc.Record(ctx, "r730xd", scan("1.0"), t0); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Record(ctx, "r730xd", scan("2.0"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stored, _ := e.db.Firmware().Changes(ctx, "r730xd", 1000)
	found := false
	for _, c := range stored {
		found = found || (c.ComponentID == "159" && c.Field == firmware.FieldRunning)
	}
	if len(stored) != MaxChangesPerScan || !found {
		t.Fatalf("the BIOS change was not recorded: %+v", stored)
	}
}
