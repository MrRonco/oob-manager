package fwinventory

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/firmware"
	"oob-manager/internal/fleet"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

type fakeFleet struct {
	mu     sync.Mutex
	states []fleet.ServerState
}

func (f *fakeFleet) Servers() []fleet.ServerState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fleet.ServerState(nil), f.states...)
}

func (f *fakeFleet) Server(id string) (fleet.ServerState, bool) {
	for _, s := range f.Servers() {
		if s.ID == id {
			return s, true
		}
	}
	return fleet.ServerState{}, false
}

func (f *fakeFleet) Polled() bool { return true }

type env struct {
	t         *testing.T
	db        *store.DB
	fl        *fakeFleet
	svc       *Service
	now       time.Time
	refresh   error
	refreshd  []string
	events    []notify.Event
	auditDown bool
}

// flakyRecorder is the audit logger, failing while env.auditDown is set.
type flakyRecorder struct {
	admin.Recorder
	e *env
}

func (f flakyRecorder) Record(ctx context.Context, en audit.Entry) (store.AuditRecord, error) {
	if f.e.auditDown {
		return store.AuditRecord{}, errors.New("audit down")
	}
	return f.Recorder.Record(ctx, en)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newEnv(t *testing.T, p firmware.Policy) *env {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "fw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	inv := bmc.NewInventory(bmc.InventoryParams{InventoryInfo: bmc.InventoryInfo{Model: "PowerEdge R730xd"}})
	e := &env{t: t, db: db, now: t0, fl: &fakeFleet{states: []fleet.ServerState{
		{ID: "r730xd", Name: "R730XD", FirmwareEnabled: true, HasInventory: true, Inventory: inv},
		{ID: "r240", Name: "R240", FirmwareEnabled: true},
	}}}
	e.svc = e.open(p)
	return e
}

func (e *env) open(p firmware.Policy) *Service {
	e.t.Helper()
	lg := audit.NewLogger(e.db.Audit(), nil, func() time.Time { return e.now }, quiet())
	svc, err := New(context.Background(), Config{DB: e.db, Audit: flakyRecorder{Recorder: lg, e: e},
		Emit:  func(ev notify.Event) { e.events = append(e.events, ev) },
		Fleet: e.fl, Kind: func(id string) string { return map[string]string{"r730xd": "idrac8", "r240": "idrac9"}[id] },
		Refresh: func(id string, tier fleet.Tier) error {
			if tier != fleet.TierFirmware {
				e.t.Errorf("tier %q", tier)
			}
			e.refreshd = append(e.refreshd, id)
			return e.refresh
		},
		Policy: p, Now: func() time.Time { return e.now }, Logger: quiet()})
	if err != nil {
		e.t.Fatal(err)
	}
	return svc
}

func (e *env) auditRows(action string) []store.AuditRecord {
	e.t.Helper()
	recs, err := e.db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: action, Limit: 100})
	if err != nil {
		e.t.Fatal(err)
	}
	return recs
}

func it(state, comp, version, fqdd string) bmc.FirmwareItem {
	return bmc.FirmwareItem{ID: state + "-" + comp + "-" + version, State: state, ComponentID: comp, Version: version, FQDD: fqdd,
		Name: "Component " + comp}
}

func named(i bmc.FirmwareItem, name string) bmc.FirmwareItem {
	i.Name, i.Named, i.Detailed = name, true, true
	return i
}

func idrac8Scan(biosVersion string) bmc.FirmwareScan {
	items := []bmc.FirmwareItem{
		it("Current", "159", biosVersion, ""),
		named(it("Installed", "159", biosVersion, ""), "BIOS"),
		it("Previous", "159", "2.18.1", ""),
		it("Current", "101434", "2.25", ""), // an image the BMC holds but never installed
		named(it("Installed", "101434", "2.23", ""), "Backplane 0"),
		it("Installed", "25227", "2.86.86.86", ""),
	}
	items[1].Kind, items[4].Kind, items[5].Kind = bmc.FirmwareBIOS, bmc.FirmwareEnclosure, bmc.FirmwareBMC
	return bmc.NewFirmwareScan(items, len(items), true).WithDocs(2, 0)
}

func TestRecordFirstScanAndChanges(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	if rows := e.auditRows(ActionChanged); len(rows) != 0 {
		t.Fatalf("the first scan is not a change: %+v", rows)
	}
	v, err := e.svc.Server(ctx, "r730xd")
	if err != nil || len(v.Rows) != 3 || !v.Scanned || v.Scan.Components != 3 || !v.Scan.Complete || v.Scan.DocsRead != 2 {
		t.Fatalf("server view %+v %v", v, err)
	}
	if v.Rows[0].Kind != bmc.FirmwareBMC || v.Rows[1].Display != "BIOS" || v.Rows[1].Previous != "2.18.1" {
		t.Fatalf("rows by kind: %+v", v.Rows)
	}
	// The BIOS was updated: running and previous change; the scan does not reread the
	// unchanged components' documents.
	e.now = t0.Add(24 * time.Hour)
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.20.0"), e.now); err != nil {
		t.Fatal(err)
	}
	rows := e.auditRows(ActionChanged)
	if len(rows) != 1 {
		t.Fatalf("audit rows %+v", rows)
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(rows[0].ParamsJSON), &p)
	if rows[0].Principal != "system" || rows[0].ServerID != "r730xd" || p["component"] != "BIOS" || p["field"] != "running" ||
		p["before"] != "2.19.0" || p["after"] != "2.20.0" {
		t.Fatalf("audit row %+v params %v", rows[0], p)
	}
	v, _ = e.svc.Server(ctx, "r730xd")
	if len(v.Changes) != 1 || v.Changes[0].Name != "BIOS" || !v.Changes[0].SeenAt.Equal(e.now) {
		t.Fatalf("changes %+v", v.Changes)
	}
	bios := find(t, v.Rows, "159")
	if !bios.FirstSeen.Equal(t0) || !bios.LastSeen.Equal(e.now) {
		t.Fatalf("first/last seen %+v", bios)
	}
	if c, ok := e.svc.Counts(context.Background(), "r730xd"); !ok || c.Changes != 1 || c.Components != 3 || c.Flagged[firmware.FlagNotApplied] != 1 {
		t.Fatalf("counts %+v", c)
	}
}

func find(t *testing.T, rows []firmware.Row, id string) firmware.Row {
	t.Helper()
	for _, r := range rows {
		if r.ComponentID == id {
			return r
		}
	}
	t.Fatalf("component %s missing in %+v", id, rows)
	return firmware.Row{}
}

func TestNamesAreStickyAndNeedAsksOnlyForUnknown(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	need := e.svc.Need("r730xd", t0.Add(time.Hour))
	if need(it("Installed", "159", "2.19.0", "")) || need(it("Current", "159", "2.19.0", "")) ||
		need(it("Installed", "101434", "2.23", "")) || need(it("Current", "101434", "2.25", "")) {
		t.Fatal("named, fresh, unchanged components need no document")
	}
	if !need(it("Installed", "25227", "2.86.86.86", "")) || !need(it("Current", "999", "1", "")) {
		t.Fatal("unnamed and unknown components need their document")
	}
	if !need(it("Installed", "159", "2.20.0", "")) {
		t.Fatal("a new running version needs the document again (release date)")
	}
	// A scan that read no documents keeps the names.
	plain := bmc.NewFirmwareScan([]bmc.FirmwareItem{it("Installed", "159", "2.19.0", ""), it("Current", "101434", "2.25", ""),
		it("Installed", "101434", "2.23", ""), it("Installed", "25227", "2.86.86.86", "")}, 4, true)
	if err := e.svc.Record(ctx, "r730xd", plain, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	v, _ := e.svc.Server(ctx, "r730xd")
	if b := find(t, v.Rows, "159"); b.Display != "BIOS" || !b.Named || b.Kind != bmc.FirmwareBIOS {
		t.Fatalf("sticky name %+v", b)
	}
	// The Previous image disappeared: that is a change.
	if rows := e.auditRows(ActionChanged); len(rows) != 1 || !strings.Contains(rows[0].ParamsJSON, `"field":"previous"`) {
		t.Fatalf("changes %+v", rows)
	}
}

func TestIncompleteAndEmptyScansNeverRemove(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	partial := bmc.NewFirmwareScan([]bmc.FirmwareItem{named(it("Installed", "159", "2.19.0", ""), "BIOS")}, 21, false)
	if err := e.svc.Record(ctx, "r730xd", partial, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.svc.Server(ctx, "r730xd"); len(v.Rows) != 3 || v.Scan.Complete || v.Truncated() {
		t.Fatalf("an incomplete scan keeps the rest: %+v", v)
	}
	if err := e.svc.Record(ctx, "r730xd", bmc.NewFirmwareScan(nil, 0, true), t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.svc.Server(ctx, "r730xd"); len(v.Rows) != 3 {
		t.Fatalf("an empty listing is a glitch, not every component gone: %+v", v.Rows)
	}
	if rows := e.auditRows(ActionChanged); len(rows) != 0 {
		t.Fatalf("no change recorded: %+v", rows)
	}
	// A complete scan without a component removes it.
	full := idrac8Scan("2.19.0")
	items := full.Items()[:5] // without the iDRAC
	if err := e.svc.Record(ctx, "r730xd", bmc.NewFirmwareScan(items, 5, true), t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rows := e.auditRows(ActionChanged); len(rows) != 1 || !strings.Contains(rows[0].ParamsJSON, `"after":""`) {
		t.Fatalf("removal %+v", rows)
	}
}

func TestRecordSanitisesBMCStrings(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	long := strings.Repeat("9", 100)
	items := []bmc.FirmwareItem{
		{ID: "x", Version: long, Name: "Evil\u202e name", Named: true, Detailed: true, Kind: "cpu"},
		{ID: strings.Repeat("a", 200), Version: "1"},
	}
	if err := e.svc.Record(context.Background(), "r240", bmc.NewFirmwareScan(items, 2, true), t0); err != nil {
		t.Fatal(err)
	}
	v, _ := e.svc.Server(context.Background(), "r240")
	if len(v.Rows) != 1 || len(v.Rows[0].Running) != maxVersionLen || v.Rows[0].Display != "Evil name" || v.Rows[0].Kind != bmc.FirmwareOther {
		t.Fatalf("rows %+v", v.Rows)
	}
}

func TestTableFlagsFiltersAndCounts(t *testing.T) {
	p := firmware.NewPolicy(firmware.PolicyParams{Rules: []firmware.Rule{{BMCKind: "idrac8", Kind: "bios", Version: "2.20.0"}},
		BMCMinimum: map[string]string{"idrac8": "2.86.86.86"}})
	e := newEnv(t, p)
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	r240 := bmc.NewFirmwareScan([]bmc.FirmwareItem{named(it("Installed", "159", "2.20.0", "BIOS.Setup.1-1"), "BIOS")}, 1, true)
	if err := e.svc.Record(ctx, "r240", r240, t0); err != nil {
		t.Fatal(err)
	}
	tab := e.svc.Table(ctx, firmware.Filter{})
	if tab.Total != 4 || tab.Warn != 1 || tab.Flagged != 2 || len(tab.Rows) != 4 || len(tab.Servers) != 2 {
		t.Fatalf("table total %d warn %d flagged %d rows %d", tab.Total, tab.Warn, tab.Flagged, len(tab.Rows))
	}
	if tab.Rows[0].Primary() != firmware.FlagBelowMinimum || tab.Rows[0].Server.ID != "r730xd" ||
		tab.Rows[1].Primary() != firmware.FlagNotApplied {
		t.Fatalf("problems first: %+v", tab.Rows[:2])
	}
	if got := e.svc.Table(ctx, firmware.Filter{Flagged: true}); len(got.Rows) != 2 || got.Total != 4 {
		t.Fatalf("flagged only %+v", got.Rows)
	}
	if got := e.svc.Table(ctx, firmware.Filter{ServerID: "r240"}); len(got.Rows) != 1 || got.Rows[0].Primary() != firmware.FlagNone {
		t.Fatalf("r240 BIOS has no rule for idrac9: %+v", got.Rows)
	}
	if e.svc.WarnCount(ctx) != 1 || tab.Catalog.Active != nil {
		t.Fatalf("warn count %d", e.svc.WarnCount(ctx))
	}
	// A server the fleet no longer polls is not listed (its rows stay until it leaves
	// the registry).
	e.fl.mu.Lock()
	e.fl.states = e.fl.states[1:]
	e.fl.mu.Unlock()
	if got := e.svc.Table(ctx, firmware.Filter{}); got.Total != 1 {
		t.Fatalf("unpolled server listed: %+v", got.Rows)
	}
	if _, err := e.svc.Server(ctx, "r730xd"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("server view of an unpolled server: %v", err)
	}
	if _, ok := e.svc.Counts(context.Background(), "r730xd"); ok {
		t.Fatal("counts of an unpolled server")
	}
}

func TestRestartLoadsTheStoredView(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.19.0"), t0); err != nil {
		t.Fatal(err)
	}
	again := e.open(firmware.NewPolicy(firmware.PolicyParams{}))
	v, err := again.Server(ctx, "r730xd")
	if err != nil || len(v.Rows) != 3 || !v.Scanned || !v.Scan.ScannedAt.Equal(t0) {
		t.Fatalf("after restart %+v %v", v, err)
	}
	if again.Need("r730xd", t0)(it("Current", "159", "2.19.0", "")) {
		t.Fatal("names survive a restart")
	}
}

func TestRescan(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	a := admin.Actor{Username: "olga", Role: "operator", IP: "192.0.2.5", Method: "local"}
	if err := e.svc.Rescan(ctx, a, "r240"); err != nil {
		t.Fatal(err)
	}
	e.refresh = fleet.ErrPaused
	e.now = e.now.Add(RescanCooldown) // the per-server cooldown (review S-M4)
	if err := e.svc.Rescan(ctx, a, "r240"); !errors.Is(err, fleet.ErrPaused) {
		t.Fatalf("paused: %v", err)
	}
	if err := e.svc.Rescan(ctx, a, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	e.fl.mu.Lock()
	e.fl.states[1].FirmwareEnabled = false
	e.fl.mu.Unlock()
	if err := e.svc.Rescan(ctx, a, "r240"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no tier: %v", err)
	}
	rows := e.auditRows(ActionRescan) // newest first: started, error; started, ok
	if len(rows) != 4 || rows[0].Result != audit.ResultError || rows[0].ErrorClass != "paused" ||
		rows[1].Result != audit.ResultStarted || rows[2].Result != audit.ResultOK || rows[3].Result != audit.ResultStarted ||
		rows[2].Principal != "olga" || rows[2].ServerID != "r240" || rows[2].SrcIP != "192.0.2.5" {
		t.Fatalf("rescan audit %+v", rows)
	}
	if len(e.refreshd) != 2 {
		t.Fatalf("refresh calls %v", e.refreshd)
	}
	if rescanClass(fleet.ErrNoTier) != "unavailable" || rescanClass(errors.New("x")) != "refused" {
		t.Fatal("classes")
	}
}

func TestSyncServersAndPrune(t *testing.T) {
	e := newEnv(t, firmware.NewPolicy(firmware.PolicyParams{}))
	ctx := context.Background()
	for _, id := range []string{"r730xd", "r240"} {
		if err := e.svc.Record(ctx, id, idrac8Scan("2.19.0"), t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.Record(ctx, "r730xd", idrac8Scan("2.20.0"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SyncServers(ctx, []string{"r730xd", "r240"}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SyncServers(ctx, []string{"r730xd"}); err != nil {
		t.Fatal(err)
	}
	comps, _ := e.db.Firmware().Components(ctx)
	for _, c := range comps {
		if c.ServerID == "r240" {
			t.Fatalf("rows of a removed server stayed: %+v", c)
		}
	}
	if v, _ := e.svc.Server(ctx, "r240"); v.Scanned || len(v.Rows) != 0 {
		t.Fatalf("in-memory rows stayed: %+v", v)
	}
	e.now = t0.Add(ChangeRetention + 2*time.Hour)
	if n, err := e.svc.Prune(ctx); err != nil || n != 1 {
		t.Fatalf("prune %d %v", n, err)
	}
}

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("missing deps accepted")
	}
	if (ScanStatus{Requested: true}).Busy() != true || (ScanStatus{}).Busy() {
		t.Fatal("Busy")
	}
}

func TestTruncatedAboveTheMemberCap(t *testing.T) {
	s := ServerScan{Scanned: true, Scan: store.FirmwareScanRow{Listed: bmc.MaxFirmwareMembers + 1}}
	if !s.Truncated() || (ServerScan{Scanned: true, Scan: store.FirmwareScanRow{Listed: bmc.MaxFirmwareMembers}}).Truncated() {
		t.Fatal("Truncated")
	}
}
