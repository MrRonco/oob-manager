package fwcatalog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/catalogtest"
	"oob-manager/internal/store"
)

// importSynthetic loads the synthetic catalog into f's store.
func importSynthetic(t *testing.T, f *fixture) {
	t.Helper()
	data := catalogtest.Catalog()
	if _, err := f.im.Import(context.Background(), Input{Origin: OriginCLI, File: f.stage(t, data), Sig: f.key.Sign(t, data)}); err != nil {
		t.Fatal(err)
	}
}

func comp(id, fqdd, running, identity, stored string) firmware.Component {
	return firmware.Component{Key: firmware.Key{ComponentID: id, FQDD: fqdd}, Running: running, Identity: identity, Stored: stored}
}

func TestIndexMatching(t *testing.T) {
	f := newFixture(t)
	importSynthetic(t, f)
	ctx := context.Background()
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	if err := f.db.FirmwareUpdates().PutSkip(ctx, store.FirmwareUpdateSkipRow{ServerID: "new", ComponentID: "106864",
		Version: "E014", Comment: "window", SkippedBy: "alice", SkippedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.FirmwareUpdates().PutSkip(ctx, store.FirmwareUpdateSkipRow{ServerID: "new", ComponentID: "106883",
		Version: "2.5.13.3000", Comment: "older", SkippedBy: "alice", SkippedAt: now}); err != nil {
		t.Fatal(err)
	}
	x, imp, err := BuildIndex(ctx, f.db.Catalog(), f.db.FirmwareUpdates(), "dell", map[string]string{"ovr": "088F"}, now)
	if err != nil || x == nil || imp.Version != "26.10.22" {
		t.Fatalf("index %v %+v", err, imp)
	}
	newSrv := firmware.ServerInfo{ID: "new", BMCKind: "idrac9", SystemID: "088F"}
	cases := []struct {
		name  string
		s     firmware.ServerInfo
		c     firmware.Component
		state firmware.UpdateState
		ver   string
	}{
		{"bios available", newSrv, comp("159", "BIOS.Setup.1-1", "2.20.0", "", ""), firmware.UpdateAvailable, "2.25.2"},
		{"idrac urgent", newSrv, comp("25227", "iDRAC.Embedded.1-1", "7.00.00.182", "", "7.00.00.185"), firmware.UpdateUrgent, "7.00.00.185"},
		{"up to date", newSrv, comp("159", "", "2.25.2", "", ""), firmware.UpdateCurrent, "2.25.2"},
		{"newer than catalog", newSrv, comp("159", "", "3.0.0", "", ""), firmware.UpdateCurrent, "2.25.2"},
		{"pci exact", newSrv, comp("105897", "NIC.1", "23.31.1", "DCIM:firmware:14E4:165F:1028:08FF", ""), firmware.UpdateAvailable, "23.31.6"},
		{"pci other board", newSrv, comp("105897", "NIC.2", "23.31.1", "DCIM:firmware:14E4:1639:1028:0002", ""), firmware.UpdateAvailable, "24.0.0"},
		{"no pci: highest of all", newSrv, comp("105897", "NIC.3", "23.31.1", "", ""), firmware.UpdateAvailable, "24.0.0"},
		{"skipped exactly", newSrv, comp("106864", "", "E013", "", ""), firmware.UpdateSkipped, "E014"},
		{"skip of an older version reopens", newSrv, comp("106883", "", "2.5.13.3024", "", ""), firmware.UpdateAvailable, "2.5.13.3025"},
		{"cannot compare", newSrv, comp("106864", "", "1.2.3", "", ""), firmware.UpdateCannotCompare, "E014"},
		{"not in catalog", newSrv, comp("999999", "", "1.0", "", ""), firmware.UpdateNotInCatalog, ""},
		{"driver package ignored", newSrv, comp("102301", "", "23.0.8", "", ""), firmware.UpdateNotInCatalog, ""},
		{"old server by model", firmware.ServerInfo{ID: "old", BMCKind: "idrac8", Model: "PowerEdge R730xd"},
			comp("25227", "", "2.86.86.86", "", ""), firmware.UpdateCurrent, "2.40.40.40"},
		{"override", firmware.ServerInfo{ID: "ovr", BMCKind: "idrac9"}, comp("159", "", "2.20.0", "", ""), firmware.UpdateAvailable, "2.25.2"},
		{"generic redfish", firmware.ServerInfo{ID: "g", BMCKind: "redfish", SystemID: "088F"}, comp("159", "", "1", "", ""), firmware.UpdateNone, ""},
		{"unknown system", firmware.ServerInfo{ID: "u", BMCKind: "idrac9", Model: "PowerEdge Z9"}, comp("159", "", "1", "", ""), firmware.UpdateNone, ""},
	}
	for _, c := range cases {
		u := x.Update(c.s, c.c)
		if u.State != c.state || u.Latest.Version != c.ver {
			t.Errorf("%s: %s %q, want %s %q", c.name, u.State, u.Latest.Version, c.state, c.ver)
		}
	}
	if u := x.Update(newSrv, comp("25227", "", "7.00.00.182", "", "7.00.00.185")); !u.StoredIsLatest || u.MatchedBy != BySystemID {
		t.Errorf("stored-is-latest %+v", u)
	}
	if u := x.Update(newSrv, comp("106864", "", "E013", "", "")); u.Skip == nil || u.Skip.By != "alice" {
		t.Errorf("skip detail %+v", u)
	}
	if u := x.Update(firmware.ServerInfo{ID: "old", BMCKind: "idrac8", Model: "PowerEdge R730xd"}, comp("25227", "", "2", "", "")); u.MatchedBy != ByModelName {
		t.Errorf("by model %+v", u)
	}

	comps := []firmware.Component{comp("159", "", "2.20.0", "", ""), comp("25227", "", "7.00.00.182", "", ""), comp("999999", "", "1", "", "")}
	if cv := x.Coverage(newSrv, comps); cv.State != firmware.CoverageNormal || cv.Matched != 2 || cv.Updates != 2 || cv.Urgent != 1 || cv.Components != 3 {
		t.Errorf("coverage %+v", cv)
	}
	if cv := x.Coverage(firmware.ServerInfo{ID: "old", BMCKind: "idrac8", Model: "PowerEdge R730xd"}, comps[:1]); cv.State != firmware.CoverageLegacy ||
		cv.Newest.Year() != 2016 {
		t.Errorf("legacy %+v", cv)
	}
	for s, want := range map[firmware.ServerInfo]firmware.CoverageState{
		{ID: "g", BMCKind: "redfish"}:                  firmware.CoverageNoBMCType,
		{ID: "u", BMCKind: "idrac9"}:                   firmware.CoverageUnknown,
		{ID: "z", BMCKind: "idrac9", SystemID: "0ABC"}: firmware.CoverageNotListed,
	} {
		if cv := x.Coverage(s, comps); cv.State != want {
			t.Errorf("%+v: %s, want %s", s, cv.State, want)
		}
	}
}

type recAudit struct{ entries []audit.Entry }

func (r *recAudit) Record(_ context.Context, e audit.Entry) (store.AuditRecord, error) {
	r.entries = append(r.entries, e)
	return store.AuditRecord{}, nil
}

func (r *recAudit) RecordTx(ctx context.Context, _ *store.Tx, e audit.Entry) (store.AuditRecord, error) {
	return r.Record(ctx, e)
}

func TestCheckerIndexStatusAndSkips(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rec := &recAudit{}
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	c, err := NewChecker(CheckerConfig{Importer: f.im, Repo: f.db.Catalog(), Updates: f.db.FirmwareUpdates(), Audit: rec,
		Host: "downloads.example.com", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if c.Index(ctx) != nil || c.Status(ctx).Active != nil {
		t.Fatal("an index without a catalog")
	}
	importSynthetic(t, f)
	if c.Index(ctx) != nil {
		t.Fatal("the cached empty index was not reused within its TTL")
	}
	c.Invalidate()
	st := c.Status(ctx)
	if c.Index(ctx) == nil || st.Active == nil || !st.Signed() || st.LastCheck == nil || st.LastCheck.Result != "imported" ||
		st.Host != "downloads.example.com" || len(c.Checks(ctx, 20)) != 1 {
		t.Fatalf("status %+v", st)
	}
	a := admin.Actor{Username: "alice", Method: "session", Role: "admin", IP: "192.0.2.4"}
	srv := firmware.ServerInfo{ID: "new", BMCKind: "idrac9", SystemID: "088F"}
	bios := comp("159", "", "2.20.0", "", "")
	if err := c.Skip(ctx, a, SkipRequest{ServerID: "new", ComponentID: "159", Version: "2.25.2", Comment: "next window"}); err != nil {
		t.Fatal(err)
	}
	if u := c.Index(ctx).Update(srv, bios); u.State != firmware.UpdateSkipped {
		t.Fatalf("skip not applied at once: %s", u.State)
	}
	for _, bad := range []SkipRequest{{ServerID: "new", ComponentID: "159", Version: "2.25.2", Comment: " "},
		{ServerID: "new", ComponentID: "159", Version: "", Comment: "x"},
		{ServerID: "new", ComponentID: "159", Version: "2.25.2", Comment: "two\nlines"},
		{ServerID: "new", ComponentID: "159", Version: "2.25.2", Comment: "bad \xff utf-8"}} {
		if err := c.Skip(ctx, a, bad); !errors.Is(err, ErrBadSkip) && (bad.Version != "" || !errors.Is(err, ErrBadVersion)) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if err := c.Skip(ctx, a, SkipRequest{ServerID: "new", ComponentID: "159", Version: strings.Repeat("9", 65), Comment: "x"}); !errors.Is(err, ErrBadVersion) {
		t.Errorf("long version: %v", err)
	}
	if err := c.Unskip(ctx, a, "new", "159", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.Unskip(ctx, a, "new", "159", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second unskip %v", err)
	}
	if u := c.Index(ctx).Update(srv, bios); u.State != firmware.UpdateAvailable {
		t.Fatalf("unskip not applied: %s", u.State)
	}
	if len(rec.entries) != 3 || rec.entries[0].Action != ActionSkipUpdate || rec.entries[0].Params["comment"] != "next window" ||
		rec.entries[2].Result != audit.ResultError || rec.entries[1].ServerID != "new" {
		t.Fatalf("audit %+v", rec.entries)
	}
	if _, err := NewChecker(CheckerConfig{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestSkipCommitsWithItsAuditRow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	importSynthetic(t, f)
	changes := 0
	c, err := NewChecker(CheckerConfig{Importer: f.im, Repo: f.db.Catalog(), Updates: f.db.FirmwareUpdates(), DB: f.db,
		Audit: auditLogger(t, f.db), OnChange: func() { changes++ }})
	if err != nil {
		t.Fatal(err)
	}
	a := admin.Actor{Username: "alice", Method: "session", Role: "admin"}
	if err := c.Skip(ctx, a, SkipRequest{ServerID: "new", ComponentID: "159", Version: "2.25.2", Comment: "  window  "}); err != nil {
		t.Fatal(err)
	}
	skips, _ := f.db.FirmwareUpdates().Skips(ctx)
	recs, _ := f.db.AuditSearch().Search(ctx, store.AuditFilter{Action: ActionSkipUpdate, Limit: 5})
	if len(skips) != 1 || skips[0].Comment != "window" || len(recs) != 1 || recs[0].Result != audit.ResultOK || changes != 1 {
		t.Fatalf("skips %+v audit %+v changes %d", skips, recs, changes)
	}
	if err := c.Unskip(ctx, a, "new", "nope", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown unskip %v", err)
	}
	recs, _ = f.db.AuditSearch().Search(ctx, store.AuditFilter{Action: ActionUnskipUpdate, Limit: 5})
	if len(recs) != 1 || recs[0].Result != audit.ResultError {
		t.Fatalf("failed unskip audit %+v", recs)
	}
}

func TestFleetChangedDoesNotLoseACall(t *testing.T) {
	f := newFixture(t)
	importSynthetic(t, f)
	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	base := f.im.Want
	f.im.Want = func(ctx context.Context) (catalog.Want, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			<-release // the first re-parse is slow; a second trigger arrives meanwhile
		}
		w, err := base(ctx)
		if n > 1 {
			w.SystemIDs["0627"] = true
		}
		return w, err
	}
	c, _ := NewChecker(CheckerConfig{Importer: f.im, Repo: f.db.Catalog(), Updates: f.db.FirmwareUpdates(), Audit: &recAudit{}})
	done := make(chan struct{})
	go func() { c.FleetChanged(context.Background()); close(done) }()
	for c.reparsing.Load() == false {
		time.Sleep(time.Millisecond)
	}
	c.FleetChanged(context.Background()) // returns at once: the running call goes round again
	close(release)
	<-done
	c.mu.Lock()
	defer c.mu.Unlock()
	if !strings.Contains(c.lastWant, "s:0627") {
		t.Fatalf("the second trigger was lost: last re-parse for %q", c.lastWant)
	}
}

func TestNarrowAndLegacyEdges(t *testing.T) {
	rows := []store.CatalogReleaseRow{
		{Version: "1", VendorID: "14E4"}, // vendor only: matches any device of the vendor
		{Version: "2", VendorID: "14E4", DeviceID: "165F", SubVendorID: "1028", SubDeviceID: "0001"},
		{Version: "3"}, // generic
	}
	got := narrow(rows, catalog.Key{VendorID: "14e4", DeviceID: "165F"}) // no sub-IDs on the component
	if len(got) != 1 || got[0].Version != "2" {
		t.Fatalf("the more specific package must win: %+v", got)
	}
	if got := narrow(rows, catalog.Key{VendorID: "14E4", DeviceID: "9999"}); len(got) != 1 || got[0].Version != "1" {
		t.Fatalf("vendor-only package for another device %+v", got)
	}
	if got := narrow(rows, catalog.Key{VendorID: "8086", DeviceID: "1"}); len(got) != 1 || got[0].Version != "3" {
		t.Fatalf("fallback to generic %+v", got)
	}
	f := newFixture(t)
	importSynthetic(t, f)
	x, _, _ := BuildIndex(context.Background(), f.db.Catalog(), f.db.FirmwareUpdates(), "dell", nil, time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC))
	old := firmware.ServerInfo{ID: "old", BMCKind: "idrac8", Model: "PowerEdge R730xd"}
	if cv := x.Coverage(old, []firmware.Component{comp("25227", "", "2.86", "", "")}); cv.State != firmware.CoverageNormal || cv.Matched != 1 {
		t.Fatalf("a matched component is not legacy: %+v", cv)
	}
}

func auditLogger(t *testing.T, db *store.DB) *audit.Logger {
	t.Helper()
	return audit.NewLogger(db.Audit(), nil, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
}
