package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func catImport(state string, at time.Time) CatalogImportRow {
	return CatalogImportRow{Source: "dell", Origin: "online", State: state, Version: "26.10.22", ReleaseID: "R1",
		PublishedAt: at.Add(-time.Hour), ImportedAt: at, SHA256: strings.Repeat("a", 64), Signer: "FP", ETag: `"e"`,
		LastModified: "Thu", Components: 1005, ImportedBy: "system"}
}

func catRelease(system, component, version string) CatalogReleaseRow {
	return CatalogReleaseRow{SystemID: system, ComponentID: component, Version: version, Criticality: 2,
		ReleasedAt: time.Unix(1700000000, 0).UTC(), Name: "BIOS", DetailsURL: "https://www.dell.com/x", RebootRequired: true}
}

func TestCatalogImportLifecycle(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := db.Catalog()
	now := time.Unix(1800000000, 0).UTC()

	if _, ok, err := repo.Import(ctx, "dell", CatalogActive); ok || err != nil {
		t.Fatalf("no import yet: %v %v", ok, err)
	}
	first, err := repo.SaveImport(ctx, catImport(CatalogActive, now), []CatalogReleaseRow{
		catRelease("088F", "159", "2.25.2"), catRelease("088F", "25227", "7.00.00.185")},
		[]CatalogModelRow{{SystemID: "088F", Model: "PowerEdge R1"}, {SystemID: "0627", Model: "PowerEdge R7xx"}})
	if err != nil {
		t.Fatal(err)
	}
	act, ok, err := repo.Import(ctx, "dell", CatalogActive)
	if err != nil || !ok || act.ID != first || act.Kept != 2 || act.Signer != "FP" || !act.PublishedAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("active %+v %v %v", act, ok, err)
	}
	rels, err := repo.Releases(ctx, first)
	if err != nil || len(rels) != 2 || rels[0].ComponentID != "159" || !rels[0].RebootRequired || rels[0].Criticality != 2 {
		t.Fatalf("releases %+v %v", rels, err)
	}

	// A held import leaves the active one in place.
	if ms, merr := repo.Models(ctx, first); merr != nil || len(ms) != 2 || ms[0].SystemID != "0627" || ms[0].Model != "PowerEdge R7xx" {
		t.Fatalf("models %+v %v", ms, merr)
	}
	held, err := repo.SaveImport(ctx, catImport(CatalogHeld, now.Add(time.Hour)), []CatalogReleaseRow{catRelease("088F", "159", "2.26.0")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if act, _, _ := repo.Import(ctx, "dell", CatalogActive); act.ID != first {
		t.Fatalf("a held import replaced the active one: %+v", act)
	}
	if h, ok, _ := repo.Import(ctx, "dell", CatalogHeld); !ok || h.ID != held {
		t.Fatalf("held %+v", h)
	}
	// Activating it replaces the old active import, whose releases go.
	if ok, err := repo.ActivateHeld(ctx, "dell", held); !ok || err != nil {
		t.Fatalf("activate: %v %v", ok, err)
	}
	if act, _, _ := repo.Import(ctx, "dell", CatalogActive); act.ID != held {
		t.Fatalf("active after confirm %+v", act)
	}
	if rels, _ := repo.Releases(ctx, first); len(rels) != 0 {
		t.Fatalf("replaced import kept releases: %+v", rels)
	}
	if ms, _ := repo.Models(ctx, first); len(ms) != 0 {
		t.Fatalf("replaced import kept models: %+v", ms)
	}
	if ok, err := repo.ActivateHeld(ctx, "dell", held); ok || err != nil {
		t.Fatalf("nothing held: %v %v", ok, err)
	}

	// A local re-parse replaces the releases and the kept count.
	if err := repo.ReplaceReleases(ctx, held, []CatalogReleaseRow{catRelease("0627", "159", "2.19.0"),
		catRelease("088F", "159", "2.26.0"), catRelease("088F", "159", "2.21.0")},
		[]CatalogModelRow{{SystemID: "0627", Model: "PowerEdge R7xx"}}); err != nil {
		t.Fatal(err)
	}
	if act, _, _ := repo.Import(ctx, "dell", CatalogActive); act.Kept != 3 {
		t.Fatalf("kept %d", act.Kept)
	}
	if ms, _ := repo.Models(ctx, held); len(ms) != 1 {
		t.Fatalf("models after re-parse %+v", ms)
	}
	if err := repo.ReplaceReleases(ctx, first, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-parse of a replaced import: %v", err)
	}
	if _, err := repo.SaveImport(ctx, catImport(CatalogReplaced, now), nil, nil); err == nil {
		t.Fatal("a replaced import was saved")
	}
	bad := catRelease("088F", "159", "x")
	bad.Criticality = 9
	if _, err := repo.SaveImport(ctx, catImport(CatalogActive, now), []CatalogReleaseRow{bad}, nil); err == nil {
		t.Fatal("criticality 9 stored")
	}
}

func TestCatalogImportsPruned(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Unix(1800000000, 0).UTC()
	for i := range 25 {
		if _, err := db.Catalog().SaveImport(ctx, catImport(CatalogActive, now.Add(time.Duration(i)*time.Hour)),
			[]CatalogReleaseRow{catRelease("088F", "159", fmt.Sprintf("1.%d", i))}, nil); err != nil {
			t.Fatal(err)
		}
	}
	all, err := db.Catalog().Imports(ctx, "dell", 100)
	if err != nil || len(all) != catalogImportsKept || all[0].State != CatalogActive || all[1].State != CatalogReplaced {
		t.Fatalf("imports %d %v", len(all), err)
	}
	if _, err := db.Catalog().Imports(ctx, "dell", 0); err == nil {
		t.Error("limit 0 accepted")
	}
}

func TestCatalogChecksPruned(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Unix(1800000000, 0).UTC()
	old := CatalogCheckRow{Source: "dell", At: now.Add(-100 * 24 * time.Hour), Result: "download", Detail: "timeout"}
	if err := db.Catalog().AddCheck(ctx, old); err != nil {
		t.Fatal(err)
	}
	for i := range catalogChecksKept + 5 {
		if err := db.Catalog().AddCheck(ctx, CatalogCheckRow{Source: "dell", At: now.Add(time.Duration(i) * time.Second),
			Result: "not_modified", ImportID: int64(i % 2)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.Catalog().Checks(ctx, "dell", catalogChecksKept)
	if err != nil || len(got) != catalogChecksKept || got[0].At.Before(got[len(got)-1].At) {
		t.Fatalf("checks %d %v", len(got), err)
	}
	for _, c := range got {
		if c.Result == "download" {
			t.Fatal("a 100-day-old check survived")
		}
	}
	if err := db.Catalog().AddCheck(ctx, CatalogCheckRow{Source: "dell", At: now, Result: "bogus"}); err == nil {
		t.Error("an unknown result was stored")
	}
	if _, err := db.Catalog().Checks(ctx, "dell", 501); err == nil {
		t.Error("limit 501 accepted")
	}
}

func TestFirmwareUpdateSkipsAndNotified(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	repo := db.FirmwareUpdates()
	at := time.Unix(1800000000, 0).UTC()
	s := FirmwareUpdateSkipRow{ServerID: "r1", ComponentID: "159", Version: "2.25.2", Comment: "waiting for a window",
		SkippedBy: "alice", SkippedAt: at}
	if err := repo.PutSkip(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Version, s.Comment = "2.26.0", "again"
	if err := repo.PutSkip(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutSkip(ctx, FirmwareUpdateSkipRow{ServerID: "r1", ComponentID: "x", Version: "1", SkippedBy: "a",
		SkippedAt: at}); err == nil {
		t.Error("an empty comment was stored")
	}
	got, err := repo.Skips(ctx)
	if err != nil || len(got) != 1 || got[0] != s {
		t.Fatalf("skips %+v %v", got, err)
	}
	if ok, derr := repo.DeleteSkip(ctx, "r1", "159", ""); !ok || derr != nil {
		t.Fatalf("delete %v %v", ok, derr)
	}
	if ok, _ := repo.DeleteSkip(ctx, "r1", "159", ""); ok {
		t.Fatal("deleted twice")
	}
	n := []FirmwareUpdateNotifiedRow{{ServerID: "r1", ComponentID: "159", Version: "2.25.2", NotifiedAt: at},
		{ServerID: "r1", ComponentID: "25227", Version: "7.0", NotifiedAt: at}}
	fresh, err := repo.MarkNotified(ctx, n)
	if err != nil || len(fresh) != 2 {
		t.Fatalf("first %v %v", fresh, err)
	}
	fresh, _ = repo.MarkNotified(ctx, append(n, FirmwareUpdateNotifiedRow{ServerID: "r1", ComponentID: "159",
		Version: "2.26.0", NotifiedAt: at}))
	if len(fresh) != 1 || fresh[0].Version != "2.26.0" {
		t.Fatalf("second %v", fresh)
	}
	_ = repo.PutSkip(ctx, FirmwareUpdateSkipRow{ServerID: "r1", ComponentID: "159", Version: "1", Comment: "c", SkippedBy: "a", SkippedAt: at})
	if err := repo.DeleteServer(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.Skips(ctx); len(got) != 0 {
		t.Fatalf("skips after delete %+v", got)
	}
	if fresh, _ := repo.MarkNotified(ctx, n[:1]); len(fresh) != 1 {
		t.Fatal("notified rows survived DeleteServer")
	}
}
