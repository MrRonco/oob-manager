package fwcatalog

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/catalogtest"
	"oob-manager/internal/firmware/catalog/dell"
	"oob-manager/internal/store"
)

type fixture struct {
	db   *store.DB
	im   Importer
	key  catalogtest.Key
	want catalog.Want
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "oob.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := catalogtest.RSAKey(t)
	src, err := dell.NewSource(key.PublicArmored(t))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{db: db, key: key, want: catalog.Want{
		SystemIDs: map[string]bool{catalogtest.SystemIDNew: true},
		Models:    map[string]bool{catalog.NormalizeModel(catalogtest.ModelOld): true}}}
	f.im = Importer{Source: src, Repo: db.Catalog(), Dir: filepath.Join(t.TempDir(), "catalog", "dell"),
		Limits: catalog.DefaultLimits(), Want: func(context.Context) (catalog.Want, error) { return f.want, nil },
		Now: func() time.Time { return time.Unix(1800000000, 0) }}
	return f
}

func (f *fixture) stage(t *testing.T, data []byte) string {
	t.Helper()
	path, err := Stage(f.im.Dir, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *fixture) lastCheck(t *testing.T) store.CatalogCheckRow {
	t.Helper()
	cs, err := f.db.Catalog().Checks(context.Background(), "dell", 1)
	if err != nil || len(cs) != 1 {
		t.Fatalf("checks %v %v", cs, err)
	}
	return cs[0]
}

func TestImportSignedCatalog(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	data := catalogtest.Catalog()
	res, err := f.im.Import(ctx, Input{Origin: OriginCLI, File: f.stage(t, data), Sig: f.key.Sign(t, data), By: "alice",
		ETag: `"abc"`})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != store.CatalogActive || res.Kept != 9 || res.Components != 39 || res.Signer.Fingerprint != f.key.Fingerprint() ||
		res.Manifest.Version != "26.10.22" || len(res.SHA256) != 64 {
		t.Fatalf("result %+v", res)
	}
	imp, ok, _ := f.db.Catalog().Import(ctx, "dell", store.CatalogActive)
	if !ok || imp.ImportedBy != "alice" || imp.Origin != "cli" || imp.ETag != `"abc"` || imp.Kept != 9 {
		t.Fatalf("import %+v", imp)
	}
	models, _ := f.db.Catalog().Models(ctx, imp.ID)
	if len(models) != 2 {
		t.Fatalf("models %+v", models)
	}
	for _, name := range []string{res.SHA256 + ".xml.gz", res.SHA256 + ".xml.gz.sign"} {
		st, err := os.Stat(filepath.Join(f.im.Dir, name))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("cached %s: %v %v", name, st, err)
		}
	}
	if c := f.lastCheck(t); c.Result != "imported" || c.ImportID != res.ImportID {
		t.Fatalf("check %+v", c)
	}
}

func TestImportFailuresKeepThePreviousCatalog(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	data := catalogtest.Catalog()
	first, err := f.im.Import(ctx, Input{Origin: OriginCLI, File: f.stage(t, data), Sig: f.key.Sign(t, data)})
	if err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(data)
	flipped[len(flipped)/3] ^= 1
	other := catalogtest.NewRSAKey(t)
	cases := []struct {
		name, class string
		in          Input
	}{
		{"tampered", "signature", Input{Origin: OriginOnline, File: f.stage(t, flipped), Sig: f.key.Sign(t, data)}},
		{"unknown key", "untrusted_key", Input{Origin: OriginOnline, File: f.stage(t, data), Sig: other.Sign(t, data)}},
		{"unsigned", "signature", Input{Origin: OriginUpload, File: f.stage(t, data)}},
		{"not gzip", "parse", Input{Origin: OriginCLI, File: f.stage(t, []byte("junk")), Sig: f.key.Sign(t, []byte("junk"))}},
	}
	for _, c := range cases {
		_, err := f.im.Import(ctx, c.in)
		if catalog.Class(err) != c.class {
			t.Errorf("%s: %v (class %q)", c.name, err, catalog.Class(err))
		}
		if _, statErr := os.Stat(c.in.File); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s: the staged file was left behind", c.name)
		}
		if chk := f.lastCheck(t); chk.Result != c.class || chk.Detail == "" {
			t.Errorf("%s: check %+v", c.name, chk)
		}
		if imp, _, _ := f.db.Catalog().Import(ctx, "dell", store.CatalogActive); imp.ID != first.ImportID {
			t.Errorf("%s: the active catalog changed to %+v", c.name, imp)
		}
	}
}

func TestImportUnsignedOnlyWhenAllowed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.im.AllowUnsigned = true
	data := catalogtest.Catalog()
	if _, err := f.im.Import(ctx, Input{Origin: OriginOnline, File: f.stage(t, data)}); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("unsigned online catalog: %v", err)
	}
	res, err := f.im.Import(ctx, Input{Origin: OriginUpload, File: f.stage(t, data), Sig: []byte("  \n")})
	if err != nil || res.Signer.Fingerprint != "" {
		t.Fatalf("allowed unsigned upload: %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(f.im.Dir, res.SHA256+".xml.gz.sign")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an unsigned import has a .sign file")
	}
	if err := f.im.Reparse(ctx); err != nil {
		t.Fatalf("reparse of an unsigned import: %v", err)
	}
}

func TestShrinkHoldAndReparse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	data := catalogtest.Catalog()
	if _, err := f.im.Import(ctx, Input{Origin: OriginCLI, File: f.stage(t, data), Sig: f.key.Sign(t, data)}); err != nil {
		t.Fatal(err)
	}
	// A catalog that keeps far fewer rows (only the iDRAC8 system's one entry) is held.
	smaller := catalogtest.Encode(strings.ReplaceAll(catalogtest.XML(), `systemID="088F"`, `systemID="0999"`))
	res, err := f.im.Import(ctx, Input{Origin: OriginOnline, File: f.stage(t, smaller), Sig: f.key.Sign(t, smaller)})
	if err != nil || res.State != store.CatalogHeld || res.Kept != 1 || res.Previous != 9 {
		t.Fatalf("held: %+v %v", res, err)
	}
	if c := f.lastCheck(t); c.Result != "held" {
		t.Fatalf("check %+v", c)
	}
	entries, _ := os.ReadDir(f.im.Dir)
	if len(entries) != 4 { // active and held, each .gz + .sign
		t.Fatalf("cache %d files", len(entries))
	}
	// The fleet loses the iDRAC9 server: re-parsing the cached files needs no network.
	f.want = catalog.Want{Models: map[string]bool{catalog.NormalizeModel(catalogtest.ModelOld): true}}
	if err := f.im.Reparse(ctx); err != nil {
		t.Fatal(err)
	}
	act, _, _ := f.db.Catalog().Import(ctx, "dell", store.CatalogActive)
	if act.Kept != 1 {
		t.Fatalf("kept after reparse %d", act.Kept)
	}
	// A cached file that no longer verifies is reported, not re-read.
	if err := os.WriteFile(filepath.Join(f.im.Dir, act.SHA256+".xml.gz"), smaller, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.im.Reparse(ctx); catalog.Class(err) != "signature" {
		t.Fatalf("tampered cache: %v", err)
	}
	// A signed import whose cached signature is gone stays refused, even with
	// allow_unsigned set: it was signed at import.
	if err := os.WriteFile(filepath.Join(f.im.Dir, act.SHA256+".xml.gz"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.im.Dir, act.SHA256+".xml.gz.sign")); err != nil {
		t.Fatal(err)
	}
	f.im.AllowUnsigned = true
	if err := f.im.Reparse(ctx); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("missing cached signature: %v", err)
	}
}

func TestStageCapsTheSize(t *testing.T) {
	dir := t.TempDir()
	if _, err := Stage(dir, bytes.NewReader(make([]byte, MaxCatalogBytes+1))); !errors.Is(err, catalog.ErrSize) {
		t.Fatalf("oversize: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left behind %d files", len(entries))
	}
	f := newFixture(t)
	f.im.Record(context.Background(), "not_modified", nil)
	if c := f.lastCheck(t); c.Result != "not_modified" || c.Detail != "" {
		t.Fatalf("recorded %+v", c)
	}
}

type fakeScans []store.FirmwareScanRow

func (f fakeScans) Scans(context.Context) ([]store.FirmwareScanRow, error) { return f, nil }

func TestFleetWantAndAudit(t *testing.T) {
	scans := fakeScans{{ServerID: "a", SystemID: "088F"}, {ServerID: "b", Model: "PowerEdge R7xx"},
		{ServerID: "c", Model: "PowerEdge X1"}, {ServerID: "d"}}
	w, err := FleetWant(scans, map[string]string{"c": "0A01"})(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !w.SystemIDs["088F"] || !w.SystemIDs["0A01"] || !w.Models["POWEREDGE R7XX"] || w.Models["POWEREDGE X1"] || len(w.Models) != 1 {
		t.Fatalf("want %+v", w)
	}
	f := newFixture(t)
	var entries []audit.Entry
	f.im.Audit = func(_ context.Context, e audit.Entry) { entries = append(entries, e) }
	data := catalogtest.Catalog()
	if _, err := f.im.Import(context.Background(), Input{Origin: OriginCLI, File: f.stage(t, data), Sig: f.key.Sign(t, data),
		By: "cli", AuthMethod: "cli"}); err != nil {
		t.Fatal(err)
	}
	_, _ = f.im.Import(context.Background(), Input{Origin: OriginOnline, File: f.stage(t, data)})
	if len(entries) != 2 || entries[0].Action != "firmware.catalog.imported" || entries[0].Principal != "cli" ||
		entries[0].Params["kept"] != 9 || entries[1].Action != "firmware.catalog.failed" || entries[1].ErrorClass != "signature" ||
		entries[1].Principal != "system" || entries[1].AuthMethod != "system" {
		t.Fatalf("audit %+v", entries)
	}
}
