package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oob-manager/internal/firmware/catalog/catalogtest"
	"oob-manager/internal/store"
)

// catalogDeployment is a deployment whose config.yaml trusts the test key.
func catalogDeployment(t *testing.T, extra string) (deployment, catalogtest.Key) {
	t.Helper()
	d := newDeployment(t, "")
	key := catalogtest.RSAKey(t)
	keys := filepath.Join(d.dir, "catalog-keys.asc")
	write(t, keys, key.PublicArmored(t))
	f, err := os.OpenFile(d.configPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("firmware:\n  catalog:\n    extra_keys_file: " + keys + "\n" + extra)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	return d, key
}

func TestCatalogImportCLI(t *testing.T) {
	d, key := catalogDeployment(t, "")
	data := catalogtest.Catalog()
	gz, sig := filepath.Join(d.dir, "c.xml.gz"), filepath.Join(d.dir, "c.xml.gz.sign")
	write(t, gz, data)
	write(t, sig, key.Sign(t, data))
	rc, out, errOut := runCLI(t, "catalog", "import", "-config", d.configPath, gz, sig)
	if rc != 0 || !strings.Contains(out, "Imported catalog 26.10.22") || !strings.Contains(out, "signed by "+key.Fingerprint()) {
		t.Fatalf("import: %d out %q err %q", rc, out, errOut)
	}
	db, err := store.Open(context.Background(), d.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	imp, ok, _ := db.Catalog().Import(context.Background(), "dell", store.CatalogActive)
	recs, _ := db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: "firmware.catalog.imported", Limit: 10})
	_ = db.Close()
	if !ok || imp.Origin != "cli" || imp.ImportedBy != "cli" || len(recs) != 1 || recs[0].Principal != "cli" {
		t.Fatalf("import %+v audit %+v", imp, recs)
	}
	if _, err := os.Stat(filepath.Join(d.dir, "catalog", "dell", imp.SHA256+".xml.gz")); err != nil {
		t.Fatalf("not cached next to the database: %v", err)
	}
	// Unsigned is refused by default.
	if rc, _, errOut = runCLI(t, "catalog", "import", "-config", d.configPath, gz); rc == 0 ||
		!strings.Contains(errOut, "nothing imported (signature)") {
		t.Fatalf("unsigned: %d %q", rc, errOut)
	}
}

func TestCatalogImportCLIUnsignedAllowedAndUsage(t *testing.T) {
	d, _ := catalogDeployment(t, "    allow_unsigned: true\n")
	gz := filepath.Join(d.dir, "c.xml.gz")
	write(t, gz, catalogtest.Catalog())
	rc, out, errOut := runCLI(t, "catalog", "import", "-config", d.configPath, gz)
	if rc != 0 || !strings.Contains(out, "unsigned (accepted by firmware.catalog.allow_unsigned)") {
		t.Fatalf("allowed unsigned: %d %q %q", rc, out, errOut)
	}
	for _, args := range [][]string{
		{"catalog"}, {"catalog", "export"}, {"catalog", "import", "-config", d.configPath},
		{"catalog", "import", "-config", d.configPath, "a", "b", "c"},
		{"catalog", "import", "-config", d.configPath, filepath.Join(d.dir, "missing.gz")},
		{"catalog", "import", "-config", d.configPath, gz, filepath.Join(d.dir, "missing.sign")},
	} {
		if rc, _, _ := runCLI(t, args...); rc == 0 {
			t.Errorf("%v: exit 0", args)
		}
	}
	if _, err := readCapped(gz, 10); err == nil {
		t.Error("readCapped did not cap")
	}
}
