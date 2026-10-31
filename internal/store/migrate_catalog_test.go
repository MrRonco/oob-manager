package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// fwStatesSchema is the level before the update checker (0016, the firmware states fix).
const fwStatesSchema = 16

// TestUpgradeAddsFirmwareCatalog migrates a schema-0016 database: saved settings survive
// the settings_kv rebuild and the firmware.catalog keys are accepted, an existing scan
// row gets an empty system_id, and the new tables are empty.
func TestUpgradeAddsFirmwareCatalog(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, fwStatesSchema)); err != nil {
		t.Fatalf("migrate to %d: %v", fwStatesSchema, err)
	}
	for _, q := range []string{
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('history.raw_days', '14', 1000, 'alice')`,
		`INSERT INTO firmware_scans (server_id, scanned_at, listed, components, complete, docs_read, docs_failed, model)
			VALUES ('r1', 1000, 20, 15, 1, 15, 0, 'PowerEdge R7xx')`,
	} {
		if _, err = old.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rows, err := db.Settings().All(ctx)
	if err != nil || len(rows) != 1 || rows[0].Key != "history.raw_days" || rows[0].ValueJSON != "14" {
		t.Fatalf("settings %+v %v", rows, err)
	}
	for _, k := range []string{"firmware.catalog.enabled", "firmware.catalog.check_every", "firmware.catalog.notify"} {
		if err := db.Settings().Put(ctx, SettingRow{Key: k, ValueJSON: "true", UpdatedAt: time.Unix(2, 0), UpdatedBy: "bob"}); err != nil {
			t.Errorf("%s refused: %v", k, err)
		}
	}
	var sys string
	if err := db.sql.QueryRowContext(ctx, `SELECT system_id FROM firmware_scans WHERE server_id = 'r1'`).Scan(&sys); err != nil || sys != "" {
		t.Fatalf("system_id %q %v", sys, err)
	}
	if imps, err := db.Catalog().Imports(ctx, "dell", 10); err != nil || len(imps) != 0 {
		t.Fatalf("imports %v %v", imps, err)
	}
}
