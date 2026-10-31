package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"oob-manager/internal/config"
)

// v072Schema is the migration level of v0.7.x (0001–0011).
const v072Schema = 11

// TestSettingsKVAcceptsEveryKnownKey: the settings_kv CHECK list (rebuilt by 0012, and
// by any later rebuild) accepts every runtime-managed key the code knows, General and
// Integrations alike, and still refuses an unknown one. A rebuild that drops a key
// would make saving it from the browser fail.
func TestSettingsKVAcceptsEveryKnownKey(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	keys := append(config.GeneralKeys(), config.IntegrationKeys()...)
	for _, k := range keys {
		row := SettingRow{Key: k, ValueJSON: `"x"`, UpdatedAt: time.Unix(1, 0), UpdatedBy: "alice"}
		if err := db.Settings().Put(ctx, row); err != nil {
			t.Errorf("key %s refused: %v", k, err)
		}
	}
	if err := db.Settings().Put(ctx, SettingRow{Key: "gelf.queue", ValueJSON: "1", UpdatedAt: time.Unix(1, 0),
		UpdatedBy: "alice"}); err == nil {
		t.Error("an unknown key was accepted")
	}
	rows, err := db.Settings().All(ctx)
	if err != nil || len(rows) != len(keys) {
		t.Fatalf("rows %d, %v; want %d", len(rows), err, len(keys))
	}
}

// TestUpgradeFromV072Schema migrates a schema-0011 database (v0.7.x) to head: saved
// General and GELF settings and the revision survive the settings_kv rebuild, and the
// new GELF keys are accepted.
func TestUpgradeFromV072Schema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, v072Schema)); err != nil {
		t.Fatalf("migrate to %d: %v", v072Schema, err)
	}
	for _, q := range []string{
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('ui.density', '"comfortable"', 3, 'alice')`,
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('gelf.address', '"192.0.2.30:12201"', 4, 'alice')`,
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('gelf.enabled', 'true', 4, 'alice')`,
		`UPDATE settings_rev SET rev = 9`,
	} {
		if _, err = old.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	if _, err = old.ExecContext(ctx, `INSERT INTO settings_kv (key, value_json, updated_at, updated_by)
		VALUES ('gelf.pin_sha256', '"x"', 5, 'alice')`); err == nil {
		t.Fatal("schema 0011 already accepts gelf.pin_sha256; the test no longer proves the rebuild")
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade to head: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if v, verr := db.SchemaVersion(ctx); verr != nil || v != headSchema {
		t.Fatalf("schema = %d, %v; want %d", v, verr, headSchema)
	}
	rows, err := db.Settings().All(ctx)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %+v %v", rows, err)
	}
	if rev, rerr := db.Settings().Rev(ctx); rerr != nil || rev != 9 {
		t.Fatalf("rev %d %v", rev, rerr)
	}
	for _, k := range []string{"gelf.transport", "gelf.server_name", "gelf.pin_sha256"} {
		if err := db.Settings().Put(ctx, SettingRow{Key: k, ValueJSON: `"v"`, UpdatedAt: time.Unix(6, 0), UpdatedBy: "alice"}); err != nil {
			t.Errorf("%s refused after upgrade: %v", k, err)
		}
	}
}
