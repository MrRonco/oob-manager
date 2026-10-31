package store

import (
	"context"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"
)

// firmwareSchema is the level before the history migration (0014, the firmware view).
const firmwareSchema = 14

// TestUpgradeCopiesSensorSamples migrates a schema-0014 database holding the old
// sensor_samples rows: every known key is copied into sensor_keys with its kind and
// unit from the prefix and its first and last timestamps, the values into sensor_raw,
// unknown prefixes are dropped, the old table and index are gone, and saved settings
// survive the settings_kv rebuild.
func TestUpgradeCopiesSensorSamples(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, firmwareSchema)); err != nil {
		t.Fatalf("migrate to %d: %v", firmwareSchema, err)
	}
	for _, q := range []string{
		`INSERT INTO sensor_samples VALUES ('r1', 1000, 'temp:1', 40.5), ('r1', 2000, 'temp:1', 41),
			('r1', 1000, 'fan:Fan1', 7000), ('r1', 1000, 'power:consumed', 240), ('r2', 1500, 'temp:Inlet', 21),
			('r1', 1000, 'mystery:1', 3), ('r1', 1000, 'temp:', 3)`,
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('gelf.enabled', 'true', 4, 'alice')`,
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
	keys, err := db.History().Keys(ctx, "")
	if err != nil || len(keys) != 4 {
		t.Fatalf("keys = %+v, %v; want 4 (unknown prefixes dropped)", keys, err)
	}
	want := map[string]struct {
		kind SensorKind
		unit SensorUnit
	}{"r1/temp:1": {SensorTemp, UnitCelsius}, "r1/fan:Fan1": {SensorFan, UnitRPM},
		"r1/power:consumed": {SensorPower, UnitWatts}, "r2/temp:Inlet": {SensorTemp, UnitCelsius}}
	for _, k := range keys {
		w, ok := want[k.ServerID+"/"+k.Key]
		if !ok || k.Kind != w.kind || k.Unit != w.unit || k.Name != "" {
			t.Errorf("key %+v", k)
		}
		if k.Key == "temp:1" && (k.First.UnixMilli() != 1000 || k.Last.UnixMilli() != 2000) {
			t.Errorf("temp:1 first/last = %v/%v", k.First, k.Last)
		}
	}
	pts, err := db.History().Raw(ctx, keyID(t, db.History(), "r1", "temp:1"), time.UnixMilli(0), time.UnixMilli(5000), time.Time{}, 10)
	if err != nil || len(pts) != 2 || pts[0].Value != 40.5 {
		t.Errorf("raw = %+v, %v", pts, err)
	}
	var n int
	if err = db.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name LIKE 'sensor_samples%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("sensor_samples left behind: %d, %v", n, err)
	}
	var v string
	if err = db.sql.QueryRowContext(ctx, `SELECT value_json FROM settings_kv WHERE key = 'gelf.enabled'`).Scan(&v); err != nil || v != "true" {
		t.Errorf("saved setting lost: %q, %v", v, err)
	}
}

// TestUpgradeFromV072WithSamples migrates a v0.7.x database (schema 11) holding samples
// and saved settings straight to head: the samples are in the history (count, sum, first
// and last per server and sensor), the settings survive both settings_kv rebuilds, and
// the head accepts the history keys.
func TestUpgradeFromV072WithSamples(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, v072Schema)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err = old.ExecContext(ctx, `INSERT INTO sensor_samples VALUES ('r1', ?, 'temp:1', ?), ('r2', ?, 'fan:Fan1', 7000)`,
			1000+i*60000, float64(i), 1000+i*60000); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = old.ExecContext(ctx, `INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('ui.density', '"comfortable"', 3, 'alice')`); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var n, sum, first, last float64
	if err = db.sql.QueryRowContext(ctx, `SELECT count(*), sum(value), min(ts), max(ts) FROM sensor_raw r
		JOIN sensor_keys k ON k.id = r.key_id WHERE k.server_id = 'r1' AND k.key = 'temp:1'`).Scan(&n, &sum, &first, &last); err != nil ||
		n != 50 || sum != 1225 || first != 1000 || last != 1000+49*60000 {
		t.Fatalf("r1 temp:1 = %v %v %v %v, %v", n, sum, first, last, err)
	}
	if err = db.Settings().Put(ctx, SettingRow{Key: "history.raw_days", ValueJSON: "3", UpdatedAt: t0, UpdatedBy: "alice"}); err != nil {
		t.Errorf("history key refused after the upgrade: %v", err)
	}
	var v string
	if err = db.sql.QueryRowContext(ctx, `SELECT value_json FROM settings_kv WHERE key = 'ui.density'`).Scan(&v); err != nil || v != `"comfortable"` {
		t.Errorf("saved setting = %q, %v", v, err)
	}
}

// TestFailedHistoryMigrationKeepsTheSamples: a 0015 that fails after the copy rolls back
// as a whole: sensor_samples and its rows are still there, the new tables are not, and
// the schema stays at 14.
func TestFailedHistoryMigrationKeepsTheSamples(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	db, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = migrate(ctx, db, migrationsUpTo(t, firmwareSchema)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO sensor_samples VALUES ('r1', 1000, 'temp:1', 40)`); err != nil {
		t.Fatal(err)
	}
	broken := migrationsUpTo(t, 15)
	f := broken["0015_history.sql"]
	broken["0015_history.sql"] = &fstest.MapFile{Data: append(append([]byte{}, f.Data...), []byte("\nINSERT INTO no_such_table VALUES (1);\n")...)}
	if err = migrate(ctx, db, broken); err == nil {
		t.Fatal("the broken migration succeeded")
	}
	var n int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM sensor_samples`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("sensor_samples after the rollback: %d, %v", n, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name = 'sensor_keys'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("sensor_keys left behind: %d, %v", n, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&n); err != nil || n != 14 {
		t.Fatalf("schema = %d, %v", n, err)
	}
}
