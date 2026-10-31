package store

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/fstest"
)

// productionSchema is the migration level of the deployed v0.4.0 install (0001–0005).
const productionSchema = 5

// headSchema is the newest migration: 0006 servers, 0007 display defaults (S3),
// 0008 notifications (renumbered from the notifications branch's 0007 at integration), 0009
// maintenance mode, notes and acknowledgements (replaces notify_mutes), 0010 the
// open-ended maintenance reminder (tech_doc §30), 0011 the BMC security checks (§31),
// 0012 the Integrations keys (settings_kv rebuild, §34), 0013 BMC restarts (§37), 0014 the
// firmware view (§38), 0015 the sensor history (settings_kv rebuild again, §39), 0016 the
// Dell firmware states fix (§38), 0017 the firmware update checker (plan 08; settings_kv rebuild),
// 0018 ui.instance_name in General (settings_kv rebuild).
const headSchema = 18

// v050Schema is the migration level of the deployed v0.5.0 install (0001–0008).
const v050Schema = 8

// migrationsUpTo is the embedded migration set cut at version upTo, i.e. what an older
// binary carried.
func migrationsUpTo(t *testing.T, upTo int) fstest.MapFS {
	t.Helper()
	sub, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	all, err := readMigrations(sub)
	if err != nil {
		t.Fatal(err)
	}
	out := fstest.MapFS{}
	for _, m := range all {
		if m.version <= upTo {
			out[m.name] = &fstest.MapFile{Data: []byte(m.sql)}
		}
	}
	return out
}

// TestUpgradeFromProductionSchema starts from a database at schema 0005 (as deployed in
// production v0.4.0) holding a user, a session, an audit row, a saved setting and display
// preferences, migrates it to head with Open, and checks that everything survived.
func TestUpgradeFromProductionSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, productionSchema)); err != nil {
		t.Fatalf("migrate to %d: %v", productionSchema, err)
	}
	seed := []string{
		`INSERT INTO users (id, username, role, pw_hash, created_at) VALUES ('u1', 'morgan', 'admin', 'h', 1)`,
		`INSERT INTO sessions (id_hash, user_id, created_at, last_seen) VALUES (x'01', 'u1', 1, 2)`,
		`INSERT INTO audit_log (seq, ts, correlation_id, principal, auth_method, role, src_ip, server_id, action,
			params_json, result, bmc_status, error_class, prev_hash, row_hash)
			VALUES (1, 1, 'c', 'morgan', 'local', 'admin', '', '', 'app.start', '{}', 'ok', '', '', '', 'r1')`,
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('ui.theme', '"nord"', 3, 'morgan')`,
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('poll.interval', '"2m0s"', 3, 'morgan')`,
		`UPDATE settings_rev SET rev = 7`,
		`INSERT INTO user_prefs (user_id, time_zone, clock, updated_at) VALUES ('u1', 'America/New_York', '12h', 4)`,
	}
	for _, q := range seed {
		if _, err = old.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade to head: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if v, err := db.SchemaVersion(ctx); err != nil || v != headSchema {
		t.Fatalf("schema = %d, %v; want %d", v, err, headSchema)
	}
	checks := map[string]string{
		`SELECT username FROM users WHERE id = 'u1'`:                            "morgan",
		`SELECT user_id FROM sessions WHERE id_hash = x'01'`:                    "u1",
		`SELECT row_hash FROM audit_log WHERE seq = 1`:                          "r1",
		`SELECT value_json FROM settings_kv WHERE key = 'ui.theme'`:             `"nord"`,
		`SELECT value_json FROM settings_kv WHERE key = 'poll.interval'`:        `"2m0s"`,
		`SELECT CAST(rev AS TEXT) FROM settings_rev`:                            "7",
		`SELECT time_zone || ' ' || clock FROM user_prefs WHERE user_id = 'u1'`: "America/New_York 12h",
	}
	for q, want := range checks {
		var got string
		if err := db.sql.QueryRowContext(ctx, q).Scan(&got); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", q, got, err, want)
		}
	}
	for _, table := range []string{"servers", "bmc_credentials", "notify_targets", "server_maintenance",
		"server_notes", "event_acks", "security_accepts", "security_notified", "bmc_resets", "firmware_components",
		"firmware_changes", "firmware_scans", "sensor_keys", "sensor_raw", "sensor_hourly", "sensor_daily",
		"history_meta"} {
		var n int
		if err := db.sql.QueryRowContext(ctx,
			`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil || n != 1 {
			t.Errorf("table %s missing after upgrade (%d, %v)", table, n, err)
		}
	}
	// The rebuilt settings_kv (0007) accepts the S3 display-default keys.
	if _, err := db.sql.ExecContext(ctx,
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('ui.density', '"comfortable"', 5, 'morgan')`); err != nil {
		t.Errorf("new display key refused after upgrade: %v", err)
	}
	// The audit log is still append-only after the rebuilds.
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Error("audit_log delete allowed after upgrade")
	}
}

// TestMigrationVersionsAreDense: the integration renumbered the notifications migration
// to 0008 after S3's 0006 and 0007 (0009 is maintenance, 0010 its reminder, 0011 the security
// checks, 0012 the Integrations keys, 0013 BMC restarts, 0014 the firmware view, 0015 the sensor history, 0016 the firmware states fix); every version from 1 to head exists exactly once.
func TestMigrationVersionsAreDense(t *testing.T) {
	sub, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	all, err := readMigrations(sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != headSchema {
		t.Fatalf("%d migrations, want %d", len(all), headSchema)
	}
	for i, m := range all {
		if m.version != i+1 {
			t.Fatalf("migration %s has version %d, want %d", m.name, m.version, i+1)
		}
	}
	if all[headSchema-1].name != "0018_instance_name.sql" {
		t.Fatalf("head migration = %s", all[headSchema-1].name)
	}
}
