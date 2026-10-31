package store

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// v050Seed is data a v0.5.0 install (schema 0008) holds: a user and session, an audit
// row, settings, preferences, a browser-managed server with a sealed credential, a
// notification target, an active and an expired notification mute.
func v050Seed(future int64) []string {
	return []string{
		`INSERT INTO users (id, username, role, pw_hash, created_at) VALUES ('u1', 'morgan', 'admin', 'h', 1)`,
		`INSERT INTO sessions (id_hash, user_id, created_at, last_seen) VALUES (x'01', 'u1', 1, 2)`,
		`INSERT INTO audit_log (seq, ts, correlation_id, principal, auth_method, role, src_ip, server_id, action,
			params_json, result, bmc_status, error_class, prev_hash, row_hash)
			VALUES (1, 1, 'c', 'morgan', 'local', 'admin', '', '', 'app.start', '{}', 'ok', '', '', '', 'r1')`,
		`INSERT INTO settings_kv (key, value_json, updated_at, updated_by) VALUES ('ui.density', '"compact"', 3, 'morgan')`,
		`INSERT INTO user_prefs (user_id, time_zone, clock, updated_at) VALUES ('u1', 'UTC', '24h', 4)`,
		`INSERT INTO servers (id, name, kind, address, port, enabled, created_at, created_by, updated_at, updated_by)
			VALUES ('lab1', 'Lab one', 'redfish', '192.0.2.10', 443, 1, 5, 'morgan', 5, 'morgan')`,
		`INSERT INTO bmc_credentials (server_id, slot, version, key_id, secret_enc, created_at, created_by)
			VALUES ('lab1', 'readonly', 3, 'v1', x'000102030405060708090a0b0c0d', 6, 'morgan')`,
		`INSERT INTO notify_targets (id, name, kind, url, enabled, options_json, subs_json, created_at, updated_at, updated_by)
			VALUES ('phone', 'Phone', 'ntfy', 'https://ntfy.example/t', 1, '{}', '{"classes":["health"]}', 7, 7, 'morgan')`,
		`INSERT INTO notify_mutes (server_id, muted_until, updated_at, updated_by) VALUES ('lab1', ` +
			strconv.FormatInt(future, 10) + `, 1000, 'morgan')`,
		`INSERT INTO notify_mutes (server_id, muted_until, updated_at, updated_by) VALUES ('gone', 2000, 1000, 'bob')`,
	}
}

// TestUpgradeFromV050Schema migrates a database at schema 0008 (as deployed in v0.5.0)
// to head: every row survives, the active mute becomes a maintenance window (no
// reminder sent yet), the expired one is dropped, and the reminder column works.
func TestUpgradeFromV050Schema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, v050Schema)); err != nil {
		t.Fatalf("migrate to %d: %v", v050Schema, err)
	}
	future := time.Now().Add(6 * time.Hour).UnixMilli()
	for _, q := range v050Seed(future) {
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
	if v, verr := db.SchemaVersion(ctx); verr != nil || v != headSchema {
		t.Fatalf("schema = %d, %v; want %d", v, verr, headSchema)
	}
	checks := map[string]string{
		`SELECT username FROM users WHERE id = 'u1'`:                                    "morgan",
		`SELECT user_id FROM sessions WHERE id_hash = x'01'`:                            "u1",
		`SELECT row_hash FROM audit_log WHERE seq = 1`:                                  "r1",
		`SELECT value_json FROM settings_kv WHERE key = 'ui.density'`:                   `"compact"`,
		`SELECT time_zone || ' ' || clock FROM user_prefs WHERE user_id = 'u1'`:         "UTC 24h",
		`SELECT name || ' ' || address || ':' || port FROM servers`:                     "Lab one 192.0.2.10:443",
		`SELECT slot || ' v' || version || ' ' || hex(secret_enc) FROM bmc_credentials`: "readonly v3 000102030405060708090A0B0C0D",
		`SELECT name || ' ' || subs_json FROM notify_targets WHERE id = 'phone'`:        `Phone {"classes":["health"]}`,
	}
	for q, want := range checks {
		var got string
		if qerr := db.sql.QueryRowContext(ctx, q).Scan(&got); qerr != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", q, got, qerr, want)
		}
	}
	ws, err := db.Maint().Windows(ctx)
	if err != nil || len(ws) != 1 {
		t.Fatalf("windows %+v %v", ws, err)
	}
	if w := ws[0]; w.ServerID != "lab1" || w.EndsAt.UnixMilli() != future || !w.StartedNotified || !w.RemindedAt.IsZero() ||
		w.CreatedBy != "morgan" {
		t.Fatalf("migrated window %+v", w)
	}
	if err := db.Maint().MarkReminded(ctx, "lab1", time.Now()); err != nil {
		t.Fatalf("reminder column: %v", err)
	}
	var n int
	if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name = 'notify_mutes'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("notify_mutes still present (%d, %v)", n, err)
	}
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Error("audit_log delete allowed after upgrade")
	}
}
