-- 0012: Settings → Integrations (docs/tech_doc.md §34). The GELF target gains a
-- transport, a TLS server name and a pin, saved from the browser like the other
-- runtime-managed keys. SQLite cannot change a CHECK, so settings_kv is rebuilt with
-- the full key list: every key of 0005 and 0007 is listed again, plus the three new
-- ones (store.TestSettingsKVAcceptsEveryKnownKey checks the list against the code).
CREATE TABLE settings_kv_new (
    key        TEXT    PRIMARY KEY CHECK (key IN (
        'poll.interval', 'poll.stale_multiplier', 'auth.session_idle', 'auth.session_max',
        'auth.stepup_window', 'ratelimit.login_ip_per_min', 'ratelimit.login_acct_per_hour',
        'ui.time_zone', 'ui.theme', 'ui.clock_format', 'ui.date_format', 'ui.temperature_unit',
        'ui.density', 'gelf.address', 'gelf.enabled', 'gelf.transport', 'gelf.server_name',
        'gelf.pin_sha256')),
    value_json TEXT    NOT NULL CHECK (json_valid(value_json)),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL CHECK (updated_by <> '')
) STRICT;
INSERT INTO settings_kv_new (key, value_json, updated_at, updated_by)
    SELECT key, value_json, updated_at, updated_by FROM settings_kv;
DROP TABLE settings_kv;
ALTER TABLE settings_kv_new RENAME TO settings_kv;
