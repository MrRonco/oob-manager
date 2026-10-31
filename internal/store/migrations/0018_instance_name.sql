-- 0018: Settings → General gains ui.instance_name (v0.9.1), so the installation's label
-- can be set from the browser. SQLite cannot change a CHECK, so settings_kv is rebuilt
-- with every key of 0017 plus ui.instance_name (store.TestSettingsKVAcceptsEveryKnownKey
-- checks the list against the code).
CREATE TABLE settings_kv_new (
    key        TEXT    PRIMARY KEY CHECK (key IN (
        'poll.interval', 'poll.stale_multiplier', 'auth.session_idle', 'auth.session_max',
        'auth.stepup_window', 'ratelimit.login_ip_per_min', 'ratelimit.login_acct_per_hour',
        'ui.time_zone', 'ui.theme', 'ui.clock_format', 'ui.date_format', 'ui.temperature_unit',
        'ui.density', 'gelf.address', 'gelf.enabled', 'gelf.transport', 'gelf.server_name',
        'gelf.pin_sha256', 'history.raw_days', 'history.hourly_days', 'history.daily_days',
        'history.sample_psus', 'history.sample_voltages', 'firmware.catalog.enabled',
        'firmware.catalog.check_every', 'firmware.catalog.notify', 'ui.instance_name')),
    value_json TEXT    NOT NULL CHECK (json_valid(value_json)),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL CHECK (updated_by <> '')
) STRICT;
INSERT INTO settings_kv_new (key, value_json, updated_at, updated_by)
    SELECT key, value_json, updated_at, updated_by FROM settings_kv;
DROP TABLE settings_kv;
ALTER TABLE settings_kv_new RENAME TO settings_kv;
