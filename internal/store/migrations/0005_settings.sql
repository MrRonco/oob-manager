-- 0005: settings slice S2 (docs/settings_design.md §4) and per-user display preferences.

-- Runtime-managed settings saved from the browser. Precedence is file > DB > default:
-- a key also written in config.yaml is ignored here. Values are JSON (durations as Go
-- duration strings, counts as numbers, names as strings). The key list includes the S4
-- integration keys so that slice needs no table rebuild.
CREATE TABLE settings_kv (
    key        TEXT    PRIMARY KEY CHECK (key IN (
        'poll.interval', 'poll.stale_multiplier', 'auth.session_idle', 'auth.session_max',
        'auth.stepup_window', 'ratelimit.login_ip_per_min', 'ratelimit.login_acct_per_hour',
        'ui.time_zone', 'ui.theme', 'gelf.address', 'gelf.enabled')),
    value_json TEXT    NOT NULL CHECK (json_valid(value_json)),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL CHECK (updated_by <> '')
) STRICT;

-- One revision counter for every settings write; forms carry it (409 when stale).
CREATE TABLE settings_rev (
    id  INTEGER PRIMARY KEY CHECK (id = 1),
    rev INTEGER NOT NULL CHECK (rev >= 0)
) STRICT;
INSERT INTO settings_rev (id, rev) VALUES (1, 0);

-- Each user's own display preferences. NULL = use the default (the app default for
-- the time zone and theme). Values are validated by internal/display before writing.
CREATE TABLE user_prefs (
    user_id     TEXT    PRIMARY KEY REFERENCES users (id),
    time_zone   TEXT,
    theme       TEXT,
    date_format TEXT    CHECK (date_format IN ('iso', 'us')),
    clock       TEXT    CHECK (clock IN ('24h', '12h')),
    temp_unit   TEXT    CHECK (temp_unit IN ('c', 'f')),
    density     TEXT    CHECK (density IN ('compact', 'comfortable')),
    updated_at  INTEGER NOT NULL
) STRICT;
