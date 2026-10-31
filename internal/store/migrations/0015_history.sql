-- 0015: sensor history with rollups (docs/plans/02-history-graphs-csv.md, tech_doc §39).
-- The text key and server id move out of every sample into sensor_keys; raw samples,
-- hourly and daily rollups key on its integer id. The existing sensor_samples rows
-- (at most 7 days) are copied: kind and unit come from the key prefix, the display
-- name is filled by the next poll. All tables are STRICT, timestamps are unix ms UTC.
CREATE TABLE sensor_keys (
    id        INTEGER PRIMARY KEY,
    server_id TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    key       TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 160),
    kind      TEXT    NOT NULL CHECK (kind IN ('temp', 'fan', 'power', 'psu_in', 'psu_out', 'volt')),
    name      TEXT    NOT NULL DEFAULT '' CHECK (length(name) <= 128),
    unit      TEXT    NOT NULL CHECK (unit IN ('celsius', 'rpm', 'percent', 'watts', 'volts')),
    first_ts  INTEGER NOT NULL,
    last_ts   INTEGER NOT NULL CHECK (last_ts >= first_ts),
    -- archived_from: the live key this archive belonged to before its unit or kind
    -- changed (NULL: a live key); archives are matched by it, never by name.
    archived_from TEXT CHECK (archived_from IS NULL OR length(archived_from) BETWEEN 1 AND 160),
    UNIQUE (server_id, key)
) STRICT;

-- No secondary index: rollups, reads and prunes all run per key on the primary key.
CREATE TABLE sensor_raw (
    key_id INTEGER NOT NULL REFERENCES sensor_keys (id) ON DELETE CASCADE,
    ts     INTEGER NOT NULL,
    value  REAL    NOT NULL,
    PRIMARY KEY (key_id, ts)
) STRICT, WITHOUT ROWID;

CREATE TABLE sensor_hourly (
    key_id INTEGER NOT NULL REFERENCES sensor_keys (id) ON DELETE CASCADE,
    bucket INTEGER NOT NULL CHECK (bucket % 3600000 = 0),
    min    REAL    NOT NULL,
    avg    REAL    NOT NULL,
    max    REAL    NOT NULL,
    n      INTEGER NOT NULL CHECK (n > 0),
    PRIMARY KEY (key_id, bucket)
) STRICT, WITHOUT ROWID;

CREATE TABLE sensor_daily (
    key_id INTEGER NOT NULL REFERENCES sensor_keys (id) ON DELETE CASCADE,
    bucket INTEGER NOT NULL CHECK (bucket % 86400000 = 0),
    min    REAL    NOT NULL,
    avg    REAL    NOT NULL,
    max    REAL    NOT NULL,
    n      INTEGER NOT NULL CHECK (n > 0),
    PRIMARY KEY (key_id, bucket)
) STRICT, WITHOUT ROWID;

-- One row: the rollup watermarks (every hour / day before them is rolled up), the last
-- backward clock step the sampler saw (NULL: none), and the janitor's own clock: the
-- wall time of its last pass and the retention clock it prunes by, which advances at
-- most twice real time, so a clock stepped forward cannot wipe the history in one pass
-- (last_forward_jump: when the janitor last saw that, NULL: never). boot_id and
-- boot_uptime_ms are the kernel's boot ID and uptime at that pass: within one boot the
-- uptime, which a wall clock step cannot fake, bounds how far the clock may advance.
CREATE TABLE history_meta (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    hourly_done       INTEGER NOT NULL DEFAULT 0 CHECK (hourly_done % 3600000 = 0),
    daily_done        INTEGER NOT NULL DEFAULT 0 CHECK (daily_done % 86400000 = 0),
    last_clock_jump   INTEGER,
    last_pass_at      INTEGER NOT NULL DEFAULT 0,
    janitor_clock     INTEGER NOT NULL DEFAULT 0,
    last_forward_jump INTEGER,
    boot_id           TEXT    NOT NULL DEFAULT '' CHECK (length(boot_id) <= 64),
    boot_uptime_ms    INTEGER NOT NULL DEFAULT 0 CHECK (boot_uptime_ms >= 0)
) STRICT;
INSERT INTO history_meta (id) VALUES (1);

INSERT INTO sensor_keys (server_id, key, kind, unit, first_ts, last_ts)
    SELECT server_id, sensor_key,
        CASE WHEN sensor_key GLOB 'temp:?*' THEN 'temp' WHEN sensor_key GLOB 'fan:?*' THEN 'fan' ELSE 'power' END,
        CASE WHEN sensor_key GLOB 'temp:?*' THEN 'celsius' WHEN sensor_key GLOB 'fan:?*' THEN 'rpm' ELSE 'watts' END,
        MIN(ts), MAX(ts)
    FROM sensor_samples
    WHERE (sensor_key GLOB 'temp:?*' OR sensor_key GLOB 'fan:?*' OR sensor_key = 'power:consumed')
        AND length(server_id) BETWEEN 1 AND 64 AND length(sensor_key) <= 160
    GROUP BY server_id, sensor_key;
INSERT INTO sensor_raw (key_id, ts, value)
    SELECT k.id, s.ts, s.value FROM sensor_samples s
    JOIN sensor_keys k ON k.server_id = s.server_id AND k.key = s.sensor_key;
DROP INDEX sensor_samples_ts;
DROP TABLE sensor_samples;

-- Settings → General gains the History group. SQLite cannot change a CHECK, so
-- settings_kv is rebuilt with the full key list: every key of 0005, 0007 and 0012
-- (General and Integrations) again, plus the five history keys
-- (store.TestSettingsKVAcceptsEveryKnownKey checks the list against the code).
CREATE TABLE settings_kv_new (
    key        TEXT    PRIMARY KEY CHECK (key IN (
        'poll.interval', 'poll.stale_multiplier', 'auth.session_idle', 'auth.session_max',
        'auth.stepup_window', 'ratelimit.login_ip_per_min', 'ratelimit.login_acct_per_hour',
        'ui.time_zone', 'ui.theme', 'ui.clock_format', 'ui.date_format', 'ui.temperature_unit',
        'ui.density', 'gelf.address', 'gelf.enabled', 'gelf.transport', 'gelf.server_name',
        'gelf.pin_sha256', 'history.raw_days', 'history.hourly_days', 'history.daily_days',
        'history.sample_psus', 'history.sample_voltages')),
    value_json TEXT    NOT NULL CHECK (json_valid(value_json)),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL CHECK (updated_by <> '')
) STRICT;
INSERT INTO settings_kv_new (key, value_json, updated_at, updated_by)
    SELECT key, value_json, updated_at, updated_by FROM settings_kv;
DROP TABLE settings_kv;
ALTER TABLE settings_kv_new RENAME TO settings_kv;
