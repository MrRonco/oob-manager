-- 0017: the firmware update checker (docs/plans/08-update-checker.md §9). Vendor catalog
-- imports (online, upload or CLI), every check, the releases kept for the fleet's
-- systems, per-component "skip this version" and the updates already notified.

-- One row per catalog that verified and parsed. At most one is active per source; a new
-- catalog that keeps far fewer rows than the active one is held until an admin confirms
-- (plan §15). Older rows are 'replaced' and pruned to the newest 20.
CREATE TABLE catalog_imports (
    id            INTEGER PRIMARY KEY,
    source        TEXT    NOT NULL CHECK (source IN ('dell')),
    origin        TEXT    NOT NULL CHECK (origin IN ('online','upload','cli')),
    state         TEXT    NOT NULL CHECK (state IN ('active','held','replaced')),
    version       TEXT    NOT NULL CHECK (length(version) <= 64),
    release_id    TEXT    NOT NULL DEFAULT '' CHECK (length(release_id) <= 64),
    published_at  INTEGER,
    imported_at   INTEGER NOT NULL,
    sha256        TEXT    NOT NULL CHECK (length(sha256) = 64),
    signer        TEXT    NOT NULL DEFAULT '' CHECK (length(signer) <= 64),
    etag          TEXT    NOT NULL DEFAULT '' CHECK (length(etag) <= 256),
    last_modified TEXT    NOT NULL DEFAULT '' CHECK (length(last_modified) <= 64),
    components    INTEGER NOT NULL CHECK (components >= 0),
    kept          INTEGER NOT NULL CHECK (kept >= 0),
    imported_by   TEXT    NOT NULL DEFAULT 'system' CHECK (imported_by <> '')
) STRICT;
CREATE UNIQUE INDEX catalog_imports_one_active ON catalog_imports (source) WHERE state = 'active';
CREATE UNIQUE INDEX catalog_imports_one_held ON catalog_imports (source) WHERE state = 'held';

-- Every check, including 304s and failures (pruned to 90 days and 500 rows).
CREATE TABLE catalog_checks (
    id        INTEGER PRIMARY KEY,
    source    TEXT    NOT NULL CHECK (source IN ('dell')),
    at        INTEGER NOT NULL,
    result    TEXT    NOT NULL CHECK (result IN ('imported','held','not_modified','download','size',
                                                 'signature','untrusted_key','parse','disabled')),
    detail    TEXT    NOT NULL DEFAULT '' CHECK (length(detail) <= 256),
    import_id INTEGER
) STRICT;
CREATE INDEX catalog_checks_at ON catalog_checks (source, at);

-- The releases of the active (and a held) import for the fleet's systems.
CREATE TABLE catalog_releases (
    import_id       INTEGER NOT NULL REFERENCES catalog_imports (id) ON DELETE CASCADE,
    system_id       TEXT    NOT NULL CHECK (length(system_id) BETWEEN 1 AND 16),
    component_id    TEXT    NOT NULL CHECK (length(component_id) BETWEEN 1 AND 32),
    vendor_id       TEXT    NOT NULL DEFAULT '' CHECK (length(vendor_id) <= 8),
    device_id       TEXT    NOT NULL DEFAULT '' CHECK (length(device_id) <= 8),
    sub_vendor_id   TEXT    NOT NULL DEFAULT '' CHECK (length(sub_vendor_id) <= 8),
    sub_device_id   TEXT    NOT NULL DEFAULT '' CHECK (length(sub_device_id) <= 8),
    version         TEXT    NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    released_at     INTEGER,
    criticality     INTEGER NOT NULL CHECK (criticality IN (1,2,3)),
    name            TEXT    NOT NULL CHECK (length(name) <= 160),
    package_path    TEXT    NOT NULL DEFAULT '' CHECK (length(package_path) <= 512),
    details_url     TEXT    NOT NULL DEFAULT '' CHECK (length(details_url) <= 512),
    reboot_required INTEGER NOT NULL DEFAULT 0 CHECK (reboot_required IN (0,1))
) STRICT;
CREATE INDEX catalog_releases_key ON catalog_releases (import_id, system_id, component_id);

-- The catalog's model names of the kept systems, for BMCs that report only a model
-- (iDRAC8): the server's model must name exactly one system ID (plan 08 §8.1).
CREATE TABLE catalog_models (
    import_id INTEGER NOT NULL REFERENCES catalog_imports (id) ON DELETE CASCADE,
    system_id TEXT    NOT NULL CHECK (length(system_id) BETWEEN 1 AND 16),
    model     TEXT    NOT NULL CHECK (length(model) BETWEEN 1 AND 160),
    PRIMARY KEY (import_id, system_id, model)
) STRICT;

-- "Skip this version": one component, one latest version; a newer version reopens it.
CREATE TABLE firmware_update_skips (
    server_id    TEXT    NOT NULL,
    component_id TEXT    NOT NULL,
    fqdd         TEXT    NOT NULL DEFAULT '',
    version      TEXT    NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    comment      TEXT    NOT NULL CHECK (length(comment) BETWEEN 1 AND 500),
    skipped_by   TEXT    NOT NULL CHECK (skipped_by <> ''),
    skipped_at   INTEGER NOT NULL,
    PRIMARY KEY (server_id, component_id, fqdd)
) STRICT;

-- Which (server, component, version) updates were notified (once each).
CREATE TABLE firmware_update_notified (
    server_id    TEXT    NOT NULL,
    component_id TEXT    NOT NULL,
    fqdd         TEXT    NOT NULL DEFAULT '',
    version      TEXT    NOT NULL,
    notified_at  INTEGER NOT NULL,
    PRIMARY KEY (server_id, component_id, fqdd, version)
) STRICT;

-- The vendor system ID the last scan read (Dell OEM SystemID as hex; '' unknown).
ALTER TABLE firmware_scans ADD COLUMN system_id TEXT NOT NULL DEFAULT '' CHECK (length(system_id) <= 16);

-- Settings → General gains the firmware update check. SQLite cannot change a CHECK, so
-- settings_kv is rebuilt with every key of 0015 plus the three firmware.catalog keys
-- (store.TestSettingsKVAcceptsEveryKnownKey checks the list against the code).
CREATE TABLE settings_kv_new (
    key        TEXT    PRIMARY KEY CHECK (key IN (
        'poll.interval', 'poll.stale_multiplier', 'auth.session_idle', 'auth.session_max',
        'auth.stepup_window', 'ratelimit.login_ip_per_min', 'ratelimit.login_acct_per_hour',
        'ui.time_zone', 'ui.theme', 'ui.clock_format', 'ui.date_format', 'ui.temperature_unit',
        'ui.density', 'gelf.address', 'gelf.enabled', 'gelf.transport', 'gelf.server_name',
        'gelf.pin_sha256', 'history.raw_days', 'history.hourly_days', 'history.daily_days',
        'history.sample_psus', 'history.sample_voltages', 'firmware.catalog.enabled',
        'firmware.catalog.check_every', 'firmware.catalog.notify')),
    value_json TEXT    NOT NULL CHECK (json_valid(value_json)),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL CHECK (updated_by <> '')
) STRICT;
INSERT INTO settings_kv_new (key, value_json, updated_at, updated_by)
    SELECT key, value_json, updated_at, updated_by FROM settings_kv;
DROP TABLE settings_kv;
ALTER TABLE settings_kv_new RENAME TO settings_kv;
