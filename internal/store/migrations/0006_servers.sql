-- 0006: settings slice S3 (docs/settings_design.md §4): servers managed in the browser
-- and their sealed BMC credentials. Servers written in config.yaml are not stored here;
-- a row whose id is also in the file is shadowed (ignored) at startup.

CREATE TABLE servers (
    id                TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 32),
    name              TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    tags_json         TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(tags_json) AND json_type(tags_json) = 'array'),
    kind              TEXT    NOT NULL CHECK (kind IN ('idrac8', 'idrac9', 'redfish', 'ipmi')),
    address           TEXT    NOT NULL CHECK (address <> ''),
    port              INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    -- Pins are fetched trust-on-first-use and confirmed by an admin ('' = not set).
    tls_pin_sha256    TEXT    NOT NULL DEFAULT '' CHECK (tls_pin_sha256 = '' OR length(tls_pin_sha256) = 64),
    vnc_pin_sha256    TEXT    NOT NULL DEFAULT '' CHECK (vnc_pin_sha256 = '' OR length(vnc_pin_sha256) = 64),
    ssh_host_key      TEXT    NOT NULL DEFAULT '',
    fan_mode          TEXT    NOT NULL DEFAULT 'none'
                      CHECK (fan_mode IN ('host-lease', 'redfish-floor', 'ipmi-oem', 'none')),
    fan_safe_min_pct  INTEGER NOT NULL DEFAULT 0 CHECK (fan_safe_min_pct = 0 OR fan_safe_min_pct BETWEEN 20 AND 100),
    fan_max_lease_ms  INTEGER NOT NULL DEFAULT 0 CHECK (fan_max_lease_ms >= 0),
    console_serial    TEXT    NOT NULL DEFAULT 'none' CHECK (console_serial IN ('bmcssh', 'sol', 'none')),
    console_graphical TEXT    NOT NULL DEFAULT 'none' CHECK (console_graphical IN ('vnc', 'kvm-launch', 'link', 'none')),
    vnc_port          INTEGER NOT NULL DEFAULT 5901 CHECK (vnc_port BETWEEN 1 AND 65535),
    ssh_port          INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
    power_self_host   INTEGER NOT NULL DEFAULT 0 CHECK (power_self_host IN (0, 1)),
    power_impact_json TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(power_impact_json) AND json_type(power_impact_json) = 'array'),
    poll_interval_ms  INTEGER CHECK (poll_interval_ms IS NULL OR poll_interval_ms > 0),
    -- New servers start disabled (safe default); enabling validates the whole row.
    enabled           INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    -- rev: compare-and-set for edit forms. cred_seq: the last credential version issued
    -- for this server; it only grows, so a sealed credential is never re-used.
    rev               INTEGER NOT NULL DEFAULT 1 CHECK (rev >= 1),
    cred_seq          INTEGER NOT NULL DEFAULT 0 CHECK (cred_seq >= 0),
    created_at        INTEGER NOT NULL,
    created_by        TEXT    NOT NULL CHECK (created_by <> ''),
    updated_at        INTEGER NOT NULL,
    updated_by        TEXT    NOT NULL CHECK (updated_by <> '')
) STRICT;

-- AES-256-GCM sealed {username,password}; the additional data binds each row to
-- server_id|slot|kind|address|port|version, so it opens only for that BMC. Never
-- displayed: the UI shows the version, when and by whom.
CREATE TABLE bmc_credentials (
    server_id  TEXT    NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    slot       TEXT    NOT NULL CHECK (slot IN ('readonly', 'operator', 'vnc')),
    version    INTEGER NOT NULL CHECK (version >= 1),
    key_id     TEXT    NOT NULL CHECK (key_id = 'v1'),
    secret_enc BLOB    NOT NULL CHECK (length(secret_enc) > 12),
    created_at INTEGER NOT NULL,
    created_by TEXT    NOT NULL CHECK (created_by <> ''),
    PRIMARY KEY (server_id, slot)
) STRICT;
