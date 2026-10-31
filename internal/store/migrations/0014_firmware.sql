-- 0014: the read-only firmware view (docs/tech_doc.md §38). One row per component per
-- server, as last read, with the Dell member states merged: running is what the device
-- reports now (Current, else Installed), previous the rollback copy, staged an image
-- waiting for a reboot (Available), lc_installed the Installed version when it differs
-- from Current (flag Mismatch). named: the name came from the member document;
-- doc_read_at: when that document was last read (names are sticky and refreshed after 30
-- days). Rows of a server that leaves the registry are deleted with it.
CREATE TABLE firmware_components (
    server_id    TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    component_id TEXT    NOT NULL CHECK (length(component_id) BETWEEN 1 AND 128),
    fqdd         TEXT    NOT NULL DEFAULT '' CHECK (length(fqdd) <= 128),
    kind         TEXT    NOT NULL CHECK (kind IN ('bmc', 'bios', 'cpld', 'nic', 'storage', 'drive',
                                                  'enclosure', 'psu', 'lc', 'other')),
    name         TEXT    NOT NULL DEFAULT '' CHECK (length(name) <= 128),
    named        INTEGER NOT NULL DEFAULT 0 CHECK (named IN (0, 1)),
    running      TEXT    NOT NULL DEFAULT '' CHECK (length(running) <= 64),
    previous     TEXT    NOT NULL DEFAULT '' CHECK (length(previous) <= 64),
    staged       TEXT    NOT NULL DEFAULT '' CHECK (length(staged) <= 64),
    lc_installed TEXT    NOT NULL DEFAULT '' CHECK (length(lc_installed) <= 64),
    release_date INTEGER,
    updateable   INTEGER NOT NULL DEFAULT 0 CHECK (updateable IN (0, 1)),
    identity     TEXT    NOT NULL DEFAULT '' CHECK (length(identity) <= 128),
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL CHECK (last_seen >= first_seen),
    doc_read_at  INTEGER,
    PRIMARY KEY (server_id, component_id, fqdd)
) STRICT;

-- Version changes between scans ("who updated the BIOS and when"): a component that
-- appeared has before = '', one that disappeared (a complete scan no longer lists it)
-- after = ''. The janitor prunes rows after 2 years.
CREATE TABLE firmware_changes (
    id           INTEGER PRIMARY KEY,
    server_id    TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    component_id TEXT    NOT NULL CHECK (length(component_id) BETWEEN 1 AND 128),
    fqdd         TEXT    NOT NULL DEFAULT '' CHECK (length(fqdd) <= 128),
    name         TEXT    NOT NULL DEFAULT '' CHECK (length(name) <= 128),
    field        TEXT    NOT NULL CHECK (field IN ('running', 'previous', 'staged')),
    before       TEXT    NOT NULL CHECK (length(before) <= 64),
    after        TEXT    NOT NULL CHECK (length(after) <= 64 AND after <> before),
    seen_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX firmware_changes_server ON firmware_changes (server_id, seen_at);

-- The last scan of each server: when, how many members the collection listed, how many
-- components it holds, whether every listed member was considered, how many member
-- documents were read and failed, and the system model at the time (rules on a model keep
-- matching after a restart, before the inventory is read again).
CREATE TABLE firmware_scans (
    server_id   TEXT    PRIMARY KEY CHECK (length(server_id) BETWEEN 1 AND 64),
    scanned_at  INTEGER NOT NULL,
    listed      INTEGER NOT NULL CHECK (listed >= 0),
    components  INTEGER NOT NULL CHECK (components >= 0),
    complete    INTEGER NOT NULL CHECK (complete IN (0, 1)),
    docs_read   INTEGER NOT NULL DEFAULT 0 CHECK (docs_read >= 0),
    docs_failed INTEGER NOT NULL DEFAULT 0 CHECK (docs_failed >= 0),
    model       TEXT    NOT NULL DEFAULT '' CHECK (length(model) <= 128)
) STRICT;
