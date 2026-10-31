-- 0009: maintenance mode, per-server notes and event acknowledgements (docs/tech_doc.md §28).

-- One maintenance window per server: active (starts_at <= now) or scheduled. ends_at NULL
-- means "until ended". The row is deleted when the window ends (ended, expired or the
-- server removed); the audit log keeps the history. started_notified records that the
-- single "maintenance started" notification went out (a scheduled window sends it when
-- it begins).
CREATE TABLE server_maintenance (
    server_id        TEXT    PRIMARY KEY CHECK (length(server_id) BETWEEN 1 AND 64),
    starts_at        INTEGER NOT NULL,
    ends_at          INTEGER CHECK (ends_at IS NULL OR ends_at > starts_at),
    reason           TEXT    NOT NULL CHECK (length(reason) BETWEEN 1 AND 200),
    created_by       TEXT    NOT NULL CHECK (created_by <> ''),
    created_at       INTEGER NOT NULL,
    started_notified INTEGER NOT NULL DEFAULT 0 CHECK (started_notified IN (0, 1))
) STRICT;

-- The per-server notification mute (0008) becomes a maintenance window: an active mute
-- turns into a window ending at the same time, already notified (a mute never sent a
-- "started" message). Expired mutes are dropped.
INSERT INTO server_maintenance (server_id, starts_at, ends_at, reason, created_by, created_at, started_notified)
    SELECT server_id, updated_at, muted_until, 'Notifications muted (before maintenance mode)', updated_by,
           updated_at, 1
    FROM notify_mutes
    WHERE muted_until > CAST(strftime('%s', 'now') AS INTEGER) * 1000 AND muted_until > updated_at;

DROP TABLE notify_mutes;

-- Plain-text notes per server. body is at most 4 KiB (bytes, not characters). At most
-- one pinned note per server (partial unique index). author_id is the user id (ownership
-- for edit/delete), author the username shown.
CREATE TABLE server_notes (
    id         INTEGER PRIMARY KEY,
    server_id  TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    body       TEXT    NOT NULL CHECK (length(body) >= 1 AND length(CAST(body AS BLOB)) <= 4096),
    pinned     INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    author_id  TEXT    NOT NULL CHECK (author_id <> ''),
    author     TEXT    NOT NULL CHECK (author <> ''),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX server_notes_one_pin ON server_notes (server_id) WHERE pinned = 1;
CREATE INDEX server_notes_by_server ON server_notes (server_id, created_at);

-- Acknowledged BMC log entries. An entry is identified by server, log, the BMC entry id
-- and its BMC timestamp (unix ms, 0 when the BMC sent none), so a cleared log that
-- reuses an id is a different entry and is not acknowledged.
CREATE TABLE event_acks (
    server_id  TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    log        TEXT    NOT NULL CHECK (log IN ('sel', 'lifecycle')),
    entry_id   TEXT    NOT NULL CHECK (length(entry_id) BETWEEN 1 AND 128),
    created_ms INTEGER NOT NULL,
    comment    TEXT    NOT NULL DEFAULT '' CHECK (length(CAST(comment AS BLOB)) <= 500),
    acked_by   TEXT    NOT NULL CHECK (acked_by <> ''),
    acked_at   INTEGER NOT NULL,
    PRIMARY KEY (server_id, log, entry_id, created_ms)
) STRICT;
