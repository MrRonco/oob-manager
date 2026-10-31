-- 0001: initial schema (docs/tech_doc.md §5). Times are INTEGER unix milliseconds UTC.

CREATE TABLE users (
    id              TEXT    PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE,
    email           TEXT    UNIQUE,
    role            TEXT    NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    pw_hash         TEXT    NOT NULL,
    totp_secret_enc BLOB,
    totp_last_step  INTEGER NOT NULL DEFAULT 0,
    disabled        INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE sessions (
    id_hash    BLOB    PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    stepup_at  INTEGER,
    ip         TEXT    NOT NULL DEFAULT '',
    ua         TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE api_tokens (
    id           TEXT    PRIMARY KEY,
    name         TEXT    NOT NULL,
    token_hash   BLOB    NOT NULL UNIQUE,
    scope        TEXT    NOT NULL CHECK (scope = 'read'),
    created_by   TEXT    NOT NULL REFERENCES users (id),
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
) STRICT;

CREATE TABLE audit_log (
    seq            INTEGER PRIMARY KEY CHECK (seq > 0),
    ts             INTEGER NOT NULL,
    correlation_id TEXT    NOT NULL,
    principal      TEXT    NOT NULL,
    auth_method    TEXT    NOT NULL,
    role           TEXT    NOT NULL,
    src_ip         TEXT    NOT NULL,
    server_id      TEXT    NOT NULL,
    action         TEXT    NOT NULL,
    params_json    TEXT    NOT NULL,
    result         TEXT    NOT NULL,
    bmc_status     TEXT    NOT NULL,
    error_class    TEXT    NOT NULL,
    prev_hash      TEXT    NOT NULL,
    row_hash       TEXT    NOT NULL UNIQUE
) STRICT;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TABLE fan_leases (
    lease_id       TEXT    PRIMARY KEY,
    server_id      TEXT    NOT NULL,
    mode           TEXT    NOT NULL CHECK (mode IN ('boost', 'pin')),
    pct            INTEGER NOT NULL CHECK (pct BETWEEN 0 AND 100),
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    requested_by   TEXT    NOT NULL,
    state          TEXT    NOT NULL CHECK (state IN ('pending', 'applied', 'ended', 'expired', 'rejected')),
    original_value INTEGER,
    updated_at     INTEGER NOT NULL,
    CHECK (expires_at > issued_at)
) STRICT;
-- At most one active lease per server.
CREATE UNIQUE INDEX fan_leases_one_active ON fan_leases (server_id) WHERE state IN ('pending', 'applied');
CREATE INDEX fan_leases_server ON fan_leases (server_id, issued_at);

CREATE TABLE capabilities (
    server_id TEXT    PRIMARY KEY,
    probed_at INTEGER NOT NULL,
    json      TEXT    NOT NULL CHECK (json_valid(json))
) STRICT;

CREATE TABLE sensor_samples (
    server_id  TEXT    NOT NULL,
    ts         INTEGER NOT NULL,
    sensor_key TEXT    NOT NULL,
    value      REAL    NOT NULL,
    PRIMARY KEY (server_id, sensor_key, ts)
) STRICT, WITHOUT ROWID;
CREATE INDEX sensor_samples_ts ON sensor_samples (ts);

CREATE TABLE console_sessions (
    id         TEXT    PRIMARY KEY,
    server_id  TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('serial', 'vnc', 'kvm-launch')),
    user_id    TEXT    NOT NULL REFERENCES users (id),
    started_at INTEGER NOT NULL,
    ended_at   INTEGER,
    end_reason TEXT    NOT NULL DEFAULT '',
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0
) STRICT;
