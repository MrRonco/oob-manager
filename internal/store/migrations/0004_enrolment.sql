-- 0004: settings slice S1 (docs/settings_design.md §4). One-time enrolment links and
-- audit viewer indexes. api_tokens.expires_at already exists (0003).

-- An admin-issued link that lets a user set a password and enrol an authenticator.
-- Only the SHA-256 of the link token is stored; the link itself is the credential.
CREATE TABLE enrolment_tokens (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users (id),
    token_hash BLOB    NOT NULL UNIQUE,
    purpose    TEXT    NOT NULL CHECK (purpose IN ('enrol', 'reset')),
    created_by TEXT    NOT NULL REFERENCES users (id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    CHECK (expires_at > created_at)
) STRICT;
CREATE INDEX enrolment_tokens_user ON enrolment_tokens (user_id);

-- Audit viewer filters (keyset pagination on seq).
CREATE INDEX audit_log_action ON audit_log (action, seq);
CREATE INDEX audit_log_principal ON audit_log (principal, seq);
