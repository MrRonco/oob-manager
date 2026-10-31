-- 0002: schema the auth package needs (docs/tech_doc.md §10).

-- Login is refused until the user proves the authenticator works.
ALTER TABLE users ADD COLUMN totp_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (totp_confirmed IN (0, 1));

-- 1 = pending (password ok, TOTP outstanding), 2 = full. Defaults to pending: fail closed.
ALTER TABLE sessions ADD COLUMN level INTEGER NOT NULL DEFAULT 1 CHECK (level IN (1, 2));

-- Lockout counters. Keys are "acct:<username>" or "ip:<addr>"; they derive from
-- attacker input, so rows are pruned by last_failure.
CREATE TABLE login_failures (
    key          TEXT    PRIMARY KEY CHECK (key <> ''),
    failures     INTEGER NOT NULL CHECK (failures > 0),
    last_failure INTEGER NOT NULL
) STRICT;
CREATE INDEX login_failures_last ON login_failures (last_failure);
