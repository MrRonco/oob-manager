-- 0011: BMC security checks (docs/tech_doc.md §31).

-- Findings an admin accepted as a risk. An acceptance covers exactly one finding: the
-- check, its result (warn or fail) and its subject (a certificate fingerprint, account
-- names, a firmware version...). subject_hash is the SHA-256 (hex) of the whole subject
-- and is what binds; subject is a clipped copy for display. server_addr is the BMC
-- address and port the acceptance was made for: a server ID pointed at another BMC does
-- not inherit it. When the finding is resolved or changes, or the server moves, the
-- service deletes the row (audited); the audit log is the history. Removing a server
-- deletes its rows in the same transaction.
CREATE TABLE security_accepts (
    server_id    TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    server_addr  TEXT    NOT NULL CHECK (length(server_addr) BETWEEN 1 AND 64),
    check_id     TEXT    NOT NULL CHECK (length(check_id) BETWEEN 1 AND 64),
    result       TEXT    NOT NULL CHECK (result IN ('warn', 'fail')),
    subject      TEXT    NOT NULL CHECK (length(CAST(subject AS BLOB)) <= 256),
    subject_hash TEXT    NOT NULL CHECK (length(subject_hash) = 64),
    comment      TEXT    NOT NULL CHECK (length(comment) >= 1 AND length(CAST(comment AS BLOB)) <= 500),
    accepted_by  TEXT    NOT NULL CHECK (accepted_by <> ''),
    accepted_at  INTEGER NOT NULL,
    PRIMARY KEY (server_id, check_id)
) STRICT;

-- What the security notifications already reported, per server: one row per open
-- finding (item 'f:<check id>', value '<result>|<SHA-256 of the subject>') and per
-- certificate reminder (item 'cert:<port>', value '<certificate SHA-256>|<days>'), so a
-- restart neither repeats nor drops a notification.
CREATE TABLE security_notified (
    server_id   TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    item        TEXT    NOT NULL CHECK (length(item) BETWEEN 1 AND 80),
    value       TEXT    NOT NULL CHECK (length(value) <= 200),
    notified_at INTEGER NOT NULL,
    PRIMARY KEY (server_id, item)
) STRICT;
