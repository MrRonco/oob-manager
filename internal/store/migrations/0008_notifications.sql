-- 0008: notifications (docs/tech_doc.md §26). Written as 0007 on the notifications
-- branch, renumbered to 0008 at the v0.5 integration because settings slice S3 took
-- 0006 (servers) and 0007 (display defaults); no install had applied it (§27).

-- Targets created in Settings → Notifications. File-managed targets
-- (config.yaml notifications.targets) never have a row. url is not a secret but is
-- shown to admins only (an ntfy topic or a webhook path can act as one). options_json
-- holds the non-secret per-kind options, subs_json the subscription. secret_enc is
-- AES-256-GCM over the target's secrets, with additional data bound to id, kind and url.
CREATE TABLE notify_targets (
    id             TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64 AND id NOT GLOB '*[^a-z0-9_-]*'),
    name           TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    kind           TEXT    NOT NULL CHECK (kind IN ('ntfy', 'pushover', 'gotify', 'webhook', 'email')),
    url            TEXT    NOT NULL CHECK (length(url) BETWEEN 1 AND 512),
    enabled        INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    options_json   TEXT    NOT NULL CHECK (json_valid(options_json)),
    subs_json      TEXT    NOT NULL CHECK (json_valid(subs_json)),
    secret_version INTEGER NOT NULL DEFAULT 0 CHECK (secret_version >= 0),
    secret_enc     BLOB,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    updated_by     TEXT    NOT NULL CHECK (updated_by <> '')
) STRICT;

-- Per-server notification mute ("Mute notifications for …"). Expired rows are ignored
-- and removed by the next mute change. Maintenance mode (later) can build on this.
CREATE TABLE notify_mutes (
    server_id   TEXT    PRIMARY KEY CHECK (length(server_id) BETWEEN 1 AND 64),
    muted_until INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    updated_by  TEXT    NOT NULL CHECK (updated_by <> '')
) STRICT;
