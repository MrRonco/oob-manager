-- 0013: BMC restarts (docs/tech_doc.md §37). One row per Manager.Reset POST the app sent
-- (a refusal before the POST writes none). result: sent (the restart window is open or
-- the app is waiting for the BMC), refused (the BMC answered the POST with an error),
-- verified (the BMC answered a poll again), timeout (it did not by deadline_at, or the
-- window ended another way: error_class says which). The cooldown and the open window
-- survive an app restart through these rows; the janitor prunes rows after 400 days.
-- requested_at is when the admin asked (audit, cooldown); sent_at is just before the POST
-- (the window starts there, the downtime is measured from it). A window is at most 15
-- minutes (fleet.MaxRestartWindow).
CREATE TABLE bmc_resets (
    id             INTEGER PRIMARY KEY,
    server_id      TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    correlation_id TEXT    NOT NULL,
    requested_at   INTEGER NOT NULL,
    sent_at        INTEGER NOT NULL CHECK (sent_at >= requested_at),
    requested_by   TEXT    NOT NULL CHECK (requested_by <> ''),
    reset_type     TEXT    NOT NULL CHECK (reset_type = 'GracefulRestart'),
    result         TEXT    NOT NULL CHECK (result IN ('sent', 'refused', 'verified', 'timeout')),
    back_at        INTEGER,
    deadline_at    INTEGER NOT NULL CHECK (deadline_at > sent_at AND deadline_at - sent_at <= 900000),
    error_class    TEXT    NOT NULL DEFAULT '' CHECK (length(error_class) <= 32),
    -- unconfirmed: the POST got no answer (timeout, connection lost after the request was
    -- written); only the BMC's own LastResetTime can then confirm the restart.
    unconfirmed    INTEGER NOT NULL DEFAULT 0 CHECK (unconfirmed IN (0, 1)),
    -- detail on a verified row: last_reset_time_unchanged (the BMC answered again but its
    -- LastResetTime did not move), restart_unconfirmed (it answered again, but neither the
    -- POST's answer nor LastResetTime confirms a restart).
    detail         TEXT    NOT NULL DEFAULT '' CHECK (detail IN ('', 'last_reset_time_unchanged', 'restart_unconfirmed'))
) STRICT;
CREATE INDEX bmc_resets_server ON bmc_resets (server_id, requested_at);
