-- 0010: open-ended maintenance reminder (docs/tech_doc.md §30). A window that lasts
-- "until ended" sends one reminder per 24 h while it lasts; reminded_at (unix ms, NULL =
-- none yet) is when the last one went out, so a restart neither repeats nor skips one.
ALTER TABLE server_maintenance ADD COLUMN reminded_at INTEGER;
