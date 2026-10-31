-- 0003: optional API token expiry (docs/tech_doc.md §15). NULL = never expires.
ALTER TABLE api_tokens ADD COLUMN expires_at INTEGER;
