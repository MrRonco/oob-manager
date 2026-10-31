// Package auth implements local authentication for oob-manager (decision 1: LAN-only, so
// Cloudflare Access is not wired here):
//
//   - argon2id password hashing (PasswordHasher), with bounded concurrency so a login
//     flood cannot exhaust the container's 256 MiB memory limit (HashMemoryBudgetKiB);
//   - mandatory TOTP (pquerna/otp) with single-use codes: the last accepted time step is
//     stored and only later steps are accepted;
//   - two-stage login (password → pending session → TOTP → full session), the session ID
//     rotated on login and on step-up;
//   - server-side sessions: 256-bit random IDs, only SHA-256 hashes stored, idle and
//     absolute expiry, __Host- cookie with Secure, HttpOnly, SameSite=Strict;
//   - per-account and per-IP lockout with exponential backoff;
//   - step-up ("sudo mode"): a fresh TOTP within a short window for dangerous actions;
//   - first-admin bootstrap;
//   - read-only API bearer tokens, stored hashed.
//
// Persistence is behind the small interfaces in repo.go; internal/store implements them.
// Nothing in this package logs passwords, TOTP codes or secrets, session IDs or tokens.
package auth
