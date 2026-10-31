// Package ui is the server-rendered browser interface of oob-manager (task 1.5):
// login (password, then TOTP), TOTP enrolment, logout, the fleet overview, per-server
// sensors/health, event logs and inventory.
//
// Design rules:
//   - html/template only; no JavaScript, no inline styles, so the strict CSP from
//     internal/web needs no nonce here. One embedded stylesheet under static/.
//   - Every page handler goes through server.page, which authenticates the session and
//     asks authz before running; unknown routes are 404 (deny by default).
//   - Every form carries a synchronizer CSRF token bound to the session cookie (or, before
//     login, to a random pre-session cookie) in addition to CrossOriginProtection.
//   - Login, TOTP and enrolment POSTs are rate limited in memory per IP and per account.
//   - Data comes from the Fleet interface (deps.go); the UI never calls a BMC itself.
//   - BMC-supplied strings are untrusted and always escaped. Secrets are never rendered,
//     except the TOTP secret on the one-time enrolment reveal page, and never logged.
package ui
