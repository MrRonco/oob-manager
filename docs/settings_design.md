# Settings area — design

Status: **approved with decisions (2026-10-21); slices S1, S2 and S3 implemented** (S1 on branch `s1-settings`, tech_doc §16; S2 on branch `s2-general`, tech_doc §24, which also adds per-user display preferences and color themes; S3 on branch `s3-servers`, tech_doc §25); S4 on branch `s4-integrations`, tech_doc §34 (see "S4 as built" in §8). Produced by the planner agent from the repo as of
commit 80ca3b3; follows CLAUDE.md hard rules 1–12. The open questions are in §7, the maintainer's answers in §8. Adopting §3
requires rewording hard rule 3 ("server IDs from config" → "from the effective server registry") and
security.md T4 (config changes no longer need a restart).

Code facts this design relies on: `fleet.Fleet` builds pollers once in `New` (hot reload needs a new
`Apply`); the app-keys file only holds `totp_key` and new keys are derived via HKDF (`DeriveKey`), so no
new secret file is needed; `audit.Logger.Record` writes outside the caller's transaction (needs a
`RecordTx` variant); authz already has `AdminUsers`, `AdminTokens`, `AdminAudit`, `AdminAuditVerify`.

## 1. Scope

| Section | Functions |
|---|---|
| Users | list, create (enrolment link), change role, disable/enable, force TOTP re-enrol, list/revoke sessions |
| API tokens | create (shown once), optional expiry, list, revoke |
| Servers/BMCs | add/edit/disable/remove; kind; address+port; credentials (replace-only); TLS SPKI pin via TOFU; SSH host key via TOFU; poll interval; fan mode/floor; console kinds; test connection |
| Integrations | GELF target + test event + shipper state; dashboard hints (Homepage `customapi`, Kuma `/readyz` keyword `ok`) with `<token>` placeholders |
| General | poll interval, stale multiplier, session idle/max, step-up window, login rate limits, display time zone |
| Audit | filtered keyset-paginated viewer, chain verify (rows, head hash, first bad seq), last startup verify |
| About | version, commit, Go, deps hash, schema version, config hash, Apache-2.0, NOTICE, links (ldflag `main.repoURL`) |

No settings JSON API: `/api/v1` stays read-only; tokens can never reach `admin.*` (rule S4).

## 2. Source of truth

**File-only (CLI/deploy, never DB):** `listen`, `tls`, `public_url`, `auth.mode`, `auth.cfaccess`,
`storage.*`, `secrets.*`, plus new

```yaml
settings:
  locked: []                      # any of: servers, integrations, general
  bmc_networks: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7]
```

**Runtime-managed, precedence file > DB > default.** A key present in `config.yaml` wins; the UI shows
it disabled with a "Managed by config.yaml" lock badge and the file key name. A section listed in
`settings.locked` is read-only. A server whose `id` is in the file is file-managed (read-only,
credentials from the age file). A DB server with the same id is *shadowed*: ignored, logged, audited
once per start (`settings.shadowed`), shown with a warning. One validator for both sources: export
`config.ValidateServer` / `config.ValidateGeneral` from `validate*.go` so DB rows pass exactly the file rules.

**Migration (CLI, shell = trusted):** `oob-manager settings import -servers id1,id2` copies file servers
into the DB, decrypting their credentials from the age file and re-sealing them into the DB, then prints
"remove these from config.yaml". `oob-manager settings export` writes effective YAML **without
secrets** (backup/GitOps). Nothing migrates automatically; existing installs are unchanged until import.

**BMC credentials from the UI:** `bmc_credentials.secret_enc` = AES-256-GCM over `{username,password}`
JSON; key = `AppKeys.DeriveKey(PurposeBMCCred)` (HKDF info `oob-console/bmc-cred/v1`); AAD =
`bmc-cred/v1|server_id|slot|kind|address|port|version`. Changing address/port/kind makes stored
credentials undecryptable, so they must be re-entered: credentials can never be redirected to a new
host. Never displayed back: the UI shows only "set · v3 · 2026-10-20 by admin" and a Replace action.
Decrypted only at driver build, held in `secrets.Secret`.

## 3. Security

- **AuthZ:** new closed actions `admin.users.manage`, `admin.tokens.manage`, `admin.servers.view`,
  `admin.servers.manage`, `admin.integrations.view`, `admin.integrations.manage`,
  `admin.general.view`, `admin.general.manage`, `about.view`. Every `*.manage` is admin-only and in
  `RequiresStepUp`; `about.view` is viewer; `tokenReadable` unchanged.
- **Step-up per change:** each mutating form carries a `totp` field; `Authenticator.ConfirmChange(session,
  code)` verifies, advances `totp_last_step` (single-use) and rotates the session. A stale or missing code
  re-renders with 403 and no write. (Side effect: at most one change per 30 s step; see Q1.)
- **CSRF:** existing session-bound synchronizer token + `CrossOriginProtection` + `SameSite=Strict`;
  POST only; 64 KiB body cap; forms carry `rev` → 409 "changed elsewhere" on mismatch.
- **Audit:** every change writes one row, `params_json = {"target":…, "changes":[{"field","before","after"}]}`.
  Secret fields log `"[redacted] v3"` → `"[redacted] v4"` via a redaction allow-list in `settings.Diff`;
  unknown fields are redacted (fail closed). Change + audit row in one transaction
  (`audit.Logger.RecordTx`); GELF enqueue after commit; denials audited.
- **Rate limits (per user):** mutations 10/min, fingerprint fetch 6/min, test connection 6/min, GELF test
  3/min, audit verify 1/min global, `/enroll/{token}` 5/min/IP.
- **Validation (closed enums everywhere):** `id` `^[a-z0-9][a-z0-9_-]{0,63}$`, immutable after create;
  `name` 1–64 printable; tags `^[a-z0-9-]{1,32}$` ≤ 8; `kind` ∈ idrac8|idrac9|redfish|ipmi; `port` 443 or
  1024–65535 (ipmi: 623); pin 64 hex (required unless ipmi); `ssh_host_key` parses with
  `ssh.ParsePublicKey`, ed25519/ecdsa only; fan rules as today (host-lease ≥ 30 idrac8 only;
  redfish-floor 41–100 idrac9; ipmi-oem ≥ 30 with max_lease ≤ 60 m; ≥ 20 always; max_lease ≤ 2 h);
  usernames `^[a-z][a-z0-9._-]{2,31}$`; token names as `validTokenName`.
- **BMC address policy:** IP literal only (`netip.ParseAddr`; reject zones, IPv4-mapped IPv6,
  decimal/leading-zero forms by re-format compare); reject loopback, unspecified, multicast, link-local
  (incl. 169.254.169.254), broadcast, the app's own listen address; must be inside
  `settings.bmc_networks`. No hostnames (Q3).
- **TOFU fingerprint (SSRF):** `internal/tofu` does handshake-only probes.
  `FetchTLSPin(ctx, addr, port)` dials only the validated `netip.AddrPort`, 5 s dial + 5 s handshake, no
  proxy, captures the leaf in `VerifyConnection`, then closes: **no HTTP bytes sent**, so no redirects and
  no credentials leave the app. `FetchSSHHostKey` aborts in `HostKeyCallback` before auth. The result
  page shows the SPKI hex grouped by 4 plus escaped subject/issuer/validity/SANs, with the instruction
  "compare against the BMC's certificate page". Confirm posts a `pinproof` = HMAC(DeriveKey(`tofu/v1`),
  session‖addr‖port‖spki‖ts, TTL 5 min), so the saved pin is the fetched one; manual paste is also
  allowed and the audit row records which path. Errors are class-only:
  `unreachable|timeout|not_tls|bad_cert`.
- **Add-server order:** address → fingerprint → confirm → credentials → **test** (pinned, GET-only
  `Probe`) → save. Credentials are never sent before the pin is confirmed.
- **Safe defaults:** new servers `enabled=0`, fan mode `none`, graphical console `none`. Changing fan mode
  or address while a fan lease is active → 409. A server edit ends its console sessions. No self-disable
  or self-demote; the last enabled admin cannot be removed or demoted (enforced in SQL, in the transaction).
- **CLI-only:** `bootstrap-admin`, `reset-totp`, break-glass `admin-recover -username` (re-enable, set
  admin, clear lockout, revoke sessions), `gen-app-keys`, `token create`, `settings import/export`, all
  file-only keys.

## 4. Data model — `0003_settings.sql` (STRICT, unix ms)

| Table | Columns |
|---|---|
| `settings_kv` | `key` PK CHECK IN (`poll.interval`,`poll.stale_multiplier`,`auth.session_idle`,`auth.session_max`,`auth.stepup_window`,`ratelimit.login_ip_per_min`,`ratelimit.login_acct_per_hour`,`ui.time_zone`,`ui.theme`,`gelf.address`,`gelf.enabled`), `value_json` CHECK json_valid, `updated_at`, `updated_by` |
| `settings_rev` | `id` CHECK (id=1), `rev` INTEGER (bumped by every settings/server write) |
| `servers` | `id` PK, `name`, `tags_json`, `kind` CHECK, `address`, `port` CHECK 1–65535, `tls_pin_sha256`, `ssh_host_key`, `fan_mode` CHECK, `fan_safe_min_pct` CHECK 20–100, `fan_max_lease_ms`, `console_serial` CHECK, `console_graphical` CHECK, `poll_interval_ms` NULL, `enabled` CHECK 0/1, `created_at`, `updated_at`, `updated_by` |
| `bmc_credentials` | `server_id` FK→servers ON DELETE CASCADE, `slot` CHECK IN (readonly,operator,vnc), `version`, `key_id` (`v1`), `secret_enc` BLOB, `created_at`, `created_by`; PK(server_id, slot) |
| `enrolment_tokens` | `id`, `user_id` FK, `token_hash` UNIQUE, `purpose` CHECK IN (enrol,reset), `created_by`, `created_at`, `expires_at` (+24 h), `used_at` |
| `api_tokens` | + `expires_at` NULL |

Users get no new columns. A forced reset clears `totp_secret_enc`/`totp_confirmed`, runs
`LogoutEverywhere` and issues a `reset` enrolment token; `/enroll/{token}` sets the password and shows the
TOTP secret once (the token is the credential, which closes the §14 reveal-by-password takeover concern).
Users are never deleted (audit and `api_tokens.created_by` reference them), only disabled.

**General bounds (safe range only):** poll 30 s–10 min (≥ `min_interval`); stale multiplier 2–10; session
idle 5 min–2 h; session max 1–24 h and ≥ idle; step-up window 1–5 min; login/IP 1–10/min; login/account
3–20/h; time zone = IANA name via `time.LoadLocation` (embed `time/tzdata`, stdlib), display only, storage
stays UTC. Lockout backoff constants are not editable.

## 5. Packages, routes, reload, tests

**Packages:** `internal/settings` (types, bounds, `Resolve(file config.Config, db Rows) (Effective, Locks)`,
`Diff` with redaction, `Provider` = `atomic.Pointer[Effective]` + change channel); `internal/secrets/credstore`
(Seal/Open with AAD); `internal/netpolicy` (`CheckBMCAddr`); `internal/tofu`; `internal/store`
(`settingsRepo`, `serverRepo`, `credentialRepo`, `enrolmentRepo`, `WithTx`); `internal/auth` (`ConfirmChange`,
enrolment-token flow, `ListSessions`); `internal/fleet` (`Apply`); `internal/web/ui` (`admin_users.go`,
`admin_tokens.go`, `admin_servers.go`, `admin_tofu.go`, `admin_general.go`, `admin_integrations.go`,
`admin_audit.go`, `about.go`, `templates/admin/*.html`, `lockbadge` partial; no JS);
`cmd/oob-manager/reconcile.go` (rebuilds targets from `Effective` → `Apply`).

**Routes** (session + CSRF; every POST also needs a TOTP code):

| Method | Path |
|---|---|
| GET | `/admin` → `/admin/users`; `/admin/users`, `/admin/users/{id}` |
| POST | `/admin/users`, `/admin/users/{id}/role`, `…/disable`, `…/enable`, `…/reset-totp`, `…/sessions/revoke-all`, `…/sessions/{sid}/revoke` (`sid` = hex of `id_hash`) |
| GET/POST | `/enroll/{token}` (pre-login, `__Host-oob_pre` CSRF) |
| GET/POST | `/admin/tokens`; POST `/admin/tokens/{id}/revoke` (create returns a 200 reveal page, `no-store`, never a redirect) |
| GET | `/admin/servers`, `/admin/servers/new`, `/admin/servers/{id}/edit` |
| POST | `/admin/servers/fingerprint`, `/admin/servers`, `/admin/servers/{id}`, `…/pin`, `…/credentials/{slot}`, `…/test`, `…/enable`, `…/disable`, `…/delete` (type the id to confirm) |
| GET/POST | `/admin/integrations`, POST `/admin/integrations/gelf/test` |
| GET/POST | `/admin/general` |
| GET | `/admin/audit?action=&principal=&server=&result=&before=<seq>`, `/admin/audit/verify` |
| GET | `/about` |

**Hot reload without restart:** `Fleet` holds `atomic.Pointer[roster]`
(`roster{order []string; byID map[string]*poller}`, immutable). `Apply(targets)` (single writer mutex)
diffs by id and a fingerprint `sha256(kind, addr, port, pin, sshkey, cred versions, interval)`:
unchanged → keep the poller and its state; changed/removed → cancel that poller's context and wait;
added → start; then swap the roster. Readers stay lock-free; each poller has its own context derived from
the `Run` context. General settings: ui/auth/limiters read `Provider.Current()` per use (limiters keep
their buckets and read new limits, so a change doesn't grant a fresh allowance). GELF: build the new
shipper, swap, flush and close the old one.

**Tests (TDD, ≥ 80 %; auth/authz/audit per-package gates):**
- *Unit:* bounds tables; precedence + shadowing; `Diff` redaction (fuzz: no secret byte in the output);
  credstore (row swap / slot swap / address change → Open fails); netpolicy hostile table (`127.1`,
  `0x7f.1`, `2130706433`, `::ffff:127.0.0.1`, `fe80::1%eth0`, `169.254.169.254`, `010.0.0.1`,
  out-of-CIDR, hostnames); tofu against httptest TLS (the server sees **zero** HTTP requests;
  blackhole → timeout; plain TCP → `not_tls`); `Apply` (state preserved, restart on change, no goroutine
  leaks under `-race`); last-admin invariant under concurrency; `rev` conflict.
- *Integration (ui with fakes):* missing CSRF → 403; missing or replayed TOTP → 403, no write;
  viewer/operator → 403 + audited; lock badge → POST 403; shown-once token absent from logs and DB.
- *Authz matrix:* each new action × {viewer, operator, admin} × {session, token} × {step-up fresh,
  stale}; token rows deny every `admin.*`.
- *E2E (Go, then Playwright):* create user → enrol link → login; create token → API 200 → revoke → 401;
  add a third `redfishmock` via TOFU → appears in the overview within one poll, no restart; change
  address → credentials required; remove → gone; audit verify OK; password/TOTP secret/token never in
  app log or DB plaintext.

## 6. Phasing

| Slice | Content | Est |
|---|---|---|
| **S1 MVP** | authz actions, `ConfirmChange`, migration (enrolment_tokens, api_tokens.expires_at), Users, Tokens, Audit viewer + verify, About | 4 d |
| S2 | `internal/settings`, precedence + lock badges, General + Provider hot reload | 1.5 d |
| S3 | servers + credentials tables, credstore, netpolicy, tofu, `fleet.Apply`, import/export CLI | 4.5 d |
| S4 | Integrations (GELF swap, test, hints) | 1 d |

Each slice merges on its own; S1 changes nothing about how config is handled.

**Risks:**
- Threat-model shift (T4, rule 3): an admin session can add BMCs. Mitigated by address-bound credentials,
  `bmc_networks`, TOFU proof, per-change TOTP and `settings.locked`. Update security.md T4 and rule 3.
- App-key rotation would destroy TOTP enrolments and DB credentials; `key_id` exists only to allow future re-sealing.
- Fan safety (rule 8): fan-mode edits are refused while a lease is active; host-lease stays host-script cooperative.
- Admin lockout: covered by the CLI `admin-recover`.
- Fingerprint endpoint as a port scanner: bounded by admin + TOTP, the CIDR list, the rate limit and the audit trail.

## 7. Open questions

1. TOTP on every change (one change per 30 s), or allow changes within the 5-min step-up window?
2. Bind credentials to the TLS pin too (stricter, but re-type on every BMC certificate change)?
3. Ever allow hostnames (resolve once at save, store the IP)?
4. For a first install: `locked: [servers]` until S3 has soaked?
5. Audit export (`admin.audit.export`, JSONL) in S1 or later?
6. GELF over TLS in S4?

## 8. Decisions (2026-10-21)

| # | Question | Decision |
|---|---|---|
| 1 | Step-up for changes | **5-minute step-up window** (reuse the existing window; no per-change TOTP field). Every admin session still needs a fresh code before its first change. §3 "Step-up per change" is replaced by this. |
| 2 | Credentials bound to the TLS pin | **No.** Credentials stay bound to kind/address/port. On a certificate change, polling **pauses** for that server and the UI asks an admin to confirm the new fingerprint (TOFU flow); the password is kept. |
| 3 | Hostnames | **IP literals only.** |
| 4 | Lock on the first install | **Unlocked.** Server editing in the browser is enabled from the start (`settings.locked: []`, also the default). |
| 5 | Audit export | Later (not in S1). Default chosen by Claude. |
| 6 | GELF over TLS | In S4. Default chosen by Claude. |

When S3 is implemented, also reword CLAUDE.md hard rule 3 ("server IDs are looked up from config" → "from the
effective server registry: config.yaml + admin-managed DB rows") and security.md threat T4.

### Further decisions (2026-10-21, after S1)

- UI text uses **US English** ("License", "Color").
- **A fresh login counts as the step-up**, so a newly signed-in admin can make changes for 5 minutes without re-entering a code.
- **Accessibility checks run in CI:** `@axe-core/playwright` 4.13.0 (test-only, MPL-2.0) scans 9 pages for WCAG 2.2 AA in the Playwright smoke; any violation fails the build.
- F-11 confirmed on a real R730XD iDRAC8: each PSU reports `PowerInputWatts: 900` (constant, = 750 W output rating / ~83 % efficiency) while the chassis draws 263 W, so the UI labels it as a rating.

### S2 as built (2026-10-21)

Implemented as designed (tech_doc §24) with these additions and deviations:

- Paths follow S1's `/settings/*` layout: `GET/POST /settings/general`. New authz actions
  `admin.general.view`, `admin.general.manage` (step-up) and `user.prefs` (every role, no step-up).
- Requests: a display time zone (app default `ui.time_zone` plus a per-user override), per-user
  display preferences (`/preferences`: zone, color theme, date format, 12/24 h clock, °C/°F, table
  density) in a new `user_prefs` table, and six color themes with an app default `ui.theme`.
- Migration is `0005_settings.sql` (S1's enrolment migration took 0004). `settings_kv` also accepts
  `ui.theme`; S1 already had `api_tokens.expires_at`.
- The step-up window is the design's 1–5 min in config.yaml and Settings alike. (S2 first lowered
  the floor to 1 s for an e2e test; S3 restored 1 min. Tests shorten the window through a test-only
  hook in `cmd/oob-manager`, `env.stepUpWindow`, which `main` never sets and no config key reaches.)
- Poll interval changes apply after a restart until S3's `fleet.Apply`; everything else is live.

### S3 as built (2026-10-21)

Implemented as designed (tech_doc §25) with these additions and deviations:

- Paths follow the `/settings/*` layout: `/settings/servers`, `/settings/servers/new`,
  `/settings/servers/{id}` and POST sub-paths (`fingerprint`, `identity`, `connection[/fingerprint]`,
  `pin[/fetch]`, `credentials/{slot}`, `features`, `enable`, `disable`, `delete`, `test`).
- Packages: `internal/registry` (the effective server registry), `internal/netpolicy`,
  `internal/secrets/credstore`, `internal/tofu`; cmd `runtime.go` re-applies the registry.
- Migration `0006_servers.sql` (servers with a per-row `rev` and a `cred_seq` that versions every
  credential; bmc_credentials). S2's display-default keys needed `0007`; notifications are `0008` (tech_doc §27).
- A server's connection change carries the new pin (a new address is a new BMC), deletes the
  credentials and disables it. Fingerprint fetches and tests have their own 6/min limits and do not
  count against the 10/min change limit.
- Hard rule 3 and security.md T4 are reworded; T8 (scanner/SSRF) and I10 (DB credentials; first numbered I8, which notifications had already taken) added.
- Deviations: the id pattern stays the file's; `ssh-rsa` host keys are accepted (iDRAC8).
- S2 follow-ups done: step-up floor 1 min (test hook instead), Reset to default, operator account
  privileges documented (deploy/README.md); request: app-wide clock/date/temperature/density defaults.

### S4 as built (2026-10-22)

Implemented as roadmap plan 05 describes (tech_doc §34), with decision 6 (GELF over TLS):

- Path `/settings/integrations` (tab after Notifications); POST sub-paths `reset`,
  `gelf/fingerprint`, `gelf/pin`, `gelf/test`. Authz `admin.integrations.view` / `.manage` (step-up).
- Keys `gelf.enabled|address|transport|server_name|pin_sha256` (file paths `audit.gelf.*`); the
  file-only `audit.gelf.allowed_networks` defaults to the private ranges. Migration `0012_integrations.sql`
  rebuilds `settings_kv` with every key.
- TLS with an SPKI pin of the leaf or of the issuing CA; an issuer pin holds only when the leaf
  verifiably chains to it. Trust on first use with one proof per offered certificate.
- The shipper is swapped without a restart; the update row reaches the old destination, the applied
  row the new one. A pin mismatch pauses shipping (banner, `trust` notification, `/readyz` degraded).
- Open questions of plan 05 answered with its recommendations: private ranges by default, no UDP,
  and the Prometheus hint shows the scrape block plus the `metrics.enabled` and
  `metrics.allow_networks` values and the dedicated-token advice.
- Deviations: `admin.integrations.reset` (Reset to default, like General); the Prometheus snippet
  uses `authorization.credentials_file` (as deploy/README) instead of `bearer_token_file`.

### v0.9.1: instance name in General, aligned fields (2026-10-29)

- Request ("keep as much in the UI as possible"): `ui.instance_name` is now a General key
  (file > DB > default, lock badge when the file sets it, audited, Reset to default). It is
  validated by the same rule for the file and the browser (`config.validInstanceName`: at most 64
  bytes, printable, no `< > & " '`, no leading or trailing spaces; the form trims). The header, the
  sign-in page and webhook notifications read the live value. Migration `0018_instance_name.sql`
  rebuilds `settings_kv` with the key; `settings export` writes it when set.
- Settings › General fields line up: each field spans four shared grid rows (label, control, help,
  source line + reset) through CSS subgrid, a locked number keeps the editable shape with its unit
  inline, and each group heading has a separator. The catalog panel's file-only keys are a two-column
  list (`.kv-cols`). Guarded by `tests/e2e/settings_layout.spec.ts`.
- Still file-only by design: `listen`, `tls`, `public_url`, `auth.mode`, `storage.*`, `secrets.*`,
  `settings.locked`, `settings.bmc_networks` (they bound what the browser may change), the catalog's
  URL, keys, allowed networks, unsigned uploads and systems map (plan 08 T14/S10/E5),
  `audit.gelf.allowed_networks` and `metrics.*`.
