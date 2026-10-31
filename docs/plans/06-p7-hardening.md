# Plan 06 — P7 Hardening and release readiness

Status: plan, 2026-10-21. No code. **2026-10-22: the P7-early subset (§3.8 Renovate and the
dependency-doc test, §3.9 gates incl. the nightly soak, actionlint from §3.2) is built on branch
`p7-early`; tech_doc §33 records the choices. §2 below is the state before it. 2026-10-30: lane A (H1 reviews/limits/umask/CSP test, H2
recovery CLI and runbook, H6 threat model and generic deploy docs) and lane B (H3 fuzz merged; H4 ZAP,
H5 release workflow) built; §4 has the current status.** Source: task_list P7 (7.1–7.4, 2 d as written in
2026-10-20) expanded to what the codebase needs after P1–P5, S1–S3, notifications,
maintenance, metrics and the features planned in 01–05. Inputs: `.github/workflows/ci.yml`,
`Makefile`, `.golangci.yml`, `Dockerfile`, `deploy/compose.yaml`, security.md, tech_doc
§8/§10/§14/§25–§30.

## 1. Goal and non-goals

**Goal.** Make the generic build demonstrably safe to publish (P8): automated gates that
would catch a regression of any control in security.md, a verified recovery story for the
four failure classes an operator will hit, a refreshed threat model, a dependency policy
that runs itself, and a single checklist that says "ready" or names what is missing.

**Non-goals.** Pen-testing the real BMCs, new product features, changing the security
model (no bypasses, no new roles), the public-repo cut itself (P8.6).

## 2. What exists today (verified in the tree)

| Gate | State |
|---|---|
| golangci-lint v2.14.0 with gosec, forbidigo/depguard (no `os/exec`), revive length/nesting | CI job `lint`, plus `make noexec`, gofmt, go vet (`-tags e2e` too) |
| `go test -race -cover`, **total** ≥ 80 % | CI job `test`; **no per-package gate** (tech_doc §8 item 3 still open; every package is ≥ 80 % today) |
| govulncheck v1.8.0 | CI job `vulncheck` |
| Image build, non-root/no-shell smoke, Trivy v0.75.0 (fixable HIGH/CRITICAL), Syft SBOM | CI job `image`; SBOM is a workflow artifact only (`upload-release-assets: false`), **no signature, no provenance, no release workflow** |
| Go e2e + Playwright (axe WCAG 2.2 AA on ≈ 40 pages × 2 widths × 2 schemes) | CI jobs `e2e`, `e2e-ui` |
| Actions pinned by SHA, tool versions ≥ 14 days old | yes; `actionlint` run by hand, not in CI |
| Renovate/Dependabot, SECURITY.md, CONTRIBUTING.md, `.trivyignore`, gitleaks | **none** |
| Fuzz targets | **none** (`func Fuzz…` count: 0) |
| `go test -race -count=3 -shuffle=on` | run by hand before each integration (tech_doc gates), not in CI |
| ZAP baseline | **not done** (7.2) |
| Restore drills / runbook | **not done** (7.3); deploy/README has upgrade/rollback steps only |
| Audit chain verify on start and on demand | yes; truncation of newest rows detectable only against the GELF copy (§9 note) |

## 3. Work items

### 3.1 Reviews (task 7.1) — 0.5 d

security-reviewer and code-reviewer passes over the integration branch as it stands, plus
the items below that are reviews rather than code:

**Rate-limit review of every POST route** (write the table into security.md §3):

| Route(s) | Limit today | Verdict |
|---|---|---|
| `/login`, `/login/totp`, `/enroll*`, `/stepup` | 5/min/IP, 10/h/account; TOTP 5/min/IP; `/enroll/{token}` 5/min/IP | ok |
| `/logout` | CSRF only | ok (deletes own session) |
| `/prefs/theme`, `/prefs/refresh` | CSRF only, cookie write | ok (no storage) — add to the 30/min `annotate` limiter anyway for uniformity |
| `/preferences` (display prefs) | per-user change limit + audit | verify the limiter is applied (test asserting 429) |
| power actions | 10/min/user + 60 s cooldown/server | ok |
| fan lease start / end | 10/min/user | ok |
| console tickets, takeover, kvm-launch | 10/min/user | ok |
| settings changes (users, tokens, general, servers, notifications, integrations) | 10/min/user | ok |
| fingerprint fetch / test connection | 6/min/user each | ok |
| notification Send test | 3/min/user | ok |
| audit verify | 1/min global | ok |
| maintenance / notes / acks | 30/min/user | ok |
| WebSocket upgrades | single-use 30 s ticket | ok |
| `/healthz`, `/readyz` (unauthenticated GET) | none; `/readyz` pings the single DB connection | **add** a 1 s render cache (like `/metrics`) and a per-IP 60/min bucket so a flood cannot hold the writer connection |
| `/api/*`, `/metrics` | 60/min/token | ok; new CSV endpoints (plans 02/03) get 6/min/token |
| new routes from plans 01–05 | as specified in each plan | check at review |

**Session fixation / CSRF review for the wizards** (checklist with a test per line):
session ID rotated on login (yes), on step-up (yes, `rotate`); role and `disabled` are read
from the user row on **every** request (`Authenticate` → `activeUser`), so a demotion or
disable applies at once (add the test that a demoted admin's next request is 403 and a
disabled user's is 401); pre-login forms bound to the random `__Host-oob_pre` cookie
(fixation: a cookie set by an attacker before login is replaced at login — assert);
every cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict` (theme/refresh included:
verified in `prefs.go`); `CrossOriginProtection` + synchronizer token on every POST; the
S3 add-server wizard's TOFU proof is bound to session + purpose + value with a 5 min TTL
(exists; add the "proof from another server's form is refused" case if missing); enrolment
link single-use in SQL (exists); WebSocket `Origin` check against request host **and**
`public_url` host (exists; add the mismatched-port case); `rev` compare-and-set on every
settings form (exists). Logout invalidates the server-side session (yes) — add "a replayed
cookie after logout is 401".

**Secrets-at-rest review (HKDF purposes)**: master = `totp_key` (32 B, `app-keys.age`),
used directly as the AES-GCM key for TOTP secrets (AAD = user ID) **and** as the HKDF IKM
for: `oob-console/csrf/v1` (form HMAC), `oob-console/bmc-cred/v1` (DB BMC credentials, AAD
server|slot|kind|address|port|version), `oob-console/tofu/v1` (fingerprint proofs),
`oob-console/notify/v1` (notification secrets, AAD id|kind|url). Findings to record: the
master is both a working key and an IKM (acceptable — HKDF output is independent of the
IKM's other uses — but document it and reserve `oob-manager/totp/v2` for a future
re-enrolment path so no new direct use of the master is added); the `key_id = 'v1'`
columns allow a `rekey` CLI (decrypt with the old identity/keys, re-seal with new) which
is **not** built — list it as the known gap with the runbook consequence (rotation =
re-enter every sealed secret). File modes: the SQLite database is created with the
process umask; set `umask 077` at `serve` start (Linux, `golang.org/x/sys/unix.Umask`,
not banned by forbidigo) so `oob-manager.db`, `-wal`, `-shm` and VACUUM-INTO backups are
0600. The database holds sealed secrets, hashed tokens and the audit log: say so in the
backup section.

### 3.2 ZAP baseline against the container with mock BMCs (task 7.2a) — 1.0 d

- New CI job `zap` (on PR and nightly), after `e2e-bin`: start the dev harness
  (`TestDevServer`, two mock BMCs, TLS self-signed) on the runner; run the ZAP baseline
  image (`zaproxy/zap-stable`, pinned by digest, ≥ 14 days old) with
  `zap-baseline.py -t https://host:18443 -c tests/zap/rules.tsv -I -m 3`.
- Authenticated coverage: a 40-line Node script `tests/zap/signin.mjs` (reuses the TOTP
  code from the Playwright spec) signs in and prints the session cookie; ZAP gets it via
  the replacer rule (`-z "-config replacer.full_list(0).…"`), with the context excluding
  state-changing paths (`/logout`, `/servers/*/power/*`, `/servers/*/fan/*`,
  `/servers/*/console*`, `/settings/*/delete`, `/stepup`) so the passive scan never
  triggers an action; the spider is limited to GET.
- `rules.tsv` allowlists known, intended findings with a reason and an expiry date
  (e.g. "10109 Modern Web Application: no JS by design", "10049 cacheable static assets:
  versioned, public"); anything else at WARN or FAIL fails the job. The expected result on
  the current headers (CSP, HSTS, COOP/CORP, nosniff, no-referrer) is zero findings.
- Also run `zap-api-scan.py` against `/api/v1` with a hand-written minimal OpenAPI 3
  document (`docs/api/openapi.yaml`, generated once from tech_doc §6 and kept current by
  a contract test that every route in `internal/api` appears in it). The OpenAPI file is
  also the public API reference P8 needs.
- Add `actionlint` (pinned) to the `lint` job while here.

### 3.3 SBOM, signing, provenance, release workflow (task 7.2b) — 1.0 d

- `release.yml` on tag `v*` (permissions scoped to that job: `contents: write`,
  `packages: write`, `id-token: write`, `attestations: write`): `make check`-equivalent
  jobs must be green; build multi-arch (`linux/amd64`, `linux/arm64`) with buildx
  (`provenance: mode=max`, `sbom: true`), push to GHCR as `ghcr.io/<owner>/oob-manager:
  <version>` and `:<major.minor>`; `cosign sign --yes` keyless (Fulcio/Rekor) on the image
  digest; `cosign attest --predicate oob-manager.spdx.json --type spdxjson`; GitHub
  `attest-build-provenance` (pinned SHA) for the image and the binaries; release assets:
  `oob-manager_<ver>_linux_{amd64,arm64}.tar.gz`, `checksums.txt`, `oob-manager.spdx.json`,
  `CHANGELOG` section. A verify step in the same workflow runs
  `cosign verify --certificate-identity-regexp '^https://github.com/<owner>/oob-manager/'
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <image>` and
  `gh attestation verify`.
- deploy/README gains "Verifying a release" (the two commands above and `sha256sum -c`);
  `compose.yaml` keeps a digest-pinned image reference as the example.
- Until the repository is public, GHCR packages are private; the workflow works the same.

### 3.4 CSP reporting endpoint? — decision, 0.1 d

**Recommendation: no endpoint.** A `report-to`/`report-uri` receiver is a new
*unauthenticated POST endpoint* that any LAN client can flood or spoof; the app has none
today and the threat model (D1) values that. The CSP is static and tested
(`security_test`, headers snapshot); the known violations (xterm.js `<style>` injection,
truecolor `style=`) are documented, not bugs. Replace the need with a test: `pages.spec.ts`
subscribes to `securitypolicyviolation` events on every page and fails on any violation
outside an allowlist (the two xterm cases on `/servers/*/serial` only). If telemetry is
ever wanted: `Content-Security-Policy-Report-Only` with a receiver limited to 4 KiB,
5/min/IP, counting only (no storage, no body logging) — recorded as the rejected
alternative in security.md.

### 3.5 Fuzz targets (nightly) — 1.0 d

Go native fuzzing, seeds committed under `testdata/fuzz/<Target>/`, crashers become
regression tests. CI job `fuzz` nightly (`workflow_dispatch` too): each target 30 s
(`go test -run=^$ -fuzz=<name> -fuzztime=30s`), total < 10 min.

| Target | Package | Property |
|---|---|---|
| `FuzzRFBFilter` | `console/rfb` | any client→BMC byte stream either forwards only allowlisted message types or ends the session; never panics; forwarded bytes are a prefix-preserving subsequence |
| `FuzzRFBServerHandshake` | `console/rfb` | BMC-controlled version/security/ServerInit bytes never panic; names > 1 KiB refused |
| `FuzzSerialControl` | `console` | JSON control messages: only the three types decode; anything else is `protocol` |
| `FuzzSerialInput` | `console` | the quit key 0x1c never reaches the SSH side; ≤ 4 KiB enforced |
| `FuzzLogEntryDecode` | `bmc/redfish` | `flexString`/`logEntryDoc` on mutated fixture JSON never panic; message text is bounded |
| `FuzzSnapshotDecode` | `bmc/redfish` | mutated Thermal/Power/subsystem fixtures: no panic, `Problems()` classes only |
| `FuzzGELFEncode` | `audit` | encode/decode round trip, NUL terminator unique, size cap |
| `FuzzRedact` | `audit` | no value of a secret-named key survives redaction (nested) |
| `FuzzCheckBMCAddr` | `netpolicy` | accepted strings re-format to themselves and are inside the allowlist |
| `FuzzLinkify` | `web/ui` (notes) | output through `html/template` contains no unescaped `<` or `javascript:` |
| `FuzzCSVField` | `csvx` (plan 02) | RFC 4180 round trip, injection guard |
| `FuzzCompareVersions` | `firmware` (plan 03) | antisymmetric, transitive on comparable inputs, never panics |
| `FuzzTOTPCode` / `FuzzBase32` | `auth` | malformed codes/secrets never panic, never verify |
| `FuzzLeaseAck` | `fan/hostlease` | hostile ack files: at most "pending vs applied" changes |

### 3.6 Restore drills and runbook (task 7.3) — 1.0 d

Enabler: a **`backup` subcommand** (research F11, minimal): `oob-manager backup <dir>`
writes `oob-manager-<ts>.db` via `VACUUM INTO` (consistent, no locks held long; written
under `/data`, not `/tmp`), copies nothing else (config and `.age` files are the installer's own
files; the age identity is **never** included), prints the schema version and the audit
head hash, mode 0600. `oob-manager verify-audit [db]` verifies a chain offline. Restore =
stop, copy the file over `oob-manager.db`, start; the startup verify logs the result.

Drills, each executed once against the dev harness and written up in
`deploy/README.md` "Recovery runbook" with expected symptoms and commands:

| # | Scenario | What is lost / what survives | Steps |
|---|---|---|---|
| 1 | Lost database (disk failure, deleted by mistake) | lost: users, sessions, tokens, settings, browser-managed servers + credentials, notification targets, notes/acks/windows, leases, history, audit chain (GELF copy survives); survives: config.yaml, age files, TLS | start → empty DB → `bootstrap-admin`, re-mint tokens (dashboards break until then), re-add servers or `settings import`; **fan leases**: `host-lease` expires on the host by itself (NFR-7); `redfish-floor`: the raised `MinimumFanSpeed` stays until someone resets it — the runbook names the attribute and the vendor UI path; check with `/metrics` or the server page after re-adding |
| 2 | Lost age identity or app keys | credentials file unreadable → `serve` refuses to start (by design); TOTP enrolments, DB credentials, notification secrets unrecoverable; audit chain intact | new identity → re-encrypt credentials and app keys → `reset-totp` per user (CLI) → re-enter DB credentials and notification secrets; document the "offline copy of the identity" rule and test that the app really refuses to start |
| 3 | Crash mid-lease | the reconciler heals from the row at start (tested); `pending` with no ack → re-apply; expired → release | drill: kill `serve` between `pending` and `applied` in the harness; observe audit `fan.lease.reapply`/`expire` |
| 4 | Crash mid-maintenance | window and reminder watermark persist (0009/0010) | drill: kill during a window; observe no duplicate "started", reminder timing |
| 5 | Crash mid-power verification | the operation is lost; audit has `started` without a final row | runbook: how to read an orphan `started` row, what the host state tells you |
| 6 | Crash mid-BMC-reset (plan 01) | open `bmc_resets` row re-arms the window | drill after plan 01 |
| 7 | Restore an **older** backup | chain verifies, but the newest rows are gone: detectable only by comparing the head hash with the last row in GELF | runbook: the `verify-audit` head hash vs the log server's last `row_hash`; expect notifications and acks since the backup to be missing |
| 8 | Wrong `settings.locked` or bad DB row locks admins out | `admin-recover` CLI, config edit | drill the break-glass path end to end |

### 3.7 Threat-model refresh of security.md — 0.5 d

Add or revise rows for everything since P5 and for plans 01–05: BMC reset (**T9**, **D8**,
**R4**), history export (**I12**), firmware disclosure (**I13**), GELF redirection
(**T10**), vendored fonts (§6 supply chain), maintenance windows and acknowledgements as
evidence-hiding (R3 covers windows; add acks explicitly), display preferences (no new
threat; note), the second read-only SQLite connection (no new threat; note the shared
`busy_timeout`), the umask change, `/readyz` flood (D1 extension), the no-CSP-report
decision, and the per-request role re-read as the control for E1. Re-check that every ID
is unique (today: S1–S9, T1–T8, I1–I11, D1–D7, R1–R3, E1–E4) and renumber nothing
retroactively. Residual risks list re-read against the current hardware notes.

### 3.8 Dependency and base-image bump policy — 0.5 d

- `renovate.json`: `minimumReleaseAge: "14 days"` (the rule 10 waiting period), monthly
  schedule, grouped PRs (Go modules / GitHub Actions / Docker digests / npm test deps),
  `helpers:pinGitHubActionDigests`, Docker digest pinning for both base images, Go
  toolchain bumps as their own PR, `golangci-lint`/`govulncheck`/Trivy/Syft versions in
  Makefile + ci.yml tracked by regex managers so the two files cannot drift.
- A Go test `TestDependenciesDocumented`: every direct `require` in `go.mod` has a row in
  tech_doc §2 (and the vendored assets in `vendor.sha256` have a NOTICE entry).
- `.trivyignore` policy: entries need a CVE, a reason and an expiry date; a CI step fails
  on expired entries.
- Monthly cadence written into deploy/README "Ongoing": bump, `make check`, `make scan`,
  `make e2e`, read the Trivy table, redeploy.

### 3.9 Per-package coverage gate, race and shuffle in CI — 0.25 d

`make cover` additionally fails when any of `auth`, `authz`, `fan`, `power`, `audit`,
`console`, `console/rfb`, `netpolicy`, `credstore`, `tofu`, `registry` is below 80 %
(parse `go tool cover -func` per package; the rule 1 list plus the packages that gained
security controls since). Nightly job `soak`: `go test -race -count=3 -shuffle=on ./...`
(today a manual pre-integration step).

### 3.10 Deploy (task 7.4) — 0.5 d

Generic part only in the public docs: compose project, bridge network, the identity-staging
pattern, CA/auto-update exclusion, GELF stream. Install-specific values (addresses, host paths,
monitoring wiring) never enter the repository (plan 07 §4.1).

## 4. "Ready for public release" checklist (feeds P8)

Status as of 2026-10-30: every plan 06 slice (H1–H6) is merged to `main` and released as v0.12.0.

- [ ] CI green on `main`: lint (+actionlint), test (total **and** per-package ≥ 80 %),
      vulncheck, image (Trivy clean, SBOM), e2e, e2e-ui (axe 0 violations), visual (plan 04),
      zap (0 unexpected), fuzz nightly green for 2 weeks, soak nightly green.
      *Status:* every gate runs on main, zap included (quick baseline per run; the authenticated
      baseline + API scan nightly, first clean full run 2026-10-30). The test job has 25 minutes. The fuzz nightly started with H3 (merged 2026-10-30), so its two weeks end
      2026-11-13 at the earliest. The CSP violation check (§3.4) rides on e2e-ui (H1).
- [ ] `release.yml` produced a signed, attested multi-arch image and verified it.
      *Status:* workflow merged; by the maintainer's decision it runs as a dispatch dry run until
      the repository is public (keyless signing writes the repo name to the public Rekor log).
- [x] security.md refreshed (§3.7), every threat ID unique, residuals current; the
      rate-limit table and the HKDF purposes list are in it.
      *Status:* H1 (§3k rate limits, §3l fixation checklist, §3m secrets at rest) and H6 (R6, R7, I19,
      E7, D1/E1/R1 extended, residuals 6–9, no-new-threat notes); IDs checked unique.
- [x] Recovery runbook with the eight drills executed and dated.
      *Status:* H2, deploy/README "Recovery runbook", drilled 2026-10-30 against the test harness
      (drills 1, 2, 7, 8 as new tests; 3, 4, 6 mapped to existing tests; 5 a runbook reading).
- [x] `backup`/`verify-audit` CLI shipped and documented.
      *Status:* H2 (plus `admin-recover`, and CLI audit rows shipped to GELF).
- [ ] Renovate active with the 14-day rule; `TestDependenciesDocumented` green; NOTICE
      complete (fonts, noVNC, xterm.js, Go module licences).
      *Status:* P7-early built the config and the test (green); the Renovate dashboard issue has not
      been seen yet, so "active" is unconfirmed.
- [ ] No install-specific details in the tree: a whole-tree test for RFC 1918 literals, host
      paths, real-looking MAC addresses and home-network host names, plus gitleaks, trufflehog and
      a grep for private identifiers over the exact exported tree (P8.6).
      *Status:* plan 07 §4.1 (`internal/repopolicy` `TestPublicTreeHasNoNetworkDetails`) and §4.6
      (`scripts/public-cut.sh`) on branch `public-cut`. H6 made `deploy/compose.yaml` generic
      (TEST-NET addresses, `/srv/oob-manager`) and added the generic deploy sections (§3.10).
- [ ] SECURITY.md (private vulnerability reporting), CONTRIBUTING.md, CODE_OF_CONDUCT.md,
      issue templates incl. "Hardware report" (P8.5/8.5a), `docs/hardware.md` with the
      verified cells from plans 01/03.
      *Status:* P8, not started.
- [ ] Hardware statement: exactly what was verified on iDRAC8 2.86 and iDRAC9 7.00;
      everything else marked untested.
      *Status:* P8, not started (the facts are in tech_doc and the plans).
- [ ] Screen-reader pass done (plan 04 §9, audit F15) and the accessibility statement
      updated.
      *Status:* maintainer task, not done.
- [ ] Open questions in plans 01–05 answered or recorded as decisions.
      *Status:* plan 06's own §7 questions are answered (2026-10-29: ZAP smoke per PR + full
      nightly, keyless signing live only after go-public, the backup CLI, umask 077); plans 01–05 not
      re-read for this.

## 5. Effort

| Item | Days |
|---|---|
| 3.1 reviews (security/code agents, rate-limit table, fixation checklist, secrets review, umask, `/readyz` cache) | 1.0 |
| 3.2 ZAP baseline + API scan + OpenAPI stub + actionlint | 1.0 |
| 3.3 release workflow: multi-arch, cosign, attestations, verify docs | 1.0 |
| 3.4 CSP decision + violation test | 0.1 |
| 3.5 fuzz targets + nightly job | 1.0 |
| 3.6 backup/verify-audit CLI + eight drills + runbook | 1.0 |
| 3.7 threat-model refresh | 0.5 |
| 3.8 Renovate, dependency-doc test, trivyignore policy | 0.5 |
| 3.9 per-package gate, soak job | 0.25 |
| 3.10 deploy (generic part) | 0.5 |
| **Total** | **≈ 6.75 d** (task_list had 2 d for the original four items) |

A cheap **P7-early** subset (3.8 Renovate, 3.9 gates, actionlint, the dependency-doc test:
≈ 0.75 d) can land immediately and protects every other plan while it is built.

## 6. Risks

- ZAP in CI adds ~5 min and some flakiness (spider timing); run it on PR with a short
  spider and nightly in full.
- Keyless signing needs the repository on GitHub with OIDC; it works for private repos but
  the Rekor transparency log entry reveals the repository name and tag — acceptable (the
  project will be public).
- Fuzzing finds real crashers in the RFB filter or decoders; budget the fixes in the
  slice, not after.
- The umask change alters file modes of existing installs only for new files; the runbook
  tells owners to `chmod 600` the existing database once.

## 7. Open questions

1. Run ZAP on every PR (slower CI) or nightly only with a PR-time smoke of the headers?
2. Keyless cosign (Fulcio) or a repository-held cosign key? Keyless is recommended.
3. Is a `backup` CLI in P7 acceptable (research F11 placed it pre-release), or defer it
   and drill with `docker stop` + file copy only?
4. Confirm the per-package 80 % list in §3.9.
5. Approve `umask 077` at `serve` start (changes the mode of newly created files under
   `/data`).
