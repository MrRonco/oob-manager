# Technical document — oob-manager

## 1. Stack decision

### Chosen: Go

| Criterion | Go | Python (FastAPI + python-redfish / pyghmi) | Rust |
|---|---|---|---|
| Deployable | Single static binary on distroless (~15–25 MB image) | Interpreter + wheels; larger image, more CVE surface | Static binary, small |
| Redfish lib | **gofish** v0.27.0 (2026-10-05), BSD-3, active | `python-redfish-library` (DMTF), active | No mature client; hand-rolled serde |
| IPMI 2.0 lib | **go-ipmi** v0.9.1 (2026-08-31), Apache-2.0, native RMCP+, cipher selection, SOL streams, ships a **reference BMC server for tests** | pyghmi: development moved to opendev, GitHub mirror archived; few maintainers | `ipmi-rs` immature, no RMCP+ SOL |
| Multi-vendor abstraction | bmclib v2.3.5 (Apache-2.0) exists and uses gofish + go-ipmi | — | — |
| Concurrency for pollers + WS console pumps | Native goroutines, `context` timeouts | asyncio, fine | tokio, fine but slower to write |
| Fit with existing ecosystem | `idrac_exporter` (MIT, Go) is the reference for iDRAC Redfish quirks | Dell's sample scripts are Python (GPL-2.0, reference only) | — |
| Maintenance by one maintainer | Simple toolchain, `govulncheck` is reachability-aware | Dependency churn | Steeper |

**Decision: Go**, current stable toolchain pinned with `toolchain` in `go.mod` (1.26.x at
time of writing; Go 1.25+ is required for `http.CrossOriginProtection`).

### bmclib: borrow the pattern, not the dependency

bmclib (Tinkerbell/Equinix lineage) is the obvious multi-vendor choice and is maintained.
It is **not** used directly because:
- its provider set (asrockrack, supermicro, intelamt, rpc, ipmitool shell-out, …) widens the
  dependency graph and the `ipmitool` provider shells out, which this project forbids;
- we need control over TLS pinning, cipher-suite policy and session lifecycle that its
  generic options hide;
- its last release (2026-03) lags gofish.

What we borrow (Apache-2.0, attribution in `NOTICE` if any code is adapted): the
provider-registry + "try in order, record which provider succeeded" pattern, and its
capability-feature naming.

### Front end

Server-rendered `html/template` with small first-party scripts (`app.js`, `palette.js` (§52), `console.js`,
`serial.js`). No SPA, no Node build in production, no htmx (planned, then not needed: §13).
Console pages add the only vendored libraries, **xterm.js** (MIT) and **noVNC** (MPL-2.0,
unmodified files, license kept alongside); §2 lists them. No charting library is vendored:
the history charts and sparklines are server-rendered SVG (`internal/history/svg`, §39), which keeps
the strict CSP and works without a script (uPlot was considered and is not needed). OpenBMC
**webui-vue** (Apache-2.0) is used as an information-architecture reference for page
layout (Overview / Hardware status / Logs / Operations / Settings), not as code.

## 2. Libraries (planned)

| Purpose | Module | License |
|---|---|---|
| Redfish | `github.com/stmcginnis/gofish` | BSD-3 |
| IPMI 2.0 + SOL | `github.com/bougou/go-ipmi` (pin exact version; pre-1.0 API) | Apache-2.0 |
| BMC SSH | `golang.org/x/crypto/ssh` (part of `golang.org/x/crypto`, already a direct dependency for argon2; no new module). Used by `internal/bmc/bmcssh` with the supported, non-insecure algorithm sets only (§22) | BSD-3 |
| Password hashing | `golang.org/x/crypto/argon2` | BSD-3 |
| Vendor catalog signatures | **None (standard library).** A small OpenPGP verifier in `internal/firmware/catalog/dell` (`pgp_armor.go`, `pgp_packet.go`, `verify.go`): ASCII armor with CRC-24, v4 RSA/DSA primary keys, v3/v4 signature packets, `crypto/rsa` and `crypto/dsa` (deprecated, used for verification only: Dell signs with DSA-1024). `golang.org/x/crypto/openpgp` (decision 2 in plan 08) was dropped after merge: govulncheck flags the whole package tree, including `armor`, as GO-2026-5932 ("unmaintained, unsafe by design", no fix), which fails the CI gate. Verified against Dell's real v3 DSA/SHA-1 catalog signature and a real Ubuntu archive v4 RSA/SHA-512 signature. Dell's public key (`dell-ca77951d.asc`) is embedded from linux.dell.com and pinned by fingerprint | — |
| TOTP | `github.com/pquerna/otp` | Apache-2.0 |
| JWT/JWKS (CF Access) | `github.com/coreos/go-oidc/v3` (verifier with remote key set) | Apache-2.0 |
| SQLite (no cgo) | `modernc.org/sqlite` | BSD-3 |
| Migrations | embedded SQL files + tiny runner (no framework) | — |
| Secrets at rest | `filippo.io/age` | BSD-3 |
| WebSocket (console relay) | `github.com/coder/websocket` **v1.8.15** (2026-06-15). The stdlib has no WebSocket server and `x/net/websocket` lacks close handshakes, read limits and `NetConn`; used only for the graphical console upgrade | ISC |
| VNC client in the browser (vendored, not a Go module) | **noVNC 1.7.0** (2026-04-28): the 52 ES-module files `core/rfb.js` imports, unmodified, under `internal/web/ui/static/vendor/novnc-1.7.0/` with LICENSE.txt and licence texts; SHA-256 per file in `internal/web/ui/vendor.sha256`, re-verified by a unit test; entry in `NOTICE`. No build step, no npm dependency at run time | MPL-2.0 (core, file-level), pako MIT, des.js BSD |
| Terminal in the browser (vendored, not a Go module) | **xterm.js 6.0.0** (`@xterm/xterm`, 2025-12-22) and **@xterm/addon-fit 0.11.0** (same day): `lib/xterm.mjs`, `css/xterm.css`, `lib/addon-fit.mjs` and both LICENSE files, unmodified, under `internal/web/ui/static/vendor/xterm-6.0.0/` and `internal/web/ui/static/vendor/xterm-addon-fit-0.11.0/`; npm tarball shasums checked against the registry; SHA-256 per file in `vendor.sha256` (re-verified by a unit test); entry in `NOTICE`. No build step. Why not stdlib/own code: a VT100/xterm emulator with screen-reader support is a large, specialised component | MIT |
| Web fonts (vendored, not a Go module) | **Inter 4.1** (UI) and **JetBrains Mono 2.304** (numerals, IDs, code): one variable woff2 each (wght 400–700, Latin subset, 41.9 KB + 14.3 KB), with the OFL text, under `internal/web/ui/static/vendor/fonts/<family>-<version>/`; SHA-256 in `vendor.sha256` (re-verified by a unit test), size budget test (≤ 120 KB per family, ≤ 250 KB total), entry in `NOTICE`, credited on the About page. **Subsets** (Modified Versions under the OFL) of the upstream release TTFs: Inter `v4.1` asset `https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip` (SHA-256 `9883fdd4…6b11e`; `InterVariable.ttf` `4989b125…0ccaf`) and JetBrains Mono `v2.304` asset `https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip` (`6f6376c6…f7bbf`; `fonts/variable/JetBrainsMono[wght].ttf` `662a196d…ac016`); full hashes, the fontTools 4.67.0 commands and the byte-identical rebuild (`tools/fonts/build-fonts.sh`, not run in CI) in §35. New bytes need a new versioned directory (`TestFontBuildsAreAppendOnly`). Why not system fonts: stacks differ per OS, so the visual baseline and the redesign's type would differ per machine (§35). No CDN, no build step in the app | SIL OFL 1.1 |
| Icons (vendored, not a Go module) | **Lucide 1.53.0** (2026-10-08; at least 14 days old when vendored): 43 icon SVGs (40 in slice B, 3 more in slice C), unmodified, from the release asset `lucide-icons-1.53.0.zip` (`https://github.com/lucide-icons/lucide/releases/download/1.53.0/lucide-icons-1.53.0.zip`, SHA-256 `9b493937acd827896739aad925e2978731375fdca11233d663cfb1c48af53d3f`, equal to the digest GitHub records for the asset), under `internal/web/ui/iconsrc/lucide-1.53.0/icons/` (embedded, **not served**), plus the repository's `LICENSE` at tag `1.53.0` (`b495047b…0329c57`) under `internal/web/ui/static/vendor/lucide-1.53.0/` (served, for the About page); SHA-256 per file in `vendor.sha256` (re-verified by a unit test); entry in `NOTICE`. At startup `sprite.go` re-serialises each file's shapes through an allow-list into one inline `<svg>` sprite per page (§40). Why not own drawings: a consistent, maintained 24-grid set; why not a JS icon library: the sprite is server-rendered, no script, no build step | ISC (Feather-derived icons also MIT) |
| Visual baseline runner (test only) | **`mcr.microsoft.com/playwright:v1.63.0-noble`**, pinned by its multi-arch index digest in the Makefile (`PW_IMAGE`, always run as `--platform linux/amd64`), built 2026-09-04; Renovate moves it together with `@playwright/test` and `TestPlaywrightImageMatchesTestRunner` requires the same version. Runs `tests/e2e/visual.spec.ts` only (`make visual`, CI job `visual`); never shipped. Why: screenshots are only comparable when made by the same Chromium, fonts and fallbacks (§35) | Apache-2.0 (image contents: Ubuntu, Chromium) |
| VNC authentication (DES) | stdlib `crypto/des` (RFC 6143 §7.2.2); no new dependency | BSD-3 (Go) |
| Config | `gopkg.in/yaml.v3` + explicit validation functions | MIT/Apache |
| Logging | `log/slog` (stdlib) + custom GELF handler | — |
| Accessibility checks (test only) | `@axe-core/playwright` 4.13.0 in `tests/e2e` (WCAG 2.2 AA scan in the Playwright smoke; never shipped in the image) | MPL-2.0 |
| Host lease reader tests (test only) | `bats` **1.13.0** (2025-11-07), run through `npx --yes bats@1.13.0` by `make host-test`; never installed globally, never shipped. Bash has no stdlib test runner; the reader is bash + awk because the host has no python | MIT |
| Release cut scanners (release only) | `scripts/public-cut.sh` (plan 07 §4.6) runs **gitleaks v8.30.1** (2026-03-21), **trufflehog v3.99.2** (2026-10-08) and **ExifTool 13.59** (2026-05-27) over the tree exported from a release tag. By default they run from container images pinned by digest in the script; ExifTool has no official image, so its GitHub tag archive (SHA-256 pinned in the script) runs in `perl:5.45.2-slim-bookworm`. `--scanners=local` uses binaries on PATH instead. The bats tests (`make cut-test`, same bats pin) use stub scanners. Never shipped, never linked, not run in CI. No stdlib or in-repo equivalent for secret detection or image metadata parsing | MIT (gitleaks), AGPL-3.0 (trufflehog), Artistic-1.0 or GPL-1.0+ (ExifTool, Perl) |
| Workflow lint (CI only) | `github.com/rhysd/actionlint` **v1.7.12** (2026-03-30), run with `go run …@v1.7.12` by `make actionlint` and the CI lint job; not in go.mod, never shipped. No stdlib equivalent checks GitHub Actions expressions, inputs and the job graph; it also runs shellcheck on every `run:` script when shellcheck is on PATH (§33) | MIT |
| Dependency update PRs (repository service, not code) | Renovate (GitHub app), configured by `renovate.json`; it only opens PRs, held 14 days, none automerged (§33). Not a module, nothing runs in the build | AGPL-3.0 (the bot; nothing is linked) |
| Metrics (optional, `metrics.enabled`) | **None**: the text exposition format 0.0.4 is hand-written on the stdlib (`internal/metrics`, §29). `client_golang` was planned and dropped: it would add a module tree for a format that is a few dozen lines to write | — |
| BMC security probes (§31) | **None**: TLS handshakes with `crypto/tls`, the SSH banner and KEXINIT read by hand (RFC 4253 §4.2, §7.1) and HEAD requests with `net/http` (`internal/secprobe`). `x/crypto/ssh` cannot stop after KEXINIT without starting authentication | — |
| IDs | `github.com/oklog/ulid/v2` | Apache-2.0 |
| Terminal echo-off for `bootstrap-admin` | `golang.org/x/sys/unix` (termios ioctls; already in the graph via x/crypto, now direct) | BSD-3 |

Rule: any new dependency needs a line in this table with its license and why stdlib is
not enough.

## 3. Repository layout

```
cmd/oob-manager/            main.go (wire-up only), healthcheck subcommand
internal/config/            load + validate (fail fast)
internal/secrets/           age decrypt, typed Secret values with redaction
internal/bmc/               driver.go, types.go (values only), errors.go
internal/bmc/redfish/       generic Redfish
internal/bmc/dellredfish/   Dell OEM (licenses, KVM session, thermal attributes)
internal/bmc/ipmi/          generic IPMI 2.0 via go-ipmi
internal/bmc/dellipmi/      Dell OEM raw fan
internal/bmc/bmcssh/        "console com2" only
internal/fleet/             per-server poller, breaker, snapshots
internal/fan/               lease model, arbiter, appliers (hostlease, redfishfloor, ipmioem)
internal/power/             action service
internal/console/           broker, serial pump, rfb auth terminator, kvm launch
internal/auth/              local, cfaccess, sessions, tokens, stepup
internal/authz/             permission matrix
internal/audit/             chain, gelf shipper
internal/store/             sqlite, migrations, repositories
internal/web/               routes, middleware, templates, handlers
internal/api/               JSON v1 handlers
web/static/                 vendored assets + VENDORED.md (versions + sha256)
web/templates/
testdata/redfish/idrac8/    recorded (sanitized) JSON payloads
testdata/redfish/idrac9/
test/integration/           httptest Redfish mock, go-ipmi reference BMC, fake SSH server
deploy/compose.yaml
internal/covergate/         `go run` tool: total + per-package coverage gate for `make cover` (§33)
internal/repopolicy/        test-only: dependencies documented, Renovate policy, tool pins (§33)
deploy/host/                example host-side fan lease reader (bash + awk) and its bats tests
scripts/public-cut.sh        release cut: export a tag with git archive and scan that tree (plan 07 §4.6); bats tests in scripts/test/
.github/workflows/ci.yml   lint (+ actionlint), test, vulncheck, image, e2e, e2e-ui
.github/workflows/nightly.yml  soak: go test -race -count=3 -shuffle=on
.github/CODEOWNERS          owner review for .github/, renovate.json, Makefile and the gate code
renovate.json               dependency PR policy (14-day minimum release age)
```

Files stay 200–400 lines; functions < 50 lines; no package-level mutable state except the
`atomic.Pointer` snapshot holders.

## 4. Configuration (`config.yaml`, read-only mount)

```yaml
listen: ":8443"
tls: { cert_file: /run/secrets/tls-cert, key_file: /run/secrets/tls-key }
public_url: https://oob.example
auth:
  mode: local            # local | cfaccess+local
  cfaccess: { team_domain: example.cloudflareaccess.com, aud: "<app aud tag>" }
  session_idle: 30m
  session_max: 12h
  stepup_window: 5m
audit:
  gelf: { address: 192.0.2.20:12201, transport: tcp }   # confirm the input type on the log server
  # also server_name, pin_sha256 (transport: tls) and the file-only allowed_networks (§34)
poll: { interval: 60s, min_interval: 30s, stale_multiplier: 3 }
ratelimit: { login_ip_per_min: 5, login_acct_per_hour: 10 }    # slice S2 (§24)
ui: { instance_name: "", time_zone: UTC, theme: graphite,     # display only; storage stays UTC
      clock_format: 24h, date_format: iso, temperature_unit: c, density: compact }  # app defaults
settings: { locked: [] }                                      # general | servers | integrations
servers:
  - id: r730xd
    name: Storage node R730XD
    tags: [critical, storage]
    bmc: { address: 192.0.2.10, kind: idrac8 }
    tls_pin_sha256: "<spki hash>"
    ssh_host_key: "ssh-ed25519 AAAA..."
    credentials: { readonly: r730xd-ro, operator: r730xd-op, vnc: r730xd-vnc }
    fan: { mode: host-lease, safe_min_pct: 30, max_lease: 2h }
    console:
      serial: bmcssh
      graphical: vnc                                   # none | vnc (kvm-launch, link: legacy values)
      vnc: { port: 5901, tls: true }   # iDRAC8 default quirks: safe_encodings, low_colour, rsa_kex_tls
      ssh: { port: 22 }                # serial (bmcssh); iDRAC8 default quirk: idrac8_legacy_ssh
  - id: r240
    name: Edge node R240
    tags: [critical, edge]
    bmc: { address: 192.0.2.11, kind: idrac9 }
    tls_pin_sha256: "<spki hash>"
    ssh_host_key: "..."
    credentials: { readonly: r240-ro, operator: r240-op }
    fan: { mode: redfish-floor, safe_min_pct: 20, max_lease: 2h }
    console: { serial: bmcssh, graphical: kvm-launch }
```

Credential refs resolve to entries in the age-encrypted `bmc-credentials.age`
(`{ref: {username, password}}`). Validation fails startup on: unknown keys, duplicate IDs,
fan mode not allowed for the BMC kind, missing pin, `safe_min_pct` < 20. The General keys
(`poll.interval`, `poll.stale_multiplier`, `auth.session_*`, `auth.stepup_window`, `ratelimit.*`,
`ui.time_zone`, `ui.theme`) can also be set in the browser (Settings → General); a key written in
the file wins and is shown locked there (§24).

## 5. Data model (SQLite)

| Table | Columns (abridged) | Notes |
|---|---|---|
| `users` | id, username, email, role, pw_hash, totp_secret_enc, totp_last_step, disabled, created_at | TOTP secret encrypted with app key |
| `sessions` | id_hash, user_id, created_at, last_seen, stepup_at, ip, ua | server-side |
| `api_tokens` | id, name, token_hash, scope(`read`), created_by, last_used_at, revoked_at | |
| `audit_log` | seq, ts, correlation_id, principal, auth_method, role, src_ip, server_id, action, params_json, result, bmc_status, error_class, prev_hash, row_hash | append-only, hash chain; triggers block UPDATE/DELETE |
| `fan_leases` | lease_id, server_id, mode, pct, issued_at, expires_at, requested_by, state(`pending/applied/ended/expired/rejected`), original_value | reconciled at startup |
| `capabilities` | server_id, probed_at, json | latest only |
| `sensor_keys` | id, server_id, key, kind, name, unit, first_ts, last_ts | one row per sampled sensor (§39) |
| `sensor_raw` | key_id, ts, value | every reading; `history.raw_days` (7) |
| `sensor_hourly`, `sensor_daily` | key_id, bucket, min, avg, max, n | rollups; 90 days, 2 years (§39) |
| `history_meta` | hourly_done, daily_done, last_clock_jump | one row: rollup watermarks |
| `console_sessions` | id, server_id, kind, user_id, started_at, ended_at, end_reason, bytes_in, bytes_out | |
| `schema_migrations` | version, applied_at | |

## 6. HTTP surface

### UI (session cookie)
| Method | Path | Role |
|---|---|---|
| GET | `/` (fleet overview) | viewer |
| GET | `/servers/{id}` (Overview tab: verdict, status, Now, consoles, events, system) | viewer |
| GET | `/servers/{id}/sensors` (temperatures, fans, PSUs, rails; §41) | viewer |
| GET | `/servers/{id}/events` (SEL / Lifecycle; `/servers/{id}/logs` redirects, §41) | viewer |
| GET | `/servers/{id}/activity` and `/activity` (actions only, §41) | viewer |
| GET | `/servers/{id}/fan` (Fan boost page, §41) | viewer |
| GET | `/servers/{id}/inventory` | viewer |
| GET | `/servers/{id}/history` (`range`, `focus`) and `/servers/{id}/history.csv` (`sensor`, `range`, `raw`; `all=1` operator) | viewer (§39) |
| POST | `/servers/{id}/power` | operator / admin (per action) + step-up |
| GET/POST | `/servers/{id}/bmc/reset` (confirm page; POST restarts the BMC, §37) | admin + step-up |
| POST | `/servers/{id}/fan/lease` | operator + step-up |
| POST | `/servers/{id}/fan/lease/end` | operator |
| GET/POST | `/servers/{id}/serial` (page; POST mints the ticket, `takeover=1`) + `GET /servers/{id}/serial/ws?ticket=` | admin + step-up (§22) |
| GET | `/servers/{id}/console/vnc` (page) + `GET /ws/vnc/{id}?ticket=` | admin + step-up |
| POST | `/servers/{id}/console/kvm-launch` → 303 to iDRAC | admin + step-up |
| GET/POST | `/login`, `/login/totp`, `/logout`, `/stepup` | — |
| GET | `/admin/audit`, `/admin/audit/verify`, `/admin/users`, `/admin/tokens` | admin |

### API v1 (bearer token, read-only)
| GET | Returns |
|---|---|
| `/api/v1/servers` | `{data:[{id,name,health,power_state,last_poll,…,bmc_restarting}], meta:{total}}` |
| `/api/v1/servers/{id}` | snapshot: temps, fans, PSUs, power watts, voltages, `power_telemetry`, health, stale flag, `bmc` (restart state, §37) |
| `/api/v1/servers/{id}/events?since=` | SEL entries, paginated (`limit` ≤ 200) |
| `/api/v1/servers/{id}/fan` | owner (curve/lease/auto), applied %, lease expiry |
| `/api/v1/servers/{id}/history/sensors` | sampled sensors `{key, kind, name, unit, first, last}` (§39) |
| `/api/v1/servers/{id}/history?sensor=&range=` (or `from`, `to`, `step`) | `{data:[{t,min,avg,max,n}], meta:{sensor,kind,unit,tier,tiers,step_s,from,to,points,clock_jump}}`, points ≤ 2000 |
| `/api/v1/servers/{id}/history.csv?sensor=&range=[&raw=1]` | one sensor's CSV (§39) |
| `/api/v1/version` | version, commit, go version, deps hash (for external scanners) |

Errors: RFC 9457 Problem Details (`application/problem+json`). Unauthenticated:
`/healthz` (process alive), `/readyz` (DB ok, ≥ 1 BMC polled, audit shipper state; no
details beyond status). Optional `/metrics` (Prometheus text format, read-only bearer token, off by default; §29).

### Integrations
- **Dashboards:** a JSON widget (for example a `customapi`-style one) on `/api/v1/servers/{id}` with a
  read-only token, so the dashboard holds no BMC credentials.
- **Uptime monitors:** HTTP keyword monitor on `/readyz`.
- **Automation tools:** read-only token; e.g. a weekly digest pulls `/api/v1/servers` and recent SEL.
- **Image scanners:** `/api/v1/version` adds app-level detail to what a scanner sees in the image.
- **Prometheus (optional):** scrape `/metrics`; off by default.

## 7. Testing strategy

- **Unit:** decoding recorded iDRAC8/iDRAC9 Redfish payloads; lease validation (table tests
  with hostile inputs); authz matrix (every route × role); CSP/headers; rate limiter; hash chain.
- **Integration:** `httptest` Redfish mock (plus DMTF Redfish-Mockup-Server mockups if useful);
  go-ipmi's **reference BMC server** for IPMI flows incl. cipher refusal; in-process SSH
  server for `console com2`; RFB fake server for the auth terminator.
- **Host script:** `bats` tests for the example lease reader (`deploy/host/fan-lease-reader.sh`),
  run on macOS and in CI, with `ipmi-raw`/`ipmi-sensors` stubbed.
- **E2E:** Playwright against the container with mock BMCs: login + TOTP, step-up, power
  action audit, lease lifecycle, serial console echo.
- **Security:** `gosec`, ZAP baseline against the running container, Trivy, govulncheck.
- Coverage ≥ 80 % overall and for every package on its own (in-repo test doubles excluded); the
  critical packages `auth`, `authz`, `fan`, `power`, `audit`, `console`, `console/rfb`, `netpolicy`,
  `secrets/credstore`, `tofu`, `registry` must be present (`make cover`, §33).

## 8. Implementation notes (P0 0.1–0.3, 2026-10-20)

Where the build differs from the text above or from the other docs:

1. **Runtime base is `distroless/static-debian12:nonroot`** (digest `sha256:afa5c872…f7ab`),
   as the P0 brief asked. `security.md` §6 says `static-debian13`. Switching is a one-line
   change: the debian13 `nonroot` index digest on 2026-10-20 was
   `sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087` (left as an open choice).
2. **The age identity can be staged, not mounted straight from the boot medium.** Decision 8 keeps the
   only persistent copy off the data volume, for example on a root-only vfat boot drive, which uid 65532
   cannot read. A boot hook copies it to `/run/oob-manager/identity` (owner 65532, mode 0400) and the
   container mounts that read-only. See `deploy/README.md` "Keeping the identity off the data volume".
3. **`make cover` measures `./...`** (with `-race`), not `./internal/...`. The internal packages
   have no statements yet, so the old target always reported 0 %. Per-package gates for
   `auth`/`authz`/`fan`/`power`/`audit` are still to be added once those packages exist.
   *Done 2026-10-22 (§33): every package is gated; these five and six more must be present.*
4. **Tool pins follow the 14-day rule:** golangci-lint v2.14.0, govulncheck v1.8.0 (not v1.9.0),
   Trivy v0.75.0 (not v0.76.0, released 2026-10-14), Syft v1.54.0. CI actions are pinned by commit SHA.
5. **The no-shell-out rule is enforced three ways:** the `make noexec` grep, golangci `depguard`
   (bans the `os/exec` import) and `forbidigo` (bans exec/ForkExec/StartProcess call sites).
6. **Make target names:** `lint`, `vulncheck` and `docker` were added, with `vuln`, `image` and
   `scan` kept as the names CLAUDE.md uses.
7. **`main.version` is a package-level `var`.** `-ldflags -X` requires this. It is written only at
   link time.
8. **No `CMD` in the image yet.** `serve` does not exist, so the container only answers `version`
   and `healthcheck`.
9. **task_list 7.4 still says "br0 static IP".** Decision 7 replaces that: the app uses a bridge
   network published on the Docker host's address (for example `192.0.2.20:8443`).
10. **The Dockerfile avoids BuildKit-only syntax** (`--platform=$BUILDPLATFORM`, `COPY --chmod`,
    `# syntax=`), so a legacy (non-BuildKit) builder can build it too.

## 9. Implementation notes (P0 0.4–0.7, 2026-10-20)

Deviations from and additions to §4–§5, with reasons:

- **Config keys added** (all optional, absolute paths): `storage: {db_path, lease_dir}`
  (defaults `/data/oob-manager.db`, `/leases`; the pre-rename `/data/oob-console.db` is opened instead
  when db_path is unset and only that file exists, §36) and `secrets: {credentials_file, identity_file}`
  (defaults `/run/secrets/bmc-credentials.age`, `/run/secrets/age-identity`). The §4 example
  had no place for these paths. Config hash (`Config.SHA256`) is computed for the T4 audit record.
- **Fan modes:** canonical values are `host-lease`, `redfish-floor`, `ipmi-oem`, `none`. The
  aliases `hostlease`, `redfishfloor` and `ipmioem` (decision 5's spelling) are accepted and normalised.
  Floors: `host-lease` ≥ 30 (idrac8 only), `redfish-floor` 35–100 (idrac9 only, Dell
  `MinimumFanSpeed` range, boost-only), `ipmi-oem` ≥ 30 with `max_lease` ≤ 60m, everything ≥ 20.
  So the §4 example's R240 `safe_min_pct: 20` is now rejected; use 35 or more.
- **BMC `address` must be a literal IP** (no DNS, so DNS spoofing cannot redirect credentials).
  `tls_pin_sha256` is required for every kind except `ipmi`. `kvm-launch` needs idrac9;
  `bmcssh` needs an iDRAC and `ssh_host_key`; `vnc` needs `credentials.vnc`.
- **GELF:** only `transport: tcp` is implemented; an empty `audit.gelf.address` disables shipping.
  (S4 adds `tls` with a pin and browser-managed settings, §34.)
- **Credential file** plaintext is YAML or JSON `{ref: {username, password}}`, strict (unknown
  fields fail). The identity file's permissions are not checked by the app (deploy concern).
- **Store:** one SQLite connection (serialises writers, which the audit chain relies on),
  WAL, foreign keys on, STRICT tables, times as unix milliseconds UTC. `audit_log.seq` is
  assigned by the audit package inside the append transaction (it is part of the hash), not
  AUTOINCREMENT. `fan_leases` gains `updated_at` and a partial unique index (one active lease
  per server). A `capabilities` repository exists; `console_sessions` has its table but no
  repository yet (P4).
- **Audit chain limit:** the chain detects edits, deletions and reordering, but not truncation
  of the newest rows. `Verify` returns the head hash; compare it with the last `row_hash`
  shipped to the log server to catch that.

## 10. Implementation notes (P0 0.8–0.10, 2026-10-20)

Deviations from and additions to the design above, made while building `web`, `auth`, `authz`:

- **Dependencies pinned:** `golang.org/x/crypto v0.57.0` (2026-09-08; v0.58.0 was < 14 days old),
  `github.com/pquerna/otp v1.5.0` (2024-12-31). Indirect: `golang.org/x/sys v0.48.0` (via x/crypto),
  `github.com/boombuler/barcode` (pulled by otp for QR images, MIT; not called by our code).
- **argon2id parameters:** m=19 MiB, t=2, p=1 (OWASP), not RFC 9106's 64 MiB profile, because the container
  has `mem_limit: 128m`. `PasswordHasher` also caps concurrent hashes (callers choose the limit; 2 is
  suggested) and rejects stored hashes with out-of-range parameters.
- **Schema additions the store must carry** (see `internal/auth/repo.go` for the interfaces):
  `users.totp_confirmed` (bool; login is refused until enrollment is confirmed), `sessions.level`
  (1 = pending: password ok, TOTP outstanding; 2 = full), `sessions.stepup_at` already listed.
  A `login_failures(key, failures, last_failure)` table backs `LockoutRepo`; keys are `acct:<username>` and
  `ip:<addr>`, and rows older than 24 h should be pruned (keys derive from attacker input).
- **TOTP secret at rest:** sealed with AES-256-GCM (`auth.NewAESGCMSealer`, 32-byte key from the app-keys
  secret), AAD = user ID, so a ciphertext cannot be moved to another user row.
- **Replay protection:** `UserRepo.AdvanceTOTPStep` must be an atomic compare-and-set
  (`UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?`). The login TOTP also counts as
  a step-up.
- **Lockout:** exponential backoff, per account (5 free, 30 s doubling to 15 min) and per IP (10 free, 10 s
  doubling to 15 min). Accepted trade-off: someone on the LAN can keep an account in backoff for up to
  15 min at a time.
- **Not yet built (needs routes/handlers):** the synchronizer CSRF token (security.md T1; cross-origin
  protection and `SameSite=Strict` are in place), the token-bucket rate limits of security.md §3, and the
  bootstrap CLI subcommand (`auth.Authenticator.BootstrapAdmin` + `ConfirmTOTP` exist).
- **Request time limit** is a context deadline (`web.RequestTimeout`, 25 s), not `http.TimeoutHandler`,
  which buffers responses and would break the P4 console WebSockets. WebSocket routes will need their own
  write-deadline handling instead of the server's 30 s `WriteTimeout`.
- **Extra headers** beyond security.md §3: `X-Frame-Options: DENY` (legacy browsers) and
  `Cache-Control: no-store` on every response.

## 11. Implementation notes (P1 1.2–1.3, 2026-10-20)

### `bmc`, `bmc/redfish`, `bmc/dellredfish`

Deviations from the design text and things the next phase must know:

- **gofish v0.27.0** (released 2026-10-05). In this release the typed schemas live in
  `github.com/stmcginnis/gofish/schemas` (no `redfish` package any more).
- **`bmc.Driver` is read-only in P1:** `Probe`, `Snapshot`, `EventLog(since)`, `Inventory`.
  `Power` from the system_design sketch is not on the core interface; P2 adds it as an
  optional interface discovered by type assertion (like `FanController`), so read-only
  drivers never have to stub it. `EventLog` returns a `bmc.EventLog` value (entries +
  source URI + `Complete` flag) rather than a bare slice.
- **Basic auth, not X-Auth-Token sessions, in P1.** Creating a session is a POST and this
  phase is GET-only (the transport refuses every non-GET/HEAD method). Session auth with
  delete-on-shutdown returns with P2, when writes are allowed. Each GET carries the
  read-only credentials; the TLS pin is checked before any request is sent.
- **TLS pin:** `Config.PinSHA256` is the hex SHA-256 of the leaf certificate's SPKI
  (colons/case ignored). Chain verification is replaced by a `VerifyConnection` pin check
  (runs on full and resumed handshakes, constant-time compare, fail closed). No proxy, no
  redirects, HTTP/1.1, 4 MiB body cap, per-request timeout (default 10 s, also the
  response-header timeout), 5 s dial/handshake timeouts. `redfish.SPKIPin(cert)` computes
  the value for config.
- **Probe** walks root → Systems (first member) → System `Links.Chassis/ManagedBy` (falls
  back to the Chassis/Managers collections). Absent endpoints turn capabilities off; HTTP
  5xx, decode errors, auth, TLS and timeouts fail the probe.
- **Snapshot** prefers legacy `Thermal`/`Power` (one GET, thresholds included) and falls back
  to `ThermalSubsystem`/`PowerSubsystem` when the legacy resource is absent or empty. Only a
  ComputerSystem read failure (or an expired parent context) is an error; other sections
  degrade into `Snapshot.Problems()` as `"<section>: <error class>"` (no BMC text).
  The subsystem path has no chassis-level watts, so `PowerDraw` stays empty there.
- **SEL location:** standard `<Manager>/LogServices/<..Sel>/Entries`, then OEM fallbacks
  (`dellredfish` adds the iDRAC8 `<Manager>/Logs/Sel`). iDRAC8 SEL entries use
  `[{"Member": "..."}]` arrays for `EntryCode`/`SensorType`, so log entries are decoded with a
  tolerant local struct, not gofish's `LogEntry`. Paging follows `nextLink` (≤ 8 pages,
  ≤ 2000 entries); a log is `Complete=false` when a later page fails or when
  `Members@odata.count` exceeds what was read (the iDRAC8 fixture: 85 vs 15, empty nextLink).
- **Dell firmware** is parsed from FirmwareInventory member IDs
  (`<State>-<ComponentID>-<Version>[__<FQDD>]`), one GET instead of one per component; any
  unparseable ID falls back to per-member GETs. Component names are only hard-coded where
  the iDRAC9 FQDDs confirm them (BIOS 159, iDRAC 25227, LC 28897, CPLD 27763, Driver Pack
  18981, Diagnostics 25806, OS Collector 101734).
- **Licence tier:** iDRAC9 via DMTF `LicenseService/Licenses` members (`Description`/`Name`
  parsed for Basic/Express/Enterprise/Datacenter). iDRAC8 has no licence API:
  tier `unknown`, source `unavailable`, plus `GraphicalConsole` from the Manager. The
  `Oem/Dell/DellLicenses` endpoint named in system_design.md is **not** used (not captured).
- **Fixture gaps (capture in a follow-up 1.1 session):** licence member resources, firmware
  member resources, `ThermalSubsystem/Fans` + `ThermalMetrics`, `PowerSubsystem/PowerSupplies`,
  the `LogServices/Sel` and `Lclog` resources/entries, `UpdateService`, `LicenseService`, and
  the Systems/Chassis/Managers collections. Tests that need these use clearly-marked
  SYNTHETIC overlays; `redfishmock` synthesises the top-level collections from the captured
  members. With only the captured data the R240 licence tier reads `unknown`.
- **Test helper:** `internal/bmc/redfishmock` (httptest TLS server over `testdata/redfish/*`,
  unauthenticated service root, Basic auth elsewhere, 405 for non-GET, request log for
  "no writes" assertions, per-path overlay/missing/status/delay). Production code must not
  import it.

## 12. Implementation notes (P1 1.4/1.6 + wiring)

### Fixture follow-up (1.1 capture of 2026-10-20)

- Tests now use the real captures (licence members, firmware members, ThermalSubsystem/Fans,
  ThermalMetrics, PowerSubsystem/PowerSupplies, Lifecycle logs, top-level collections); synthetic
  overlays remain only for shapes no capture has (percent-only fans, a populated PowerSupplies
  collection, SEL paging, error injection), each marked SYNTHETIC.
- **Licence choice:** the R240 carries an expired *Enterprise Evaluation* trial next to its perpetual
  *Enterprise* licence. On equal tiers a `LicenseType: Production` licence now wins, so the reported
  description is "iDRAC9 Enterprise License". `Oem/Dell/DellLicenses` is captured but still unused.
- Both Lifecycle captures hold 15 entries of 2090 / 3385 (`Complete=false`).

### Store ↔ auth (`internal/store/authrepo`)

- **Adapter package, not methods on store types**, so `store` never imports `auth` and `auth` keeps
  its fakes. `authrepo.New(db)` returns the four `auth.*Repo` values; it only maps types and sentinels
  (`store.ErrNotFound` → `auth.ErrNotFound`, `store.ErrConflict` on `CreateFirst` → `auth.ErrUsersExist`).
  `SessionRepo.Delete` is a no-op when absent, as auth requires.
- **Migration `0002_auth.sql`:** `users.totp_confirmed`, `sessions.level` (default 1 = pending, so a
  missing level fails closed; a zero `store.Session.Level` is stored as pending), and
  `login_failures(key, failures, last_failure)` with an index on `last_failure`.
- **Atomicity, all inside SQLite:** `CreateFirst` is one `INSERT … SELECT … WHERE NOT EXISTS (SELECT 1 FROM
  users)`; `AdvanceTOTPStep` is the conditional UPDATE from §10; `Sessions.Replace` is a transaction whose
  DELETE must hit a row before the INSERT runs; `RecordFailure` is one `INSERT … ON CONFLICT DO UPDATE …
  RETURNING`. Concurrency tests cover CreateFirst and RecordFailure.
- `SetTOTP(id, enc, confirmed)` keeps `totp_last_step`; the older `SetTOTPSecret` (re-enrollment) now
  also clears `totp_confirmed`.
- The `serve` janitor deletes expired sessions and prunes `login_failures` older than 24 h, hourly.

### `internal/fleet` (1.4)

- **Read side for the UI and API:** `fleet.Reader` — `Servers() []ServerState` (config order),
  `Server(id) (ServerState, bool)`, `Polled() bool`. `*fleet.Fleet` implements it. `ServerState` is a value:
  latest `bmc.Snapshot`, SEL and Lifecycle `bmc.EventLog`, `bmc.Inventory`, `bmc.Capabilities` (each with a
  `Has…` flag and a per-section error class), `LastAttempt`, `LastSuccess`, `LastError`, `FailingSince`
  ("unreachable since …"), `ConsecutiveFailures`, `Breaker` and the derived `Stale` (no snapshot, or last
  success older than `StaleAfter` = 3 × interval). Copies are returned on every read.
- One goroutine per server, a real-context `CycleTimeout` (30 s) per poll, interval ± 10 % jitter
  (injectable `Rand`), and an injectable `Clock` for scheduling. Each poll publishes a new state via
  `atomic.Pointer`; nothing else is shared.
- **Breaker:** 3 consecutive snapshot failures open it for 2 min; then one half-open poll; failure
  re-opens. Only the snapshot counts: SEL / Lifecycle / inventory failures are recorded per section and
  never trip it. A poll cancelled by shutdown is not recorded as a failure.
- **Cadence:** snapshot every interval; SEL and Lifecycle (`fleet.LifecycleLogger`, i.e. dellredfish)
  every 5 min; Probe + inventory every 6 h. The SEL is re-read in full each time (≤ 8 pages / 2000 entries).
  Capabilities are persisted to the `capabilities` table as `{flags, reset_types}` JSON.
- **Samples:** keys `temp:<sensor ID or name>`, `fan:<…>`, `power:consumed` (`fleet.SampleKey`), valid
  readings only, deduplicated per snapshot. Pruned at start and hourly to 7 days. *Superseded by §39:*
  PSU and voltage keys were added, and the history service now rolls them up and prunes them.

### `internal/api` (1.6)

- Routes: `/api/v1/servers`, `/api/v1/servers/{id}`, `/api/v1/servers/{id}/events`, `/api/v1/version`, plus
  unauthenticated `/healthz` and `/readyz`. Every `/api/` path (including unknown ones, which 404) needs
  `Authorization: Bearer <token>`; query-string tokens are ignored. Each route is authorized with
  `authz.Authorize(tokenPrincipal, action, false)` (`fleet.view`, `server.view`, `server.logs.view`), so a token
  principal can never reach anything but views. Non-GET/HEAD → 405. Per-token bucket, 60/min, 429 + `Retry-After`.
- **Events:** `?log=sel|lifecycle` (default sel), `?since=<RFC 3339>`, `?limit=1..200` (default 50),
  `?cursor=<opaque>`. Newest first by (Created, numeric ID); the cursor is a keyset position
  (base64url of `unixnano|id`), stable across polls. `meta` = `{total, limit, next_cursor, complete,
  available, log}`. Error details never echo input.
- **`/readyz`:** `unavailable` (503) when the DB ping fails or no server has produced a snapshot;
  `degraded` (200) when GELF is configured but the shipper is disconnected; else `ok`. An uptime monitor (Uptime
  Kuma, for example) should match the keyword `"ok"`.
- `/api/v1/version` reports version, `vcs.revision`, Go version and the SHA-256 of the sorted module list.
- `/api/v1/servers/{id}/fan` is **not built** (needs P3).

### `cmd/oob-manager`

- Subcommands: `serve`, `bootstrap-admin`, `confirm-totp`, `gen-app-keys`, `version`, `healthcheck`. The image
  now has `CMD ["serve"]`.
- **UI wiring point:** `cmd/oob-manager/ui.go` — `type UIHandler interface{ http.Handler }`,
  `type UIDeps struct{ Config, Fleet fleet.Reader, Auth, Tokens, Audit, Samples, Logger }` and
  `func newUIHandler(UIDeps) (UIHandler, error)`, which returns a 503 Problem Details placeholder.
  `buildHandler` in `serve.go` mounts the API on `/api/`, `/healthz` and `/readyz` and the UI on `/`, all inside
  `web.NewHandler` (with `public_url`'s origin as a trusted origin). The UI branch only changes the body of
  `newUIHandler`.
- **New secret, `secrets.app_keys_file`** (default `/run/secrets/app-keys.age`): age-encrypted
  `totp_key: <64 hex>`, the AES-256-GCM key for TOTP secrets. Create it with
  `oob-manager gen-app-keys | age -r <recipient> -o app-keys.age` (plaintext never touches disk). Compose
  mounts it read-only. Losing it invalidates every TOTP enrollment.
- **`bootstrap-admin -username <name>`:** password read twice from the terminal with echo off
  (`x/sys/unix` termios; refuses to run without a TTY), policy-checked before hashing, then
  `BootstrapAdmin`; the TOTP secret and `otpauth://` URI are printed once on stdout, then up to 3 codes are
  accepted to confirm. If that is interrupted, `confirm-totp` finishes it. Both write audit rows.
- **`serve`:** loads config → app keys → store → audit (+ GELF shipper) → auth → credentials → drivers
  (idrac8/idrac9 → dellredfish, redfish → redfish; `ipmi` servers are skipped with a warning until P2) →
  fleet → API/UI. It verifies the audit chain at startup (logged, not fatal), records `app.start` with the
  config hash (T4), and on SIGTERM/SIGINT: `Shutdown` (10 s) → stop pollers and janitor → record `app.stop`
  → flush the shipper.
- App logs are JSON on stderr only; they are not yet sent to the log server (only audit rows are).

### Gaps and follow-ups

- `golangci-lint v2.14.0` reports ~70 findings in pre-existing P0/P1 files (noctx in tests, govet shadow,
  gosec G101/G115, revive comments, staticcheck deprecations). The new packages are clean. `make check`
  passes only because lint is skipped when the binary is missing; CI will flag these.
- No per-package coverage gate yet for `auth`/`authz`/`audit` (§8 item 3); all are ≥ 90 % today.
- Homepage and Kuma wiring docs (task 1.6) are covered by §6 "Integrations" plus the `/readyz` keyword above;
  no separate how-to was written.

## 13. Implementation notes (P1 1.5 UI)

Package `internal/web/ui` (server-rendered `html/template`, templates and CSS embedded with `embed.FS`).
`ui.New(Deps) (http.Handler, error)` returns the bare UI mux. **The wiring must wrap it with `web.NewHandler`**
(security headers, CSP, CrossOriginProtection, body/time limits) and serve it over TLS: every cookie is `__Host-`.

- **Routes:** `GET/POST /login`, `GET/POST /login/totp`, `POST /logout`, `GET/POST /enroll`, `POST /enroll/reveal`,
  `GET /` (`fleet.view`), `GET /servers/{id}` (`server.view`), `GET /servers/{id}/events?log=sel|lifecycle&page=N`
  (`server.logs.view`; `/logs` until slice C, now redirected, §41), `GET /servers/{id}/inventory` (`server.inventory.view`), `GET /static/app.css`.
  Anything else is 404, including other methods on page routes. Every page route goes through one wrapper that
  authenticates the session and then calls `Deps.Authorize` (default `authz.Authorize`); denials are audited.
  Logout is a self-action with no matrix entry: it needs only the session and its CSRF token.
- **Server IDs** in paths must match `^[a-z0-9][a-z0-9_-]{0,63}$` and are then looked up through `Fleet.Server`.
  Nothing from the URL is passed on otherwise.
- **No htmx and no JavaScript in this phase.** Section 1 plans htmx; it was not needed for read-only pages. So no
  nonce is used, and a test checks that every page is free of `<script`, `style=` and inline handlers. Sparklines
  (FR-5) and auto-refresh are left for later. Pages are static until reloaded, and the staleness banner covers that.
- **Data contract:** the UI reads only the `ui.Fleet` interface (`Servers`, `Server`, `Events`) and `ui.ServerView`
  values built from `bmc.Snapshot`/`Inventory`/`Capabilities`. It never imports `internal/fleet`. The adapter at
  wiring time returns `ui.ErrLogUnavailable` for a log the server lacks. Other errors are shown only by
  `bmc.Classify` class.
- **Staleness:** data is stale when `now − LastSuccess > Deps.StaleAfter` (default 3 min, i.e. three missed 60 s
  polls), or when there has been no successful poll. Stale servers get a banner on every page that shows them,
  dimmed values, the last error class, and are left out of the overview's fleet-health rollup (counted as "N stale").
- **CSRF:** a per-form synchronizer token, `ts ‖ HMAC-SHA256(key, form ‖ binding ‖ ts)`, valid for `CSRFTTL`
  (default 12 h). Signed-in forms are bound to the session cookie value. Pre-login forms (login, enrolment) are bound to a
  random `__Host-oob_pre` cookie. The TOTP form is bound to the pending-session cookie. Session rotation therefore
  invalidates old tokens. `Deps.CSRFKey` should be a 32-byte key from the app-keys secret; if nil, a random key is
  generated per process, so open forms break on restart.
- **Rate limits:** in-memory token buckets with an injectable clock. Login and enrolment allow 5/min per IP and
  10/h per account (only well-formed usernames create keys). The TOTP step allows 5/min per IP (separate key). Each limiter holds
  at most 4096 keys: refilled buckets are dropped first, then the least recently used. Responses are 429 with `Retry-After`. Limits
  sit in front of argon2; `auth` lockout (§10) still applies behind them. The client IP is `RemoteAddr`.
  `X-Forwarded-For` is ignored (LAN-only, no proxy). **Deploy check:** with Docker's userland-proxy the peer is
  the bridge gateway, which would make the per-IP limit global. Confirm on the Docker host that the published port keeps
  client IPs (iptables DNAT).
- **Audit:** `auth.login` (ok / denied with class `password`, `totp`, `csrf`, `rate_limited`, `*_locked_out`,
  `pending_expired`), `auth.logout`, `auth.totp.enroll`, `auth.totp.reveal`, plus page-authz denials under the
  authz action name. Typed usernames are **never** recorded on failure, because a password pasted into the username field
  would land in the audit log. If the audit write for a completed login fails, the new session is deleted and the
  login fails (500).
- **Status codes:** wrong credentials re-render the form with 401, CSRF failure 403, rate limit or lockout 429,
  store failure 500. Messages are generic (security.md S1, I4).
- **Enrolment:** `/enroll` confirms TOTP with username + password + code (`auth.ConfirmTOTP`). **Gap:** `auth` cannot
  re-display a pending secret, and the secret is otherwise only printed once by the (not yet built) bootstrap CLI. `ui`
  defines an optional `Enroller.RevealEnrollment(ctx, username, password, ip) (auth.TOTPEnrollment, error)`. When it is
  wired, `/enroll/reveal` shows the secret, the otpauth URI and a QR code: an inline `data:` PNG from
  `pquerna/otp`, which is not a new dependency. This page is the only one that renders a secret. It is never logged.
  `auth` needs a matching method: re-check the password for an **unconfirmed** user, mint a new secret, `SetTOTP(…, false)`,
  and return it.
- **Accessibility:** labelled inputs, a skip link, `aria-current` navigation, `role=alert` for errors and staleness,
  `:focus-visible` outlines, a dark default with a `prefers-color-scheme: light` palette, and tables that scroll inside
  their card on phones.
- **Not done (TODO):** Playwright smoke (login + TOTP, overview, stale banner, logs paging) once `cmd/` wires a
  `serve` command with mock BMCs (§7 E2E). Also: step-up page (`/stepup`, P2), admin pages, sparklines.
- **Branch note:** at the time of writing, `make check` fails in `internal/bmc/redfish` and `internal/bmc/dellredfish`
  (6 tests), because the fixture-only commit `85cbd7e` added captures those tests assumed absent. The previous commit passes.
  This is unrelated to `ui`; it needs a fix in the driver tests (owned by the 1.2/1.3 work).

## 14. Implementation notes (P1 wiring, lint, e2e)

### UI wiring (`cmd/oob-manager/ui.go`, `internal/fleetview`)

- `newUIHandler` now returns `ui.New(...)`, mounted at `/` inside `web.NewHandler` as before. `UIDeps` is
  `{Config, Fleet, Auth, Audit, CSRFKey, Logger}`; the unused `Tokens`/`Samples` fields were dropped.
- **`internal/fleetview`** is the adapter `fleet.Reader` → `ui.Fleet`. It is pure mapping and never calls a BMC:
  `Events` serves the SEL / Lifecycle logs the pollers already cache in `fleet.ServerState` (refreshed every 5 min),
  so no page view can cause BMC traffic and no request value reaches a driver. Rules: a cached log wins even if a
  later refresh failed; otherwise a recorded failure is returned as an error of the same `bmc.ErrorClass` (no BMC
  text); a log not read yet is an empty, incomplete log. `ui.ErrLogUnavailable` is returned for unknown servers,
  for a SEL the probe says is absent (or `unsupported`), and for the Lifecycle log on servers whose configured kind
  is not `idrac8`/`idrac9`.
- **Deps:** `Authorize = authz.Authorize`; `CSRFTTL = auth.session_max`; `StaleAfter = 3 × poll.interval` (same rule
  as `fleet`); `PendingTTL = auth.DefaultPendingTTL`; login rate limits keep the ui defaults (5/min/IP,
  10/h/account). `newUIHandler` refuses an empty CSRF key, so the ui's random per-process fallback is never used.
- **CSRF key:** `secrets.AppKeys.DeriveKey(secrets.PurposeCSRF)` = HKDF-SHA256(totp_key, info
  `oob-console/csrf/v1`). Form tokens survive restarts and no new field is needed in `app-keys.age`; future keys
  get their own purpose label. Rotating `totp_key` (which already invalidates enrolments) also rotates it.
- **TOTP re-display (§13 gap) — left open on purpose.** A web `RevealEnrollment` would let anyone holding only
  the password of a not-yet-confirmed account mint a fresh secret and take the account, so it is not "small and
  safe". The CLI path covers it: `bootstrap-admin` prints the secret once and `confirm-totp` finishes an
  interrupted enrolment. A lost secret is now handled by the CLI `reset-totp --user` (§15), not a web page. `ui.Deps.Enroller` stays nil,
  so `/enroll/reveal` answers 404.
- `newBMCDriver` now delegates to `bmcDriverAt(server, cred, endpoint)`. Production always passes
  `https://<bmc.address>:443`; only the e2e harness passes a mock's URL. Pin and credentials still come from config
  and the age file, so the harness exercises the real pin path.

### Lint

- golangci-lint v2.14.0: **0 issues** with `.golangci.yml` (now also `run.build-tags: [e2e]`, so the harness is
  linted). `make vet` also vets the `e2e` tag.
- Targeted nolints, each with its reason inline: G101 on the default credentials-file path and the token SQL column
  list (not credentials); G101 on malformed credential-file test inputs and a dummy hash; G705 in `redfishmock`
  (JSON fixtures served as `application/json`); SA1019 on `ThermalFan.FanName` (iDRAC8, Redfish 1.0 era, fills
  only that field) and `Manager.SerialConsole` (iDRAC reports it only there); G117 on the dev harness sign-in file.
- Real fixes: shadowed `err`s, bounds checks before int→uint conversions, `ClearSessionCookie` now sets
  Secure/HttpOnly/SameSite, `redfishmock` reads fixtures through `os.OpenInRoot`, context-carrying requests,
  listeners and dials in tests.

### End to end (`make e2e`, `make dev`)

- **Harness:** `cmd/oob-manager/e2e_harness_test.go` (build tag `e2e`, in package `main`, so it runs the real
  commands in-process; no `os/exec`). It starts two `redfishmock` TLS servers (`idrac8-r730xd`, `idrac9-r240`),
  writes a temp install (config with the mocks' SPKI pins and TEST-NET-1 addresses 192.0.2.10/11, age identity,
  encrypted BMC credentials, app keys from the real `gen-app-keys`, self-signed TLS pair, SQLite DB), bootstraps
  `admin` through the real `bootstrap-admin` (password over a pipe, the code computed from the printed secret for
  the *previous* 30 s step so a login code for the current step is accepted at once), mints an API token, then runs
  `serve` and waits until the API reports both servers reachable.
- **`make e2e-go`** (`TestE2E`): probes; signed-out redirects; forged CSRF token → 403 and no session; wrong
  password → 401 without echo; login → TOTP → overview with both servers and real values; R730XD server page has 6
  fan rows; R240 server and inventory pages show the Enterprise licence; SEL and Lifecycle pages render for both;
  unknown server 404, bad log kind 400; logout → 303 and the session is gone; API: no token 401, bad token 401,
  `/api/v1/servers` lists both reachable in config order, Lifecycle events with `limit=5`, POST → 405. On shutdown:
  zero non-GET requests reached either mock, audit rows `admin.bootstrap`, `admin.totp_confirmed`, `app.start`,
  `auth.login`, `auth.logout`, `app.stop` exist, and the app log contains neither the password, the TOTP secret nor
  the token. Runs in ~1 s.
- **`make e2e-ui`**: builds `bin/e2e.test`, then Playwright (`tests/e2e`, `@playwright/test` pinned to 1.63.0,
  released 2026-09-04) starts it as its web server (`TestDevServer`) and drives Chromium: login → TOTP (RFC 6238
  computed in the spec with `node:crypto`, no extra dependency) → overview (screenshot
  `tests/e2e/test-results/overview.png`) → server page → sign out. `make e2e` runs both.
- **`make dev`** runs the same stack until Ctrl-C on `DEV_ADDR` (default `127.0.0.1:8443`) and prints the URL, the
  sign-in file and a fresh TOTP code every 30 s. The sign-in file (`dev-credentials.json`: URL, username, the
  throwaway password, TOTP secret, API token, cert path) is mode 0600 in the temp install and deleted on exit;
  `OOB_DEV_STATE` may only name a file, which is always created in the OS temp dir. Browser: accept the self-signed
  certificate warning.
- **CI:** new jobs `e2e` (`make e2e-go`; the image job now also needs it) and `e2e-ui` (`make e2e-ui
  PW_INSTALL_FLAGS=--with-deps`, uses the runner's preinstalled Node so no extra action needs pinning, uploads the
  screenshots). `actionlint` v1.7.7 reports no problems.

### Remaining gaps before a real deployment

- *Closed in §15:* R240 PSUs "Unknown" (now "Not monitored by this server" + voltages), TOTP reset (`reset-totp`),
  API tokens (`token create|list|revoke`), client-IP check and TLS (`gen-tls`, fail-fast `serve`).
- No admin pages, token management UI or step-up page yet (`/stepup` is P2).
- App logs still go to stderr only (not GELF); audit rows do.

## 15. Implementation notes (pre-deploy: tokens, TOTP reset, power capability, TLS)

### API tokens CLI (`cmd/oob-manager/tokens*.go`)

- `oob-manager token create --name <label> [--expires <N>d|<Go duration>|never] [--owner <user>] [-config path]`.
  Only the token (`oobk_…`) goes to stdout, alone on one line, so it can be piped. The ID, name and expiry go to
  stderr. The default lifetime is `never`. Lifetimes must be 1 h to 730 days (`auth.MinTokenLifetime`/`MaxTokenLifetime`),
  and the check runs before the DB is opened. `--owner` defaults to the only active admin and is required when there is
  more than one. `api_tokens.created_by` is a foreign key to `users`, so a token always has an owner. Scope is `read`, as before.
- `token list` is a table (ID, NAME, CREATED, LAST USED, EXPIRES, STATUS = active/revoked/expired). `TokenService.List`
  strips the stored hash, so not even the hash reaches output. `token revoke <id>` revokes an unrevoked token (an unknown or
  already revoked ID is an error). Flags may come before or after the ID (`parseInterleaved`).
- **Audit:** `token.create` `{token_id, name, owner, expires}` and `token.revoke` `{token_id, name}`, principal `cli`. If the
  create audit write fails, the token is revoked and is never printed. If the revoke audit write fails, the command exits 1
  (the revocation stands).
- **Schema:** migration `0003_token_expiry.sql` adds nullable `api_tokens.expires_at` (NULL = never). `Verify` rejects a
  token at or after its expiry (`APIToken.StatusAt`). The e2e harness now mints its token through the real CLI.

### `reset-totp` (`cmd/oob-manager/resettotp.go`, `auth.ResetTOTP`)

- `oob-manager reset-totp --user <name> [-config path]`. It refuses unless stdout is a terminal (`env.stdoutTTY`; `docker exec -it`),
  and that check runs before anything changes. It then mints a fresh secret, sealed with AAD = user ID, clears
  `totp_confirmed`, **deletes every session of the user**, and writes `admin.totp_reset`. Only after a successful audit
  write does it print the secret and `otpauth://` URI, once. The user confirms on `/enroll` or with `confirm-totp`. Login is
  refused until then. There is no web route, and no password is needed (shell = trusted).
- **New `auth.UserRepo.ReEnrollTOTP`** (store `SetTOTPSecret`) resets `totp_last_step` to 0, unlike `SetTOTP`. That is safe for a
  freshly generated secret, because no code of it has ever been accepted, and confirming it records its step again. Keeping the
  old step would have blocked confirmation and the next login for up to a minute after a reset (the codes the user has are
  for steps ≤ the last login's).

### Power telemetry capability (`bmc/power.go`, `bmc/redfish/power.go`)

- `bmc.PowerTelemetry` on the snapshot: `available` (PSUs, or any non-zero draw figure), `unavailable` (the power read
  succeeded and reported neither), `unknown` (not read, or the read failed). `bmc.ClassifyPower` decides it. In the
  unavailable case it replaces an all-zero `PowerDraw` with an empty one, so 0 W is never shown or sampled.
- It lives on the snapshot rather than in the 6-hourly probe `CapabilityFlags`. The fact comes from the power read itself,
  every poll, and a failing read must not flip it.
- **Voltages:** `bmc.Voltage{ID, Name, Context, Volts, Health}` from legacy `Power.Voltages` (≤ 64), kept across the
  PowerSubsystem fallback, which has no voltages. Discrete "PG" sensors have null readings and show "—" with their health.
  `redfish.powerData.empty()` now uses the same rule, so an all-zero PowerControl also triggers the fallback.
- **UI:** with `unavailable`, the overview's PSUs and Power draw read "Not monitored by this server" (no Unknown badge).
  The server page replaces the PSU table and the chassis power table with that note, and every server page has a Voltages
  table (sensor, location, reading, status). The R240 fixture (0 PSUs, empty PowerControl, 14 voltages) is the test case.
- **API:** `/api/v1/servers/{id}` gains `power_telemetry` and `voltages[] {id, name, context, volts, health}`.
- gofish quirk: `schemas.Power` fails to decode (`unexpected end of JSON input`) when `PowerControl` is absent. Every
  capture has it; synthetic overlays must include `"PowerControl": []`.

### TLS (`internal/certgen`, `cmd/oob-manager/gentls.go`, `serve`)

- `oob-manager gen-tls --host <ip|name> [--host …] --out <dir> [--days N]`. It makes an ECDSA P-256 self-signed leaf with
  a random 127-bit serial and server-auth EKU only (not a CA). SANs come from `--host` (IPs vs DNS names; no wildcards,
  schemes or duplicates; ≤ 32), and the CN is the first host. NotBefore is now − 5 min. Validity is 1–825 days (825 by
  default, Apple's limit). It writes `tls.key` 0600, then `tls.crt` 0644, both with `O_EXCL` (never overwrites). The key is
  removed again if the certificate write fails. It prints the SHA-256 fingerprint in Keychain's format.
- `serve` now loads the key pair **before** opening the DB, building drivers or listening, so a missing or unreadable pair
  fails fast with a hint to use `gen-tls`. Tests assert that no DB file is created, no driver is built and no listener is
  opened. It opens exactly one listener (TLS), and a plain-HTTP request to it gets Go's 400 with no `Location`. There is no
  redirect port.
- `compose.yaml` now mounts `tls/tls.crt` and `tls/tls.key` read-only at `/run/secrets/tls.{crt,key}`.

### Deploy docs

- `deploy/README.md` is now a generic first-install checklist (192.0.2.0/24), covering:
  - directories and ownership, age identity, app keys and the credentials format;
  - `gen-tls`, trusting the certificate on a Mac, and replacing it with your own;
  - the SPKI pin `openssl` pipeline (checked to equal `redfish.SPKIPin` on a generated cert);
  - a validated `config.yaml` example with iDRAC8 and iDRAC9 entries;
  - `bootstrap-admin`, `token create`, health checks, `reset-totp`, upgrade and rollback.
  Unraid is covered as one example platform.
- Client IPs: a published port on a Docker bridge network keeps the client IP (DNAT, verified on the target host), so
  the per-IP login limit from §13 works as deployed. This closes that §13/§14 deploy check.

### Review follow-ups (accepted residuals)

- `ResetTOTP` ends the user's sessions before *and* after replacing the secret, so a failure leaves either nothing
  changed or only the sessions gone, and a login racing the reset is ended too.
- `ConfirmTOTP` writes back the secret it verified. A `reset-totp` landing in the milliseconds between that verify and
  write would be overwritten (the old secret confirmed). It needs a CLI action racing a web form; a conditional update
  (`WHERE totp_secret_enc = ?`) is the fix if it ever matters.
- `unavailable` is decided per poll. A BMC that briefly answers an empty Power resource (e.g. while it resets) shows
  "Not monitored" for that poll. Revisit (sticky "available") if the soak shows flapping.
- `token revoke` exits 1 when the revoke succeeded but the audit write failed; the message says so.

### Still open before a real deploy

- Image build, `docker compose config`, the read-only start and the HEALTHCHECK have not been run on the target host.
- R240 power: confirm on the live iDRAC9 that `power_telemetry` reads `unavailable` and that voltages show.
- No admin pages, token UI or step-up page (`/stepup`, P2). App logs still go to stderr only.

## 16. Implementation notes (settings S1 + UI review fixes)

Branch `s1-settings`. Implements settings_design.md §6 "S1 MVP" with the §8 decisions, and the
Critical/High/Medium findings of `docs/reviews/2026-10-21-ui-layout-review.md` (per-finding status
in that file's new Status column).

### Authorization and step-up

- New actions: `admin.users.manage`, `admin.tokens.manage` (admin, **step-up required**) and
  `about.view` (viewer; not token-readable). The existing `admin.users`, `admin.tokens`,
  `admin.audit.view` and `admin.audit.verify` are the read-only page actions (no step-up).
  `authz_test.go` has a hand-written S1 matrix: action × role × session/token × fresh/stale step-up.
- **Step-up window (decision 1):** no TOTP field per change. Every mutating Settings POST goes through
  `ui.change()`: session → CSRF (form `settings`, bound to the session cookie) → `Authorize` with
  `StepUpFresh` → 10 changes/min per user → handler. A stale window answers 303 to
  `/stepup?next=<page>`; the GET/POST `/stepup` page calls `auth.StepUp` (single-use code, lockout,
  5/min/IP, session rotated, `auth.stepup` audited). The login code still counts as a step-up, so a
  fresh login can make changes for 5 minutes. Rotation invalidates forms rendered before it (they are
  bound to the old cookie): the user reloads the page.
- Every refusal (CSRF, forbidden, stale step-up, rate limit) is audited with the action name and
  an error class.

### Storage and transactions (`internal/store`)

- Repositories now run on a `querier` (`*sql.DB` or `*sql.Tx`). `DB.WithTx(ctx, fn(*Tx))` gives a
  caller-owned transaction whose repositories (`Users`, `Accounts`, `Sessions`, `Tokens`,
  `Enrolments`, `Audit`) all share it; `Tx.AfterCommit` hooks run only after a commit. Repository
  methods that used to open their own transaction (`Audit.Append`, `Sessions.Replace`,
  `Samples.Insert`) join the caller's when given one. With a single connection, code inside
  `WithTx` must use only the `Tx` repositories (anything else waits for the held connection); argon2
  hashing therefore happens before the transaction.
- **Migration `0004_enrolment.sql`:** `enrolment_tokens` (design §4; `CHECK expires_at > created_at`)
  and audit indexes on `(action, seq)` and `(principal, seq)`. `api_tokens.expires_at` is migration
  0003 from the CLI work, reused.
- **Guards in SQL** (`AccountRepository`): role change, disable and authenticator clear are single
  conditional UPDATEs: no self-demotion/self-disable/self-reset, and the last enabled admin cannot be
  demoted or disabled (`EXISTS` another enabled admin). Zero rows → `ErrNotFound` or `ErrRefused`.
  A concurrency test has two admins demote each other: exactly one wins.
- `EnrolmentRepository.Consume` is one `UPDATE … WHERE used_at IS NULL AND expires_at > now
  RETURNING`, so a link is single-use under concurrency (tested with 4 racing redemptions).
- `AuditSearcher.Search` builds its WHERE from fixed fragments with bound values; newest first,
  keyset on `seq` (`before=`), limit 1..1000.

### Audit (`internal/audit`)

- `Logger.RecordTx(ctx, tx, e)` appends inside the change's transaction and enqueues the GELF copy
  in `AfterCommit`: a rolled-back change has no audit row and is never shipped. `Record` is unchanged
  for non-transactional events.
- Params are redacted fail-closed before encoding (any key containing password/secret/passphrase/
  private, or exactly token/code/totp/link/uri/url/otpauth → `[redacted]`; nested maps too; the
  caller's map is not modified). Callers still never pass secrets.
- `audit.Viewer` (search, distinct actions, full `Verify`) backs the viewer.

### Service (`internal/admin`)

- One service for the browser and the CLI. Each change runs `fn(tx)`, which returns the audit entry
  to record in the same transaction (entries are built immutably). Refused/not-found changes are
  audited as `denied` outside the rolled-back transaction.
- Users: `CreateUser` (username `^[a-z][a-z0-9._-]{2,31}$`; the row gets an argon2 hash of a random
  placeholder, no TOTP, so it cannot sign in) + an `enrol` link (24 h). `SetRole`, `SetDisabled`
  (disable also ends sessions and unused links), `ResetEnrolment` (clears the authenticator, ends
  sessions, supersedes old links, issues a `reset` link; also how an expired invitation is renewed),
  `Sessions`/`RevokeSession` (id = hex of the stored hash, deleted only if owned by that user)/
  `RevokeSessions`. Users are never deleted.
- Tokens: `auth.TokenService.Mint` generates without storing; `admin.CreateToken` stores it in the
  transaction with `token.create`. **The CLI `token create|revoke` now calls the same service**
  (principal `cli`), so a token can no longer exist unaudited and the old "revoke on audit failure"
  path is gone.
- Links: `LookupLink` (no side effect) and `RedeemLink` (password policy, argon2 and sealing before
  the tx; in the tx: consume, set password, new unconfirmed secret with last step 0, end sessions,
  audit `auth.enrol` by the user, method `link`). The user then confirms a code on the existing
  `/enroll` form (`auth.ConfirmTOTP`), which now refuses an account with no secret.
- Audit actions added: `admin.user.create|role|disable|enable|reset_totp`,
  `admin.session.revoke|revoke_all`, `auth.enrol`, `auth.stepup`, `admin.audit.verify`.

### UI (`internal/web/ui`)

- Routes: `/settings` (→ users), `/settings/users[/{id}]`, POST `/settings/users`,
  `…/{id}/role|disable|enable|reset-totp|sessions/revoke-all|sessions/{sid}/revoke`,
  `/settings/tokens`, POST `/settings/tokens`, `…/{id}/revoke`, `/settings/audit`,
  POST `/settings/audit/verify`, GET/POST `/enroll/{token}`, GET/POST `/stepup`, `/about`,
  `/servers`, `/events`, POST `/prefs/refresh`. Paths follow the review's `/settings/*` layout rather
  than design §5's `/admin/*`. Without `Deps.Admin`/`AuditLog` the Settings pages answer 404.
- Token and link reveal pages are 200 responses with `Cache-Control: no-store` (never redirects).
  Enrolment links use `public_url`, else the request host. The link path is replaced by
  `/enroll/[redacted]` in the panic log (`web.LogPath`).
- Audit verify is POST (it writes an audit row), limited to once a minute globally, and shows rows,
  head hash or the first bad seq and reason.
- All computed redirects go through `redirectLocal` (same-origin path check); user IDs in Location
  are re-encoded hex.
- `/events` merges the cached SEL and Lifecycle logs of every server, newest first by BMC time,
  filter by log and severity; like the per-server pages it never causes BMC traffic.
- Navigation and chrome per review §3; servers are listed in menus and error pages only for
  principals allowed `fleet.view`. Footer version/links only when signed in.
- **Auto-refresh is opt-in** (cookie `__Host-oob_refresh=on`, toggled by POST with CSRF). The
  review proposed default-on; axe flags a default meta refresh (WCAG 2.2.1), and absolute poll times
  plus the page generation time already keep a frozen page truthful.
- `/about`: version (`main.version`), commit (`vcs.revision`), Go, schema (`DB.SchemaVersion`),
  compiled modules, Apache-2.0 + NOTICE placeholder. Links appear only when the build sets
  `-X main.repoURL=https://…` (Makefile `REPO_URL`, Dockerfile `ARG REPO_URL`).
- Static assets are cacheable for an hour; the stylesheet URL carries `?v=<version>`. Pages stay
  `no-store`.
- No JavaScript was added; CSP unchanged. axe-core 4.10 (run ad hoc, not a repo dependency) over 15
  pages × dark/light × 1440/390 px: 0 violations, no horizontal page scroll.

### Power (F-11)

The iDRAC8 capture reports `PowerInputWatts` 900 on each 750 W PSU while the chassis draws 263 W, so
it is the rated input. The redfish driver moves per-PSU inputs to `bmc.PSU.RatedInputWatts` when they
add up to more than 1.5 × the chassis draw; rated output falls back to `InputRanges[].OutputWattage`;
live output prefers `LastPowerOutputWatts`. The API gains `psus[].rated_input_watts`.

### Tests and gates

- Coverage: admin 86 %, audit 93 %, auth 94 %, authz 100 %, store 91 %, ui 93 %, total 92.6 %.
- UI Settings tests run over the real SQLite store, auth, audit and admin service.
- `make e2e-go` adds: token via UI → API 200 → revoke → 401; invite → link → password → secret →
  confirm → login as viewer (no Settings); audit verify; app log free of every password, secret and
  token. Playwright smoke: login → Settings → token shown once → revoke; create user → link in a
  fresh browser context → enrol → sign in; audit verify; sign out.

### Open

- S2–S4 not started (TODO hooks: `settingsRoutes`, the Settings nav note).
- Self-service password change and a user's own session list are not built.
- en-US vs en-CA spelling (UI now uses en-US "License").
- Confirm F-11 on the live iDRAC8 (rating vs live input).
- Optional: add axe-core to the Playwright gate (needs a tech_doc §2 row).

## 17. Implementation notes (Redfish sessions, per-kind timeouts, poll tiers)

Prompted by field data from 2026-10-21. On a real iDRAC8 (fw 2.86), every Basic-auth GET
took 5.5–9.5 s, so the R730XD poll timed out every cycle and the breaker opened after 3.
A session login took about 6.6 s, after which GETs took 1.0–3.4 s and the DELETE about 2.1 s.
This supersedes the "Basic auth, not X-Auth-Token sessions" item in §11.

### Redfish session auth (`bmc/redfish/session.go`, `request.go`, `transport.go`)

- **gofish is no longer the HTTP client.** The driver sends its own requests through the
  guarded `http.Client` (pinned TLS, no proxy, no redirects, capped bodies). gofish remains
  for the `schemas` types only. Non-2xx answers become a `statusError` that unwraps to the
  matching `bmc` sentinel and never keeps the body.
- **Login:** on first use the driver GETs the unauthenticated service root, takes
  `Links.Sessions` (`/redfish/v1/Sessions` on iDRAC8, `/redfish/v1/SessionService/Sessions`
  on iDRAC9), and POSTs `{UserName, Password}` there. The `X-Auth-Token` header is kept as
  a `secrets.Secret`. Our session URI comes from `Location`, or failing that the body
  `@odata.id`. It is accepted only as `<collection>/<one segment>` on the same host. If no
  URI is valid, the session is still used but is never DELETEd.
- **Sharing and re-login:** one session per driver, created under a mutex, so concurrent
  requests wait for a single login. A 401 on a GET drops the session (compare-and-swap, so
  only the session that failed), waits `reauthBackoff` (500 ms, honours ctx), logs in again
  and retries once. A second 401 is returned as `ErrAuth`; there is no loop. 403 is not
  retried.
- **No SessionService:** a missing `Links.Sessions`, or a 404/405/501 on the POST, is
  `ErrUnsupported` with "set bmc.auth: basic" in the message. `bmc.auth: basic` keeps the
  old per-request Basic auth, and in that mode the guard allows no POST or DELETE.
- **Close / SetCredentials:** `Close(ctx)` marks the driver closed (later requests get
  `ErrInvalidConfig`) and DELETEs our session with its own token. A 401 or 404 there means
  the BMC already dropped the session, and is not an error. `SetCredentials` deletes the
  old session and then swaps the credentials. The next request logs in with the new ones.
  `dellredfish.Driver` delegates both. The password is copied into a Secret in `New`, and
  `cfg.Password` is cleared.
- **Allowlist:** `Driver.allowRequest` is the guard's policy: GET anywhere; POST only to the
  discovered collection; DELETE only to the current session's URI. Query strings and
  fragments are refused for every method. Before discovery, not even the sessions
  collection can be POSTed to. Tests cover every refused combination, and assert that a
  refused request never reaches the mock.
- **`redfishmock`:** serves POST login (201, token, Location, body `@odata.id`), DELETE
  logout (204), X-Auth-Token auth, `WithTokenOnly` (refuses Basic auth, which proves
  tokens are used), `WithoutSessions`, and `ExpireSessions`. It counts `SessionStats`
  (`Created`, `Deleted`, `Rejected`, `TokenGETs`, `BasicGETs`) and records the auth kind per
  request. `OtherWrites()` counts any non-GET other than a session login or logout;
  `assertNoWrites` and the e2e shutdown check use it. The e2e shutdown check also requires
  exactly one login and one logout per BMC, no Basic auth GETs, and no live session left.

### Per-kind timeouts (`config/bmc.go`)

- `bmc.auth: session|basic` (default session) and `bmc.timeouts: {request, cycle}`.
  Zero fields take the kind default: **idrac8 30 s / 150 s; idrac9, redfish and ipmi
  15 s / 60 s**. A partial override keeps the other default.
- Bounds: `request` 5 s–2 min (the driver's own maximum), `cycle` from `request` to 10 min.
- **Interval ≥ cycle:** `Config.PollInterval(s)` = max(`poll.interval`, cycle). Adjusted,
  not rejected, so that the default 60 s interval works with the iDRAC8's 150 s cycle.
  `serve` logs one INFO line per server whose interval was raised. Each server's stale
  threshold is 3 × its own interval (`ServerState.StaleAfter`, used by the UI through
  `ServerView.StaleAfter`).
- `request` becomes `redfish.Config.Timeout`. That bounds every single HTTP attempt
  (login, GET, re-login, retried GET each get their own, through `http.Client.Timeout`).

### Poll tiers (`fleet/poller.go`, `fleet/tiers.go`)

- **Fast tier**, every interval: `Snapshot` (System, Chassis, Thermal, Power: health
  rollup, temperatures, fans, PSUs, voltages, power state).
- **Logs tier**, every `EventsEvery` (5 min): SEL plus the Dell Lifecycle log.
- **Inventory tier**, at startup and every `InventoryEvery` (6 h): Probe (capabilities)
  plus inventory, firmware and licence.
- Each tier runs under its **own** cycle-timeout budget. Before this change one 30 s
  budget covered snapshot, logs and inventory together. The worst-case cycle is now
  3 × cycle, and that happens only at startup and once every 6 h. A tier that fails keeps
  its previous value and its error class. It is retried after min(its period, 5 min), not
  after a full 6 h. Slow tiers run only after a good snapshot and never trip the breaker.
- `ServerState` now has `SELAsOf`, `LifecycleAsOf` and `InventoryAsOf` (the time of the
  last successful read). The derived `*Overdue` is true when the kept value is older than
  the tier period plus 2 × interval. The UI shows a per-section "last read at …; its refresh
  is overdue" banner only in that case: on the System card and the inventory page for
  inventory, and on the logs page for the SEL and Lifecycle log. The API detail has
  `sections.{sel,lifecycle,inventory}.{as_of,overdue}`.
- **Tests** use the fake clock: per-target intervals, the 8-minute overdue SEL, recovery,
  the inventory retry after 5 min, separate budgets (each tier sleeps 150 ms under a
  250 ms cycle), and session reuse across a whole first cycle against the mock.

### Observability

- `fleet: poll recovered` (INFO, once, with `failures`, `failing_for` and `duration`) when a
  server succeeds after failures; `fleet: poll ok` (DEBUG, with `duration`) for every good
  poll; `fleet: poll failed` (WARN) now also has `duration`. `serve` logs at INFO, so the
  DEBUG line is visible only with a debug logger.
- `ServerState.LastPollDuration` is the wall time of the last snapshot read (monotonic
  clock, not the scheduling clock). The API detail has `last_poll_duration_ms` (null before
  the first poll) and `poll_interval_s`. The server page shows "Last poll took 4.2 s".
- Shutdown: `Fleet.Run` closes every driver that implements `fleet.Closer` after all
  pollers have returned. The drivers close in parallel, bounded at 10 s, so the BMC
  sessions are deleted.

### Container memory (field finding, same day)

- On the real host the container was OOM-killed at `mem_limit: 128m` (kernel memcg OOM,
  anon-rss about 68 MB at the kill). An operator was running `docker exec … bootstrap-admin`
  while several argon2id logins happened close together. Exec processes count against the
  container's cgroup. `deploy/compose.yaml` now sets `mem_limit`/`memswap_limit: 256m` and
  `GOMEMLIMIT=200MiB` (deploy/README "Memory limit").
- The argon2 cap is now provable. `auth.HashMemoryBudgetKiB` = 100 MiB, and a stored hash
  may declare at most 48 MiB (down from 256 MiB). `MaxHashConcurrency` = budget / 48 MiB =
  2, and `NewPasswordHasher` refuses a higher concurrency. So N simultaneous logins use at
  most 2 × 48 MiB, and 2 × 19 MiB with the default parameters. `serve` uses
  `auth.MaxHashConcurrency`.

### Open

- Not yet verified against the real iDRAC8: that its `Location` header is absolute or
  relative (both are handled); how long its session timeout is; and that the 150 s cycle
  is enough for the first inventory pass.
- Credentials are still loaded only at startup. `SetCredentials` exists for a future
  reload path.

## 18. Implementation notes (P5 graphical console)

Branch `p5-console`. Scope per task_list P5 (core console only, no Java sidecar). Research and design:
docs/research/console.md §4.2 (tier A) and §4.4 (detection). Deploy steps: deploy/README.md "Enabling the
graphical console". Threats: security.md S5, S6, T5, I6, §3a (third POST exception) and §3b.

### Config and secrets (`config/console.go`, `secrets`)

- `servers[].console.graphical: vnc` takes `console.vnc {port (5901), tls (true), tls_pin_sha256, quirks}`.
  `quirks` absent = the kind default (idrac8: `idrac8_safe_encodings`, `idrac8_low_colour`,
  `idrac8_rsa_kex_tls`; others none); `[]` = none; unknown or duplicate quirks fail validation. With `tls: true` a pin is required: the VNC pin
  if set, else the server's web pin (`Server.VNCPin`). `kvm-launch` and `link` are still accepted as legacy
  values (no VNC); the native launch is feature-detected instead (below).
- `graphical: vnc` requires `credentials.vnc` only. `credentials.operator` is required by fans, the serial
  console and `kvm-launch`, not by VNC; without it the native launch is not offered and the card says why
  (`KVMNote`).
- Top-level `console {idle_timeout 15m [1m, 2h], max_session 4h [idle, 12h], close_on_stepup_expiry false}`.
- Credential entries may now be password-only (`{password: …}`), for VNC. `Credential.HasLogin` tells login
  accounts apart; the Redfish driver still refuses an entry without a user name.
- A missing VNC credential or operator credential is a startup **warning**, not an error: the card says
  "Needs setup". `console.PasswordWarnings` (logged at startup and shown to admins on the card, never with the
  password) flags passwords longer or shorter than 8 bytes and, on iDRAC9, missing complexity.

### RFB (`internal/console/rfb`)

- `ClientHandshake` (app → BMC): RFB 3.3/3.7/3.8 (3.4–3.6 as 3.3, above 3.8 as 3.8), picks VNC auth when a
  password is configured, else None; Tight, VeNCrypt etc. are refused. DES key = first 8 password bytes,
  zero padded, bit-reversed per byte; vectors cross-checked against noVNC's own DES. ClientInit shared=0.
  BMC failure reasons are read and discarded, never put in errors or logs. ServerInit names > 1 KiB refused.
- `ServerHandshake` (app → browser): offers only None, reads and ignores ClientInit, sends the ServerInit.
- `Filter`: SetPixelFormat (8/16/32 bpp, sane depth, else dropped), SetEncodings (≤ 64; allowlist of picture
  encodings and harmless pseudo-encodings; anything that would make noVNC send another message type, such as
  QEMU extended keys −258, ExtendedDesktopSize −308, Fence −312, ContinuousUpdates −313, xvp −309,
  extended clipboard, extended mouse buttons −316, is removed; Raw is always present), FramebufferUpdateRequest,
  KeyEvent, PointerEvent, ClientCutText (≤ 64 KiB forwarded, ≤ 1 MiB skipped, larger ends the session). Any
  other type ends the session: its length is unknown, so the stream cannot be resynchronised.
- Quirks: `idrac8_safe_encodings` narrows SetEncodings to Raw, CopyRect, DesktopSize. `idrac8_low_colour`
  rewrites the desktop name to "Intel(r) AMT KVM", the name noVNC special-cases to request 8-bit colour
  (core/rfb.js); the page shows the configured server name instead. Intercepting SetPixelFormat alone would
  need pixel translation in the relay. Whether iDRAC8 2.86 needs one or both is task 5.1 (spike).
- Quirk `idrac8_rsa_kex_tls` (dial, not the filter): the VNC TLS config lists the ECDHE AEAD suites, then
  `TLS_RSA_WITH_AES_256_GCM_SHA384`, `TLS_RSA_WITH_AES_128_GCM_SHA256` (no CBC, no SHA-1), MinVersion TLS 1.2;
  TLS 1.3 is unaffected. Only `console.vncTLS` uses it; the web/Redfish transport never does. A startup
  warning per server records that the VNC port has no forward secrecy.

### Broker (`internal/console`)

- `Service.Issue(Grant)` mints a ticket (256-bit, SHA-256 stored, 30 s, single use, max 64 outstanding)
  after checking: configured, credential present, no 60 s cooldown after a rejected password, not in use
  unless takeover. `Serve` redeems it (bound to server and to `SessionHash(cookie)`), claims the server's
  slot (takeover cancels the holder with cause `taken_over` and waits ≤ 5 s for it to close, because the BMC
  takes one VNC session), writes `console.vnc.start` (**no audit row, no console**), dials (pinned TLS),
  authenticates, runs the browser handshake (10 s deadline) and relays.
- Relay: BMC→browser bytes are copied unchanged; browser→BMC goes through the Filter. Every
  `CheckEvery` (10 s) it checks idle (no key/pointer/clipboard input), max session and the watchdog. End
  reasons: `browser_closed`, `bmc_closed`, `protocol`, `idle_timeout`, `max_session`, `taken_over`,
  `shutdown`, `session_ended`, `stepup_expired`, `forbidden`. `console.vnc.stop` carries reason,
  `duration_s`, `bytes_to_browser`, `bytes_to_bmc`, `dropped_messages`, with the start row's correlation ID.
  Failed connects are `console.vnc.stop` with result `error` and class `tls_pin`, `tls`, `bmc_auth`,
  `bmc_protocol`, `browser_protocol`, `timeout` or `unreachable`. `console.vnc.takeover` records the previous
  user, session and duration.
- TLS never downgrades: a `tls: true` target that answers plain RFB is `ErrTLS` / probe state `tls`.
- Banner probe: connect (TLS if configured), read the 12-byte ProtocolVersion, close; states `ok`, `refused`,
  `pin`, `tls`, `not_rfb`, `unreached`. At startup, then on the slow tier (6 h; failures retried after 5 min),
  checked every minute; a server with an active console is skipped. A successful console connection also
  refreshes the cached state.
- `Shutdown` (called by `serve` before `http.Server.Shutdown`, which does not wait for hijacked connections)
  ends every console so their stop rows precede `app.stop`.
- `rfbtest` is the fake BMC VNC server (RFB 3.8, VNC auth with a known password, optional TLS with a generated
  certificate and pin, solid red frames in the client's pixel format, a record of every client message).

### Hardware findings (spike, 2026-10)

- iDRAC9 7.x: VNC port 5901 is TLS 1.3 (TLS_AES_256_GCM_SHA384) with the same certificate as the web port
  (same SPKI pin); a plain client gets no banner. VNC auth works; ServerInit 1024x768, name "OpenVNC", 16 bpp;
  Raw framebuffer updates carry real content.
- iDRAC8 2.8x (SSL "Auto Negotiate"): VNC TLS is 1.2 only and offers **only RSA key-exchange suites**
  (AES128/256-GCM, AES256-SHA256, AES256-SHA; no ECDHE). Go's default client config fails with
  "remote error: tls: handshake failure"; adding the two RSA-kex GCM suites works (VNC auth, 1024x768
  "OpenVNC", 16 bpp). Certificate identical to the web port. With SSL on it still sends a plain
  "RFB 003.008\n" banner to a client that sends no ClientHello, so the app must never fall back to plain.

### Redfish (`bmc/redfish/action.go`, `bmc/dellredfish/kvm.go`, `redfishmock/kvm.go`)

- `redfish.WithActionPolicy(policy)` + `Driver.PostAction`: the guard allows a POST to an action URI only when
  the driver was built with a policy that accepts it; `checkURI` still applies; a 401 is not retried.
- `dellredfish.Probe` adds `CapabilityFlags.KVMLaunch`: GET the manager's `Links.Oem.Dell.DelliDRACCardService`
  (fallback `<manager>/Oem/Dell/DelliDRACCardService`) and look for
  `Actions["#DelliDRACCardService.GetKVMSession"].target`. The target must match `IsKVMActionURI` and sit under
  that service. Detection errors leave the flag off; they never fail the probe.
- `LaunchKVM(cfg, host)`: a fresh driver with the operator login and the KVM policy; minimal walk (service root →
  first manager → card service), POST `{"SessionTypeName": "oob-manager"}`, validate `TempUsername` /
  `TempPassword` (printable ASCII, ≤ 128), log out, return
  `https://<host>/console?username=<operator>&tempUsername=…&tempPassword=…` as a `secrets.Secret`.
  **Unverified on hardware:** the meaning of `SessionTypeName` (Dell's sample passes a file name) and the
  launch URL format come from Dell's sample script and OpenStack Ironic (research §1.3); confirm in the spike.
- `redfishmock`: a second account (`OperatorUser`), `WithKVMSession()` serves the card service and answers the
  action for operator sessions only (403 otherwise), counted in `KVMStats` and not in `OtherWrites`.

### Authorization

- `console.vnc` (open), new `console.vnc.takeover`, `console.kvm_launch`: admin + fresh step-up. Tokens never.
- Console start, takeover and launch share a limit of 10/min per user. A stale step-up redirects to
  `/stepup?next=…` and comes back; refusals are audited with the action and class.

### UI (`web/ui/console*.go`, templates `console.html`, `console_partials.html`, `kvm_launch.html`)

- Routes: `GET /servers/{id}/console` (page with Connect, or Take over when in use), `POST /servers/{id}/console`
  (`takeover=1` for takeover; renders the page with the ticket, 200 `no-store`, never a redirect),
  `GET /servers/{id}/console/ws?ticket=` (upgrade), `POST /servers/{id}/console/kvm-launch` (200 `no-store`
  page with the one-time link). A redirect to the BMC is not used: CSP `form-action 'self'` would block it,
  and a link keeps the temporary login out of our Location headers.
- The upgrade checks cookie (401), role + fresh step-up (403), Origin (coder/websocket: request host or
  `public_url` host), then clears the server's read/write deadlines on the hijacked connection, accepts
  subprotocol `binary`, sets a 68 KiB read limit and hands a `websocket.NetConn` to `Serve` with a context
  detached from the 25 s request timeout. Go's HTTP/2 server does not enable extended CONNECT (RFC 8441), so
  browsers open the WebSocket over HTTP/1.1.
- Server page card (`consolecard`): Ready / In use (user, since; Take over) / Needs setup (missing or rejected
  password, VNC server not answering, pin or TLS mismatch, not configured; with the three setup steps) / Needs a
  higher BMC licence (Basic or Express) / Not supported ("use the serial console") / Not checked yet. It adds
  "Open native iDRAC console" when the BMC advertises `GetKVMSession` and an operator login is configured
  (without the login it is a disabled button with the reason, direction B C-10), and an "Open the BMC web interface" link (task 5.5) in the setup, licence and unsupported states. The old
  "Graphical console: not available yet" action row is hidden when consoles are wired.
- Console page: toolbar (role `toolbar`): Send Ctrl-Alt-Del, Full screen, Scale to window (`aria-pressed`),
  View only (`aria-pressed`, noVNC's client-side view-only), Disconnect; a live status region; the screen
  region; a hidden Reconnect form shown on disconnect. Script: `static/console.js` (ES module, imports
  `vendor/novnc-1.7.0/core/rfb.js`); styles: `static/console.css`, using only the app's CSS variables (the
  stylesheet link sits in the page body so the layout template is unchanged). The limits shown come from config.
- CSP unchanged (security.md §3). The about page links the noVNC licence.

### Tests and gates

- Unit: rfb (handshakes per version, failures, filter, encodings), console (tickets, end to end with rfbtest:
  password never on the browser side, quirks, disallowed message, one session, takeover, idle, max, watchdog,
  wrong password + cooldown, refusals, audit fail-closed, shutdown, banner states incl. TLS pin), redfish
  action policy, Dell detection and launch, mock, UI handlers incl. a real WebSocket, cmd wiring.
- `make e2e-go`: R730XD (idrac8 defaults) console over TLS to the fake VNC server through a real
  `wss://` upgrade: ServerInit name rewritten, encodings narrowed, Ctrl-Alt-Del's six key events at the BMC,
  disallowed message never forwarded, no password bytes on the socket, replayed ticket opens nothing; R240
  native launch link; shutdown requires one login/logout per mock plus one per launch and
  `console.vnc.start`, `console.vnc.stop`, `console.kvm_launch` rows.
- Playwright: open console → Connect → noVNC canvas shows the fake BMC's red frame → Ctrl-Alt-Del reaches the
  fake server (read from a loopback debug endpoint of the dev harness) → View only → Disconnect → Reconnect;
  axe WCAG 2.2 AA scans of the console page before and after connecting (0 violations). Screenshot
  `tests/e2e/test-results/console.png`.
- Coverage: console 88.6 %, rfb 88.1 %, rfbtest 86.6 %, ui 93.0 %, authz 100 %, total 92.3 %.

### Open (needs hardware)

- Task 5.1 spike on the R730XD (iDRAC8 2.86): VNC with SSL on (is the iDRAC the TLS server on 5901, which TLS
  versions, does the VNC port reuse the web certificate), which of the two quirks is needed, VNC password
  rules. The racadm attribute values in deploy/README (e.g. `SSLEncryptionBitLength "Auto Negotiate"`) are
  from documentation, not from these machines.
- iDRAC9: confirm `SessionTypeName` semantics and the `/console?…` launch URL on fw 7.00.
- `console_sessions` (schema 0001) is still unused; the audit trail carries the session data.
- With `close_on_stepup_expiry: false` (default) a running console survives the 5-minute step-up window; a
  session rotation (stepping up in another tab) ends it, because the watchdog follows the cookie it started with.

## 19. Implementation notes (UI redesign, direction B)

Design record: `docs/design/direction-b.md` (tokens, components, patterns, deviations);
audit status: `docs/reviews/2026-10-21-ux-audit.md`; screenshots: generated by `OOB_SCREENSHOTS=1` runs of `tests/e2e/pages.spec.ts`, not committed.

### Config and wiring

- New optional key `ui.instance_name` (≤ 64 bytes, printable, no `< > & " '`), shown in
  the top bar and on the sign-in page. (Since v0.9.1 it is a General setting, editable in the
  browser; settings_design.md "v0.9.1".) `ui.Deps` gains `InstanceName` and `StepUpWindow`
  (from `auth.stepup_window`, default 5 min). `ui.ServerView.Tags` carries the config tags
  (copied in `fleetview`); the tag `critical` renders a "Critical server" tag.

### Shell and preferences (`layout.go`, `chrome.go`, `prefs.go`)

- `layoutFor` computes the sidebar (every server with health and its hottest temperature
  or data age), the fleet pill, the clock's data age (oldest current data) and the 24 h
  warning/critical event count from the cached logs (`Fleet.Events`, no BMC traffic).
- Theme: cookie `__Host-oob_theme` (`dark`/`light`; absent follows the OS), set by
  `POST /prefs/theme` (session + CSRF form `prefs`, closed values, `next` through
  `localPath`). `render` now takes the request so it can apply the cookie on every page,
  signed in or not. Static assets are versioned only on signed-in pages, so the sign-in
  page does not reveal the build.
- `static/app.js` (optional, `'self'`): Escape/outside click closes `<details class=menu>`,
  Copy buttons (`data-copy`), role button disabled until changed. Pages load it with
  `defer`; CSP is unchanged.
- `static/palette.js` (optional, `'self'`, signed-in pages only, since 2026-10-30): the Go to palette and the
  keyboard shortcuts, §52.

### Pages

- Overview: `overviewOf` sorts rows by severity (`bySeverity`), counts the fleet, adds
  warning/critical events of the last 24 h to Needs attention (`withRecentEvents`) and a
  6-entry feed; `Healthy` collapses the strip. `?view=` is no longer used. No servers: a
  first-run checklist (admins) or "ask your administrator".
- Server: `serverpage.go` builds the head (identity, tags, BMC link only when
  `authz.PowerOn` would be allowed), the verdict (first attention item, else a stale or
  OK sentence; unread sections listed), the action bar and the tabs. Meters
  (`meter.go`): scale = critical × 1.1 (or warning × 1.16), "close" = within 5 °C of
  warning. Power-good (`voltages.go`): names matching `(^|\s)PG(\s|$)`, Good/Fault/Unknown.
  Display names drop "System Board " and " RPM"/" Temp"/" Status"; full names in `title`.
- New `GET /servers/{id}/operations` (authz `server.view`): placeholder with every action
  disabled and its reason. `GET /help` is public (static text) and uses the signed-in
  chrome when a session exists.
- Events (`events.go`, `eventlog.go`): `foldRepeats` merges iDRAC "previous log entry was
  repeated N times" markers into the entry they follow (×N+1); Info severity for log
  entries; filters `server` (configured IDs only), `log`, `severity` (default `warning`),
  `range` (`24h`, default `7d`, `30d`, `all`), `q` (≤ 64 printable characters,
  case-insensitive on message and message ID). Server logs fold repeats too.
- Audit (`audit_text.go`): sentences per action, user IDs resolved through
  `Admin.Users`, parameters as a sorted key/value list, unknown actions as "who: action".

### Confirm interstitials (UX-06/07, `confirm.go`, `confirm_specs.go`)

- Routes: `GET` and `POST` on `/settings/users/{id}/disable`, `/reset-totp`,
  `/sessions/revoke-all`, `/sessions/{sid}/revoke`, and `/settings/tokens/{id}/revoke`.
  `GET` (view authz) renders the confirm page; enable and role changes stay direct.
- `confirmed()` order: session → Settings backend → CSRF → target lookup from the path
  (404 when gone) → `confirm=yes` (else 303 to the confirm page, audited `unconfirmed`) →
  typed name, exact (reset authenticator; a token used in the last 24 h) else 422,
  audited `confirm_mismatch` → step-up: fresh, or an inline code (`auth.StepUp`, same
  limiter, lockout and audit as `/stepup`; the session rotates and the cookie is set) →
  role (`authorizeChange`) → per-user rate limit → handler. The admin service still
  audits the change itself and still refuses self-disable and last-admin demotion.
- `/stepup` names the action from `next` (closed set of labels; only configured server
  names and existing usernames are interpolated) and offers only Continue when fresh.
- A role change to the current role redirects with `done=role-unchanged` and writes
  nothing.

### Messages

- Rate limits say "Try again in N seconds/minutes" (`tryAgainIn`); account lockout stays
  generic. US English in templates is enforced by `copy_test.go`.

### Tests and gates

- Go: `views_b_test.go`, `eventlog_test.go`, `serverpage_test.go`, `shell_test.go`,
  `confirm_test.go`, `audit_text_test.go`, `copy_test.go`, config `ui_test.go`; the earlier
  review tests were updated to the new markup with their intent kept.
- Playwright: `pages.spec.ts` (axe on 25 pages × 2 widths × 2 schemes, one h1, no
  horizontal scroll at 390, verdict/data age/fleet pill in the first 390x844 viewport,
  theme switch without JavaScript) and the updated smoke test (confirm-based revoke,
  role radios, enrollment axe). `workers: 1`: TOTP codes are single-use per 30 s step.

### Open

- Deferred audit items (status table in the audit copy): acknowledge/"seen up to" for
  events, per-server Logs severity filter, display time zone (S2), code-only enrollment
  confirmation, column sorting, Dell component names, show-password hints.
- Power (§20) and the fan lease (§21) share the confirm template and `confirmStepUp`; the serial
  console uses the console step-up flow like the graphical console (§22, §23).

## 20. Implementation notes (P2 power control)

Branch `p2-power`. Tasks 2.1 and 2.3; **2.2 (IPMI chassis control) deferred**: `github.com/bougou/go-ipmi`
is not in `go.mod` and adding it needs its own review (rule 10). No new dependency was added.

### Redfish (`bmc/redfish/reset.go`, `redfishmock/power.go`)

- `redfish.OpenResetter(ctx, cfg)` builds a fresh driver with the **operator** login and
  `WithActionPolicy(IsResetActionURI)` (exact `^/redfish/v1/Systems/[A-Za-z0-9._-]{1,64}/Actions/ComputerSystem\.Reset$`),
  walks service root → first system, and accepts the advertised target only when it equals
  `<system>/Actions/ComputerSystem.Reset` (else `ErrUnsupported`; a failed open logs out). `Allowed()` is the
  system's `ResetType@Redfish.AllowableValues`; `Reset(rt)` refuses anything outside the closed set
  `On, GracefulShutdown, GracefulRestart, ForceOff, PowerCycle, ForceRestart` or not allowed by the BMC before
  sending, and posts `resetBody{ResetType}` (exactly `{"ResetType":"…"}`); `PowerState` re-reads the system;
  `Close` logs out (bounded 10 s, detached from a cancelled ctx). Pollers never get this policy.
- Dell: iDRAC8 2.86 lists `On, ForceOff, ForceRestart, GracefulShutdown, PushPowerButton, Nmi` (no
  GracefulRestart, no PowerCycle); iDRAC9 7.00 lists all six plus PushPowerButton/Nmi. Nothing is mapped or
  emulated: an unlisted action is disabled "Not offered by this BMC".
- `redfishmock.WithPowerControl(transition)`: operator sessions only (403 otherwise, `PowerStats.Rejected`),
  canonical body only and a type both simulated and advertised (400), `On` when on / off-type when off → 409
  (`Refused`), else 204 and a transition: off-types report `PoweringOff`, `On` reports `PoweringOn`, restarts
  report `Off`, each until `transition` passes. `FailNextReset(code)` and `Stick()` inject failures. GETs of
  `SystemPath` carry the simulated `PowerState`, so the pollers see the change too. Resets are not counted in
  `OtherWrites`.

### Service (`internal/power`)

- `Action` is the URL slug enum (`on`, `graceful-shutdown`, `graceful-restart`, `force-off`, `power-cycle`,
  `force-restart`) with `ResetType`, `Authz` (existing `power.*` authz actions), `Forced`, `Label`, `Effect`,
  `TakesDown`, `Restarts`, `Applies(state)` (On only when not on; the rest only when not off; Unknown allows).
- `Request(ctx, id, action, actor)`: unknown server / no operator / unknown action → `denied` audit and
  `ErrNotConfigured` / `ErrNoOperator` / `ErrUnsupported`; cooldown (default 60 s, reserved before any BMC
  traffic, `*CooldownError{Left}`, `denied:cooldown`); `started` audit **fail-closed** (`ErrAudit`, nothing sent,
  cooldown returned); then login, AllowableValues, live state, POST. A refusal before the POST returns the
  cooldown; a BMC error after it keeps the cooldown. Errors other than the refusals wrap `ErrBMC` with the
  `bmc.Classify` class. A new request after the cooldown supersedes a running verification.
- Verification runs in the background with the same session: an immediate read, then every `PollEvery`
  (3 s in `serve`) until the end state (`Off`; `On` for On; for restarts a non-On reading then `On`), or the
  timeout (graceful 5 min, others 2 min). Outcomes: `done` (audit `ok`, `outcome: verified`), `unconfirmed`
  (restart never seen leaving On: audit `ok`, `outcome: unconfirmed`), `failed` (`error` with `not_confirmed`,
  `superseded` or `stopped`). The session is logged out before the result is published. `Shutdown` stops
  every verification (they record `stopped`) and refuses new requests; `serve` calls it after the consoles
  end and before `app.stop`.
- Every row carries the correlation ID of its request, server ID, principal, role, source IP and
  `reset_type`; GELF shipping is the audit logger's. `Last(id)` is an immutable `Operation` (phases
  `sending`, `pending`, `done`, `unconfirmed`, `failed`); `Info(id)` gives operator/self-host/impact.

### Config (`config/power.go`)

New optional per-server block `power: { self_host: bool, impact: [string] }` (≤ 8 lines, each 1–200 bytes
of printable text). It changes only warnings and typed-name rules; it never enables an action. Example:

```yaml
  - id: gateway1
    tags: [critical]
    power: { impact: ["Network gateway: all internet access drops"] }
  - id: storage1
    power: { self_host: true }
```

### UI (`web/ui/power*.go`, `confirm.go`, templates `operations.html`, `confirm.html`)

- Routes: `GET /servers/{id}/power/{action}` (confirm page) and `POST` (run). `Deps.Power` nil → 404 and the
  old placeholders. The Operations tab links each available action to its confirm page; disabled ones show the
  first reason: not determined / not offered by this BMC / needs an operator BMC account / needs the
  operator|admin role / already on|off (newest of snapshot and last verified operation) / cooldown. The latest
  operation is a `role="status"` line. The server page's "Power…" links to `#pw-h` on the tab.
- Confirm page (direction B C-11) reuses `confirm.html` and `confirmStepUp`: `confirmView` gained `Warnings`,
  `Impact` ("What goes down") and unexported `form` (CSRF form, here `power`), `chrome` (server layout) and
  `serverID` (audited with step-up refusals). Typed server name: forced actions always; safe take-downs of
  `critical` or `self_host` servers; never Power on. Self-host warning: "This server runs oob-manager; the
  console will go offline until it boots." (plus "needs another way in" for non-restarts). Badges: Safe /
  Forced action.
- POST order: CSRF → availability → confirm → typed → step-up (inline) → authorize → 10/min/user (shared
  `changeLimit`, key `power:<user>`) → service. The service call is detached from the 25 s request deadline;
  if that passes first, the browser goes to the Operations tab ("Sending"). Errors: cooldown 429 +
  Retry-After, not offered / state changed / not set up 409, audit failure 503, BMC 502.
- `/stepup?next=/servers/<id>/power/<action>` names the action ("Force off · <server>").

### Wiring (`cmd/oob-manager/power.go`, `serve.go`, `ui.go`)

`buildPower` makes one target per server: an opener (`redfish.OpenResetter` with the operator login, per-kind
request timeout and `bmc.auth`) when `credentials.operator` resolves, else nil with a warning; `kind: ipmi`
servers never get one. The e2e/dev endpoint seam is `env.kvmEndpoint`. `runServer` takes extra stop hooks.

### Tests and gates

- Unit: power 99.5 % (fake controller and clock: verify, cooldown, refusals, fail-closed audit, BMC failures,
  every verification outcome, supersede, shutdown), redfish reset (URI pattern, bodies at the mock, refusals
  before sending, foreign targets, login failure), mock transitions, config, authz power matrix (role × kind ×
  freshness), UI (buttons and reasons, confirm pages, typed name, CSRF incl. a Settings token, stale step-up
  refused and inline code accepted, service errors, rate limit, status texts, step-up label), cmd wiring
  against the mock. Total 92.4 %.
- `make e2e-go`: R240 force off with a wrong then the exact typed name → 303, verified Off at the mock,
  exact body at the mock; next action 429 with Retry-After (POST and confirm page) and no BMC traffic; iDRAC8
  shows PowerCycle as not offered; self-host warning on the R730XD. A second stack with
  `stepup_window: 2s`: refused without a code (401, `denied:stepup_required` with server ID), accepted with
  an inline code, graceful restart verified. Shutdown: session logins = 1 + KVM launches + resets, all logged
  out; `power.force_off` rows `denied:confirm_mismatch`, `started`, `ok`; `power.on` `denied:cooldown`.
- Playwright `power.spec.ts`: Operations tab → Power cycle confirm (Cancel focused, critical warning, What goes
  down) → wrong name error → exact name → "Power cycle done"; self-host page; axe WCAG 2.2 AA on the tab, the
  confirm page at 1440 and 390, its error state and the self-host page. `pages.spec.ts` adds three confirm
  pages to the matrix.

### Open

- 2.2 IPMI chassis control (needs go-ipmi, a §2 review and an RMCP+ reference BMC).
- Hardware: operator accounts (`0x11`) do not exist yet on either iDRAC; verify reset behaviour, the
  `PowerState` transitions seen during GracefulShutdown/ForceRestart and the timeouts on iDRAC8 2.86 and
  iDRAC9 7.00 before relying on "unconfirmed" vs "done".
- The cooldown and timeouts are code defaults (not config).

## 21. Implementation notes (P3 fan control)

Branch `p3-fans`. Tasks 3.2–3.5 and 3.7 are built against mocks; 3.6 (`ipmi-oem`) is deferred;
the host script patch (3.4) is a drop-in that is **not applied anywhere**.

### Spike results (3.1, iDRAC9 fw 7.00, read-only)

`/redfish/v1/Managers/System.Embedded.1/Attributes`: `ThermalSettings.1.MinimumFanSpeed` = 255
(integer, 255 = not set), `ThermalSettings.1.MFSMinimumLimit` = 35, `MFSMaximumLimit` = 100,
`ThermalProfile` "Default Thermal Profile Settings", `FanSpeedOffset` "Off". The code reads the two
limits live and clamps to them. **To verify on hardware:** that the limit attributes carry the
`ThermalSettings.1.` prefix like `MinimumFanSpeed` (the reader fails closed with "unsupported" if
not). Config requires `safe_min_pct` ≥ 35 for `redfish-floor`, the BMC's own lower limit
(lowered from 41 on 2026-10-21).

### Model and arbiter (`internal/fan`)

- `ParseRequest`: pct must be 1–3 ASCII digits ≤ 100 and is raised to `safe_min_pct`; minutes
  1–4 digits within [5 min, `max_lease`]. `Start` re-checks the request (no trust in callers).
- `Service.Start`: per-server mutex; one active lease (store partial unique index + check);
  `Applier.Prepare` (reads the value to restore, clamps) → row stored as `pending` **with**
  `original_value` → `Apply` → `applied` when immediate (redfish), else stays `pending` until the
  host acks. A failed apply releases (restores) and marks the row `rejected`. Mode is always
  `boost`; `pin` (quieter than the curve) is not offered.
- `End`: release first, then `ended`; a failed release keeps the lease active (expiry still
  applies) and returns `ErrRelease`.
- `Run`: startup reconcile (expired → release + `expired`; unexpired → `Apply` again, which is
  idempotent; orphan server → closed; `Sweeper` removes a stray lease file of a server without an
  active lease), then every 15 s (expiry; `pending` → `applied` on ack). Restore failures are
  retried each pass. A crash between steps is healed from the row alone (tests: `TestCrashRestart`).
- Audit: `fan.lease.create`/`fan.lease.end` (user, with pct, minutes, mode, lease_id, expires_at),
  `fan.lease.applied`, `fan.lease.expire`, `fan.lease.reapply` (principal `system`); GELF via
  `audit.Logger`. Error classes only, never error text.

### Appliers

- `hostlease`: lease file and ack formats are in the package comment and `deploy/host/README.md`
  (golden file `internal/fan/hostlease/testdata/golden.lease`, shared with the bats tests).
  Atomic write (O_EXCL temp + fsync + rename + dir fsync) through `os.Root`. Ack: Lstat + open +
  `SameFile`, 512-byte cap, strict grammar, unknown keys ignored; stale after 3 min; `reason=invalid`
  after the lease was issued → "rejected" warning; `owner=guard` → guard warning.
- `redfishfloor` over `dellredfish.FanFloorClient`: `Prepare` reads current + limits, target =
  `min(max(pct, safe_min, MFSMin), MFSMax)`, never below an already-set floor; refuses when the
  BMC maximum is below `safe_min_pct`. `Release` restores the recorded value, or 255 if it is
  implausible. `Observe` uses the row only (no BMC traffic on page views).
- `redfish.WithAttributePatch(uri, keys...)`: the fourth transport exception (security.md §3a).
- `ipmi-oem`: **deferred**. go-ipmi is not a dependency yet (P2/P4 decide), and the mode needs an
  app-owned manual mode with re-assert and restore-on-shutdown. A configured `ipmi-oem` server is
  logged and left without fan control.

### UI (`web/ui/fan.go`, `fan_view.go`, `fan_partials.html`, shared `confirm.html`)

- Operations tab card: owner (host fan curve / BMC automatic / "Lease by u: at least N %" / thermal
  guard / curve above the floor), badge (No lease, Pending, Applied, Guard, "…, check"), reported
  speed and time, ends-at + minutes left (server-rendered; the page's opt-in auto-refresh updates
  it), warnings from the applier, End now, and the start form (floor, duration select).
- `POST /servers/{id}/fan/lease`: without `confirm=yes` renders the review page (values editable,
  consequences per mode); with it: CSRF (form `fan`) → role → `ParseRequest` (422) → inline step-up
  (fresh window or code; same limiter/lockout/audit as `/stepup`) → 10/min/user → `Start`.
  `POST /servers/{id}/fan/lease/end`: CSRF → role → rate limit → `End`; no step-up (PRD FR-14).
  Results come back as `?fan=started|ended|none` (closed set).
- `Deps.Fans` (nil: "not set up"); templates `*_partials.html` are now loaded by glob.
- The review page is the shared confirm interstitial (`confirmView.Lease` adds the floor and duration
  fields, `EmptyNote` stands in for the consequences while the input is invalid) and the inline step-up
  is `confirmStepUp` (folded together at integration, §23).

### Host snippet (`deploy/host/`)

`fan-lease-reader.sh` (bash + awk, sourced): `fan_lease_read`, `fan_lease_apply <curve>`,
`fan_lease_ack <applied>`, `fan_lease_ack_guard`. `tr -c` maps any byte outside the alphabet
(NUL included) before awk; `head -c` caps the read. 23 bats tests (`make host-test`): golden file,
none/valid/expired/future/too long/oversized/garbage/CRLF/NUL/duplicates/unknown keys/wrong
server/symlink/directory/owner uid, never lowers the curve, AUTO passthrough, ack contents, ack
through a planted symlink, reader/writer race and a torn write.

### Wiring and tests

- `cmd/oob-manager/fans.go`: one applier per server from config; `serve` runs the reconciler
  until shutdown (before the store closes). The e2e stack uses `host-lease` on the R730XD mock and
  `redfish-floor` on the R240 mock (`redfishmock.WithFanFloor`).
- `make e2e-go`: lease file contents, host ack → applied, End now removes the file, PATCH 50 then
  restore 255, hostile input, audit rows, session accounting (each floor read/PATCH is one
  operator login/logout). Playwright `fan.spec.ts`: review → confirm → countdown → End now in both
  modes with axe (dark/1440, light/390).
- Coverage: fan 91 %, hostlease 90 %, redfishfloor 100 %, ui 92 %, total 92 %. golangci-lint
  v2.14.0: 0 issues.

### Open

- Hardware: the host script change for `host-lease` (run every minute, decision 4) and *Configure* for
  the iDRAC9 operator account (`oob_kvm`) are install steps, not code; verify the iDRAC9 PATCH (some firmware wants `If-Match`)
  and the limit attribute names.
- `/api/v1/servers/{id}/fan` (tech_doc §6) is not built.
- `ipmi-oem` (3.6) deferred, see above. CI has no per-package coverage gate for `fan` yet.

## 22. Implementation notes (P4 serial console)

Branch `p4-serial`. Scope per task_list P4. Deploy steps and the host how-to (task 4.5): deploy/README.md
"Enabling the serial console". Threats: security.md S3, S7, T6, I3, I7, D3.

### Config (`config/serial.go`)

- `servers[].console.ssh {port (22), quirks}`. `quirks` absent = the kind default (idrac8: `idrac8_legacy_ssh`;
  others none); `[]` = none; unknown or duplicate quirks fail validation.
- `console.serial: bmcssh` still needs an iDRAC kind and `credentials.operator` (ref), but **`ssh_host_key` is
  no longer required at startup**: like a missing VNC password, a missing host key or a missing operator entry
  in the secrets file is a startup warning and the card says "Needs setup". Getting the key needs a trusted
  read of the BMC, so it is a setup step, not a reason to refuse to start.
- `serial: sol` is accepted but not implemented (task 4.3 deferred, below); the card says "Not supported yet".
- The serial console shares the app-wide `console.idle_timeout` / `console.max_session` (15 min / 4 h) with the
  graphical console. security.md D3 previously said "serial max 2 h"; it now says 4 h (same setting).

### Driver (`internal/bmc/bmcssh`)

- `Open(ctx, Config, Size)`: dial (bounded by `Timeout`, default 10 s; the connection deadline follows ctx),
  SSH handshake with `HostKeyCallback` = exact match of the pinned key's wire form (constant-time compare) and
  `HostKeyAlgorithms` limited to the pinned key's type (RSA: `rsa-sha2-512`, `rsa-sha2-256`). A wrong key or a key
  of another type fails before authentication: **the password is never sent to an unverified host** (tested:
  zero auth attempts at the fake).
- Algorithms: `ssh.SupportedAlgorithms()` key exchanges, ciphers and MACs (x/crypto's defaults also include
  insecure ones such as `ssh-rsa`, `diffie-hellman-group14-sha1`, `hmac-sha1-96`; the client config sets the
  lists explicitly). Quirk `idrac8_legacy_ssh` adds only `diffie-hellman-group14-sha1` and, when the pinned key is
  RSA, `ssh-rsa` (SHA-1 signatures). No CBC ciphers and no `hmac-sha1-96`. Startup warning per server using it.
  Whether iDRAC8 2.86 also needs a CBC cipher is unverified (open, below).
- Auth: password, plus keyboard-interactive that answers only a single hidden prompt. Client version
  `SSH-2.0-oob-manager`.
- Session: `pty-req` (`xterm`, 80x24 default, clamped to 20–400 x 5–200, ECHO off, 115200), then exactly one
  `exec "console com2"` (`bmcssh.Command`). Stdout and stderr share one pipe. The exported `Session` API is
  `Read`, `Write`, `Resize` (`window-change`), `Break` (RFC 4335, 500 ms), `Quit` (writes the iDRAC quit key
  0x1c, then closes) and `Close` — a test pins this method set, so no other command, shell, subsystem or
  arbitrary request can be sent. The fake (`bmcssh/sshtest`) refuses shell, subsystem, a second exec and any
  command other than `console com2`, and records every request.
- Errors carry no BMC text: `ErrConfig`, `ErrHostKey`, `ErrAuth`, `ErrAlgorithms`, `ErrRefused` (PTY/exec refused);
  `Classify` maps them to `config`, `host_key`, `bmc_auth`, `algorithms`, `bmc_protocol`, `timeout`, `unreachable`.

### Broker (`internal/console/serial*.go`)

- `SerialService` reuses the graphical console's machinery: the ticket store (`tickets`, 256-bit, 30 s, single
  use, bound to server and `SessionHash(cookie)`), the one-session `broker` (takeover waits ≤ 5 s), the idle/max
  `watch` loop, the session `Watchdog` and the audit helper (now the shared `recordAudit`). It has **its own**
  ticket store and slots: a serial ticket cannot open a graphical console (tested), and a server can have one
  serial and one graphical session at the same time.
- `ServeSerial`: redeem → ready checks (configured, `bmcssh`, operator login, host key, 60 s cooldown after a
  rejected login) → claim → `console.serial.takeover` (if any) → `console.serial.start` (fail closed: no audit
  row, no BMC contact) → open → relay. `SerialOpener` is the transport seam (`bmcssh` now; IPMI SOL later);
  `SerialConfig.Dial` (the `sshDial` hook in cmd) lets the e2e harness redirect TEST-NET addresses.
- WebSocket protocol (subprotocol `oob-serial.v1`): binary messages are terminal bytes both ways (browser
  messages ≤ 4 KiB). Text messages are JSON: browser → app `{"type":"resize","cols","rows"}`, `{"type":"break"}`,
  `{"type":"quit"}` only, decoded strictly (unknown fields, unknown types, trailing data, > 256 bytes or sizes
  outside 1–10000 end the session with reason `protocol`); app → browser `connected`, `error` (with the class) and
  `end` (with the reason). **The quit key 0x1c is stripped from typed input** (counted as `dropped_bytes`): only
  the toolbar's quit control sends it, and the app closes the SSH session right after, so a user can never detach
  from `console com2` into the iDRAC's racadm shell.
- Idle = no keystrokes or break from the browser (BMC output does not count). End reasons as §18 plus `quit`.
  `console.serial.stop` params: `reason`, `duration_s`, `bytes_to_browser`, `bytes_to_bmc`, `dropped_bytes`,
  `breaks`; failed connects are `result: error` with the class. Refusals are `console.serial.start` denied with
  `in_use`, `cooldown`, `no_credential`, `no_host_key`, `unsupported`.
- The pumps use a context detached from the session's, so the final `end` message still reaches the browser
  after a takeover or timeout; coder/websocket closes the connection when a Read's context is cancelled.
- No periodic probe (an SSH login would count against the BMC's session table and lockout); the card uses the
  outcome of the last connection attempt (`SerialStatus.Last`).

### IPMI SOL (task 4.3): deferred

`go-ipmi` is not in go.mod and no vetted pure-Go IPMI SOL implementation is present; adding one is a new
dependency (rule 10) for a path no configured server uses (both iDRACs use `bmcssh`). The seam is
`console.SerialOpener` / `SerialLink` (Read, Write, Resize, Break, Quit, Close); a SOL implementation must also
follow rule 7 (RMCP+ cipher 17/3 only). Until then `serial: sol` shows "Not supported yet".

### Authorization

- `console.serial` is now **admin + step-up** (was operator, no step-up), and new `console.serial.takeover` is
  admin + step-up: a serial console reaches the BIOS, the boot loader and an OS login, which is physical access
  like the graphical console. The operator role description in Settings changed accordingly. Tokens never.
- Starts and takeovers share the console rate limit (10/min/user) with the graphical console.

### UI (`web/ui/serial*.go`, templates `serial.html`, `console_partials.html` "serialcard", `static/serial.js`, `serial.css`)

- Routes: `GET /servers/{id}/serial` (page), `POST /servers/{id}/serial` (ticket; `takeover=1`; 200 `no-store`),
  `GET /servers/{id}/serial/ws?ticket=` (same upgrade checks as §18: cookie 401, role + fresh step-up 403,
  Origin, then deadlines cleared and a 5 KiB read limit). `sessionWatchdog(token, action)` replaces
  `consoleWatchdog` and serves both consoles.
- Card (server page and Operations tab, Serial tab in the server tabs): Ready / In use (Take over) / Needs setup
  (operator login missing, host key missing, login rejected, host key mismatch, no common algorithms, console
  refused; with the setup steps) / Not supported (BMC reports no serial console, or `sol`) / Not checked yet.
  Warnings: legacy SSH quirk on, last attempt unreachable, and always the "blank console means the host does not
  use COM2" hint.
- Page: toolbar (role `toolbar`): live status, Send break, Send Ctrl-\ (end console), Copy (selection or the
  whole transcript), A−/A+ (10–28 px, kept in localStorage behind try/catch), Disconnect. xterm.js runs with
  `screenReaderMode: true`; a **plain-text transcript** (`<pre role="log" aria-live="off">`, ANSI sequences
  stripped, last 200 000 characters) sits below it with an "Announce new output" switch (sets `aria-live` to
  polite). Ctrl+Alt+Shift returns focus to the toolbar (WCAG 2.1.2). If no byte arrives within 8 s of connecting,
  a hint explains BIOS serial redirection and `console=ttyS1,115200n8`.
- **CSP:** unchanged (`style-src 'self'`). xterm.js's DOM renderer injects `<style>` elements (theme colors,
  font size, cell layout); the browser blocks them and logs CSP violations. `serial.css` therefore carries the
  same rules statically: layout, cursor, selection and the full default 256-color palette (generated once with a
  script from xterm's defaults). Font size and family go through a CSS variable set via the CSSOM, which CSP
  allows. Truecolor (24-bit SGR) text uses `setAttribute('style')`, which CSP blocks: it renders in the default
  color. The sourcemap comments in the vendored files point at maps that are not shipped (a 404 only with
  devtools open).

### Tests and gates

- Unit: bmcssh (exact command and PTY, method set, wrong host key and type mismatch before auth, bad config,
  wrong password, keyboard-interactive, legacy quirk needed/sufficient/minimal, insecure algorithms absent by
  default, resize clamp, break, quit, silent host, handshake timeout, redirect dial, classes); sshtest (refuses
  everything but `console com2`); console serial (echo, controls, quit key stripped, audit rows, ticket replay and
  binding, no cross-use with VNC tickets, one session + takeover, idle, max, watchdog, shutdown, protocol
  violations, browser/BMC close, host key failure, auth cooldown, refusals, audit fail-closed, silent host, legacy
  from config); UI (card states, pages, authz and stale step-up, CSRF, ticket page, takeover, errors, WebSocket
  and refusals, vendored assets, palette CSS); cmd (`buildSerial` warnings).
- `make e2e-go`: R730XD (idrac8, legacy-only fake) echo, resize, break and quit through a real `wss://` upgrade;
  operator password never on the socket; replayed ticket opens nothing; R240 silent host; audit rows
  `console.serial.start/stop` at shutdown.
- Playwright: open the card → Connect → type into xterm.js → the fake's echo appears in the transcript and the
  keystrokes reach the fake (loopback debug endpoint `/ssh`) → break → A+ → Send Ctrl-\ → "Console ended" →
  Reconnect; silent R240 shows the hint; axe WCAG 2.2 AA before and after connecting and on the silent page, plus
  `/servers/r730xd/serial` in `pages.spec.ts` (both widths and schemes). Screenshot `test-results/serial.png`.
- Coverage: bmcssh 86.3 %, sshtest 85.9 %, console 91.3 %, ui 92.4 %, authz 100 %, total 92.1 %.

### Open (needs hardware)

- Not run against a real iDRAC (mocks only). To confirm on iDRAC9 7.00 and iDRAC8 2.86: `exec "console com2"`
  works without a shell and the channel closes when the console ends; the privilege an account needs for
  `console com2` (IPMI SOL "minimum privilege" is Administrator on the target servers; the operator account may
  be refused, which the card reports as "refused"); whether iDRAC8 needs more than `ssh-rsa` +
  `diffie-hellman-group14-sha1` (for example `aes128-cbc`); whether the iDRAC honours the RFC 4335 `break`
  request; whether `window-change` has any effect (the host's serial getty never learns the size).
- Host side: BIOS serial redirection is off on the target servers, so a real session will connect and stay blank
  until the host steps in deploy/README.md are done (decision 6: at the next planned reboot).
- `console_sessions` (schema 0001) is still unused; the audit trail carries the session data.
- Integrated with P2/P3 (§23): the Operations tab has no "Not yet" banner; the serial card is live when
  `Deps.Serial` is wired.

## 23. Implementation notes (P2 + P3 + P4 integration)

Branch `ops-integration` merges `p2-power`, `p3-fans` and `p4-serial` (in that order) onto main.

### Merge resolutions (union, never one side)

- Mock BMC (`redfishmock`): power simulation, the fan floor attributes and the KVM action are all
  options of one server; the write router accepts the three exceptions (Reset POST, MinimumFanSpeed
  PATCH, GetKVMSession POST) and nothing else.
- `serve`: `buildFeatures` builds the graphical and serial consoles, power and fans; fan reconciliation
  runs until serve returns; `runServer` takes `consoleDeps` (it shuts down the VNC and serial brokers)
  plus the power service's `Shutdown` hook, before `app.stop` is recorded.
- e2e: both mock iDRACs simulate power; the R240 also has the fan floor and KVM launch; both have a
  pinned fake SSH console; the R730XD uses `host-lease`. The login/logout check counts native console
  launches, power resets and fan floor logins. Audit coverage asserts every power, fan and serial event.
- security.md: §3c power, §3d serial; power threats renumbered S8/T7 (S7/T6 are the serial ones);
  one `oob_op` row in §4 with the iDRAC bitmask and the `console com2` caveat.

### Semantics reconciled

- Operations tab: Power, Fan lease and Serial console are all live. A service the installation did not
  wire (only possible in tests) says "Not set up in this installation."; nothing says "in this version".
  The server page's Fans action links to the fan card; inventory capabilities say per server whether the
  action is offered, needs an operator login, is off (`fan.mode: none`) or is not set up.
- Credentials (config validation, `operatorFeatures`): `credentials.operator` is required by
  `fan.mode` redfish-floor / ipmi-oem, any `console.serial` other than none, and `console.graphical:
  kvm-launch`, and the error names each feature. host-lease and VNC do not need it (VNC needs only
  `credentials.vnc`). Power control is optional: without an operator login its actions are disabled
  with that reason.
- AuthZ: `TestMatrixCoversEveryAction` and `TestRequiresStepUp` cover every action (power, fan, serial included). Step-up: every action that starts something dangerous needs a
  fresh step-up (power, fan lease create, consoles, takeovers); ending a lease does not (FR-14).
- One confirm implementation: power and the fan lease use `confirm.html` + `confirmStepUp`; consoles
  use the `/stepup` page, which now names "Open the serial console · <server>".
- Audit: action names are the authz names (`power.*`, `fan.lease.create|end`, `console.serial`), with
  lifecycle events `fan.lease.applied|reapply|expire` and `console.serial.start|stop|takeover`. Every
  server-scoped refusal (fan, consoles, power) now records `server_id`. GELF ships the same rows.
- deploy/README.md: one "Enabling …" section per feature and a single "BMC account privileges per
  feature" table.

## 24. Implementation notes (S2 General settings, display preferences and themes)

Branch `s2-general`. Implements settings_design.md §6 "S2" with the §8 decisions, plus the maintainer's
display requests: a display time zone (app default and per user), per-user display preferences and
color themes.

### Source of truth and precedence (`internal/config`, `internal/settings`)

- New file keys: `poll.stale_multiplier` (default 3), `ratelimit.login_ip_per_min` (5),
  `ratelimit.login_acct_per_hour` (10), `ui.time_zone` (`UTC`), `ui.theme` (`graphite`) and
  `settings.locked` (any of `general`, `servers`, `integrations`). `Config.FileKeys` records which
  General keys are actually written in the file (read from the YAML node tree before defaults), so
  "set in the file" is distinguishable from "defaulted".
- **One validator** for the file and the browser: `config.ValidateGeneral(General, min_interval)`
  with the design's safe ranges: poll 30 s–10 min (≥ `min_interval`), stale multiplier 2–10,
  session idle 5 min–2 h, session max 1–24 h and ≥ idle, step-up window 1–5 min (S2 shipped a
  1 s floor for an e2e test; S3 restored 1 min, see §25), login per IP 1–10/min,
  login per account 3–20/h, a canonical IANA zone (or UTC) and a known theme. **Breaking for
  existing files:** the step-up window maximum drops from 15 to 5 minutes.
- `settings.Resolve(file, rows, rev)`: file > DB > default per key. A DB row for a key the file sets
  is ignored ("shadowed by config.yaml"); a row that does not decode, or that combined with the rest
  fails the validator, is ignored and logged at startup, so a bad row can never stop the app.
  `Effective` (a value) carries the General values, the revision, the section lock and one `Field`
  per key (form value, source, who saved it when). `Provider` publishes it through an
  `atomic.Pointer`; readers call `Current()` per use.
- `Service.UpdateGeneral(actor, rev, form)`: only submitted keys are considered (disabled inputs are
  not sent); an unchanged value is fine, a changed file-managed key or any change in a locked section
  is `ErrLocked`; the merged values go through `ValidateGeneral`; nothing changed writes nothing. In
  one transaction: upsert the changed rows, `BumpRev(rev)` (compare-and-set → `ErrConflict` = 409),
  the audit row (`admin.general.update`, params `{"target":"general","rev":n,"changes":[{"field",
  "before","after"}]}` with units, e.g. `30 min → 45 min`), then the re-read settings are published
  after commit. Locked and conflict refusals are audited as `denied` with class `locked`/`conflict`.
- `Diff(keys, before, after, public)` redacts every field not on the section's allow-list (fail
  closed). All General keys are public; S3 will pass its own list for server/credential fields.
- Migration **`0005_settings.sql`**: `settings_kv` (key CHECK list includes the S4 GELF keys so S4
  needs no table rebuild; `value_json` CHECK `json_valid`), `settings_rev` (single row, starts at 0)
  and `user_prefs` (one row per user; NULL = use the default; CHECKs on the closed sets).

### Live vs restart

| Key | Applies |
|---|---|
| `poll.interval` | **after a restart** (pollers read it once; S3's `fleet.Apply` can make it live). The page lists saved-but-not-running keys. |
| `poll.stale_multiplier` | live: `fleet.Config.StaleMultiplier` is read on every view (UI and API `stale` flag) |
| `auth.session_idle`, `auth.session_max`, `auth.stepup_window` | live: `auth.Config.Policy` is read on every check; the janitor uses it too; existing sessions follow the new limits |
| `ratelimit.login_*` | live: the login limiters read their rate per attempt and keep their buckets (no fresh allowance) |
| `ui.time_zone`, `ui.theme`, `ui.clock_format`, `ui.date_format`, `ui.temperature_unit`, `ui.density` | live (next page) |

The UI CSRF token lifetime is the 24 h maximum session when Settings is wired (tokens stay bound to
the session, which carries the real limit).

### UI

- **Settings → General** (`/settings/general`, authz `admin.general.view`; POST through `change()`
  with `admin.general.manage`: session, CSRF, role, the 5-minute step-up window — a fresh login
  counts — and 10 changes/min). Each field shows its unit, bounds, help and source ("Default.",
  "Saved by alice on …", or a **Managed by config.yaml** lock badge with the file key; such inputs
  are disabled text). A locked section shows a notice and no Save button. Errors: 422 with the
  validator's message and `aria-invalid` on the field, 403 for a locked key, 409 "changed elsewhere".
- **Display preferences** (`/preferences`, authz `user.prefs`: every role, sessions only, no
  step-up; CSRF form `display`; the per-user change limit; audited `user.prefs.update`, invalid input
  audited `denied/invalid`). Reached by clicking the top bar clock (a plain link, so it works without
  JavaScript), from the account menu and the phone Menu sheet. Fields: time zone (`<select>` with
  "App default (…)" first, then optgroups per region, UTC first; every canonical IANA zone, 312 from
  tzdata 2026d), color theme (radio cards with a live swatch per theme: status badges, a table row,
  a warning row, a button, a field, a focus ring, a link), date format (ISO `2026-10-21` / US
  `10/21/2026`), clock (24 h / 12 h), temperature (°C / °F) and table density (compact /
  comfortable). Choosing a built-in default stores "default", so later default changes reach the user.
- **Per-request view.** `requireSession` resolves `display.View` (zone, theme, formats, unit,
  density) for the user; signed-out pages use the app defaults. Every server-rendered time goes
  through `timeFmt` (`full`, `clockOf`, `short`) in that zone with its abbreviation (EDT/EST/JST…):
  top bar clock, "page generated", events and logs, audit, users/sessions/tokens, step-up and lease
  end times, power and console sessions, inventory probes. `<time datetime>` stays RFC 3339 UTC;
  relative times are unchanged. There is no JavaScript clock (the clock is the page generation time),
  so nothing needs the zone in a data attribute.
- **Temperature unit.** Readings and thresholds are converted before meters are built
  (`tempUnit.convert`), the "close to warning" band scales (5 °C = 9 °F), and the units in the fleet
  and temperature table headers, the status panel and the sidebar follow the user.
- `time/tzdata` is embedded by `internal/display` (stdlib; the image is distroless). Zone names are
  validated against the curated list *and* `time.LoadLocation`; links (`US/Eastern`), abbreviations,
  `Local` and paths are refused. `TestEveryZoneLoads` checks the list against the embedded tzdata.

### Themes (`static/themes.css`)

- Six palettes, each with dark and light variants over the direction B tokens: **Graphite** (the
  default, identical to `app.css`), **High contrast** (black/white, text ≥ 7:1, `--focus-w: 4px`),
  **Solarized**, **Nord**, **Dracula** (Alucard in light mode) and **Color-blind safe** (Okabe-Ito:
  OK blue, warning orange, critical vermillion, at different lightness; glyphs unchanged, so status
  never relies on color alone).
- `<html data-palette="…">` is server-rendered from the user's choice or the app default (no flash,
  no JavaScript, CSP unchanged: no inline styles). Mode stays separate (System / Dark / Light, the
  existing cookie). The selectors also match any element with `data-palette`, which is how the
  Display page previews each theme. Density is `<html data-density>`.
- `TestThemeContrast` parses `themes.css` and checks, per palette and mode: text and muted ≥ 4.5:1
  (7:1 for High contrast) on page, card and inset; links and every status color ≥ 4.5:1 on those and
  on each status background; field borders and the focus ring ≥ 3:1; on-accent and on-danger ≥ 4.5:1;
  the focus ring at least 1.5:1 from the warning color; both copies of each light block identical.
  `TestGraphiteMatchesBaseTokens` keeps Graphite equal to `app.css`.

### Tests and gates

- Unit: `display` (zones, themes, prefs, resolve), `config` (defaults, file keys, bounds, shared
  validator), `store` (settings rows, rev CAS, prefs), `settings` (precedence, shadowing, locked
  section, refusals, no-op, audit params, pending restart, redacting Diff), `auth` (live policy),
  `fleet` (live stale multiplier), `authz` (S2 rows in the matrix), UI (General page sources/locks,
  live apply + audit, refusals 422/403/409/400, locked section, step-up and viewer refusals, no
  backend → 404, live login limit, user override wins with US dates/12 h/°F/Dracula/comfortable,
  invalid zone and CSRF, no step-up for preferences, sign-in page uses the app theme, audit sentences).
- e2e (Go): the stack's config sets `ratelimit.login_acct_per_hour`; `checkGeneral` sees it locked,
  is refused for it (403) and for `US/Eastern` (422), sets America/New_York (clock in EDT/EST), and the
  enrolled viewer sets Asia/Tokyo + Nord for themselves only (JST), while the admin keeps Eastern.
- Playwright: `pages.spec.ts` adds Settings → General and Display preferences to the axe matrix
  (1440/390 × dark/light); `themes.spec.ts` runs axe on Overview, Server and Display for every palette
  × scheme with JavaScript disabled, follows the clock link, checks the own zone and the UTC
  `datetime`, and posts an unknown zone (422).

### Open

- The step-up window maximum is now 5 minutes (was 15): a config.yaml with a longer window fails
  validation at startup.
- Poll interval changes need a restart until S3's `fleet.Apply`.
- "Reset to default" for a saved key is not offered (set the default value instead; the row stays,
  source "Saved by …").

## 25. Implementation notes (S3 Servers)

Branch `s3-servers`. Implements settings_design.md §6 "S3" with the §8 decisions (5-minute step-up
window, credentials not bound to the TLS pin, IP literals only, no section locked by default), plus three S2
follow-ups and a request.

### S2 follow-ups and a request

- **Step-up window floor back to 1 min.** `config.MinStepUpWindow` is 1 minute again (design range
  1–5 min) for config.yaml and Settings. Tests shorten the window through `env.stepUpWindow` in
  `cmd/oob-manager`, a test hook `main` never sets and no config key reaches (the e2e power step-up
  check uses 2 s through `startStackStepUp`).
- **Reset to default.** Each General field saved from the browser has a "Reset to default" button
  (a `formaction` on the General form, no JavaScript): `settings.Service.ResetGeneral` deletes the
  row, bumps the revision (compare-and-set) and writes `admin.general.reset` (before → after) in one
  transaction; file-managed keys and locked sections answer 403, stale revisions 409.
- **App-wide display defaults** (request): `ui.clock_format` (24h|12h), `ui.date_format`
  (iso|us), `ui.temperature_unit` (c|f) and `ui.density` (compact|comfortable) join the General
  keys with the same precedence as `ui.time_zone`/`ui.theme` (file > DB > built-in default, lock
  badge, audited, step-up). `display.Resolve(user, app Prefs)` applies user > app > built-in, so
  the sign-in page uses the app defaults. The Display page offers "App default (…)" first for every
  format, naming the current default; choosing it stores nothing. Migration
  **`0007_display_defaults.sql`** rebuilds `settings_kv` with the longer key CHECK.
- deploy/README "BMC account privileges per feature" lists the operator account bitmasks (iDRAC8
  `oob_op` 0x31, iDRAC9 `oob_kvm` 0x33).

### Data and packages

- Migration **`0006_servers.sql`**: `servers` (CHECKs on every closed set, `rev` for compare-and-set
  edits, `cred_seq` that only grows) and `bmc_credentials` (one AES-GCM blob per server and slot,
  `ON DELETE CASCADE`). Both STRICT; unix ms.
- **`config`**: `bmc.port` (443, ipmi 623, or 1024–65535) and `BMCConfig.Endpoint()` (the drivers,
  the power, fan and launch endpoints and the BMC link honour it); `settings.bmc_networks` (default
  the private ranges; `/0` refused); `servers` may be empty (an empty fleet is ready); `Normalise`
  and `ValidateServer` are exported so browser servers pass exactly the file rules. The id pattern
  stays the file's `^[a-z0-9][a-z0-9-]{0,31}$` (stricter than the design's).
- **`netpolicy.CheckBMCAddr`**: canonical IP literal only (rejects `127.1`, `0x7f.1`, `2130706433`,
  `010.0.0.1`, upper-case or expanded IPv6, zones, IPv4-mapped IPv6), never loopback, unspecified,
  multicast, link-local (incl. `169.254.169.254`), broadcast or the app's own addresses (every
  local interface address plus a literal listen or `public_url` address), and inside
  `settings.bmc_networks`. 100 % covered by a hostile table.
- **`secrets/credstore`**: AES-256-GCM, key `DeriveKey(PurposeBMCCred)` (`oob-console/bmc-cred/v1`),
  AAD `bmc-cred/v1|server_id|slot|kind|address|port|version` (`|` refused in the fields). Tests: a
  moved address, port, kind, slot swap, row swap or old version is undecryptable; tampering and
  another key fail; no plaintext in the blob.
- **`tofu`**: `FetchTLS` completes one handshake and closes (the test server sees zero HTTP
  requests); RSA key exchange can be offered for an iDRAC8 VNC port. `FetchSSHHostKey` aborts in the
  host key callback (no auth attempt, tested with the fake BMC SSH). 5 s dial and handshake bounds;
  class-only errors. `Prover` signs `ts.HMAC(DeriveKey(PurposeTOFU), session‖purpose‖kind‖addr‖port‖value‖ts)`
  (length-prefixed parts), valid 0–5 min; the purpose is the confirming form's path, so a proof
  from Add server cannot confirm another server's pin. Certificate fields shown to the admin are
  stripped of control and bidi characters and truncated to 200 characters.
- **`registry`** (the "effective server registry" of rule 3): `Resolve(file, rows, creds, policy)`
  lists file servers, then DB rows by id; a DB row with a file id is **shadowed** (ignored, warned,
  audited `settings.shadowed` once per start, deletable). A DB row that fails `ValidateServer` or the
  address policy, or lacks a credential its features need, gets `Problems` and does not run.
  `Service` changes rows in one transaction with the audit row (`admin.server.create|update|pin|
  credential|enable|disable|delete|import`, params `{"target":"server:<id>","rev":n,"changes":[…]}`;
  credentials appear only as `"[redacted] v3" → "[redacted] v4"`), compare-and-set on the row
  `rev`, then publishes and signals `Changes()`. Rules: new servers start disabled with no
  features; a draft must pass the validator as if every credential were stored; an enabled server
  must stay complete; a connection change requires the new pin, deletes the credentials, clears the
  VNC pin and host key and disables the server; a pin change keeps the credentials (decision 2);
  fan and connection changes are refused while a fan lease is active (checked **before** the
  transaction: the store has one connection, and a check inside it hung the e2e run).

### Hot apply

- **`fleet.Apply`**: an immutable roster behind an `atomic.Pointer` (lock-free readers). Targets
  carry a fingerprint (cmd: SHA-256 over the server's JSON, endpoint, login and interval; never
  logged); an unchanged one keeps its poller and state (name and tags update in place, the new
  driver is closed unused); a changed or removed one is stopped and its driver closed (Redfish
  session deleted) before replacements start. A pin mismatch sets `PinMismatch`/`Paused` and the
  poller waits for a new target instead of retrying.
- `console.Service`/`SerialService.SetTargets` swap target maps; a console on a changed or removed
  server ends with audit reason `config_changed`. `power.Service.SetTargets` stops a removed
  server's verification (`config_changed`) and keeps cooldowns of servers that stay.
  `fan.Service.SetTargets` **restores leases first**: a changed or removed server's lease is
  released through its old applier and closed (`fan.lease.end` by system, reason `config_changed`;
  a failed release still closes it and is audited as an error); per-server mutexes are replaced so
  work that waited on an old one is refused. The service now starts empty and gets its setup through
  `SetTargets`, so startup does not release leases.
- **`serverRuntime`** (cmd) builds every target from the active registry entries and re-applies on
  each registry or General settings change: fans, consoles, power, launcher, links, then the
  fleet. **`poll.interval` is now live** (S2 listed it as "after a restart"): the settings
  provider signals changes, and the pollers are rebuilt with the new interval. Browser credentials are
  opened at build time into in-memory refs `db/<id>/<slot>` (age-file refs cannot contain `/`).
  A failed apply is retried every 30 s. On disable or removal the fan service releases an active
  lease through the applier it already holds (built with the old credentials), so deleting the
  stored credentials first does not strand the lease.

### Test connection, CLI

- **Test connection** runs in the background (bounded by the cycle timeout + 30 s; the page
  refreshes): Redfish service root, system and manager (product, Redfish version, model, firmware),
  the kind they suggest (13G → idrac8, later → idrac9, else redfish; a mismatch fails the step),
  reset actions, license, iDRAC9 fan floor limits (read with the read-only login), VNC banner over
  the pinned connection, SSH host key compared with the confirmed one. Only GETs plus the session
  login/logout that polling also does (asserted against the mock). Audited `admin.server.test`.
- `oob-manager settings import -servers id1,id2` copies file servers into the DB enabled, re-sealing
  their credentials from the age file, all in one transaction, and prints what to remove from
  config.yaml; file-only tuning (`bmc.auth`, timeouts, VNC TLS and quirks) is reported as dropped.
  `oob-manager settings export` prints the effective General values and running servers as
  config.yaml keys without secrets (DB credentials named `<id>-<slot>`); it reads back strictly.

### UI (`/settings/servers`, direction B)

- List: status (Shadowed, Disabled, Needs setup, Certificate changed, Unreachable, Polling, Waiting),
  kind, BMC, source (lock badge for config.yaml), last test; warnings. The Settings tab
  "Servers (coming)" became a link (the only nav change).
- Add server: step 1 form → `POST /settings/servers/fingerprint` (address policy before any dial)
  → confirm page (200, `no-store`, proof) → `POST /settings/servers`. A pasted pin skips the fetch
  (audited `pin_via: manual`).
- Server page: stepper; sections Connection (identity form; move = fetch + confirm), Fingerprints
  (HTTPS, VNC when graphical is VNC, SSH when serial is bmcssh; fetch-and-confirm or paste), the
  "Certificate changed" and "SSH host key changed" alerts with a fetch button, Credentials per slot
  (status, Store/Replace, `autocomplete=new-password`, never echoed), Features, Test connection,
  Review (Enable; Disable and Remove through the confirm interstitial with the typed name / id).
  File servers render read-only; Test connection works for them.
- AuthZ `admin.servers.view` / `admin.servers.manage` (step-up). Mutations use `change()` (10/min
  per user); fingerprint fetches and tests use the new `probe()` (session, CSRF, admin, step-up)
  with their own 6/min limits, so a quick wizard is not throttled by its own fetches.

### Tests and gates

- Unit/integration: netpolicy hostile table, credstore AAD binding, tofu (zero HTTP requests,
  blackhole timeout, plain TCP `not_tls`, RSA-kex VNC, no SSH auth), store rows and CHECKs,
  registry (flow, refusals, shadowing, move, lease, conflict, import/export, no secrets in audit or
  DB), fleet Apply (keep/change/remove, pin pause, race with readers, no leaked goroutines),
  console/serial/power/fan SetTargets (incl. a fan race test), cmd runtime hot-apply race, prober
  against the mocks, CLI import/export, UI handlers (TOFU flow, refusals, rate limit, file server
  read-only, typed removal, audit sentences).
- e2e (Go): a third mock, reachable only through the harness dialer, is added in the browser,
  polled without a restart, tested, moved and removed; no BMC password in the log, DB file or audit.
- Playwright: `servers.spec.ts` (the same flow in Chromium, axe on every step in both schemes);
  the page matrix adds the Servers pages at 1440/390.
- Coverage: registry 89 %, netpolicy 100 %, credstore 88 %, tofu 92 %, fleet 97.5 %, fan 91 %,
  console 91 %, power 99.6 %, ui 89.7 %, cmd 86.7 %.

### Open

- The registry id pattern stays the file's (no `_`, ≤ 32 chars), not the design's.
- SSH host keys of type `ssh-rsa` are accepted (iDRAC8 has no other); the design asked for
  ed25519/ECDSA only.
- A paused server (certificate changed) never retries on its own; config.yaml servers need a
  restart with the new pin.
- Test connection logs in (a Redfish session, like polling): "nothing written" means no settings.
- Losing the app keys loses browser-stored credentials (as it loses TOTP enrolments); `key_id`
  `v1` leaves room for re-sealing later.
- `cred_seq` restarts if a server is deleted and re-created with the same id.
- Inside a bridge container the host's own LAN address is not a local interface: an admin could
  add the Docker host (or another LAN service inside `settings.bmc_networks`) as a "BMC" and send
  it the read-only login on Test connection. Narrowing `bmc_networks` to the BMC subnet closes it;
  denying listed addresses explicitly would need a new setting.
- A fan lease started between the lease check and a connection or fan change is not refused
  (the check runs before the transaction because the store has a single connection).
- Security review of this slice (2026-10-21): no critical or high findings; the medium and low
  ones are fixed (committed binary, local interfaces, proof purpose, certificate text, apply
  retry) or listed here.

## 26. Implementation notes (notifications)

Branch `notifications`. Implements research item F1 (`oob-console-research/2026-10-21-feature-research.md`)
with the decision: BMC log text off by default, per-target opt-in. No new dependency: stdlib
`net/http`, `net/smtp`, `mime/quotedprintable`, `crypto/hmac` (rule 10). Operator guide: deploy/README.md
"Notifications"; threats: security.md S9, I8, I9, D6, R3 and §3e.

### Package `internal/notify`

- **Event** (value): closed `Class` (`health`, `reachability`, `sel`, `psu`, `fan`, `power`, `console`,
  `auth`, `audit`, `trust`, `notify`; `test` for Send test only), `Severity` info < warning < critical,
  `Recovery` (carries the severity of the problem it resolves, so it passes the same filters), a dedupe
  `Key`, title/message without BMC text, optional `Detail` (BMC text, dropped unless the target has
  `IncludeDetail`).
- **Detector** (`detect.go`, `detect_logs.go`): owned by the service goroutine; every 15 s it reads
  `fleet.Reader.Servers()` (atomic loads, no BMC call) and diffs per server. A `tracker` debounces a signal
  (`notifications.debounce`, default 90 s ≈ two polls) against a healthy baseline, so a problem present at
  start is reported once and a one-poll blip never. Signals: health verdict = worst of the rollup and every
  temperature, fan and PSU health (Unknown ignored); unreachable = stale after the stale threshold (a server
  never polled is not judged; one that never had a snapshot counts from `FailingSince`); trust = last error
  class `tls` (pin mismatch) and resolved; PSU redundancy = healthy PSUs < the most PSUs ever seen (≥ 2), so
  a pulled PSU stays "lost"; logs = SEL and Lifecycle entries unseen by ID or newer than the newest seen
  (a cleared log restarts IDs), first read = baseline, one event per refresh with the count and the worst
  severity. Health/PSU/logs are only judged on a current snapshot.
- **Tap** (`tap.go`): implements `audit.Sink`, so it sees every audit record after it is written:
  `power.*` started/ok/error, `fan.lease.create|end|expire` and any fan error, `console.vnc.start` and
  `console.serial.start` (started), `console.kvm_launch`, takeovers, `auth.*` denials (`*_locked_out` →
  lockout; 5 `password`/`totp` denials in 10 min → failed sign-ins; 15 min cooldown each, no account names),
  `admin.audit.verify` error `tampered` (critical). The startup verification sets `core.chainBroken`, sent
  once the service exists. `TrustEvent(server, name, what, resolved, now)` is the **TOFU hook for S3**
  (`what` = "TLS certificate" or "SSH host key"); call `Service.Emit(notify.TrustEvent(...))`.
- **Dispatcher** (`dispatch.go`): one worker and one bounded queue (64) per target, so order is kept per
  target and a dead receiver blocks nobody; token bucket per target (10, then 1/30 s); 4 attempts with
  exponential backoff 2 s → 60 s for retryable classes (dns, timeout, network, 429, 5xx, SMTP 4xx); a
  message that fails all attempts counts as a failure; 3 in a row make the target **failing**: the service
  emits a `notify` event to every other target (`ExcludeTarget`) and the Overview shows a banner; a success
  clears it with a recovery. Status (last success/failure, error class, sent, dropped) is in memory.
  `SendNow` (Send test) is one synchronous attempt, outside the queue and rate limit.
- **Wire formats** (`kinds.go`, `email.go`, golden files in `internal/notify/testdata/golden/`): ntfy POST
  to the topic URL, text body, headers `Title`, `Priority` 3/4/5 (recovery and test 3), `Tags`, optional
  Bearer token; Pushover form POST (`token`, `user`, `title` ≤ 250, `message` ≤ 1024, `priority` −1/0/1,
  emergency 2 with `retry=300&expire=3600` only with the opt-in, `timestamp`); Gotify JSON to
  `<base>/message` with `X-Gotify-Key`, priority 2/5/8; webhook JSON v1 (`WebhookPayload`) with
  `X-OOB-Event`, `X-OOB-Delivery`, `X-OOB-Timestamp` and optional `X-OOB-Signature: sha256=HMAC(secret,
  ts + "." + body)`; email RFC 5322, UTF-8 quoted-printable, Q-encoded subject, `Auto-Submitted`. Control
  characters in titles and BMC text become spaces (no header or line injection).
- **Transport** (`transport.go`, `policy.go`): a one-shot `http.Client` per send with `Proxy: nil`, no
  keep-alive, `CheckRedirect` → `ErrUseLastResponse` (3xx = `redirect` failure), 10 s timeout, response
  headers ≤ 16 KiB, body read to 4 KiB and discarded. Its `DialContext` resolves the host through
  `Policy.resolve` and dials `ip:port`; TLS still verifies the URL's host name. Policy: allowlisted CIDR →
  ok; otherwise public unicast only (refuses loopback, RFC 1918, link-local incl. 169.254.169.254, CGNAT,
  ULA, multicast, documentation, benchmarking, 240/4, NAT64, 6to4, zoned and IPv4-mapped forms); plaintext
  only to the allowlist; any disallowed answer of a host name refuses the whole name. SMTP dials the same
  way; STARTTLS is required when selected, AUTH only over TLS (`PlainAuth` refuses plaintext anyway).
  Errors carry a class only; the receiver's response text is never kept.
- **Secrets** (`seal.go`): `AppKeys.DeriveKey("oob-console/notify/v1")`, AES-256-GCM, AAD
  `notify/v1|id|kind|url`. Update keeps blank fields, but a changed URL never carries the old secrets
  (they would not open anyway): required ones must be entered again; optional ones can be removed.
  `secret_version` counts changes; the audit shows `[redacted] vN`.
- **Service** (`service.go`, `service_change.go`): registry (file targets first, then DB rows; a DB row
  with a file id is shadowed and flagged) published through `atomic.Pointer`, rebuilt after every change.
  Changes run in one transaction with `audit.RecordTx`: `admin.notify.create|update|delete`, plus
  `admin.notify.test` (ok or error + class) and `server.notify.mute|unmute`. Params: target id, kind,
  name, host and `changes[{field,before,after}]`; a destination change is recorded as host only
  ("(path or query changed)" on the same host). Validation errors (`ErrInvalid`) are not audited;
  `ErrLocked` refusals are. Mute: `notify_mutes.muted_until` per server, ≤ 7 days, suppresses
  `Class.Mutable()` classes only (health, reachability, sel, psu).

### Storage, config, authz

- Migration **`0008_notifications.sql`** (written as `0007` on this branch; renumbered at the v0.5
  integration, §27, because S3 took 0006 and 0007): `notify_targets` (CHECKs on id shape, kind enum, JSON
  validity) and `notify_mutes`.
- Config (file-only): `notifications.allowed_networks` (CIDRs or IPs), `notifications.debounce` (0–30 min),
  `notifications.targets[]` (`id`, `name`, `kind`, `url`, `secret_ref`, `enabled`, `allow_plaintext`,
  `include_detail`, `classes`, `min_severity`, `pushover_emergency`, `email{from,to,security}`). Secrets
  from the age credential file: password = token/HMAC key; Pushover username = user key, password = app
  token; email username/password = SMTP AUTH. `settings.locked: [integrations]` locks browser targets.
- Authz: `admin.notifications.view` (admin), `admin.notifications.manage` (admin, step-up),
  `server.notify.mute` (operator, no step-up: it cannot mute security classes; CSRF, 10 changes/min, audited).

### UI and wiring

- `/settings/notifications` (list with status, Send test, Edit, Delete…, add-target kind chooser),
  `/settings/notifications/new?kind=…` and `/settings/notifications/{id}` (per-kind form; secret inputs are
  `type=password`, never pre-filled; "Secret set · vN"), POST `…/{id}/test` (3/min/user),
  GET/POST `…/{id}/delete` (confirm interstitial), POST `/servers/{id}/mute` (closed durations 1 h–7 d or
  `off`). Server pages show a Notifications card (muted until …; the form for operators); Overview shows a
  banner while a target is failing (linked for admins). A Settings tab was added (order settled in §27).
- `cmd/oob-manager/notify.go`: `buildNotify` after the fleet; `core.init` derives the key and installs the
  audit sink as GELF ⊕ a late-bound tap (`lateTap`), so audit wiring is unchanged when notifications are
  idle. `serve` runs `Service.Run` with the other background loops.

### Tests

- Unit: golden wire files per kind (`go test ./internal/notify -update` rewrites them), priority table,
  SSRF table (hostile literals, rebinding answer, single lookup + dial of the checked IP, private receiver
  without allowlist, http without opt-in, plaintext outside the allowlist, redirect not followed, 4 MiB
  body capped, TLS failure), seal binding, retries/backoff timing, permanent failures, failing/recovery
  transitions, rate limit and queue bound, debounce/dedupe/recovery per signal, log baseline and cleared
  logs, tap mapping and cooldowns, service CRUD with secrets absent from audit, log and DB plaintext,
  mute scope, self-alert routing. Fake SMTP server (`smtp_fake_test.go`): STARTTLS + AUTH, implicit TLS,
  missing STARTTLS refused before AUTH, 4xx/5xx classes, header injection.
- Integration (`integration_test.go`): real poller + Dell Redfish driver against `redfishmock` (new runtime
  `SetOverlay`/`SetDown`): health Critical → recovered and BMC down → recovered each reach a webhook once.
- UI: add/edit/test/delete, invalid input (422, secret not echoed), email/Pushover forms, file target lock,
  operator/viewer refusals, stale step-up, mute/unmute and the banner, pages hidden without the service.
- e2e (Go): the stack gets a signed file webhook on a local receiver; the main flow's power and console
  actions reach it; a second stack drives Send test, add/test/delete, mute/unmute and checks the audit and
  that the secret is in neither the log nor a page. Playwright: four new pages in the axe matrix and
  `notify.spec.ts` (test, wizard error, add, edit without secret, delete, mute) at 1440 and 390 px.

### Open

- To turn it on: create a target in Settings → Notifications (or `config.yaml`). Pushover needs an
  application token and the user key; ntfy a long random topic URL (plus a token if protected); Gotify the
  server URL and an app token; email an SMTP server with STARTTLS/TLS, sender, recipients and optionally a
  login; a LAN receiver also needs its address in `notifications.allowed_networks`.
- Maintenance mode (F2) can build on `notify_mutes`; delivery status is not persisted across restarts.
- The S3 hooks (TrustEvent, server sync, migration order) are wired in §27.

## 27. Implementation notes (v0.5 integration)

Branch `v05-integration` from `main`: merges `s3-servers` (§25), then `notifications` (§26), as a union
(both features complete), plus the cross-feature hooks each branch left open.

### Merge decisions

- **Migrations.** S3 owns `0006_servers.sql` and `0007_display_defaults.sql`; the notifications migration
  (written as `0007_notifications.sql`) is now **`0008_notifications.sql`**. No install had applied it
  (production v0.4.0 is at 0005). `store.TestUpgradeFromProductionSchema` builds a database with the
  0001–0005 migrations, seeds a user, a session, an audit row, saved settings, the settings revision and
  display preferences, opens it with the current binary and checks: schema 8, every row intact, the new
  tables present, the rebuilt `settings_kv` accepts the S3 display keys, `audit_log` still append-only.
  `TestMigrationVersionsAreDense` pins 1…8 with `0008_notifications.sql` last.
- **Settings nav** (one `settingstabs` partial): Users, API tokens, General, Servers, Notifications, Audit
  log. About stays a top-level page (it is not a setting). The "Servers (coming)" placeholder is gone.
- **AuthZ**: `admin.servers.view|manage` and `admin.notifications.view|manage` are admin; both `manage`
  actions need step-up; `server.notify.mute` stays operator without step-up.
- **UI name clashes**: notify's per-user Send-test limiter is `notifyLimit` (S3 keeps `testLimit` for
  Test connection, `fpLimit` for fingerprint fetches); notify's `kindOption(s)` became
  `notifyKindOption(s)`, its mute redirect `backToServerPage` (S3's `backToServer` is the Settings page).
- **cmd**: notifications are built after `newRuntime`, over the runtime's live `fleet.Fleet`, so the
  detector always reads the current roster.

### Cross-feature hooks

- **Trust events.** The poller's pin mismatch sets `PinMismatch`/`Paused`; the detector's trust signal
  now keys on `PinMismatch` (and, as before, `LastError == tls`) → `TrustEvent(id, name, "TLS certificate")`.
  Confirming a new pin replaces the target; the first good poll resolves it. Outside polling,
  `notify.Tap.Trust(server, what, ok)` takes the S3 checks: Test connection's VNC banner (`ProbePin`) and
  SSH host key comparison (`cmd/oob-manager/prober.go`, through `lateTap.Trust`), and console stops in the
  audit trail (`console.serial.stop` error `host_key` → "SSH host key", `console.vnc.stop` error `tls_pin`
  → "VNC certificate"). A mismatch is critical, once per check per 15 minutes; a later success resolves
  only an open mismatch (no stray recoveries). Constants `notify.TrustTLS|TrustVNC|TrustSSHKey`.
- **Servers added/removed in the browser.** After every successful apply (and once at startup)
  `serverRuntime.syncNotify` hands every registry id (file and DB, enabled or not) to
  `notify.Service.SyncServers` and `Tap.Keep`. Mutes of ids that no longer exist are deleted in one
  transaction with `server.notify.unmute` by `system`, params `{"reason":"server_removed"}`, so a server
  re-created with the same id is not silently muted; trust cooldowns of removed servers are dropped.
  The detector drops the state of any server that leaves the fleet (`Detector.forgetExcept`): a
  **disabled** server is not polled, raises no reachability/health/PSU/log events, and starts from the
  healthy baseline when re-enabled. A disabled server keeps its mute.
- **Sealed secrets.** Both use AES-256-GCM under HKDF-SHA256 subkeys of the app keys, one purpose each,
  all defined in `internal/secrets`: `oob-console/bmc-cred/v1` (credstore, AAD
  `bmc-cred/v1|server|slot|kind|address|port|version`) and `oob-console/notify/v1` (notify, AAD
  `notify/v1|id|kind|url`); `notify.PurposeNotify` aliases `secrets.PurposeNotify`. Tests: the four
  derived keys (CSRF, BMC credentials, TOFU, notifications) are pairwise distinct and none is the master;
  even under one key a notification blob never opens as a BMC credential or the reverse (different AAD
  domains). No key or purpose is reused.
- **`settings.locked`.** `servers` locks the registry (`registry.Effective.Locked`), `integrations` the
  notification targets (`notify.Service.Locked`); `TestSettingsLockedCoversServersAndIntegrations` loads a
  config with both and checks each section refuses changes. Mutes stay available when `integrations` is
  locked (an operator action, as in §26).

### Docs

- deploy/README: one **Settings in the browser** section (tabs, precedence, the `settings.locked` table,
  `settings.bmc_networks` guidance, sealed secrets), with General, Servers and Notifications under it.
  The generic text says to narrow `bmc_networks` to the subnet or range the BMCs live in, excluding the
  app's own host and other LAN services (§25 Open: inside a bridge container the Docker host is not a
  local address). For example, two BMCs at
  192.0.2.70 and 192.0.2.72 fit `settings.bmc_networks: [192.0.2.48/28]`, which leaves out a Docker host at
  192.0.2.20.

### Gates (2026-10-21)

gofmt clean; `go vet ./...` and `-tags e2e`; golangci-lint v2.14.0 0 issues (also with `--build-tags e2e`);
`make check` (total 91.3 %, every package ≥ 80 %, lowest `console/rfbtest` 84.8 %); `make noexec`;
`make e2e` (Go e2e and 9 Playwright specs); `go test -race -count=3 -shuffle=on ./...`.

### Open

- Servers already in config.yaml stay file-managed; narrow `bmc_networks` before adding any BMC from the
  browser.
- A trust mismatch found only by the periodic VNC banner probe (not a console connect or Test
  connection) is shown on the server page but not notified.

## 28. Implementation notes (maintenance mode, notes, acknowledgements)

Branch `maintenance`. Implements roadmap item R2 (research F2, plus the UX-04 part 2 "Acknowledge" the
UX audit deferred). No new dependency (rule 10). Operator guide: deploy/README "Notifications"; threats:
security.md R3 and §3e.

### Package `internal/maint`

- One service, three kinds of state, each change one transaction with its audit row
  (`audit.RecordTx`), then an immutable state reloaded and published through `atomic.Pointer`
  (lock-free reads for every page view, the API and the notification router).
- **Maintenance windows.** At most one per server, active or scheduled. `Start(actor, server,
  {Reason, Duration, StartsAt})`: reason one line, 1–200 characters; duration 0 ("until ended") or
  5 min–7 days; start now or up to 30 days ahead; a second window is `ErrExists` (an expired one that
  `Run` has not closed yet is closed first). `End` ends it now (`reason: ended`) or cancels a
  scheduled one (`cancelled`). `Run` (every 15 s) sends "started" when a scheduled window begins and
  closes expired windows as `system` (`expired`); `SyncServers` (called by the runtime after every
  registry change, like the old mute sync) closes the windows of removed servers as `system`
  (`server_removed`); a disabled server keeps its window. Audit: `server.maintenance.start`
  (`reason`, `until` RFC 3339 or "until ended", `minutes`, `starts` when scheduled) and
  `server.maintenance.end` (`reason`, `window_reason`). Rows are deleted when a window ends; the
  audit log is the history.
- **Notes.** Plain text: CRLF → LF, trimmed, valid UTF-8, no control characters except newline and
  tab, ≤ 4096 bytes (CHECK on the byte length too), ≤ 100 per server. Authors edit their own; authors
  delete their own and admins delete any (checked in the service by user id and role, not only by
  the UI); any note writer pins any note (one pin per server, partial unique index). Audit
  `server.note.add|edit|delete|pin` with the note id, byte lengths and author, **never the text**
  (a note may hold anything that was pasted, and the audit is shipped off the box). An unchanged edit
  writes nothing.
- **Acknowledgements.** An entry is `EventRef{server, log (sel|lifecycle), BMC entry id, BMC
  timestamp}`; the timestamp is stored as unix ms (0 when the BMC sent none), so a cleared log that
  reuses an id is a different entry and a new entry of the same kind is never covered by an old ack.
  `Ack(actor, server, refs, comment)` (1–500 refs of one server, comment one line ≤ 500 bytes,
  re-acking replaces comment and acknowledger) and `Unack`. Audit `server.event.ack|unack` with the
  count, up to 20 `log:id` entries and the comment. Acks older than 400 days are pruned daily.

### Storage

Migration **`0009_maintenance.sql`**: `server_maintenance` (one row per server, `ends_at` NULL = until
ended, CHECK `ends_at > starts_at`, `started_notified`), `server_notes` (+ `server_notes_one_pin`
partial unique index), `event_acks` (primary key server, log, entry id, created ms). Every active
`notify_mutes` row becomes a window ending at the same time, already notified, with the reason
"Notifications muted (before maintenance mode)"; expired mutes are dropped; `notify_mutes` is
dropped. `TestMutesBecomeMaintenanceWindows` upgrades a schema-8 database with an active and an
expired mute; `TestMigrationVersionsAreDense` and `TestUpgradeFromProductionSchema` now expect 9.

### Notifications

- The per-server mute is gone from `notify` (`Mute`, `MutedUntil`, `SyncServers`, the store
  methods). `notify.Config.Suppress` takes a `notify.Suppressor` (`InMaintenance`, `Acked`),
  implemented by `*maint.Service`. `route` drops `Class.Mutable()` events (health, reachability,
  sel, psu) of a server with an active window; every other class, and app-wide events, always go
  out (`TestMaintenanceSuppressionMatrix` checks every class × in maintenance / not / no server).
- The detector leaves acknowledged entries out of new-log-entry events (`Detector.acked`).
- New class **`maintenance`**: `notify.MaintenanceEvent` builds "<server>: maintenance started"
  (until, who, reason) and "… maintenance ended" (`recovery: true`, "expired" or "ended by …"),
  severity warning but normal priority on every kind (`Event.quiet`, ntfy tag `wrench`). It is not
  subscribable; `Target.Wants` sends it to every enabled target subscribed to at least one class
  maintenance suppresses (and passing its minimum severity), so existing targets get it without an
  edit. Webhook receivers see `class: "maintenance"` (additive).
- When "ended" is routed the detector forgets that server (`Detector.Forget`): a problem that is
  still present is reported again once after the debounce, and logs are baselined again, so
  entries written during the window are not sent afterwards (`TestMaintenanceEndForgetsServer`).
- cmd: `attachNotify` builds maint first (it is the notifications' Suppressor), then the
  notifications, and binds maint's `Emit` late (`lateEmit`); the runtime syncs the registry to
  maint. `serve` runs `maint.Run` with the other background loops.

### Authz, UI, API

- Authz: `server.maintenance`, `server.notes.write`, `server.event.ack` are operator, no step-up
  (they pause or annotate, never act on a BMC), sessions only; `server.notes.moderate` (delete any
  note) is admin. `server.notify.mute` is removed. Routes go through `annotate()`: session, CSRF,
  role, every refusal audited, and a per-user limit of 30 changes/min (separate from the Settings
  limit of 10/min, since acknowledging entries one at a time is normal work).
- Routes: `POST /servers/{id}/maintenance`, `…/maintenance/end`, `…/notes`, `…/notes/pin`
  (`note=<id>|0`), `…/notes/{nid}`, `…/notes/{nid}/delete`, `…/acks` (`ref` repeated, `comment`,
  `back` = a local path), `…/acks/remove`. A ref is `<log>|<unix ms>|<entry id>`; every ref must
  name a warning or critical entry present in the server's cached log (else 400), so nothing
  outside the poller's copy can be acknowledged.
- Fleet verdict: `fleetCounts.Maintenance`; a server in an active window is counted there only
  (never as critical, warning, stale or OK). Pill: "2 OK · 1 in maintenance" (`gp-maint`, glyph ‖,
  "maint." on phones with the full text for screen readers) or "1 critical · 1 in maintenance".
  Overview: its sensor and event problems move to an "In maintenance" panel (badge, reason, who,
  until; not counted in the strip or Needs attention); the healthy line says "All other servers
  healthy · N in maintenance". Sidebar: ‖ after the name (full badge text in `title` and for screen
  readers). Server pages: the badge under the heading on every tab; the Maintenance panel replaces
  the Notifications (mute) panel; the pinned note is shown above the verdict.
- Notes are rendered through `html/template` only: `linkify` splits the text into text and link
  segments (`http(s)://` matched, re-parsed with `url.Parse`, trailing punctuation dropped), links get
  `rel="noopener noreferrer" target="_blank"`, newlines are kept by CSS `white-space: pre-wrap`.
  Tests post `<script>`, `<img onerror>` and `javascript:` text and check the escaped output.
- Events and Logs: an "Acknowledged" column with "Acked by X at T: comment" and Un-acknowledge, or a
  `<details>` Acknowledge form with an optional comment; "Acknowledge all N shown" on a server's
  Logs page and on Events filtered to one server. Acknowledged entries leave Needs attention, the
  Overview event counts and the nav count; the feed still lists them.
- API (additive): `/api/v1/servers` and `/servers/{id}` carry `maintenance` (null, or
  `{active, starts_at, ends_at (null = until ended), reason, by}`); `/servers/{id}` carries `acks`
  (`[{log, entry_id, created, by, at, comment}]`, newest first, `[]` when none); each event of
  `/servers/{id}/events` carries `ack: {by, at, comment}` when acknowledged.

### Tests and gates

- Unit: store (rows, CHECKs, pin index, byte cap, prune, mute migration), maint (lifecycle,
  persistence, expiry, scheduled start, cancel, replace an expired window, validation, removed
  servers, no DB, Run; notes ownership/admin/pin/no text in audit/validation/cap; acks identity,
  re-ack, unack, validation, prune), notify (suppression matrix, maintenance routing and priority,
  acked entries, forget after the window), authz matrix, UI (maintenance form and refusals, custom
  end in the user's zone, schedule, Overview group and pill, notes XSS and ownership, acks single
  and bulk, refusals, open-redirect `back`), API (fields with and without the service).
- e2e (Go, `checkMaintenance` in the notifications stack): start → badge, Overview group, API
  window, "started" webhook; note added and pinned (escaped, safe link); every critical SEL entry
  acknowledged at once, visible in the UI and the API; end → "ended" webhook; all audited.
- Playwright `maint.spec.ts`: the same flow with axe at 1440 and 390 px (both schemes are covered by
  the page matrix and the theme spec, which include the new server-page panels). The e2e config's
  `login_acct_per_hour` is now 20 (the specs sign the admin in more than ten times within the hour).
- Gates (2026-10-21): gofmt clean; `go vet ./...` and `-tags e2e`; golangci-lint v2.14.0 0 issues (also
  `--build-tags e2e`); `make check` (total 91.4 %; maint 90.4 %, notify 93.4 %, ui 90.1 %, api 98.5 %,
  store 90.5 %, authz 100 %, cmd 86.9 %); `make noexec`; `make e2e` (Go e2e + 10 Playwright specs);
  `go test -race -count=3 -shuffle=on ./...`.

### Open

- "Until I end it" windows never expire (the research suggested a 7-day cap for every window); the
  badge stays visible everywhere and the start message says so. **Decided in §30:** they stay
  open-ended, with an Overview warning after 24 h and a daily reminder.
- Notes and acks of a removed server are kept (they suppress nothing); a server re-created with the
  same id shows them again.
- The per-user "seen up to" marker (UX-04) is still not built.
- `server.notes.moderate` is enforced in the service by role; it only exists in authz so the UI can
  decide whether to show Delete on other people's notes.

## 29. Implementation notes (Prometheus metrics)

Roadmap R3 (research F3). `GET /metrics`, off by default.

### Shape

- **`internal/metrics`** (no dependency). `Write` renders `[]Family` in the text exposition format 0.0.4
  (`# HELP`/`# TYPE`, label escaping of `\`, `"` and line feed, `NaN`/`+Inf`/`-Inf`, shortest `'g'` floats).
  `allSpecs()` is the single ordered list of families, and a test checks names, uniqueness and that
  counters and only counters end in `_total`. A per-scrape `builder` sanitizes label values
  (`SanitizeLabelValue`: invalid UTF-8 → U+FFFD, control characters removed, trimmed, 64-byte cap on a
  rune boundary), drops duplicate label sets and undeclared families, caps each family at 4096 series and
  reports everything left out in `oob_scrape_series_dropped`. It is discarded after the render.
- **`Collector`** takes a `Config` of read-only sources: `fleet.Reader` (required), and optional function
  hooks for fan state, console activity, notification targets, the GELF shipper, the startup audit chain
  result, the `LoginCounter`, the maintenance hook and build info. A nil source leaves its families out
  (maintenance reads 0). `Render` is serialised behind a mutex and reuses the bytes for `CacheFor` (1 s).
  `ServeHTTP` sets `text/plain; version=0.0.4; charset=utf-8` and `Cache-Control: no-store`. OpenMetrics
  negotiation was left out (optional in the brief): Prometheus scrapes 0.0.4 by default.
- **No BMC calls.** Everything comes from the poller's published snapshots, `fan.Service.Status` (a lease
  table read plus, for host-lease, the ack file; both never contact a BMC), `console.Service.Status` /
  `SerialService.Status` (broker state), `notify.Service.Targets` (dispatcher state) and atomics.
  `TestScrapeNeverCallsTheBMC` runs a real `fleet.Fleet` with a counting driver: 50 scrapes add no call.
  The e2e test checks the same on the mock BMCs' request logs (a burst overlapping a background poll is
  retried, up to 3 times).
- **Freshness.** Sensor, fan, PSU, voltage and power values are left out while the server is stale (or has
  no snapshot), and health / power state read `unknown`. Timestamps, poll duration and data age stay, so
  dashboards can show how old the last good data is. The health verdict is the worst of the BMC rollup and
  every temperature, fan and PSU health, the same rule as the notification detector.
- **Caps.** 64 items per per-server list (temperatures, fans, PSUs, voltages), 64 notification targets
  (enabled ones only), 4096 series per family. Series keys are the BMC member ID (`sensor`, `fan`, `psu`),
  or the name when the BMC sends no ID; `name` carries the display name.

### Auth model (decision)

- `/metrics` lives in `internal/api` (`metricsRoute`): method (GET/HEAD) → `allow_networks` (TCP peer from
  `RemoteAddr`, IPv4-mapped addresses unmapped, no forwarding headers; checked **before** the token) → the
  existing `protected` chain (bearer token, `authz.ViewFleet`, the token's 60/min bucket). Without a
  collector the route answers 404 Problem Details.
- **Read tokens are reused; there is no `metrics` scope yet.** A new scope needs migration 0001's
  `CHECK (scope = 'read')` relaxed, which this slice avoids (the maintenance branch owns 0009). Read tokens
  already cannot reach operator or admin actions. The deploy docs tell users to mint a dedicated
  `prometheus` token. A metrics-only scope (which could not read `/api/v1` and its SEL text) is a small
  follow-up: a migration, `auth.ScopeMetrics`, `Verify` accepting it only for `/metrics`, `token create
  --scope metrics`.
- No authz action was added: reusing `fleet.view` keeps the matrix (and the maintenance branch's edits to it)
  untouched.

### Config (`config.MetricsConfig`, file-only)

`metrics: { enabled: false, allow_networks: [], include_inventory: false }`. `allow_networks` entries are
validated like `notifications.allowed_networks` (IP or CIDR, no zone); `Networks()` returns masked prefixes,
single IPs as /32 or /128. Unknown keys fail the load (strict YAML), as everywhere.

### Wiring and shared-file edits

- `cmd/oob-manager/metrics.go`: `buildMetrics` (nil when disabled) and the adapters, and `buildAPI` (moved out
  of `buildHandler` to keep it under 50 lines). `serve.go` mounts `api.PathMetrics` on the API handler.
- `core.go`: `c.logins` (`metrics.LoginCounter`), passed as `auth.Config.OnFailure`, a new optional hook
  called from `Authenticator.fail` for each failed password or TOTP stage (`TestOnFailureHook`).
- `oob_audit_chain_ok` reads `core.chainBroken` (startup verification; not re-run per scrape).
- `oob_server_maintenance` is a hook (`Config.Maintenance`), nil for now. When the maintenance branch lands,
  pass its "is server in maintenance" lookup there. (Done in §30.)

### Tests

Golden scrape (`testdata/scrape.golden`, `-update` to rewrite) over a healthy, a stale and a never-polled
server with hostile names; a strict independent line parser over every sample line; escaping and
sanitizing; family caps, per-server caps and the target cap with exact dropped counts; identifiers absent
unless `include_inventory`; optional sources left out; the render cache; HEAD. API: disabled 404; no token,
wrong token and a session cookie → 401 with a challenge; invalid principal → 403; addresses outside
`allow_networks` → 403 without the token verifier being called; POST 405; 429 with `Retry-After`. e2e:
enabled through config.yaml, token scrape with real mock data, 401 for no token and for a signed-in admin's
cookie, no `serial=` labels, POST 405, no BMC requests during scrapes.

### Gates (2026-10-21)

gofmt clean; `go vet ./...` and `-tags e2e`; golangci-lint v2.14.0 0 issues; `make check` (total 91.2 %,
every package ≥ 80 %, `internal/metrics` 98.2 %); `make noexec`; `make e2e`; `go test -race -count=3
-shuffle=on ./...`.

### Open

- Enabling it is a config change plus a token (`deploy/README.md` "Prometheus metrics").
- Follow-ups: a `metrics` token scope (migration), the maintenance hook once that branch merges, optional
  OpenMetrics.

## 30. Implementation notes (v0.6 integration)

Branch `v06-integration`: `maintenance` (§28, R2) merged first, then `metrics` (§29, R3), then the
items below. No new dependency (rule 10).

### Merge

- Conflicts resolved as a union: `api.Deps` carries both `Maintenance` and `Metrics`/`MetricsNetworks`;
  `buildAPI` (cmd, from the metrics branch) passes both, and `buildHandler` calls it.
- security.md: the maintenance wording of **R3** is kept (the metrics branch still had the mute text).
  The table had two **I8** rows (notifications' secrets, then S3's DB credentials, which reused the
  number); the older notifications row keeps I8, DB credentials become **I10**, and the metrics
  disclosure threat (I10 on its branch) is **I11**; D7 was free. settings_design.md's reference was
  updated. Every threat ID is now unique.

### Metrics ↔ maintenance

- `metrics.Config.Maintenance` is now `func(id) MaintenanceState{Active, Until}` and a new
  `Config.Acked` hook takes the same arguments as `notify.Suppressor.Acked`. cmd's `maintMetrics`
  adapts `*maint.Service` (`Active`, `Acked`: lock-free reads of its published state; no BMC, no DB).
- New families: `oob_server_maintenance_until_timestamp_seconds` (end of the active window; 0 when
  none or "until ended") and `oob_events_unacknowledged{server, severity=warning|critical}` (entries of
  both cached logs not acknowledged, keyed by log, BMC id and BMC timestamp exactly like the UI; left out
  for a server with no cached log). Without the hooks nobody is in maintenance and every entry counts.
- **Health stays real in maintenance** (decision): `oob_server_health`, sensors and `oob_log_entries`
  are not masked, because the data is true and dashboards may want it. Overview's rule (a server in
  maintenance is counted only as "in maintenance") is reproduced in PromQL with `unless on (server)
  (oob_server_maintenance == 1)`; the HELP text of `oob_server_health` says so and deploy/README
  "Prometheus metrics" gives the queries. `oob_events_unacknowledged` covers the whole cached log, while
  Needs attention shows the last 24 h.
- Tests: `TestMaintenanceAndAckFamilies`, `TestNoMaintenanceOrAckSource`, the golden scrape (a
  lifecycle log, an acked entry, a timed and an open-ended window), `TestMetricsReadMaintenance` (cmd,
  real `maint.Service`), and e2e `checkMetricsMaintenance` (a window started in the UI appears in the
  next scrape with its end time; health is not hidden).

### Open-ended maintenance (decision)

"Until I end it" stays open-ended (no cap). Two guards so it cannot be forgotten:

- **Overview warning.** `maint.Service.OpenEnded()` lists active until-ended windows older than
  `maint.OpenEndedAfter` (24 h), oldest first; Overview shows "Open-ended maintenance: <server> since
  <time> (<by>: <reason>) …" as an `a-warn` status line above the verdict (escaped; servers no longer in
  the fleet left out). `ui.Maintenance` gained `OpenEnded()`.
- **Daily reminder.** `Window.ReminderDueAt`: notified, active, until ended, and 24 h since the start or
  the last reminder. `Tick` sends `notify.MaintenanceEvent{Reminder: true, Since}`: class `maintenance`
  (so `Target.Wants` routes it to the same targets as start/end), severity warning, normal priority,
  not a recovery; "<server>: still in maintenance … since <UTC time> (N days) with no end time".
  Not audited (nothing changed; the start is audited). The start message of an open-ended window now
  says a reminder follows daily.
- **Storage:** migration **`0010_maintenance_reminder.sql`** adds `server_maintenance.reminded_at`
  (unix ms, NULL = none); `MaintRepository.MarkReminded`; `PutWindow` clears it. Persisting it means a
  restart neither repeats nor skips a reminder, and after downtime one reminder goes out, not one per
  missed day. A separate migration rather than an edit of 0009, so a database that ran the maintenance
  branch upgrades too.
- Tests: `TestOpenEndedReminder` (none before 24 h, one per day, none after a restart that follows a
  reminder, one after a 3-day gap, none after End, timed and scheduled windows never), `TestOpenEndedListOrder`,
  `TestMaintenanceReminder` (store), `TestMaintenanceReminderEvent` (text, routing, priority),
  `TestOpenEndedMaintenanceWarning` (UI: not before 24 h, escaped, timed window not listed, gone after End).

### Upgrade from v0.5.0

`TestUpgradeFromV050Schema` builds a schema-0008 database (as deployed in v0.5.0) holding a user, a
session, an audit row, a setting, preferences, a browser-managed server with a sealed credential, a
notification target and an active and an expired mute, opens it at head (10) and checks every row,
the active mute as a notified window with no reminder yet, the expired one and `notify_mutes` gone,
the reminder column writable and the audit log still append-only. The 0005 → head test and the dense
version test now expect 10.

### Repository hygiene

`cmd/oob-console/oob-console` (a 36 MB build output, already in `.gitignore`) was tracked by
accident; it is untracked (`git rm --cached`). `git ls-files` has no other file over 1 MB and no
ELF/Mach-O binary. The public repository starts from a fresh history cut from a release tree
(`scripts/public-cut.sh`), so the blob was never published.

### Gates (2026-10-21)

gofmt clean; `go vet ./...` and `-tags e2e`; golangci-lint v2.14.0 0 issues (also `--build-tags e2e`);
`make check` (total 91.5 %, every package ≥ 80 %: maint 90.4 %, metrics 98.4 %, notify 93.4 %, store
90.6 %, ui 90.2 %, api 98.6 %, cmd 85.7 %); `make noexec`; `make e2e` (Go e2e + 10 Playwright specs);
`go test -race -count=3 -shuffle=on ./...`.

### Open

- A `metrics` token scope (§29) is still a follow-up; it would now be migration 0012 (0011 is the security checks, §31).
- Reminders go to targets subscribed to a suppressed class; there is no per-target opt-out of them
  beyond unsubscribing from those classes.

## 31. Implementation notes (BMC security checks)

Roadmap R5 (research item 5). A read-only security review of every Redfish BMC: a **Security** tab per
server, a Security column in the fleet tables (Overview, Servers), notification class `security` and two
metric families. No new dependency (rule 10). Migration **0011**, which ships first in 0.7.0: no released
database has run an earlier form of it (v0.6.0 is at 0010; e2e and dev databases are temporary), which is
why the review's column additions were made in place rather than as a 0012.

### Decisions

- **Read-only, no new BMC privileges.** The checks read what `credentials.readonly` can read. When the BMC
  refuses a resource (401/403) the check says "Can't read … with the read-only account" (result
  `cant-read`); it never asks for more privileges (research decision). Whether a ReadOnly account may read
  AccountService and the Dell attribute documents is **untested on hardware**, so every resource is
  optional and each section records its own read state (`ok`, `absent`, `forbidden`, `failed` with an error
  class, `skipped` with a reason, not tried).
- **The transport allowlist did not grow (rule 12).** The Redfish part runs on the poller's own driver and
  session (D4): GETs only, plus the login that driver already has. New `redfish.Driver.ReadOptional` is a
  GET whose 401/403 is final (no re-login), so a privilege refusal cannot churn the BMC's session table.
  A run (`postureRun`) in Basic auth mode stops its optional reads at the first 401/403 (every request
  carries the password, and a BMC may count each refusal as a failed login): the sections after it are
  `skipped` with the reason, and the Dell driver passes a refused attribute document on
  (`PostureOptions.Refused`) so the generic part reads nothing either. The Dell driver calls
  `Driver.Warm` (one normal Manager GET, which may log in again) before its ReadOptional of the attribute
  document, so an expired session never reads as "forbidden".
- **Probes outside the transport** (`internal/secprobe`) reach only the configured BMC address, on the
  configured Redfish port, the configured VNC port (graphical console `vnc` over TLS), the serial console's
  SSH port (else the port the BMC reports, else 22) and the HTTP port the BMC reports (else 80). They send
  no credentials and no application data: TLS handshakes; the SSH banner and KEXINIT, then close (never
  authentication); `HEAD /` on the plain HTTP port (`GET` only if HEAD is refused with 405/501), no
  redirect followed; `HEAD /wsman` plus `HEAD` of a control path, only over a TLS connection that matched
  the pin. A service the BMC reports off is not probed. The VNC port gets the identity handshake only
  (`TLSTarget.IdentityOnly`: its certificate is all the checks use; the version and suite checks apply to
  the web port) and is skipped while a graphical console session is open (the BMC takes one VNC client);
  `TLSTarget.Abort` is asked before every further handshake and stops the scan with a reason when a
  console opens meanwhile (`TLSProbe.Partial`).
  An iDRAC8's VNC port is never opened (`VNCTarget.NotProbed`, set from the kind): its single-client VNC
  server stays busy for minutes after a connection ends, so a probe would lock the console out, and it
  collided with the console's own banner probe, which runs on the same 6-hour tier (fw 2.86, 2026-10-22:
  handshakes on 5901 hung for 35 s after one had completed, while 443 answered in under a second). Its
  `tls.vnc_cert` is then info, "Not checked" with that reason (the port presents the web certificate), and
  an SSH or HTTP port the BMC reports on that VNC port is not probed either. TLS variants are spaced by `Options.ProbeGap` (150 ms); a
  variant is refused only on a peer TLS alert that means refusal: protocol_version (70), handshake_failure
  (40) or insufficient_security (71) (`*net.OpError` with `Op == "remote error"`, told by the alert text that
  `tls.AlertError` of the same number produces); any other alert (internal_error), a reset, EOF or timeout
  leaves it unknown; if the version the identity handshake negotiated is not accepted by its
  own variant, every variant is unknown (`Partial` says why), so the evaluator never passes a port that
  drops connections. The plain-HTTP probe reports a closed port only on a connection refused
  (`HTTPProbe.Refused`); any other failure is unknown. Each probe connection ends when its context does.
  The TLS results are tied to the BMC by the SPKI pin; the SSH and plain-HTTP results are not: they are
  unauthenticated reads of whatever answers on those ports, and their evidence says so.
- **No IPMI, SNMP or Telnet packets.** IPMI cipher suite 0 is not readable over Redfish on iDRACs, so
  `svc.ipmi_cipher0` is `unknown` (the `IPMICipherZero` fact and its fail path exist for a future reader).
  SNMP versions and Telnet come from Redfish and the Dell attributes only.
- **Evaluated at read time.** The fleet keeps the last posture (facts with their source, and probe results);
  `bmcsec.Evaluate(server, posture, inputs, now)` is pure and runs on each page view, scrape and watch pass,
  so expiry countdowns stay current and a catalog change needs no new BMC read.

### Packages

| Package | Adds |
|---|---|
| `internal/bmc` | `Posture`, `Fact[T]{Known, Value, Source}`, `Section` read states, `PostureReader`, probe result types |
| `internal/bmc/textclean` | `Clean(s, n)`: the one sanitizer every BMC string passes through (the Redfish and Dell readers, the probes): invalid UTF-8, Cc, Cf (zero-width characters, bidirectional overrides, BOM), Zl and Zp removed, trimmed, capped on a rune boundary. `GraphicASCII` tells the account evidence when to show a name in quoted-ASCII form |
| `internal/bmc/redfish` | `ReadOptional`; posture readers: ManagerNetworkProtocol, AccountService and its accounts (at most 16 member GETs), the manager clock (app time read just before and after), BMC firmware release date, BIOS version, licences |
| `internal/bmc/dellredfish` | Dell attributes from `<manager>/Attributes` (iDRAC8) or `<manager>/Oem/Dell/DellAttributes/<id>` (iDRAC9). Only an allowlist is decoded (`attrKeep`: IPMI LAN, Telnet, SSH, web server, SNMP, VNC, NTP, syslog, IPv4 DHCP, IPv6, IP blocking, `Users.N.{UserName,Enable,Privilege,IpmiLanPrivilege,SolEnable}`); the IPMI encryption key, community strings and password hashes are dropped while decoding and never stored. Strings go through `textclean.Clean` (invalid UTF-8, control and format characters, line separators removed) and are capped at 64 bytes. Accounts come from the attributes when AccountService is refused |
| `internal/secprobe` | `ScanTLS` (an identity handshake with the app's own settings, then 7 variants: TLS 1.0, 1.1, 1.2 and 1.3 alone; RC4/3DES, RSA key exchange and ECDHE suites alone; identity-only for the VNC port), `ScanSSH` (banner and KEXINIT; one packet of at most 35 000 bytes, RFC 4253 §6.1; each name-list capped at 1 KiB), `CheckHTTP`, `CheckWSMan`. A `readOnlyTransport` refuses every method but HEAD and GET before a byte is sent |
| `internal/bmcsec` | The catalog (31 checks), `Evaluate`, `Collector` (the Redfish read, then the probes), `Service` (acceptances, re-runs, the watch loop and its notifications) |
| `internal/fleet` | The posture tier (below), `RequestPosture` |
| `internal/store` | `0011_security_checks.sql`: `security_accepts` and `security_notified` |
| `internal/notify` | Class `security`: `SecurityEvent`, `CertExpiryEvent` |
| `internal/metrics` | `oob_security_checks{server,result}`, `oob_tls_cert_expiry_timestamp_seconds{server,port}` |
| `internal/web/ui` | The Security tab, the fleet column, the accept / remove / re-run handlers |

### Check catalog

Each check has an ID, title, why it matters, what to do (generic, plus a Dell iDRAC hint where it helps)
and an optional reference link. Results: `pass`, `info`, `warn`, `fail`, `unknown`, `cant-read`. A check
that does not apply is left out (`tls.vnc_cert` needs the VNC console over TLS; `ssh.algorithms` needs an
SSH probe).

| Group | Check | Warn / fail when |
|---|---|---|
| TLS and SSH | `tls.cert_expiry` | warn < 30 days; fail expired or not yet valid |
| | `tls.cert_issuer` | warn self-signed factory default (CN `idrac…`, OU Remote Access Group, or "default"); other self-signed is info |
| | `tls.cert_key` | fail RSA < 2048, ECDSA < 256 or MD5; warn SHA-1 |
| | `tls.protocols` | warn TLS 1.0 or 1.1 accepted (also shows the BMC's own TLS setting and whether 1.3 is offered) |
| | `tls.ciphers` | warn RC4/3DES, or only RSA key exchange at TLS 1.2; RSA key exchange offered next to ECDHE is info |
| | `tls.vnc_cert` | info when the VNC port presents the web certificate (one certificate: the web checks and reminders cover it), and info "Not checked" on an iDRAC8, whose VNC port is never opened; unknown when the port could not be read this run (a timeout or an open console session); else the worse of expiry and key for the VNC port |
| | `ssh.algorithms` | warn when a class (key exchange, host key, cipher, MAC) offers only weak algorithms (`ssh-rsa`, SHA-1 KEX/MACs, CBC, 3DES); weak next to strong is info; MACs ignored when every cipher is AEAD |
| Services | `svc.ipmi` | warn IPMI over LAN on (RAKP hash disclosure, CVE-2013-4786); shows the channel privilege limit |
| | `svc.ipmi_cipher0` | fail if readable and accepted; unknown on iDRACs |
| | `svc.snmp` | warn agent on with v1/v2c; unknown when the version is not reported |
| | `svc.telnet` | fail on |
| | `svc.http` | warn plain HTTP answers without redirecting to HTTPS (or redirects elsewhere), or the BMC reports its redirect off |
| | `svc.ssh` | info on (notes when the serial console uses it) |
| | `svc.vnc` | warn on without TLS, or with TLS optional (Dell "Auto Negotiate": plain VNC is also accepted); on with TLS required is info |
| | `svc.virtual_media` | info on |
| | `svc.ssdp` | warn on |
| | `svc.wsman` | info when `/wsman` answers differently from the control path (WS-Management on); unknown when both answer the same |
| | `svc.ntp` | warn off, or on with an empty server list; a list the BMC does not report is unknown and passes |
| | `svc.clock` | warn drift > 60 s from the app clock |
| | `svc.syslog` | info off (the BMC's log lives only on the BMC) |
| Accounts | `acct.enabled` | info: enabled accounts with roles, disabled count, source; an account whose state is not reported counts as enabled and is named; a list cut at 16 or with pages not followed is noted. Account subjects are sorted names |
| | `acct.default_names` | warn an enabled `root`, `admin`, `Administrator` or `USERID` (any case); the evidence says passwords cannot be checked |
| | `acct.ipmi_sol` | warn accounts with IPMI LAN access while IPMI over LAN is on; SOL access is listed |
| | `acct.policy` | warn minimum password length < 8, or no lockout and no IP blocking; nothing is concluded while a document that may hold it was refused |
| | `acct.admins` | info: enabled Administrator accounts |
| Firmware | `fw.bmc` | warn older than `security.min_firmware.<kind>` (dotted numeric comparison; unknown when not comparable; info when none is configured); shows the release date when reported |
| | `fw.bios` | info: the version |
| | `fw.license` | warn expired or < 30 days left; trials are info (expired trial still installed too); unknown when not reported |
| Network | `net.ip_filter` | warn Dell IP range filter off; pass with the allowed range |
| | `net.dhcp` | info DHCP |
| | `net.ipv6` | info on |

### Posture tier

`fleet.Target.Posture` (nil: no checks) runs on the poller's goroutine after the snapshot and the other
slow tiers: at start (after the first good poll), every `security.every` and on `RequestPosture`, which
wakes the poller (the snapshot is polled first). Budget: the server's cycle timeout. A failed run keeps the
previous posture, records its error class (shown on the tab) and is retried after min(every, 5 min); it
never trips the breaker. A run also counts as failed when its context ended before the probes were done
(`Collect` returns the context error, so a deadline never leaves a posture with holes) and when a probe
could not reach the BMC (`Posture.TransportFailure`: a probe section failed with a timeout, or unreachable
without a refusal). A refused connection on any probed port (`Refused` on the TLS, SSH and HTTP probes) is
a known closed port, a result; a protocol error is an answer; neither fails the run. The VNC port never
fails a run: it takes one client at a time, so a timeout there is expected while another session holds
it, and the run is kept with `tls.vnc_cert` unknown. The VNC port is not
probed when the BMC reports its VNC server off, whatever the console configuration says. Failed runs back
off: the first retry after the events period (5 min), then double that for each further consecutive
failure, up to the posture period, so a BMC behind a firewall that drops a port is not re-read every few
minutes forever (it keeps its last complete posture; let the port through or turn the service off on the
BMC). `PostureAsOf` is the run's start (`Posture.Started`). A paused server (pin mismatch) refuses re-runs (`ErrPaused`). The state carries
`PostureEnabled`, `Running`, `Requested`, `Overdue`, `AsOf` and `Every`.

### Accepted risks and notifications

- An admin accepts a warn or fail with a comment (1–500 bytes, control characters removed) through
  `annotate()` (session, CSRF, role, 30 changes/min/user, refusals audited): `server.security.accept` with
  check, title, result, subject hash and comment. The form carries `seen` (`Finding.Seen()`: result and
  subject hash as rendered); `Service.Accept` re-evaluates under its write lock and answers `ErrChanged`
  when the finding differs (the UI re-renders the tab with a notice, 409). The acceptance covers exactly
  (check, result, **subject hash**: SHA-256 of the whole subject, a certificate fingerprint, account lists,
  a firmware version…; `subject` is the clipped display copy) and records `server_addr`, the BMC host:port
  from the server's inputs. The binding is enforced where acceptances are applied: `Report` marks a finding
  accepted only when the acceptance's `server_addr` is the address the server has now (and the hash
  matches), so a server moved or re-created under the same ID at another address never inherits one, even
  before the sweep runs or while the sweep cannot delete rows (the audit log down). When the finding is
  resolved or changes, or the server's address differs, the watch pass deletes it, audited as `system`
  (`server.security.unaccept`, reason `resolved`, `changed` or `server changed`); a finding that cannot be
  read right now, or a server the registry has no inputs for, keeps its acceptance. `registry.Delete`
  removes a server's acceptances and notification state in its own transaction; the service reloads its
  in-memory copy at every sweep and after every change attempt (even a failed one), so rows deleted
  elsewhere leave memory within one pass. An accepted finding stays listed with who, when and why, counts
  as "Accepted risk" and is not notified. Admins can remove it (reason `removed`).
- `Service.Run` looks every 15 s (an in-memory evaluation) and sends one message per server whose run
  found new problems: a check that newly warns or fails, got worse, or changed subject. Severity warning
  (every new finding is a warning or a failure, and targets subscribe to "warning and above" by default);
  normal priority; maintenance never pauses it. A finding that turns unknown or can't-read (a probe
  hiccup, a refused read) keeps its notified state, so it is not reported again when it is readable; only
  a pass, an info or a check that no longer applies forgets it. The message names check titles and
  results only (catalog text, never BMC strings). Certificate reminders (HTTPS and VNC) go out 14, 7 and 1
  days before expiry, once per certificate and bucket, none for an accepted finding. `security_notified`
  holds the state (subject **hashes**, not subjects), so a restart neither repeats nor drops a message; a
  server that leaves the fleet is forgotten.
- Re-run: admin, `server.security.rerun`, 5 min cooldown per server reserved before the fleet is asked and
  given back if it refuses (429 with `Retry-After`). Audited fail-closed like a power action: a `started`
  row is written before the fleet is asked (no row, no request: the cooldown is given back and the admin
  sees an error), then one final row, `ok` or `error` with the refusal's class (`paused`, `refused`); a
  cooldown refusal is a `denied` row.

### UI and authz

- `GET /servers/{id}/security` (`server.view`): summary panel (verdict, counts by result, last and next
  run, the run's error class), the Re-run control (a form for admins, a disabled button with its reason
  for an operator, a role note for a viewer), then the groups, problems first. **Findings need `server.security.view` (operator)**: a viewer
  sees only the summary, because the findings describe weaknesses. Each finding: evidence lines, accepted
  note, "Why it matters and what to do" (`<details>`, with the Dell hint and the reference), and for admins
  the accept form (or Remove acceptance).
- `server.security.rerun` and `server.security.accept` are admin; `server.security.accept` (accept and
  remove) also requires a fresh step-up (`authz.RequiresStepUp`; `annotate()` redirects a stale one to
  `/stepup`). `notify.Tap` maps the audit rows: an accept is a `security` warning
  (`security/accept/<server>/<check>`, "Accepted risk: <title> on <server>", who and the comment), an
  unaccept an info event (`security/unaccept/...`, with the reason). The fleet column shows "1 fail · 2
  warn", "OK", "Unknown" (nothing failed or warned, but more than half of the checks could not be evaluated; the
  tab's verdict says the same), "Not checked yet", "Checking now" or "Disabled" (checks off for that server; not "Off", which reads as
  powered off) and links to the tab.

### Config (`config.SecurityConfig`, file-only)

```yaml
security:
  enabled: true        # default; false: no posture tier, no Security tab or column
  every: 6h            # 1h to 168h
  min_firmware:        # "minimum known good" per kind; empty: report the version only
    idrac8: "2.86.86.86"
    idrac9: "7.10.30.00"
    redfish: ""
```

Versions must be dotted numbers (1–6 segments). Unknown keys (an `ipmi` kind, a typo) fail the load. No
version is looked up online.

### Wiring (cmd)

- `serverRuntime.postureFor` binds `bmcsec.Collector.Collect` to each server's `bmcsec.Target` (address,
  port and pin; VNC port, VNC pin and `idrac8_rsa_kex_tls` when the graphical console is VNC over TLS; the
  serial SSH port; the live console state). The target fingerprint already hashes the whole server config,
  so a changed port or pin rebuilds the poller. `securityInputs` (kind, minimum firmware, console set-up) is
  replaced on every registry apply.
- The probes dial through **`env.probeDial`**: `main` sets a `net.Dialer`; nil **refuses every address**, so
  no test (or tool that builds an `env`) can reach the network from a probe. The e2e harness maps the
  TEST-NET addresses to the fakes.
- `buildSecurity` (after the notifications, nil when off) → `consoleDeps.security` → the UI, `/metrics`
  (`securityCounts`) and the background goroutines (`background()`, split out of `runServer`).

### Synthetic fixtures

Written by hand from the Redfish and Dell attribute schemas (not captured from hardware), with TEST-NET
addresses, a documentation MAC, made-up user names and no real serials, service tags or licence IDs:

- `testdata/redfish/idrac8-r730xd/`: `Managers_iDRAC.Embedded.1_AccountService.json`, `…_Accounts.json`,
  `…_Accounts_1.json` … `_4.json`, `Managers_iDRAC.Embedded.1_Attributes.json`.
- `testdata/redfish/idrac9-r240/`: `AccountService.json`, `AccountService_Accounts.json`,
  `AccountService_Accounts_1.json` … `_5.json`, `Managers_iDRAC.Embedded.1_Oem_Dell_DellAttributes_iDRAC.Embedded.1.json`.

The secret-bearing attributes hold `FIXTURE-SECRET-*` markers; tests assert they never reach the posture,
a finding, a page or the log.

### Tests

- Readers: every section's read states with overlays, 401/403 per resource (`ReadOptional`: no re-login,
  no leaked session), the allowlist (markers dropped), hostile strings, the account cap.
- Probes: fake TLS servers per variant (versions, suite groups, pin mismatch, timeouts), fake SSH servers
  (legacy, truncated, oversized, not SSH), HTTP redirect variants, the WS-Man control path, and the
  read-only transport refusing POST.
- Catalog and evaluator: every result branch of every check; `can't read` vs `unknown`; Dell hints only for
  Dell kinds; catalog text rules (no BMC text in titles, why/fix present).
- Service: acceptances (subject binding, expiry as `system`, audit rows), re-run cooldown, notification
  diffing across restarts, cert reminder buckets, forgotten servers. Store: migration 0011 and the upgrade
  test from v0.6 (schema 10).
- **No writes:** `TestCollectReadsRedfishAndProbesOnlyReading` and the cmd test assert the mock saw only
  GET, HEAD and the session login, and the SSH fake no authentication. e2e `checkSecurity` repeats it for
  the whole flow (both mocks, port 80 fake, SSH fakes, VNC fake: the iDRAC8's port never dialled by the
  checks, counted per address because the console reaches the same fake; no VNC authentication)
  and covers the tab, accept and remove, re-run and its 429, the fleet column, `/metrics` and the webhook.
- Playwright: `security.spec.ts` (findings, accept, remove, re-run, fleet link) with axe at 1440 and 390;
  both Security tabs are in the page matrix (both schemes).

### Needs hardware verification

1. ReadOnly access on iDRAC8 2.86 and iDRAC9 7.00 to AccountService, its accounts and the Dell attribute
   documents (the code expects 401/403 and shows "can't read").
2. The Dell attribute names and paths used (`<manager>/Attributes` on iDRAC8, `Oem/Dell/DellAttributes` on
   iDRAC9; `WebServer.1.TLSProtocol`, `IPBlocking.1.*`, `VNCServer.1.SSLEncryptionBitLength`, `Users.N.*`).
3. The factory certificate detection (subject of a real iDRAC default certificate).
4. What `/wsman` answers with no credentials, and that the control path differs.
5. iDRAC8's SSH KEXINIT lists (expected: legacy only, like the console's quirk).
6. Plain HTTP behaviour on port 80 (redirect status and Location).
7. ManagerNetworkProtocol's `DHCP` meaning on each firmware (address assignment vs the DHCP client).
8. Whether firmware inventory reports a `ReleaseDate`.
9. TLS probe variants against iDRAC8's web server (old TLS stacks may drop rather than refuse).

Seen on real hardware with v0.7.0 (iDRAC8 2.86 and iDRAC9 7.00, 2026-10-22):

- Neither iDRAC logged a failed login for any probe: their syslog showed only the poller's own session
  login and logoff (USR0030/USR0032), so the unauthenticated `HEAD /wsman`, SSH banner and TLS handshakes
  are not counted against the IP-blocking threshold.
- iDRAC8: SSH answers `SSH-2.0-OpenSSH_7.4` within 0.5 s; port 80 answers 302; the web port negotiates
  TLS 1.2 with ECDHE in under a second. Its VNC server is single-client and stays busy for minutes after a
  connection ends, hence `NotProbedIDRAC8`. The iDRAC8 does not send VNC session events to syslog; the
  iDRAC9 logs every VNC connection as a short session (USR0150/USR0151).

### Open

- Set `security.min_firmware` to the versions considered good; until then `fw.bmc` is info.
- IPMI cipher 0 stays unknown unless an IPMI probe is added (deliberately not done: no IPMI packets).
- Factory passwords cannot be detected (no login attempts, ever); `acct.default_names` says so.

## 32. Implementation notes (round-2 UX audit fixes)

Branch `audit2-fixes`. Fixes the functional findings of `oob-console-design/2026-10-21-round2/UX-AUDIT-2.md`
(A4, A5, A6, A9). Mocks only; no new dependency (rule 10). One commit per fix.

### Powered-off servers (R2-01)

A host that is not running is its own non-OK state. The sensor rollup is meaningless while it is off,
and "All servers healthy" is never said about a fleet with a server down.

| Power state (fresh data) | Badge (label · class) | Fleet count | Needs attention | Notification (health class) | `oob_server_health` |
|---|---|---|---|---|---|
| On | sensor verdict | as before | as before | as before | sensor verdict |
| Off, PoweringOff | "Powered off" / "Powering off" · `off` (glyph ⏻) | `Off` | warning: "Powered off since <time>." | warning | `off` |
| … on a `critical`-tagged server | "Powered off" · `crit` | `Critical` | critical | critical | `off` |
| … after a **graceful shutdown** this app ran for a user | "Powered off" · `off` | `Off` | info: "Powered off (by alice, <time>): graceful shutdown." | warning / critical (the source is not known to the detector yet; see R2-08) | `off` |
| … after a **forced** power-off this app ran | as unplanned, text "… (forced off by admin)." | | warning / critical | | |
| PoweringOn | "Powering on" · `off` (replaces an OK badge only) | `Off` (a warning stays `Warning`) | info: "Powering on." (after any sensor item) | not judged | sensor verdict |
| Unknown | "Power unknown" · `unknown` (replaces an OK badge only) | `Unknown` (a warning stays `Warning`) | info: "Power state not reported by the BMC." (after any sensor item) | not judged | sensor verdict |

Precedence of exclusive row states: maintenance > stale or no data > critical sensor rollup > powered
off > warning > OK. A critical rollup keeps its badge; the power-off item is still the first attention
item. A server in maintenance shows the item inside its "In maintenance" group and is not counted.
Powering on and an unknown power state replace only an OK badge: a sensor warning keeps its badge,
count and row tint, as it does in the metrics and notifications, and the power item follows the
sensor items (a host that is down leads with its power item). Fleet rows sort critical, powered off,
warning, stale, unknown, maintenance, OK (`healthRank`, `rowRank`); the header pill lists critical,
warning, stale, off, unknown, so "1 stale · 1 off" takes the stale class and glyph.

- **Fleet:** `ServerState.PowerSince` is when the current power state was first seen by this process
  (zero: unknown onset, the first poll already found it so). The poller moves it only when the state
  changes between polls, or a verified power action publishes a new one (`poller.mergePower` in
  `publish`, `poller.observePower`; `poller.go`). `fleetview` copies it to `ui.ServerView`.
- **UI** (`power_state.go`): `powerContextFor` ties the server's state to the last *verified*
  power operation (`Power.Last`) when it ended in that state and `PowerSince` lies within one stale
  threshold of its end, so an older operation never explains a newer power-down. `hostBadge`,
  `powerAttention` and `powerNote` implement the table; `summary.withPowerState` applies them, and
  `countFleet`/`pillOf` gained the `Off` count ("2 OK · 1 off" when nothing else is wrong, class
  `gp-off`; "1 warning · 1 off" otherwise). The sidebar shows ⏻ and "off"; the fleet row is tinted
  `r-warn` (unplanned) or `r-off`; the Status panel's Power value carries the note ("since …",
  "graceful shutdown by alice at …", "forced off by admin at …"); the verdict panel takes the power
  item's severity (`p-crit`, `p-warn`, or plain). The strip gained a "Powered off" cell. The `off`
  token reuses the info colors (`.b-off`, `.s-off`, `.gp-off`, `.k-off`, `.r-off`): no theme change.
- **Notifications** (`detect.healthValue`): the health tracker observes `Off` (below a critical
  rollup); events "<server>: powered off" (warning; critical when tagged) and "<server>: powered on
  again" (recovery). PoweringOn and Unknown leave the sensor verdict in charge.
- **Metrics:** `oob_server_health` has a fifth state `off` (`serverHealthStates`); log severities are
  untouched. Golden scrape and deploy/README updated.
- Tests: `fleet.TestPowerSinceTracksTransitions`, `fleetview` mapping, `ui/power_off_test.go` (five
  scenarios incl. planned, forced, transitional, unknown, the pill), `notify.TestPoweredOffIsAHealthEvent`,
  `metrics.TestHealthStateOff`/`TestOffStateIsExposed`.

### Auto-refresh and typed input (R2-02)

The opt-in auto-refresh reloaded the server page while a maintenance reason or a note was being
typed. Fix: no page that refreshes carries typed input, and the refresh itself pauses for an editor.

- **Forms moved to their own pages:** `GET /servers/{id}/maintenance/new` (authz
  `server.maintenance`), `GET /servers/{id}/notes/new` and `GET /servers/{id}/notes/{nid}/edit`
  (`server.notes.write`; the edit page is the author's only, 403 otherwise, 404 for an unknown note).
  The POST routes are unchanged; a validation error re-renders the form page (422) with the values
  kept and `aria-invalid` on the field, instead of a bare error page. The server page's Maintenance
  card keeps only the badge and the End/Cancel button; the Notes card keeps pin and delete
  (button-only forms) and links to the add and edit pages. With a window in place the start page
  shows the window and the way back, not a second form.
- **No-script fallback:** `layout.html` renders `<noscript><meta http-equiv="refresh"></noscript>`
  plus `<meta name="oob-refresh" content="N">`. Browsers without scripts refresh the Overview, Servers
  and server Hardware pages (the only pages that opt in); every page with a form is outside the
  refresh set, so nothing typed can be lost. One page with forms refreshes on its own: the Settings
  server page while a connection test runs (every 5 s). It sets `RefreshScriptOnly`, so it gets the
  script refresh (paused while editing) and no `<noscript>` meta refresh; without scripts its test
  panel says to reload the page. `refresh_forms_test.go` asserts both, and that the Security tab
  (accept comments) never refreshes.
- **With scripts** (`app.js`): the reload is a timer that first checks `editing()`: a focused
  text-like control, or any control whose value differs from its default (`defaultValue`,
  `defaultChecked`, `defaultSelected`). While editing, `<html data-refresh-paused="1">` is set and the
  check repeats every 5 s; the reload happens on the first idle tick.
- Harness: `env.autoRefresh` (test hook) ← `OOB_DEV_REFRESH` (the dev server, `3s` in
  `playwright.config.ts`); `UIDeps.AutoRefresh` carries it to `ui.Deps.AutoRefresh`.
- Tests: `ui/refresh_forms_test.go` (no typed input on refreshed pages, the two metas, the form
  pages, 403/404, 422 re-render with values), the adapted maintenance/notes UI and Go e2e checks,
  Playwright `maint.spec.ts` (axe on the new pages) and `refresh.spec.ts` (no typed controls while
  on, a focused/dirty probe field pauses the reload, leaving it resumes).

### Step-up expiry keeps the form (R2-03)

A change posted after the step-up window lapsed (Add server, a credential, General settings, a
notification target…) was redirected to `/stepup` and the form was lost. Now (`resume.go`):

- `authorizeChange` → `stepUpURL`: a refused POST is kept in `pendingStore` and the redirect carries
  `resume=<128-bit hex id>`. The stash holds the route path, the CSRF form name and the fields minus
  the old CSRF token, **sealed** (AES-256-GCM under an HKDF key derived from the CSRF key, AAD
  `session|path|form`), so a typed password never sits in clear in memory, a log or the audit trail.
  Bound to the session binding that posted it; TTL = step-up window + 1 min; at most 64 entries of
  at most 8 KiB (the parsed body cap), the oldest evicted first, and at most 4 per session binding
  (that session's oldest goes first), so one session cannot flush the stash and evict the forms
  other admins are keeping.
- `/stepup` names the real action (new: "Add server", "Change server · <name>", "Change general
  settings", "Change notifications", "Accept or remove security risks · <name>") and, when a kept
  form is pending for this session, names what it will do (`keptFormLabel`: "Accept a security
  risk · <name>", "Remove an accepted risk · <name>", and the maintenance, note and acknowledgement
  routes, which need no step-up today), says "Your form is kept and will be submitted once you
  confirm" and carries `resume` as a hidden field. After a
  valid code the session rotates as before; `pendingStore.take` consumes the stash (single use,
  binding and expiry checked) and `replay` runs it through the UI router with a CSRF token issued for
  the rotated session, the new session cookie, the browser's other cookies and address, and the
  request's context. The route re-checks authz with the fresh step-up and its rate limit and writes
  its own response (the TOFU confirm page for a fingerprint fetch, the 303 of a saved change, a 422).
  Another session's code cannot resume it; a stale id just returns to `next`.
- Tests: `ui/resume_test.go` (store: sealed at rest, bound, single use, TTL, bounds, the per-session cap; Add server with a
  pasted pin replayed; a credential form with a password replayed and stored, password in no log;
  another session refused), and the four existing stale-step-up tests now check the resume id too.

### One power state after an action (R2-08)

After a verified power action the header said "now: On" while the status said "reported Off": the
poller's snapshot lagged by up to a poll cycle. Now the verified end state is published at once.

- `bmc.Snapshot` carries `PowerAsOf` (zero = `TakenAt`) and `WithPowerState(st, at)` returns a copy
  with the power state overlaid; snapshots stay values.
- `fleet.Fleet.ObservePower(id, PowerObservation{State, At, Action, By})` overlays the published
  state with a CAS loop: only an observation newer than the published power state is taken;
  `PowerSince` moves when the state changed; `ServerState.PowerCause{Action, By, At}` records the
  action. `poller.publish` now merges with a CAS too (`mergePower`): a verified state newer than the
  poll's `TakenAt` is carried over the poll (a poll that started before the reset cannot undo it), a
  confirming poll keeps the onset and the cause, a poll that sees another state is the newest truth
  (new onset, cause cleared). Every reader (UI, API `power_state`, `oob_server_power_state`, the
  notification detector) sees the same state without waiting for the next poll.
- `power.Config.OnVerified(id, Observation)` is called from `finish` for phase `done` only
  (unconfirmed or failed verifications report nothing); cmd's `powerObserver` adapts it to the fleet.
- UI: `powerContextFor` prefers the fleet's `PowerCause` (falling back to `Power.Last` with the
  stale-threshold rule); `powerNote` reads "verified <time> (force off by admin)" next to the power
  state on the Status panel and in the Operations header ("now: Off · verified …"); the attention
  item reads "Powered off since <time> (forced off by admin)." Notifications: a planned graceful
  shutdown (`PowerCause.Action == graceful-shutdown`) is reported at **info** severity ("powered off
  (graceful shutdown by alice)") and so is its return; the R2-01 table's "warning / critical" for that
  row now reads info.
- Tests: `bmc.TestSnapshotWithPowerState`, `fleet.TestObservePowerOverlaysUntilAPollConfirms`,
  `power.TestVerifiedTransitionIsObserved`, `ui.TestVerifiedPowerStateIsShownEverywhere`,
  `notify.TestPlannedShutdownIsInformational`, and `checkPower` (Go e2e) asserts the API, the
  Operations header and the Overview agree right after the verified force-off.

### Unique pager landmarks and a long log in CI (R2-25)

A list longer than one page rendered two `<nav class="pager" aria-label="Event pages">` landmarks
(axe `landmark-unique`), which CI never saw because the recorded fixtures hold fewer than 50 entries.

- `pagerView.Bottom()` labels the second pager "<label>, bottom" (events.html, logs.html).
- The e2e R240 mock serves a synthetic SEL of 60 OK entries (`e2e_sel_test.go`, `bigSELPath`
  overlay): old and informational, so Needs attention, the 24 h feed and the notification detector
  are unaffected, while `/events?severity=all&range=all` (in the Playwright axe matrix as
  `events-all`) and `/servers/r240/logs` page. `checkUI` asserts both labels on both pages.
- Tests: `ui.TestPagerLandmarksAreUnique` (60 warnings: one top and one bottom landmark on Events and
  Logs; three entries: no pager).

### Fleet table on laptop widths (R2-04)

At 1024–1536 px the Overview's fleet table overflowed its scroll region and the Draw and Data
columns, the "can I trust this?" signals, sat off-screen. CSS only (`app.css`):

- The right rail (Needs attention, In maintenance, Events) stacks under the table below **100rem**
  (1600 px) instead of 75rem, so the table has the full width on every laptop.
- Below 80rem (1280 px) the Inlet and CPU meters show their number without the bar (the bar is
  decorative, the headroom text stays for screen readers) and the Issue column wraps at 16rem.
- From 51.3125rem to 100rem (821–1600 px, below the width where the side rail stacks), where main's Security column made ten columns, the
  fleet cells take .35rem of horizontal padding (also under the comfortable density), headers
  lose most of their letter spacing and a long server name may wrap: at 1024 px the table's
  min-content width is 626 px in a 744 px region, whatever the Security cell says.
  Nothing health-relevant is hidden at any width; the phone layout (stacked rows) is unchanged.
- Playwright `layout.spec.ts`: at 1024, 1280, 1366, 1440 and 1536 px the region's `scrollWidth`
  equals its `clientWidth` and the Draw, Security, Data and Issue headers are in the viewport.

### Confirm pages on phones (R2-05)

Every confirm page autofocused Cancel, and on a phone the browser scrolled the title, the critical
warning and "What goes down" away (`scrollY` 425). Cancel keeps the default focus (round-1 decision);
on phones (≤ 51.25rem) the button row (`cf-actions`, in `confirm.html` and the TOFU confirm) is pinned
to the bottom of the viewport with `position: fixed`, so the focused Cancel is already in view and no
scroll happens; the body reserves room under it and `scroll-padding-bottom` keeps a focused typed-name
field above it. Desktop is unchanged. Playwright `confirm.spec.ts` (390×844): Cancel focused,
`scrollY` 0, the h1, the critical warning and the confirm button in the first viewport.

### Danger styling only where it belongs; status, not controls, for viewers (R2-15, R2-11)

- `confirmView.Tier` picks the treatment: **neutral** (reversible, safe: Power on, a fan lease):
  accent button and an info panel (`p-info`); **caution** (service impact that recovers: graceful
  shutdown or restart, disable account, end sessions, disable server): warning panel and an outlined
  warning button (`btn-caution`); **danger** (forced power actions, reset authenticator, revoke token,
  remove server, delete notification target): the red treatment and, as before, a typed name. The
  reversible badge reads "Reversible" (info), "Safe action" is info rather than warning. List
  buttons follow the same split (Disable account…, End session…, End all sessions…, Disable…
  server are `btn-caution`; Reset authenticator…, Revoke…, Delete…, Remove… stay
  `btn-danger-outline`; forced power actions on Operations stay `btn-danger-outline`).
- Viewers: the server page's action bar renders one line, "Actions need the operator role.", instead
  of Power…/Fans buttons that led to a tab where everything was disabled; the Operations tab lists the
  power actions as text with the role line ("Your role is read-only …") and the BMC support line; the
  fan card shows "Fan leases need the operator role." without a dead button; the serial placeholder
  shows "Needs the admin role.". An operator, one role step away from the forced actions, still sees
  those disabled with the reason, and the console button disabled with its reason (unchanged).
  The Security tab follows suit: a viewer sees "Re-running the checks needs the admin role." instead
  of a disabled Re-run button; an operator still sees the button disabled with its reason. The fleet
  Security cell reads "Disabled" when the checks are off for a server (it read "Off", like a powered-off
  host).
  Authz rules and their tests are unchanged.
- Tests: `ui/tiers_test.go` (power, fan, account, token, server tiers; viewer vs operator gating);
  the viewer-based placeholder tests now sign in as an operator and check the viewer's note.

### Response compression (A9, R2-28)

`web.Compress()` (stdlib `compress/gzip`, pooled writers) sits in the standard chain after the
security headers: text responses (HTML, CSS, JavaScript, SVG, JSON, Problem Details, plain text)
are gzipped for clients whose Accept-Encoding lists gzip, `Content-Length` is dropped and
`Vary: Accept-Encoding` is set on every response. Left alone: other media types, declared bodies
under 512 bytes, Range requests, HEAD, any request with an Upgrade header (the console
WebSockets hijack the raw connection; the wrapper also exposes `Unwrap` for `http.ResponseController`
and forwards `Flush`), and HTML that answers a GET with a query string (BREACH, docs/security.md §3:
such pages can reflect the query next to a CSRF token). A Flush before any write decides first, so
the headers it sends match the body; Accept-Encoding q-values are parsed (0 to 1, at most three
decimals; `q=0.0` or a malformed q refuses gzip); `Vary` names Accept-Encoding once. Tests:
`web/compress_test.go` (round trip, Vary, type table, small bodies, ranges, upgrades keep the
hijacker, streaming flushes, the chain), `compress_edge_test.go` (q-values, HEAD, 304, an existing
encoding or Vary, an explicit status, flush first), `compress_breach_test.go` (HTML for a GET with a
query is not compressed; HTML without one, CSS and JSON with one are), and `checkUI` (Go e2e)
asserts a gzipped Overview.

## 33. Implementation notes (P7-early: dependency policy and gates)

Branch `p7-early`, plan 06 §3.8 (Renovate, dependency-documentation test), §3.9 (gates) and the
actionlint item of §3.2, plus the follow-ups of the security and code reviews of that branch. No new
Go dependency; no app code changed.

### Coverage gate (`internal/covergate`, `make cover`)

- `make cover` runs `go test -race -count=1 -covermode=atomic -coverprofile=cover.out ./...` as before,
  then `go run ./internal/covergate -profile cover.out -min 80 -module $(go list -m) -exclude
  "$(COVER_EXCLUDE)" $(COVER_REQUIRED)`. It prints one line per package (`ok   …/internal/fan 89.8%`,
  `FAIL … 79.9% < 80%`, `skip … (excluded)`) and exits 0 (pass), 1 (a gate failed) or 2 (usage,
  unreadable or malformed profile).
- **Every package with statements is gated at 80 % on its own**, plus the module total, so a new package
  is gated without editing a list. A package means that import path alone: `fan` does not include
  `fan/hostlease`. Packages without statements (the test-only `internal/repopolicy`) are not gated.
- `COVER_EXCLUDE`: the in-repo test doubles `bmc/redfishmock`, `bmc/bmcssh/sshtest`, `console/rfbtest`.
  They are never linked into the binary (`go list -deps ./cmd/oob-manager`), and their coverage says
  nothing about shipped code. They are still printed. An exclusion that matches no package fails, so the
  list cannot rot.
- `COVER_REQUIRED`: `auth`, `authz`, `fan`, `power`, `audit` (rule 1) plus `console`, `console/rfb`,
  `netpolicy`, `secrets/credstore`, `tofu`, `registry` (plan 06 §3.9). They must be present in the
  profile, so a rename or move fails instead of silently leaving the gate; a package both required and
  excluded fails.
- The tool reads the profile itself rather than `go tool cover -func`, whose per-function percentages
  cannot be summed per package. A block listed twice counts once (covered if any copy ran); the result
  equals the per-package `coverage:` lines of `go test` and the `total:` line of `go tool cover -func`
  (checked on the 2026-10-22 profile: total 91.9 %). The comparison is exact: 2499/3125 = 79.968 % fails
  an 80 % gate although it prints as 80.0 %. A profile without statements fails (a broken run is not
  100 %). The profile must be written **without `-coverpkg`**; each package's figure is then its own
  tests' coverage of it (Makefile comment).
- Lowest packages on 2026-10-22: `cmd/oob-console` 85.7, `admin` 86.2, `bmc/bmcssh` 86.3, `credstore`
  87.8, `console/rfb` 88.1, `registry` 89.3, `fan` 89.5–91.0 (it varies a little between runs) (%).

### Nightly soak (`.github/workflows/nightly.yml`, `make soak`)

`go test -race -count=3 -shuffle=on -timeout 30m ./...` at 04:17 UTC daily and on `workflow_dispatch`,
the step that was run by hand before each integration (web/ui alone took 153 s for three runs locally;
the timeout keeps a slow runner clear of the 10 min default). The shuffle seed is in the log; replay with
`-shuffle=<seed>`. Read-only token, actions pinned like ci.yml. Fuzz targets (plan 06 §3.5) will join
this workflow.

### actionlint

`make actionlint` runs `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12` over
`.github/workflows/`; the CI lint job calls it with `ACTIONLINT_VERSION` from the workflow env.
v1.7.12 was released 2026-03-30 (GitHub releases API); the Go module proxy's origin record for it names
the same commit as the tag (`914e7df2`). `go run pkg@version` is verified against the checksum database
and leaves go.mod alone, like govulncheck. actionlint shellchecks every `run:` script only when
shellcheck is on PATH, so the lint job first runs `command -v shellcheck && shellcheck --version`
and fails if the runner image ever drops it; locally the shellcheck half is skipped without it (the
Makefile says so). Both workflows lint clean, with shellcheck 0.11.0.

### Renovate (`renovate.json`)

| Setting | Value | Why |
|---|---|---|
| `minimumReleaseAge` | `14 days`, also inside `vulnerabilityAlerts` | rule 10. Renovate lets security PRs skip the age check by default; here they wait too, so a hostile "fix" release is held like any other. An urgent fix is a hand bump after reading the advisory |
| `minimumReleaseAgeBehaviour` | `timestamp-required` | a release without a timestamp is treated as too new (Renovate ≥ 42 default; explicit so an older self-hosted Renovate behaves the same) |
| `internalChecksFilter` | `strict` | no PR for a pending version; pending ones show on the Dependency Dashboard |
| schedule | `schedule:monthly` (first day of the month, early UTC) | plan 06; vulnerability PRs ignore the schedule (Renovate rule) but not the age |
| `automerge`, `platformAutomerge` | `false` | every bump is reviewed and goes through CI |
| presets | `config:recommended`, `:semanticCommits`, `helpers:pinGitHubActionDigests`, `docker:pinDigests` | SHA-pinned actions with the tag comment; digest-pinned base images; `chore(deps): …` titles |
| action digest updates | `dependencyDashboardApproval: true` for github-actions `digest` updates, which are **not** in the GitHub Actions group | a tag moved to another commit shows up as a digest-only update with the same version, which is what a tag rewrite looks like; it gets its own branch, created only after approval on the Dashboard |
| `enabledManagers` | gomod, github-actions, dockerfile, npm, custom.regex | `deploy/` (the locally built image), `testdata` and `node_modules` are ignored; `tests/e2e` is **not** ignored (config:recommended would skip `**/tests/**`) |
| groups | Go modules, GitHub Actions, Docker base images, e2e test dependencies, CI and build tools: non-major updates only | majors get their own PR |
| Go toolchain | its own group: go.mod `go`/`toolchain` lines and the `golang` build image together | plan 06 |
| `postUpdateOptions` | `gomodTidy` | go.sum stays consistent |

Tool versions that no built-in manager sees carry a `# renovate: datasource=<ds> depName=<name>` line
directly above the pin, in the Makefile and in any env block of a workflow (top, job or step level),
read by one regex custom manager:
golangci-lint, govulncheck and actionlint (`go` datasource), Trivy and Syft (`github-releases`), bats
(`npm`). The same depName in several files lands in one PR, so the files move together. Indirect
go.mod requirements are not bumped on their own (Renovate default); they move with their parents and
`go mod tidy`.

Verified with Renovate 44.145.1 (2026-10-07): `renovate-config-validator --strict` passes (also after
the review changes), and a local extract-only dry run (`--platform=local --dry-run=extract`) found the 8
direct modules, both base images (`golang:1.27.3@sha256:…`, `static-debian12:nonroot@sha256:…`), every
SHA-pinned action, the two npm test dependencies and all nine annotated pins (five in ci.yml, four in
the Makefile).

Known limit: the distroless `nonroot` tag is a digest-only update; if the registry gives no release
timestamp, the update stays pending (by `timestamp-required`) and is bumped by hand as the Dockerfile
comment describes.

### Repository settings for the maintainer

- **Install the Renovate GitHub app** on the repository (only it; no token or secret goes into CI).
  Until then nothing opens PRs.
- **Branch protection on `main`** requiring a pull request review **from code owners**, plus the CI
  checks. `.github/CODEOWNERS` assigns `/.github/`, `/renovate.json`, `/Makefile`,
  `/internal/repopolicy/` and `/internal/covergate/` to the maintainer, but GitHub
  enforces it only with that setting; it is a repository setting, not something the tree can do.

### Repository policy tests (`internal/repopolicy`)

A test-only package (a `doc.go` and tests that read repository files relative to the package):

- `TestDependenciesDocumented`: every direct `require` in go.mod has a §2 row; a backticked path in the
  Module column equal to the module or below it counts (`golang.org/x/crypto/argon2` documents
  `golang.org/x/crypto`). Indirect requirements are not checked.
- `TestVendoredAssetsDocumented`: every top-level directory of `internal/web/ui/vendor.sha256` is named
  in §2 and has a NOTICE entry (`internal/web/ui/static/vendor/<dir>/`). The xterm.js row now names
  `xterm-6.0.0/` and `xterm-addon-fit-0.11.0/` for this.
- `TestWorkflowsHardened`: every workflow in `.github/workflows` and every composite action in
  `.github/actions/**/action.y*ml`, **every YAML document** in each (`yaml.NewDecoder`). The `uses`
  values come from the parsed YAML (any mapping with a `uses` key: `jobs.*.steps[]`, `jobs.*.uses`,
  `runs.steps[]`), so flow style, quoted keys and second documents cannot hide one. Each must be
  `owner/repo[/path]@<40 hex>`; a `./` local reference passes only if it points at a file the test
  also checks. A block-style line regex cross-checks the count (a mismatch means a flow-style step,
  which fails) and supplies the `# v…` tag comment each pinned line must carry. Workflows also need a
  top-level `permissions:` block with no `write-all` and no scope set to `write` (writes are granted
  per job), no job with `permissions: write-all`, and no `pull_request_target` or `workflow_run`
  trigger (string, list or map form). Every `actions/checkout` needs `persist-credentials: false`
  (a YAML boolean). Negative cases cover each rule and form.
- `TestCoverExcludedPackagesAreNotShipped`: no non-test Go file under `cmd/` or `internal/` (outside
  the excluded packages themselves) imports a package on `COVER_EXCLUDE` (read from the Makefile,
  `go/parser` imports only), which is the premise of excluding them from the coverage gate.
- `TestRenovateKeepsTheFourteenDayRule`: the age, timestamp, filter and digest-preset settings above,
  and no `automerge` or `platformAutomerge` set to true anywhere in the file.
  `TestActionDigestUpdatesNeedApproval`: the Dashboard-approval rule for action digests, and no
  grouped github-actions rule that includes digest updates.
- `TestEveryToolPinIsTrackedByRenovate`: the Makefile and every workflow file match one of the custom
  manager's `managerFilePatterns`, and its `matchStrings` (compiled with Go's regexp; the pattern uses
  the RE2-compatible subset) capture every `*_VERSION` pin's value **at that pin's own position**, so
  an annotated pin with an equal value elsewhere does not count. Pins are found at any indentation
  (job- and step-level env too). A new pin without the annotation fails.
- `TestToolPinsAgree`: every occurrence of a `*_VERSION` in any workflow, at any level, equals the
  Makefile value, and
  golangci-lint, govulncheck and actionlint are pinned in both the Makefile and ci.yml.
- `TestCodeownersCoverSupplyChainFiles`: CODEOWNERS keeps owners for `/.github/`, `/renovate.json`,
  `/Makefile`, `/internal/repopolicy/` and `/internal/covergate/`.

Each check was seen to fail on a mutated copy (a dropped §2 row, a removed annotation, a drifted pin in
nightly.yml at top and job level, a tag-pinned and a flow-style action, an unpinned composite action, a
shipped file importing a mock, a 3-day release age, `automerge: true`).

### Not done here (rest of plan 06)

`.trivyignore` expiry policy (there is no `.trivyignore` yet), the monthly bump cadence in deploy/README
"Ongoing", ZAP, the release workflow, fuzz targets, drills, the threat-model refresh.

## 34. Implementation notes (S4 Integrations)

Branch `s4-integrations`. Implements roadmap plan 05 (`docs/plans/05-s4-integrations.md`) and
settings_design.md §6 "S4" with decision 6 (GELF over TLS). §33 is reserved for the P7-early branch.
No new dependency (rule 10): `crypto/tls`, `crypto/x509` and `net` only.

### Open questions (plan §17), answered with the plan's recommendation

1. `audit.gelf.allowed_networks` defaults to the private ranges (RFC 1918 and ULA:
   `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7`). A hosted log service needs its range listed.
2. No UDP GELF: TCP and TLS only (`transport: udp` is refused with a message that says so).
3. The Prometheus hint shows the scrape block **and** the current `metrics.enabled` state, the
   `metrics.allow_networks` value and the advice to mint a dedicated token (the plan left the
   contents open; both values are file-only facts that make a first scrape fail when missed).

### Keys, precedence, migration (`internal/config`, `internal/settings`, `internal/store`)

- Settings keys `gelf.enabled`, `gelf.address`, `gelf.transport`, `gelf.server_name`,
  `gelf.pin_sha256`; their file paths are `audit.gelf.*` (`config.FilePath`; `gelf.enabled` is a
  non-empty `audit.gelf.address`). Precedence file > DB > default per key, lock badge for a key the file
  writes. An **empty** `audit.gelf.address` (the deploy example's `address: ""`) counts as not set,
  so the browser manages the whole target.
- `config.ValidateGELF` is the one validator (file and browser): `host:port` with an IP literal
  (no zone) or an LDH DNS name ≤ 253 chars and a port 1–65535; transport `tcp|tls`; server name a DNS
  name (not an IP); pin 64 lower-case hex (forms accept colons, spaces and upper case); `tls` needs a
  pin once enabled. A disabled target is a draft (shape-checked only).
- `config.GELFAddrAllowed` is the static policy: never loopback, unspecified, link-local, multicast,
  broadcast or IPv4-mapped, and inside `allowed_networks`. **Breaking for config.yaml:** a literal GELF
  address outside the allowed networks (for example `127.0.0.1:12201`) now fails startup.
- `settings.Resolve` applies the saved GELF rows together and then checks the combination with the
  validator and the static policy; a combination that fails is ignored as a whole (logged), so a
  half-applied target never ships. `Effective.Integrations`, `IntegrationsLocked`, `IntegrationFields`.
- `UpdateIntegrations` / `ResetIntegrations` follow the General rules: only submitted keys, unchanged
  file values allowed, compare-and-set revision (409), the audit row in the same transaction, locked and
  conflict refusals audited as `denied`. A changed pin also writes `admin.integrations.gelf.pin`
  (`pin_via: fetched|manual`, `pinned: leaf|issuer` when fetched) in the same transaction.
  `admin.integrations.reset` mirrors `admin.general.reset` (not in the plan's table).
- Migration **`0012_integrations.sql`** rebuilds `settings_kv` with every key of 0005/0007 plus the
  three new ones. `TestSettingsKVAcceptsEveryKnownKey` inserts every `config.GeneralKeys()` and
  `config.IntegrationKeys()` entry (and refuses an unknown one); `TestUpgradeFromV072Schema` migrates a
  schema-0011 database with saved rows; the dense test expects 1…12.

### TLS pin (`internal/tlspin`, `internal/tofu`)

- `tlspin` is the shared "trust exactly this key" config (the Redfish driver's `pinnedTLSConfig` now
  calls it): TLS 1.2 minimum, `VerifyConnection` on every handshake, constant-time compare, fail
  closed. Mode `Leaf` (BMCs) or `AnyInChain` (GELF).
- **An issuer pin holds only when the leaf chains to the pinned CA** (and, since the review below,
  is valid for the server name or address). A CA certificate is public, so
  "any certificate in the presented chain matches" would let an impostor send its own leaf followed
  by the real CA certificate. `AnyInChain` therefore accepts a non-leaf match only after
  `x509.Verify` of the leaf with that certificate as the only root (signature and validity; no
  system roots, no host name). The handshake proves the leaf's key. `TestIssuerPinNeedsASignedLeaf`
  covers the forged chain. With an issuer pin an expired leaf is refused like a wrong one.
- `tofu.FetchTLS` (handshake only, no application byte; tested against a raw TLS listener that counts
  bytes) also returns the presented chain (at most four), `SelfIssued` and `IssuerVerified`, and sends
  SNI when asked. `Recommended()` is the issuer only when it verifiably issued the leaf.

### Shipper and hot swap (`internal/audit`, `internal/integrations`)

- `audit.SwitchSink`: an `atomic.Pointer` to the current sink; no target drops and counts. core
  builds it once and the audit logger always tees it with the notifications tap.
- Shipper additions: `TLS *tls.Config` (cloned per connection, handshake inside the dial timeout, no
  plaintext fallback: a plain-TCP input yields class `tls`), pin mismatch → class `tls_pin`, dialling
  paused for `PinPause` (5 min) while rows keep queueing (1 024, then dropped and counted),
  `OnPinMismatch` once per episode, `OnConnected`, `OnRecovered`. Stats: `Active`, `TLS`,
  `PinMismatch`, `Reconnects`, `LastSuccess`, `ConnectedSince`; `LastError` is now a class only
  (`dial`, `timeout`, `tls`, `tls_pin`, `policy`, `write`). `Probe` makes one synchronous write through
  the worker (answered even while it backs off). A flush that gives up counts what it left as dropped.
- `integrations.Service`: `New` builds the shipper for the settings in force and installs it (rows
  recorded before `Run` queue as before); `Run` starts it and on shutdown flushes every shipper. `Apply`
  is serialised: build and start the new shipper, swap, cancel the old one (it flushes 3 s in the
  background), then record `admin.integrations.applied` (principal `system`; enabled, address,
  transport). **`Update` order:** the destination policy accepts the new address → the settings
  transaction commits the update row, which is queued on the **current** shipper → swap → applied row
  on the new one. So the previous log server records who redirected the audit stream, and where to
  (`TestApplyOrdering`, e2e). A build failure keeps the old shipper and records `applied` with error
  `build`.
- `integrations.Policy` (security.md T10): the static policy plus the app's own listen endpoints
  (every interface and literal listen/public_url address × the listen and public_url ports, so a log
  server on the same host on another port is fine); a DNS name is resolved on **every dial**, every
  answer must pass or the name is refused, and the connection goes to the checked address
  (`TestDialerDialsTheCheckedAddress`, a rebinding resolver). The shipper's `Dial` hook is the policy
  dialer; errors carry class `policy` or `dns`.
- `Fingerprint` (policy, then `tofu.FetchTLS`, audited `admin.integrations.gelf.fingerprint` with
  address, port and class), `SendTest` (5 s, audited `admin.integrations.gelf.test` with
  `connected_before`, `connected_after`, `class`; the frame is a GELF message `log_type=test`).
- Trust: `OnPinMismatch` → `notify.ShipperTrustEvent(false)` (class `trust`, critical, no server, so
  maintenance never suppresses it), resolved by the next connection that passes the pin, including a
  new shipper after a confirmed pin. cmd routes it through `lateTap` once notifications exist.

### UI (`internal/web/ui/*integrations*`, templates `settings_integrations*.html`)

- `/settings/integrations` (`admin.integrations.view`, admin): state badge (Connected, Disconnected,
  Disabled, Paused: certificate changed), destination, queued/sent/dropped/reconnects, connected since,
  last row sent, last error class with a sentence; the form (On/Off radios, address, transport radios
  with "unencrypted" on plain TCP, server name, the pinned fingerprint grouped plus a paste box: empty
  keeps the pin), sources, lock badges, Reset to default, the allowed networks, a warning when rows are
  queued, Save and apply, Fetch and confirm (a `formaction` on the same form, no JavaScript), Send test.
  A locked section shows the notice and no buttons. Right panel: Homepage `customapi`, Uptime Kuma
  (`/readyz` keyword `ok`; the `/metrics` keyword monitor when metrics are on) and Prometheus
  (`authorization.credentials_file`, as deploy/README's scrape config, rather than the plan's
  `bearer_token_file`) with `<token>` placeholders, `public_url` (else the request host) and the first
  server id; Copy buttons are the existing `data-copy` enhancement.
- POST `/settings/integrations` and `/settings/integrations/reset` and `/settings/integrations/gelf/pin`
  go through `change()` (`admin.integrations.manage`, step-up, CSRF, 10/min); `/gelf/fingerprint`
  (6/min, the Servers fetch limit; refused while locked) and `/gelf/test` (3/min) through `probe()`.
  Every refusal is audited.
- The confirm page (200, `no-store`) offers the leaf and, when it verifies, the issuer (preselected),
  each with its own proof: purpose `/settings/integrations/gelf/pin`, kind tls, the host as typed, the
  port and the value. Confirming saves the carried form values with the pin and transport `tls`.
- Overview: a critical banner while shipping is paused on a pin mismatch (linked for admins).
  Settings tabs: … Notifications · **Integrations** · Audit log.

### Metrics and readiness

New families `oob_audit_shipper_tls`, `_pin_mismatch`, `_reconnects_total`,
`_last_success_timestamp_seconds`; no shipper family is written while shipping is disabled.
`/readyz` is `degraded` while a configured shipper is disconnected or paused, `ok` when shipping is off.

### Tests and gates

- Unit: tlspin (leaf/issuer, forged chain, fail closed), tofu (chain, SNI, zero application bytes,
  unrelated CA), audit (switch under concurrent enqueue with exact accounting, TLS leaf/issuer pins,
  wrong pin: zero bytes, pause, one callback; recovery after the pause; no plaintext fallback; reconnect
  counter; probe incl. during backoff), config (validator, file keys, refusals), store (key list,
  upgrade), settings (precedence, bad combination, updates, refusals, reset), integrations (policy
  table, rebinding, apply ordering, disable, refusals, fingerprint, test, pin mismatch and recovery),
  authz matrix, metrics (families, golden), api (readiness), UI (page, save/apply/test, rate limits,
  refusals incl. viewer and stale step-up, file-managed and locked, fetch → confirm with proof tamper,
  manual pin, reset, banner, no token on the page), cmd (self ports).
- e2e (Go) `TestE2E/integrations`; Playwright `integrations.spec.ts` and the page matrix entry.

### Security review fixes (same branch)

A security review of the slice (security-reviewer agent, 2026-10-22) found no critical issue; its high
and medium findings are fixed, the low ones fixed or listed below.

- **Issuer pins check the name (high).** A CA signs certificates for many names, and a public CA for
  anyone: "the leaf chains to the pinned CA" alone would accept a certificate the same CA issued to
  someone else. `tlspin.IssuerConfig(pin, name, …)` also requires the leaf to be valid for `name`
  (`x509.VerifyHostname`): the server name when set, else the host of the address (DNS name or IP
  literal). An empty name refuses every issuer match; leaf pins are unchanged (that exact key).
  `tofu` computes the same with the name it fetched for (`IssuerVerified`, `IssuerProblem`
  `unrelated|wrong_name`) and flags a CA trusted by the system roots (`IssuerPublic`); the confirm page
  then preselects the **leaf** and warns, and explains a wrong name ("set Server name to a name the
  certificate carries"). `TestIssuerPinChecksTheName`, `TestFetchTLSIssuerName`,
  `TestIntegrationsIssuerNeedsTheName`.
- **Never a BMC (medium).** `Policy.Deny` lists every BMC address of the effective registry (file and
  browser servers, disabled and shadowed ones too), read per check: a GELF address or a certificate
  fetch on any port of a managed BMC is refused ("the address of a BMC this console manages"), so the
  rule "nothing user-supplied reaches a BMC" holds for this page too. `TestPolicyDeniesManagedBMCs`, e2e.
- The app's own endpoints also include the addresses `public_url`'s host name resolves to at startup
  (a bridge container does not see the Docker host's address among its interfaces).
- Trust callbacks are bound to the shipper generation: a late callback of a replaced shipper is
  ignored, and a new target that also mismatches is reported again (`TestTrustPerGeneration`).
- `Apply` reads the settings under its lock, so overlapping saves end with the newest target.
  `admin.integrations.applied` records `queued_on_previous` (rows the old destination may lose).
- The audited host of a fingerprint fetch is truncated to 253 characters.

Accepted (documented, not changed): the default `allowed_networks` stays the private ranges (decision
decision 1), so a compromised admin session can aim the stream at any LAN host there; narrow it to the log
server's address. A TLS → plain TCP change is allowed (audited, step-up, shown as unencrypted). Fetch
errors keep their classes (`unreachable`, `timeout`, `not_tls`) and DNS refusals name the cause, as for
Settings → Servers (admin, step-up, 6/min, audited).

### Second review round (after the P7-early rebase)

Security and code reviews of the rebased branch found nothing critical or high. Fixed:

- **Redirect record (sec M3).** `Apply` waits up to `PreviousTimeout` (2 s) for the current shipper
  to write everything queued (`Shipper.WaitSent`, which counts frames settled after being queued),
  so the committed `admin.integrations.update` row reaches the previous destination before the swap;
  `admin.integrations.applied` records `previous_confirmed` and `queued_on_previous`. Best effort by
  nature (GELF has no acknowledgement); the page warns before Save when shipping is on but not
  connected. T10 and deploy/README say exactly this.
- **Target changes notify (sec M2).** The notify tap turns `admin.integrations.update` and `.reset`
  (ok) into an `audit`-class event naming the fields before → after: critical when shipping goes off,
  transport goes tls → tcp or the address changes, else a warning (`TestTapIntegrationsChange`).
- **Visible when off (sec M1).** `oob_audit_shipper_enabled` is always written (0/1); deploy/README
  gives an `absent()`-safe alert. `/readyz` stays `ok` when shipping is turned off in the browser (by
  design, documented): the metric and the critical notification cover that case.
- **Audit.** A destination refused on save is audited `denied` with class `policy`; the fingerprint
  fetch and Send test write a `started` row first and do nothing when it cannot be written
  (`TestNoAuditRowNoNetwork`), then the result row with the same correlation id; a typed server name
  is validated before it is used as SNI.
- **Shipper (code M2, M3, L1, L2).** `send`/`dial` return `*ShipError` with the recorded class, so
  Send test reports `tls` or `write` instead of `dial`. A probe may dial during a pin pause (the pin is
  still checked before anything is written) and a good handshake ends the pause and the mismatch. A
  finished shipper refuses and counts late frames; a frame held for a retry when Run is cancelled goes
  to flush; flush no longer counts the remainder twice. The wrong-pin test uses a fake clock.
- **Expired certificates (code L9).** Under an issuer pin, a leaf that chains to the pinned CA for the
  right name but is outside its validity period yields `tlspin.ErrExpired` → class `tls_expired`,
  pausing like a mismatch but notified as "certificate expired" (renew it), with no impostor wording.
- **Trust lifecycle (code L4).** `integrations.TrustChange` is mismatch, expired, resolved or withdrawn;
  disabling shipping or moving it to another address closes an open alert ("certificate alert
  closed"); a new pin for the same address resolves it on the next good connection.
- **Service (code L5, L6).** `Apply` after `Run` returned does nothing; sent, dropped and reconnect
  counters are carried across swaps; the policy dialer tries every allowed DNS answer in order.
- **Saved rows not in force (code M5).** `Effective.IntegrationsNote` explains a combination of saved
  rows that no longer validates (for example after `allowed_networks` was narrowed); the page shows it
  and, for admins, Overview.
- **Config (code M4, L7).** An empty `audit.gelf.address` unsets the whole section (no other key
  locks); host names may contain `_` (TLS server names stay LDH); a refused literal names the
  `allowed_networks` entry to add. deploy/README "Upgrading to Settings → Integrations" lists what now
  fails startup.
- **UI (code M1, L8).** Reset buttons submit a separate form (`form=`), so Enter in a field saves
  (Playwright presses Enter in Address); `aria-invalid` is on the radio inputs; the confirm page says
  when shipping stays off; the paused banner mentions the 1,024-row cap.
- serveCmd is under 50 lines again (`loadServeCert`); new fixtures use TEST-NET addresses and a
  synthetic user.
### Third review round

Re-checks found nothing critical or high. Fixed:

- **Dial deadlines (code N1).** The policy dialer gives each DNS answer its share of the remaining
  dial time (`remaining / answers left`, at least 0.5 s), so a black-holed first answer cannot starve a
  reachable second one (`TestDialerSharesTheTimeout`, a real `net.Dialer` for the second answer).
- **Locks (sec N1, code N3).** `Apply` is serialised by `applyMu`; the state mutex is held only for
  the swap itself, so page renders (`Applied()`, an atomic snapshot) and shutdown never wait behind the
  wait for the previous destination (`TestApplyWaitDoesNotBlockReaders`). The wait is
  `Config.PreviousTimeout` (default 2 s; 300 ms in tests).
- **Counters (code N4).** `Stats` reads one atomically published state: the current shipper, the
  replaced ones still flushing (read live, so their late sends and drops count) and the totals of those
  that finished. A scrape never sees a dip (`TestCountersNeverDip`).
- **Pause reason (code N5).** `Stats.PauseReason` (`tls_pin`/`tls_expired`) is kept apart from the
  last error; a probe that fails during the pause cannot change it. The Overview banner and the page
  state read it (code N2: "certificate expired" vs "does not match").
- **Notifications (sec N2, N4).** A changed `gelf.pin_sha256` or `gelf.server_name` is critical like
  an address change. deploy/README notes that these notifications carry the log server's address and
  pin to the push services.
- **Multi-answer names (sec N3).** The certificate fetch visits every DNS answer (at most four) and
  refuses the name when they present different certificates (class `multi_cert`): the simplest rule
  that keeps the confirmed pin valid for whichever answer the shipper connects to.
- Fixtures: the config tests replace validYAML's GELF line by pattern (no real address in the new
  tests); the token-on-page check mints a token for a synthetic user.

### Final review lows (branch `s4-followup`)

- **Trust withdrawal after the wait (L-A).** The withdrawal of an open certificate alert moved from the
  top of `Apply` into `install`: after the generation is bumped (the old shipper's callbacks no longer
  count) and before the new shipper starts (its own mismatch is never withdrawn). A mismatch the old
  shipper reports while `Apply` waits up to `PreviousTimeout` for it is closed with the rest, so a later
  good connection sends no spurious recovery. A build failure keeps the old target and its alert.
  `TestTrustWithdrawnAfterTheWait` (move, and disable then enable).
- **Parallel certificate fetch (L-B).** The answers of a name (at most 4) are fetched concurrently, each
  within the tofu dial and handshake bounds, so the request budget `integrations.FetchTimeout`
  (2 × dial + handshake: resolve, then one round) holds for any number of answers; the per-user limit
  (6/min) is unchanged. `TestFingerprintSlowAnswersInParallel`.
- **First setup is a warning (L-C).** A first address, pin or server name (empty before) saved in the
  same change that turns shipping on (the first Fetch and confirm) is a warning; a value replacing
  another, a first pin while shipping is already on, and every other change listed above stay critical.
  `TestTapIntegrationsFirstSetup`.

### Open

- **Needs a real TLS GELF input to verify** (plan README): Graylog's GELF TCP input with
  `tls_enable`, its certificate pinned through Fetch and confirm, then Send test and a certificate
  renewal (with an issuer pin, shipping should continue; with a leaf pin it pauses).
- An install whose config.yaml sets `audit.gelf.address` keeps a file-managed target (lock badges)
  until that line is removed; a LAN log server address is inside the default private ranges.
- Shipper tuning (queue size, timeouts) is not a config key yet (the plan lists it as file-only;
  the defaults are unchanged).
- A frame handed to a replaced shipper after its flush finished (a swap-window race) is dropped and
  counted by that shipper, but no longer reaches the totals once it was folded in.

## 35. Implementation notes (round-2 redesign, slice A: fonts, OKLCH tokens, visual baseline)

Branch `redesign-slice-a`, rebased onto `main` @ 01652fc (P7-early). Plan 04 §10 slice A. The maintainer chose direction A
(Quiet signal) on 2026-10-22, with C's 24-hour flight recorder and B's incident mode borrowed
later (plan 04 §11). Slice A is foundations only. **The only visible change is the font**: every
colour is painted exactly as in v0.7. No new Go dependency, no migration, no route change; CSP
unchanged (`font-src 'self'` already allowed the fonts).

### Fonts (`static/vendor/fonts/`, `static/tokens.css`)

- **Inter 4.1** (`inter-4.1/inter-var-latin.woff2`, 41,908 bytes) for the UI and **JetBrains
  Mono 2.304** (`jetbrains-mono-2.304/jetbrains-mono-var-latin.woff2`, 14,308 bytes) for
  numerals, IDs and code. Both are SIL OFL 1.1; the OFL text sits next to each file as
  `OFL.txt`. Neither font declares a Reserved Font Name, so the subsets keep their names.
- **Provenance.** The files are the round-2 mockup package's subsets, and they are
  **reproduced byte for byte** from the upstream releases by `tools/fonts/build-fonts.sh`
  (a maintainer tool, not run in CI; checked 2026-10-22). They are Modified Versions under the
  OFL, not upstream files.

  | | Inter | JetBrains Mono |
  |---|---|---|
  | Release tag | `v4.1` (rsms/inter) | `v2.304` (JetBrains/JetBrainsMono) |
  | Asset URL | `https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip` | `https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip` |
  | Asset SHA-256 | `9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e` | `6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf` |
  | Source TTF (in the zip) | `InterVariable.ttf` | `fonts/variable/JetBrainsMono[wght].ttf` |
  | Source TTF SHA-256 | `4989b125924991b90d05b2d16e0e388c48f7d5bb8b30539bbf9c755278d0ccaf` | `662a196d58f1183bf2d77428b6d5283fe3f45161ab021bea4036bc98e5cac016` |
  | Vendored woff2 SHA-256 (= the mockup package's file) | `d9eab0e0b0eb9d3a39b1cc3e7db9482d008d8da0cfae413333ad708400cde60b` | `d28e451b398ad90050633ecdf8b96d4bb9d85c7f2e558fe70b7ecfb8b0565651` |
  | `SOURCE_DATE_EPOCH` (sets `head.modified`) | `1792637339` (2026-10-22 02:48:59 UTC) | `1792637351` (02:49:11 UTC) |

  Tools: **fontTools 4.67.0** with **brotli 1.2.1** (the woff2 bytes depend on the encoder),
  installed into the script's own throwaway venv from `tools/fonts/requirements.txt` with
  `pip install --require-hashes --only-binary=:all:` (`FONT_TOOLS_ALLOW_SDIST=1` switches to
  `--prefer-binary` on a platform without wheels). The file pins the exact versions and the
  SHA-256 of every file PyPI publishes for them (58 for fontTools, 143 for brotli, wheels and
  sdists), copied from the PyPI JSON API (`urls[].digests.sha256`) on 2026-10-22 and checked by a
  hash-enforced install that rebuilt both woff2 byte-identically. Downloads use
  `curl --proto '=https' --proto-redir '=https'`; a temporary work directory is removed on exit.

  **Dated exception to the 14-day rule (CLAUDE.md rule 10), recorded 2026-10-22:** fontTools
  4.67.0 was uploaded on 2026-10-14 and brotli 1.2.1 on 2026-10-22, so both are younger than 14
  days. They are kept because they are the versions that produced the vendored bytes, the tool is
  maintainer-only (never run in CI, never shipped, its output checked against `vendor.sha256`),
  and the install is hash-pinned. From **2026-11-05** both are past the waiting period and the
  exception lapses by itself. Anyone re-running the script must still get byte-identical output;
  if a different tool version is ever needed and the bytes change, the new bytes go into a new
  `-rN` directory under the ledger rule below, never over the old files.

  Commands, per font (`$U` is the code point list below):

  ```
  SOURCE_DATE_EPOCH=<epoch> python -m fontTools.varLib.instancer <source>.ttf wght=400:700 -o <name>.ttf
  SOURCE_DATE_EPOCH=<epoch> python -m fontTools.subset <name>.ttf --unicodes="$U" --flavor=woff2 \
      --no-hinting --layout-features=<features> --name-IDs=0,1,2,3,4,5,6,13,14 --output-file=<name>.woff2
  ```

  `$U` = U+0020–007E, U+00A0–00FF, U+0131, U+0152–0153, U+2013–2014, U+2018–201E, U+2022,
  U+2026, U+2190–2193, U+2197, U+2212, U+2264–2265, U+2318, U+2713. Features: Inter
  `kern,ccmp,locl,mark,mkmk,calt,case,tnum,zero,ss02` (Inter's `opsz` 14–32 axis is kept);
  JetBrains Mono `ccmp,locl,mark,mkmk,case,zero` (no ligatures). The only field that varied
  between runs was `head.modified`, which `SOURCE_DATE_EPOCH` pins. The script checks the asset,
  TTF and output hashes and stops on any mismatch.
- **Latin only (deviation from plan 04 §6, which said latin + latin-ext):** every UI string is US
  English (`copy_test`), the budget favours small files, and the only user-typed text is names
  and notes. A character outside the subset (for example ő or ł in a server name) is drawn by the
  metric-matched fallback face, so it still renders, just in Arial or Liberation Sans. Adding
  latin-ext later is a new subset, so a new versioned directory (below).
- The status glyphs ▲ ✕ ◆ ◷ ◔ ● ‖ ⏻ are not in the subsets either and come from a system font;
  slice B replaces most of them with the Lucide sprite.
- **Versioned directories, append-only.** New font bytes (a new release, or a new subset of the
  same one) go into a new `<family>-<version>[-rN]` directory with a new entry in the
  `fontBuilds` ledger (`internal/repopolicy/fonts_test.go`): `TestFontBuildsAreAppendOnly` fails
  if a vendored woff2 is missing from the ledger or its bytes differ from its entry, so the
  immutable one-year cache can never serve stale bytes under an old URL.
  `TestFontBuildScriptMatchesVendoredVersions` keeps the script's versions on the vendored
  directories.
- No italic face is vendored. `.nodata { font-style: italic }` ("Not reported") therefore gets a
  synthesised oblique of Inter; accepted for slice A (it reads as before, slightly slanted
  rather than a true italic) and replaced by a non-italic muted treatment in slice B.
- `@font-face` with `font-display: swap`, plus metric-matched local fallbacks so a late swap
  barely reflows: "Inter Fallback" = Arial / Liberation Sans / Helvetica at size-adjust 107.51 %,
  ascent 90.11 %, descent 22.44 %; "JetBrains Mono Fallback" = Courier New / Liberation Mono at
  99.98 % / 102.02 % / 30 % (the package's fontTools measurements). `--font-ui` and
  `--font-mono` drive every font stack in `app.css`. The serial console keeps its own xterm.js
  stack (`serial.css` untouched; plan 04 §6: only a mono with box-drawing coverage would replace it).
- Served from the embed like every static file, but `*.woff2` under `/static/vendor/fonts/`
  gets `Content-Type: font/woff2` (distroless has no mime table) and
  `Cache-Control: public, max-age=31536000, immutable`. The version is in the directory name, so
  the URL needs no `?v=` build fingerprint, which the sign-in page must not reveal. `layout.html`
  preloads both files (`<link rel="preload" as="font" type="font/woff2" crossorigin>`) on every
  page, signed in or not. woff2 is not in the gzip type table (already compressed).
- `vendor.sha256` lists the four files; `TestVendoredNoVNCMatchesManifest` (since slice B `TestVendoredFilesMatchManifest`) requires them.
  `NOTICE` has the entry; the About page credits both fonts and links their OFL texts.

### Tokens: OKLCH primitives behind one semantic layer

- **Load order** `tokens.css` → `themes.css` → `app.css`. `app.css` defines no colour token any
  more (`TestTokenLayers`).
- **`tokens.css`**: the fonts; a scale for slices B–D that nothing uses yet (`--sp-1…8` on a
  4 px base, `--r-1/2`, `--fs-0…5` with two fluid `clamp()` sizes, `--lh-tight/body`,
  `--dur-1` 120 ms, `--dur-2` 200 ms, `--ease`, `--elev-1/2`, plus `--bar-h`); the mode
  (`color-scheme: dark` by default, light from the OS unless `data-theme`, or from
  `data-theme="light"`); and the **semantic layer**, written once: `--bg: var(--p-neutral-0)`,
  `--text: var(--p-neutral-9)`, `--ok: var(--p-ok-7)` and so on for the 22 names `app.css` has
  always used. The semantic block's selector is `:root, [data-palette]`, so a Display swatch
  with its own `data-palette` re-resolves the names against its own primitives (custom
  properties resolve `var()` where they are declared).
- **Primitive steps**: `neutral-0` canvas, `-1` surface, `-2` surface-2, `-3` border, `-6` field
  border, `-8` muted, `-9` text, `-10` focus; per family (`accent`, `ok`, `warn`, `crit`, `info`,
  `stale`) `-7` is the ink, `-1` its tinted background, `-0` the ink on a filled `-7`
  (`--on-accent`, `--on-danger`). `--danger` is `crit-7` (it was equal to `--crit` in every
  palette). Steps rise with contrast against the canvas, so the light mode is a flip of the
  same names.
- **`themes.css`**: six blocks of `--p-*` only, `light-dark(light, dark)` carrying both modes
  (OKLCH, `L` as a percentage). Each palette is written once instead of three times (dark, OS
  light, `data-theme` light), 174 → 167 lines; every line ends with the v0.7 hex it reproduces,
  which makes the file larger (14.6 KB, 4.3 KB gzipped). Graphite is `:root,
  [data-palette="graphite"]` and comes first: it is the default, and any later palette on the
  root wins by source order at equal specificity. High contrast keeps `--focus-w: 4px`.
- **Conversion**: a one-off script converted each v0.7 hex to OKLCH (sRGB → OKLab → LCH,
  Ottosson's matrices) at the shortest precision (L 2 decimals in %, C 4, H 2) that converts
  back to the same 8-bit value and stays inside the gamut; near-greys with C < 0.00005 are
  written `oklch(L 0 0)`. Not committed: slice B regenerates the ramps from the anchors
  (below), and the tests below define what any generator must satisfy.
- **Browser floor**: `light-dark()` needs **Chromium 123, Safari 17.5, Firefox 120** (`oklch()`
  alone: 111, 15.4, 113). Older browsers would see every palette value as invalid, so
  `tokens.css` ends with `@supports not (color: light-dark(#000, #fff))`, which sets the 22
  semantic names to plain Graphite dark hex (`TestLightDarkFallback` holds it to the golden
  file): every palette and mode looks like Graphite dark there, but stays readable.
  `forced-colors` rules are unaffected.

### Tests

- `oklch_test.go` (test-only helpers): CSS `oklch()` / `#rrggbb` → gamma-encoded sRGB without
  clamping. A colour is **out of gamut** when a channel needs more than half an 8-bit step of
  clipping, and is then reported instead of silently clipped. `light-dark()` splitting.
- `theme_contrast_test.go`: parses the semantic layer and the palette blocks, resolves
  `var()` chains (depth-limited) through each palette for each mode, and runs the unchanged pair
  checks (`TestThemeContrast`: text and status ≥ 4.5:1, 7:1 for text in High contrast, field
  border and focus ≥ 3:1, focus ring distinct from warning; every palette must define every
  primitive it is resolved through, so nothing falls through to Graphite).
  **`TestPalettesMatchV07Hex`** holds all 264 palette × mode × token values to
  `testdata/theme-hex-v07.txt` (generated from the v0.7 `themes.css`), exactly. `TestTokenLayers`:
  palettes define only `--p-*` (and `--focus-w`), no `color-mix()` or relative colours in the
  semantic layer, no colour token in `app.css`, Graphite is the default.
  `TestGraphiteMatchesBaseTokens` is gone (its job is now done for every palette).
  `TestColorMath`, `TestResolveErrors`: the converter, gamut detection, parse errors and
  resolver failures.
- `oklch_test.go`'s parser rejects malformed numbers (`oklch(1.2.3% 0 0)`), not just bad syntax.
- `fonts_test.go`, `tokens_fonts_test.go`: the size budget (≤ 120 KB per family, ≤ 250 KB total)
  and OFL texts; every `@font-face` url exists and swaps, one fallback per family, and
  `--font-ui` / `--font-mono` start with the face, then its fallback, then system fonts; the font
  headers and the unchanged one-hour cache elsewhere; both preloads and the sheet order on the
  sign-in page and a signed-in page; the About credit.
- `themes.spec.ts` gains "painted colours equal the v0.7 palette values": Chromium's computed
  colours, read back through a canvas as 8-bit sRGB (a colour that is not fully opaque is
  reported as such, so transparent cannot pass for black), for the page and 20 samples per
  Display swatch covering all 22 semantic names (`danger` = `crit`), in all six palettes; with
  the mode from the OS (dark, light) and from the app's own Theme switch (`data-theme=light`
  under an OS dark scheme and the reverse). It passes: the browser paints exactly v0.7.
- `internal/repopolicy`: `TestFontBuildsAreAppendOnly`, `TestFontBuildScriptMatchesVendoredVersions`,
  `TestPlaywrightImageMatchesTestRunner` (PW_IMAGE tag = locked `@playwright/test` = package.json
  pin), `TestRenovateTracksPlaywrightImage` (a regex manager extracts tag and digest; one
  "Playwright" group holds both).

### Visual baseline (plan 04 step 0)

`tests/e2e/visual.spec.ts`, policy in `tests/e2e/README.md`. 27 pages (the `pages.spec.ts` list
minus run-created content and the consoles) at 1440 × 900 and 390 × 844, dark and light, plus a
second clip one viewport down on pages taller than 1.5 viewports: 172 PNGs, about 17 MB.
Tolerance: `maxDiffPixelRatio` 0.2 % (0.5 % on text-heavy pages) and a per-pixel pixelmatch
`threshold` of **0.02**. The first version used 0.2, which is blind to tonal changes inside a
theme (pixelmatch compares a YIQ distance against 35215 × threshold²: 1409 at 0.2, while Graphite
`--bg` against `--border` is only 581). Checked: a Graphite border moved by 2.6 % OKLCH lightness
failed 37 of the 43 dark 1440 images at 0.02 and none at 0.03.

Excluded pages, compared with `pages.spec.ts`: the ones whose content the run creates (users, a
user, its disable and reset-TOTP confirms, API tokens and the revoke confirm, the audit log, the
enrollment link), the two consoles (live connection state drawn by script), and
`notify-new-pushover`, `notify-new-email` and `stepup` (form variants of pages already covered;
the step-up page also shows a run-dependent freshness window).

- **Deviation from plan 04 §3**: instead of "Linux only on CI's Ubuntu runner", the spec runs
  only inside the **pinned Playwright image** (`PW_IMAGE` in the Makefile, Playwright 1.63.0
  noble, multi-arch index digest run as linux/amd64, built 2026-09-04). `make visual` cross-compiles the harness
  (`GOOS=linux GOARCH=amd64 CGO_ENABLED=0`, so the image needs no Go) and runs the spec with
  Docker; CI's new **`visual`** job runs the same target on the runner. Local and CI therefore
  make the same pixels, and a runner image update (new system fonts) cannot rot the baseline.
  Without Docker the target refuses and explains the CI route. Outside the container the spec
  skips; `.gitignore` refuses `-darwin`/`-win32` PNGs. The container sees the repository
  read-only (only `tests/e2e` is writable: `node_modules`, `test-results`, `visual-baseline`;
  `npm ci --ignore-scripts`), runs as the invoking user with `--cap-drop=ALL`,
  `--security-opt no-new-privileges` and a 1 GB `/dev/shm` instead of the host IPC namespace.
- **Determinism**: reduced motion, animations off, hidden caret, CSS scale, fonts awaited, and
  a wait for the mock servers' first security check (the fleet table shows "Checking now" until
  then). Masks: times, clock, the data-age chips (their own `age-chip` class, so the Events
  count and filter chips are compared), the data-age line, poll durations, footer, step-up lines,
  mock certificate fingerprints, the inventory "Probed" value, the notification delivery table.
  A mask hides pixels but not width, so `visual.css` (injected while shooting through
  `stylePath`; the contexts set `bypassCSP` because the strict CSP blocks the injected `<style>`)
  fixes the width of the masked inline boxes and gives times tabular digits. Three template
  hooks, no visible change: `span.strip-age` on Overview, `p.polltook` on Inventory, and the
  `age-chip` class on the data-age chip partial.
- **Determinism is not yet proven where it matters.** The only evidence is a dry run on macOS
  Chromium outside the container: after one `--update-snapshots=all`, every compare run passed on
  all 172 images (five runs at threshold 0.2, three at 0.03 after the age-chip hook, two at 0.02).
  Inside the pinned image it is **unproven until the first baseline exists and a second run
  compares against it**. Procedure: push the branch; run the `ci` workflow by hand with
  `visual_update=true` (it runs `make visual-update`: write every PNG, then one compare run in the
  same job, which is the first determinism check); download the `visual-baseline` artifact into
  `tests/e2e/visual-baseline/` and commit it in a `[visual]` commit; the next ordinary CI run then
  compares in a fresh container (the second check). Only then does slice B make the job blocking.
- **Advisory** in slice A (`continue-on-error`); blocking from slice B. A compare run passes
  `--update-snapshots=none` (it never writes a baseline; a missing PNG fails and its
  `-actual.png` is in the `visual-diffs` artifact). The `visual-baseline` artifact is uploaded
  only by a manual run with `visual_update=true`.
- **Status of the frozen baseline**: the PNGs are **not committed on this branch**. This
  machine has no Docker and the branch is not pushed, so no image-made baseline could be
  generated, and macOS PNGs are deliberately not valid. Freeze it with `make visual-update` on
  any machine with Docker, or by running the CI workflow by hand with `visual_update=true` once
  the branch is pushed, and commit `tests/e2e/visual-baseline/` in a `[visual]` commit (the
  procedure above).

### Target anchors for slice B (decision)

Accent cyan-teal H 198; status hues OK 158, warning 78, critical 24, info 245, stale 98; a slate
"off" tone for powered-off servers; the accent at least 40° from every status hue. Today's
Graphite is already close: accent H 207 (dark) / 216 (light), OK 160 / 156, warning 75 / 64,
critical 23 / 29, info 248 / 249, stale 90 / 85. Slice B rewrites the primitives (all six
palettes, both modes) against these anchors; `TestPalettesMatchV07Hex` is then retired in the
same commit and `TestThemeContrast` stays the gate.

### Gates (2026-10-22, after the security and code review fixes, on the rebased tree)

`gofmt -l .` empty; `make vet`; `go vet -tags e2e ./...`; `make noexec`; golangci-lint v2.14.0:
0 issues; `make actionlint` ok (shellcheck is not installed on the machine that ran it; CI
requires it); `make cover`: 91.9 % total, every gated package ≥ 80 % (lowest: cmd/oob-console
86.0 %; web/ui 90.5 %); `go test -race -count=1 ./...`: 42 packages ok; `make e2e-go` ok;
`make e2e-ui E2E_PORT=18444`: 15 passed, 4 skipped (the visual spec outside its container).
`tools/fonts/build-fonts.sh` rebuilt both woff2 byte-identically.

## 36. Rename to oob-manager (2026-10-22)

The maintainer renamed the project `oob-console` → `oob-manager` (the name is free on GitHub and Docker
Hub). Branch `rename-oob-manager`. Operator steps: `deploy/README.md`, "Upgrade",
"Old names from before the rename (oob-console)".

**Renamed:** the Go module path and `cmd/oob-manager`; the binary (`/usr/local/bin/oob-manager`),
image, OCI title, Makefile/CI image and SBOM names; CLI usage, version and error output; the GELF
`host` field (`audit.DefaultHost`), the TOTP issuer of new enrolments (`auth.DefaultIssuer`), the
Dell KVM `SessionTypeName`, the bearer realm, the SSH client version (serial console and security
probes), the probes' HTTP control path, the SMTP HELO name and mail signature, the notify
User-Agent (`oob-manager-notify/1`), the gen-tls certificate Organization; every UI and help text.

**Kept on purpose:**

| Value | Why |
|---|---|
| HKDF purposes `oob-console/{csrf,bmc-cred,tofu,notify}/v1` (`internal/secrets`) and `oob-console/ui-resume/v1` (`internal/web/ui`) | HKDF inputs: a new label derives a new key, which would orphan sealed BMC credentials and notification secrets, break TOFU pin proofs and invalidate open forms. Frozen by `TestPurposeLabelsArePinned` (golden derived keys) and `TestResumePurposeIsPinned`. |
| Audit hash domain `oob-console/audit/v1` | part of every stored `row_hash`; a new domain makes `Verify` flag the whole existing chain. Frozen by `TestHashDomainIsPinned` (golden row hash). |
| Console ticket session-hash domain `oob-console/console-ticket/v1` | in memory only, but kept so the rename changes no hash or key anywhere (`TestSessionHashDomainIsPinned`). |
| Metric names (`oob_*`, including `oob_console_sessions_active`) | `console` there is the feature (console sessions), not the product; dashboards and alerts keep working. |
| `OOB_*` environment variables, the `oobk_` token prefix, the `__Host-oob_sid` cookie | no product name in them; tokens and sessions survive the upgrade. |

**Compatibility fallbacks** (`cmd/oob-manager/paths.go`, tests in `paths_test.go` with injected
temp paths via `env.paths`):
- Without `-config` the binary reads `/etc/oob-manager/config.yaml`; if that file does not exist and
  `/etc/oob-console/config.yaml` does, the old file is used. An explicit `-config` always wins; an
  explicit empty one (`-config ""`) is refused.
- The database default is now `/data/oob-manager.db`. When `storage.db_path` is not set
  (`StorageConfig.DBPathDefaulted`), the new file does not exist and `/data/oob-console.db`
  (`config.LegacyDBPath`) does, the old file is opened, so an upgrade never starts on a silent
  fresh database. If both exist, the new one is used and a warning names both. A `db_path`
  written in config.yaml is never changed.
- The database fallback sits behind `legacyDBFallback` (on). When a later release turns it off,
  an install with only the pre-rename file refuses to start and the error names both files
  (`TestLegacyDBWithoutFallbackRefusesToStart` pins that branch now).
- Only `serve` logs the warnings (`deprecated config path`, `deprecated database path`, two
  databases), once each per start; the CLI subcommands stay quiet.
- Existing authenticator entries keep their `oob-console` label: the issuer is not part of TOTP
  verification.

Historical records in this document (dated gates, coverage tables, the repository-hygiene note) and
the dated reviews keep the old name; so do references to the sibling folders outside the repository
(`oob-console-research/`, `oob-console-design/`, `oob-console-artifacts/`), which were not renamed.

The visual baseline (`tests/e2e/visual-baseline/*.png`) still shows the old name; the visual job may
fail on this branch. After the merge, regenerate it by hand: run the CI workflow with
`workflow_dispatch` and `visual_update=true`, then commit the uploaded `visual-baseline` artifact in a
`[visual]` PR.

## 37. Implementation notes (BMC restart, plan 01)

Branch `bmc-reset`, started from `main` @ `3358e51` and rebased onto `main` @ `93befdf` (2026-10-23). Plan: `docs/plans/01-bmc-reset.md`; the
decisions of 2026-10-23 are recorded in its §18. An admin restarts a hung BMC from the Operations tab
with the safety model of a forced power action; while the BMC is away the app shows "BMC restarting"
instead of raising "unreachable", and checks that it came back. Nothing was run against real hardware:
every test uses `redfishmock`.

**Decisions:** cooldown 10 minutes per server; a reset ends any console on the
server, including another admin's, and audits it (the admin has takeover rights anyway); new
notification class `bmc`; on iDRAC8 the app detects a privilege refusal and says the operator account
needs *Configure iDRAC* (whether to grant it waits for the maintainer's one-time hardware test); that test
(one reset per BMC) is the maintainer's, after merge (`deploy/README.md`, "Enabling BMC restart").

**Packages and files.**

| Where | What |
|---|---|
| `internal/bmc/redfish/managerreset.go` | `IsManagerResetActionURI`, `OpenManagerResetter`, `ManagerResetter.Reset/Close`, `managerResetOffered`, `parseLastReset` |
| `internal/bmc/redfish/probe.go`, `docs.go` | the probe decodes the Manager's `#Manager.Reset` (target, allowable values) and `LastResetTime` |
| `internal/bmc/capabilities.go`, `errors.go` | `CapabilityFlags.ManagerReset`, `.BMCLastReset`, `Capabilities.ManagerResetTypes()`; `bmc.ErrPrivilege` (wrapped with `ErrAuth`, class `auth`) |
| `internal/bmc/redfishmock/managerreset.go` | `WithManagerReset(downtime)`, `FailNextManagerReset(code)`, `ManagerResetStats`, `ManagerRestarting` |
| `internal/fleet/restart.go` | the restart window: `ExpectRestart`, `CancelRestart`, `RestartWindow`, `RestartEnd`, `Config.RestartQuiet/RestartRetry` |
| `internal/bmcreset/` | the service: `Request`, `Start` (re-arm), `SetTargets`, `State`, `Info`, `Counts`, `Deadline(kind)` |
| `internal/store/bmcresets.go`, `migrations/0013_bmc_resets.sql` | the `bmc_resets` table and repository |
| `internal/console/bmcreset.go`, `internal/fan/bmcreset.go` | `EndForBMCReset`, `ForgetProbe`, `ForgetAttempt`; `ReapplyAfterBMCReset` |
| `internal/power` | `Config.Restarting`: power refuses while the BMC restarts (`ErrBMCRestarting`, `denied:bmc_restarting`) |
| `internal/notify/tap_bmc.go` | `ClassBMC` and the audit tap mapping; `detect.go` skips reachability during a window |
| `internal/metrics/bmcreset.go`, `internal/api/bmcreset.go` | three metric families; `bmc_restarting` and the `bmc` object |
| `internal/web/ui/bmc_reset.go`, `bmc_reset_confirm.go` | BMC panel, confirm page, POST; the restarting state in `views.go`, `summary.go`, `chrome.go`, `serverpage.go`, `overview.go` |
| `cmd/oob-manager/bmcreset.go` | wiring (targets from the operator login, AfterBack, adapters); runtime, janitor, serve |

**Transport allowlist, sixth exception (security.md §3a).** Exactly `POST
/redfish/v1/Managers/<id>/Actions/Manager.Reset`, `<id>` 1–64 of `[A-Za-z0-9._-]`, no `..`, no query or
fragment, on a driver built only by `OpenManagerResetter` with `WithActionPolicy(IsManagerResetActionURI)`
and the operator login. Discovery walks service root → first system → `Links.ManagedBy[0]` (else the
first Manager); the advertised target must equal `<manager>/Actions/Manager.Reset` and list
`GracefulRestart`, otherwise `ErrUnsupported` (and the session is closed). The body is the one-field
struct `{"ResetType":"GracefulRestart"}`. A 401 is not retried (`PostAction` never retries); a 403 is
`ErrPrivilege`. `Close` treats unreachable, timeout, 5xx and (inside `Driver.Close`) 401/404 as success,
because the BMC drops the session when it restarts. Tests: the URI table (ResetToDefaults, the Dell OEM
actions, export, `..`, query, fragment, case), foreign or ResetToDefaults targets, ForceRestart-only and
absent actions refused before any POST; the poller's driver and the power resetter's driver refuse the
URI before a byte is sent.

**Discovery (read-only, inventory tier).** `#Manager.Reset` and `LastResetTime` are read leniently from
raw JSON (`managerExtras`), and the typed Manager decode never sees them, so a wrongly typed field reads
as "not offered" / "unknown" instead of `ErrDecode` breaking discovery and all polling (review S-M2).
`CapabilityFlags.ManagerReset` is true only for the manager's own action with `GracefulRestart`; both captured fixtures offer it (iDRAC8 2.86 and iDRAC9 7.00 list
`["GracefulRestart"]`). `BMCLastReset` is iDRAC9's `LastResetTime` (iDRAC8 reports none). The stored
capability JSON gains `manager_reset_types` (additive).

**Fleet restart window.** `ExpectRestart(id, window, done)` stores an immutable `restartState` in the
poller (`atomic.Pointer`) and wakes it, so the quiet period counts from the request. While it is open:
no poll for `RestartQuiet` (60 s) after `Since`; then one every `RestartRetry` (30 s), never past
`Until`, bypassing the breaker; failures set `LastError` only (no `ConsecutiveFailures`,
`FailingSince` or breaker), also for a poll that was already running when the window opened; the slow
tiers wait. On the first good snapshot the inventory tier runs at once (firmware and `LastResetTime`)
and `done(back)` fires with the state as published after the window closed. The cycle at (or after)
`Until` still polls: a good answer takes the back path; a failed one ends the window as `timeout` and
starts the failure streak there, so "unreachable since" is the deadline (review C-M1). A window may last
at most `MaxRestartWindow` (15 min), also enforced by the migration (review S-L5). `ExpectRestart`
re-checks the roster after its CAS and `Apply` drops retired pollers' windows after the roster swap, so a
window racing an `Apply` is refused or ended `config_changed`, never left on a retired poller (C-L1). A pin mismatch inside the window pauses polling and ends it (`timeout`, state
`PinMismatch`). `Apply` keeps the window of an unchanged server and ends a rebuilt or removed one with
`config_changed`; shutdown ends nothing (the row stays open and the next start re-arms it).
`CancelRestart` closes a window without the callback (a refused POST). `ServerState.Restarting` is
computed on read and false once the deadline passed. The callback runs on the poller goroutine (or in
`Apply` under the fleet lock) and must not block; the service hands the work to its own goroutine.

**Service flow (`bmcreset.Request`).** Target known → operator login → no power operation pending →
no window open and no other request in flight → cooldown reserved (10 min; `*CooldownError`) and the
server marked **busy** (review S-M1: `Busy(id)` is true from here until the request returns, and then
while the window is open; the power service's `Restarting` hook reads it, so power waits during the
login and discovery too) → `bmc.reset` `started` with `deadline_after` (fail-closed: `ErrAudit`, the
cooldown given back, nothing else happens) → operator login and discovery → fleet window and
`bmc_resets` row (`sent`), both stamped **now**, just before the POST (`sent_at`; `requested_at` stays the
request for the audit and the cooldown; review S-L1), under the service lock → every console on the
server ended (`EndForBMCReset`, reason `bmc_reset`), right before the POST (review S-L3) → one POST →
close. A failure before the POST gives the cooldown back and clears the busy mark (`not_offered` and
`restarting` are `denied`, login trouble is `error` with its class; a paused server is `tls`); these rows
carry `after_started`, so the tap closes the "requested" alert (review S-L4). A POST without an answer
(timeout, or the connection lost after the request was written: unreachable) counts as sent
(`outcome: sent_unconfirmed`, `bmc_status` the class) and marks the row `unconfirmed` (review C-M2). Any other POST failure cancels the window, closes the row as `refused`
with the class and keeps the cooldown; a 403 also sets the sticky privilege refusal (`ErrPrivilege`),
cleared by the next success, `SetTargets` (hot apply) or a restart. Deadlines per kind
(`bmcreset.Deadline`): iDRAC9 3 min, iDRAC8 and others 5 min, constants.

**Verification.** `back` → row `verified` with `back_at`; the downtime counts from `sent_at`. On a BMC
that reports `LastResetTime`, judged only when the capabilities were probed at or after the POST (review
C-M4; else `last_reset_time_check: not_done`), a value older than the POST (one second of slack, the BMC
reports whole seconds) marks the row `last_reset_time_unchanged`. An `unconfirmed` POST is confirmed
only by a newer `LastResetTime`; otherwise the row says `restart_unconfirmed` and the panel reports the
restart as not confirmed (iDRAC8 reports no `LastResetTime`). Audit `bmc.reset.verified` `ok` by
`system` with `downtime_s`, `firmware_version`, `last_reset_time` or `last_reset_time_unchanged: true`
or `last_reset_time_check`, `post_unconfirmed`, and `rearmed` when the app restarted during the window
(part of it was not watched; review S-L5). Final audit rows and row updates are retried (3 attempts); a
write that keeps failing is logged as an error naming the outcome (review S-L4). Then `AfterBack`
(2 min bound, cancelled by `Shutdown`): the VNC banner probe and the serial console's last attempt are
forgotten ("Not checked yet", re-probed on the next tick) and an active, unexpired `redfish-floor` lease
is applied again (idempotent, audited `fan.lease.reapply` with `reason: bmc_reset`; the lease's expiry
does not move; a `host-lease` is untouched), retried with backoff (5, 10, 20, 40 s) and then handed to
the fan reconciler (`fan.Service.RequestReapply`), which also gets every restart that timed out
(`AfterTimeout`): it tries again when due, backing off from 1 to 15 minutes while the BMC does not
answer, and audits only the success (review C-M3). Windows that end after `Shutdown` are ignored: the
row stays open for the next start (review C-L2). A window that ends otherwise closes the row as `timeout` with class
`timeout`, `config_changed` or `tls`, audited as `bmc.reset.verified` `error`. At startup `Start` loads
the cooldowns and the panels' last rows, re-arms every `sent` row whose deadline is still ahead and
closes the others as `timeout` / `unobserved` (the app was down when the BMC was due back; a row whose
server is gone becomes `config_changed`). A re-armed window starts at `sent_at`.

**Data model: migration 0013 `bmc_resets`.** As planned (`STRICT`, `reset_type` checked to
`GracefulRestart`, `result` in `sent, refused, verified, timeout`, index on `(server_id, requested_at)`)
plus three columns: `sent_at` (just before the POST, `>= requested_at`), `unconfirmed` (0/1: the POST got
no answer) and `detail` (`''`, `last_reset_time_unchanged` or `restart_unconfirmed`, so these verified
cases are not stored as error classes), and the window CHECK `deadline_at > sent_at AND deadline_at -
sent_at <= 900000` (15 min). Migration 0013 was edited in place during the review (it was never
released). A row exists only when a POST was
attempted. `Finish` is a compare-and-set from `sent`, so the first outcome wins. The janitor prunes rows
older than 400 days (`bmcreset.Retention`).

**Audit.** `bmc.reset`: `denied` (UI and service classes `csrf`, `unconfirmed`, `confirm_mismatch`,
`stepup_required`, `forbidden`, `rate_limited`, `cooldown`, `power_pending`, `restarting`, `not_offered`,
`no_operator`, `privilege`, `not_configured`), `started` (`reset_type`, `deadline_after`), `ok` (`outcome`,
`bmc_status`, `consoles_ended`, `deadline`), `error` (class; `after_started` when nothing was sent).
Deviation from the plan: `consoles_ended` and the deadline are on the final row, not on `started`,
because the consoles end and the window is stamped only right before the POST, long after the `started`
row (fail-closed: nothing disruptive happens without it). `bmc.reset.verified` as above. Every row carries the server and
the request's correlation ID.

**Notifications.** Class `bmc` ("BMC restarts"), not suppressed by maintenance, subscribable, listed
in `config.NotifyClasses()`. The tap maps `bmc.reset started` → warning "BMC restart requested",
`bmc.reset error` → warning "failed (class)", `bmc.reset.verified ok` → the recovery of the request
(same key `bmc/<id>`, quiet priority) "BMC back … N s after its restart", `bmc.reset.verified error`
→ critical "did not come back" for `timeout`, warning otherwise. A refusal that follows the started row
(`after_started`) is sent as the recovery of the request ("BMC restart not sent"), so the requested alert
never dangles; refusals before it and the POST's own `ok` raise nothing. The detector reports no reachability change while `Restarting`; after a timeout the next pass
reports it as usual. Targets saved with an explicit class list are not subscribed until edited (the
form marks the class as new); a target with an empty list (`config.yaml`) gets every class, `bmc`
included (`deploy/README.md`, upgrade notes).

**Metrics (additive).** `oob_server_bmc_restarting{server}`,
`oob_server_bmc_last_reset_timestamp_seconds{server}` (the BMC's `LastResetTime`, else the app's last
verified restart, else 0) and `oob_bmc_resets_total{server,result}` (`sent`, `refused`, `verified`,
`timeout`, since start). Deviation: no `name` label; like every per-server family they carry `server`
only and the name stays on `oob_server_info`.

**API (additive).** `/api/v1/servers` gains `bmc_restarting`. `/api/v1/servers/{id}` gains `bmc`:
`reset_supported`, `restarting`, `restart_requested_at`, `restart_deadline`, `last_reset_time` (null
when the BMC does not report it), `last_app_reset` `{at, by, result}` (null without one). `stale` keeps
its honest value.

**UI.** Operations: a **BMC** panel under Power (left column): model, firmware, "Last BMC restart"
(the BMC's `LastResetTime`, else the app's last verified restart, else "Not reported"), the latest
outcome as a `role=status` line, and `Restart BMC…` (`btn-danger-outline`), disabled with the first
reason that applies: Not determined yet · Not offered by this BMC · Needs an operator BMC account ·
Needs the admin role · BMC is restarting (back by HH:MM) · A power action is still being verified ·
The operator account lacks the privilege (last attempt) · Cooling down for N min. A viewer sees status
only. `GET/POST /servers/{id}/bmc/reset` reuse `confirm.html` (tier danger, badge "Monitoring pauses",
typed name always, Cancel focused, step-up inline, warnings for open consoles by name, self-host and the
fan mode). 429 with `Retry-After` during the cooldown. While a window is open: the server page verdict
reads "BMC restarting · requested … by … · expected back by …" with `role=status`, the stale banner and
the data chip say "BMC restarting", the sidebar entry and the fleet table use the stale style with that
wording, the fleet pill counts "N restarting" (its own count, not "stale"), Needs attention lists it,
and power actions are disabled ("The BMC is restarting; power actions wait until it is back"). The
step-up page names "Restart BMC · <server>"; Help gains "BMC restart" in the glossary.

**Tests.** Unit: redfish URI table, discovery and refusals, privilege, no 401 retry, other drivers
refused, probe flags; redfishmock option; fleet window with the fake clock (quiet, retries without
breaker, back with inventory, timeout then counted, hidden after the deadline, refusals, pin mismatch,
Apply keep/drop); store repository and migration density; service (order of side effects, fail-closed
audit, interlocks, cooldown reserve/return, refusals before the POST, sticky privilege, POST outcomes,
verification incl. unchanged `LastResetTime`, window ends, start re-arm); console and fan helpers;
power interlock; notify tap and detector; metrics golden scrape; API fields; UI panel reasons, roles,
status lines, confirm page, typed name, CSRF, step-up, cooldown, service errors, rate limit, restarting
wording; cmd targets and adapters. e2e (Go, its own stack: a restart drops every mock session, which
would upset the main stack's session accounting): panel on both generations, a serial console ended
with `bmc_reset`, the typed name, the window (API, pages, a power action refused), verification with
`bmc` notifications and no reachability event, the cooldown, an iDRAC8 403. Playwright:
`bmcreset.spec.ts` (panel, confirm page with axe at 1440/390 in both schemes, typed-name error, a
restart of the R240 mock with the restarting server page and the verified result) and
`confirm-bmc-reset` in `pages.spec.ts`. The e2e harness sets the window cadence to 1 s through
`env.restart` (test hook only).

**Review fixes (2026-10-23, after the rebase).** S-M1 busy marker and power interlock; S-M2 lenient
decode; S-L1 window stamped at the POST; S-L3 consoles ended right before the POST; S-L4 closing
alert and retried final rows; S-L5 15-minute cap, downtime from the POST, `rearmed`; C-M1 poll at the
deadline; C-M2/S-L2 `sent_unconfirmed` for a lost connection, `restart_unconfirmed`; C-M3 fan floor
retries and the reconciler hand-off; C-M4 fresh-probe check; C-L1 ExpectRestart/Apply race; C-L2
shutdown; C-L8 tests (busy during a blocked login, concurrent requests under `-race`, a window ending
during `Shutdown`, OnVerified before the power operation is final, recovery exactly at the deadline,
wrongly typed Manager fields, a power request during a blocked login through `powerInterlock`).

**Review fixes, second round (2026-10-23).** N1: the busy mark is keyed by the request's correlation ID,
so a late `idle`/`release` never clears (or gives back the cooldown of) a newer request. N2: the reset
re-checks for a pending power action after its reservation, and the power service re-checks the
interlock inside its own reservation, before it supersedes a running verification; that reservation
also publishes the power operation as Sending (under the same lock), so a reset sees it pending while
power writes its "started" row, and a failed write puts the previous operation and cooldown back. N3: a return that
does not confirm the restart (`restart_unconfirmed`, `last_reset_time_unchanged`) is not a restart: the
service's and the store's `LastVerified` (empty detail only), the panel's "Last BMC restart" and
`oob_server_bmc_last_reset_timestamp_seconds` ignore it; the verified row carries `restart_confirmed`
and the recovery notification then reads "restart not confirmed". (A POST without an answer whose BMC
reports a newer `LastResetTime` is confirmed by the BMC itself and counts.) `ExpectRestart` losing a race
with a hot apply of a server that still exists is tried once more. The AfterBack fan loop is
`reapplyFanFloor` (no pause after the last attempt), and it and the reconciler's pending re-apply have
deterministic tests (`internal/fan` 91.2 %).

**Not done / open.** The one-time hardware verification (after merge): privilege needed on
iDRAC8 and iDRAC9, HTTP status, downtime, fan behaviour, whether `MinimumFanSpeed` survives on iDRAC9,
`LastResetTime`; then update the "unverified" cells of plan 01 §5. IPMI `mc reset` stays out of scope.
The visual baseline is not refreshed on this branch (the Operations page changed): regenerate it after
the merge as in §36.

## 38. Implementation notes (firmware view, plan 03)

Branch `firmware-view`, from `main` @ `23915e6` (2026-10-23). Plan: `docs/plans/03-firmware-view.md`; the
decisions of 2026-10-23 are recorded in its §18. A read-only view of what firmware runs where: readable
component names instead of `Component 101068`, running / previous / staged versions, the release date and
age where the BMC reports it, a file-only "minimum known good" list, a slow poll tier with Re-scan, a CSV
export, and change detection. **Firmware updates stay out of scope (CLAUDE.md rule 11):** nothing here can
push, stage or apply firmware. Nothing was run against real hardware: every test uses `redfishmock`.

**Decisions:** firmware flags stay off Overview › Needs attention (the Firmware page and
its sidebar count carry them); `server.firmware.changed` maps to the existing `security` notification class;
`firmware.minimum` is file-only (no Settings editor in this slice) and the BMC's own minimum is
`security.min_firmware` only; the age flag is off by default. The read-only capture of the real member
documents is the maintainer's step later (deploy/README, "Capturing the firmware documents of a BMC").

**Packages and files.**

| Where | What |
|---|---|
| `internal/firmware` | pure logic: `CompareVersions`, `KindFromName`, `KindFromRelated`, `Merge` (Dell states into one `Component` per key), `Policy` / `Rule` / `Verdict` / `Flag`, `DisplayName`, `BuildRows`, `SortRows`, `Filter`, `ReleaseText`, `Diff`, `Sticky`, `NeedsDocument` |
| `internal/firmware/catalog` | the offline catalog interface (`Catalog`, `Key`, `Release`, `Info`) and `Null()`; nothing imports a catalog yet |
| `internal/bmc/firmware.go` | `FirmwareKind` (closed enum), `FirmwareScan`, the optional `FirmwareScanner`, `MaxFirmwareMembers` (64); `FirmwareItem` gains `Kind`, `ReleaseDate`, `Updateable`, `Identity`, `Detailed`, `Named` |
| `internal/bmc/redfish/firmware.go` | `FirmwareDocument`, `FirmwareMembers`, the generic `ScanFirmware` (every member document, bounded) |
| `internal/bmc/dellredfish/firmware_scan.go` | the Dell `ScanFirmware`: versions from the member IDs, one member document per component that needs it, kinds from the FQDD prefix, the known component IDs, `DellSoftwareInventory.ComponentType` and name keywords |
| `internal/bmc/redfishmock/extra.go` | `WithExtraFixtures(dir)`: SYNTHETIC documents next to the captured fixtures |
| `internal/fleet/firmware.go` | the firmware tier, `FirmwareSink`, `Tier`, `Fleet.Refresh(id, tier)`, `ErrNoTier` |
| `internal/store/firmware.go`, `migrations/0014_firmware.sql` | the three tables and the repository |
| `internal/fwinventory` | the service: `Record`/`Need` (the sink), `Table`, `Server`, `Counts`, `WarnCount`, `Rescan`, `SyncServers`, `Prune`; the CSV columns and writer, `ParseFilter`, `Query` |
| `internal/csvx` | the shared CSV writer (plan 02 reuses it) |
| `internal/config/firmware.go` | the `firmware:` block |
| `internal/notify/firmware.go` | `FirmwareEvent`: one `security`-class message per scan with changes |
| `internal/metrics/firmware.go`, `internal/api/firmware.go` | four metric families; three API resources |
| `internal/web/ui/firmware_iface.go`, `firmware_view.go`, `templates/firmware.html`, `firmware_partials.html` | `/firmware`, its CSV, Re-scan, the Inventory section, the sidebar entry |
| `cmd/oob-manager/firmware.go` | wiring: the lazily connected fleet sink, the policy, registry sync |

**Reads (all GET, read-only account, no transport exception).** The tier lists
`UpdateService/FirmwareInventory` (one GET, at most 64 members; `Members@odata.count` is kept as the
listed count). Dell parses the member IDs (`<State>-<ComponentID>-<Version>[__<FQDD>]`); any unparseable
ID falls back to the generic path, which reads every member document. Then, for each component (component
ID + FQDD) that `Need` selects, the Dell driver GETs **one** member document, of the running state's member
(Current, else Installed, else Available, else Previous): `Name`, `ReleaseDate`, `Updateable` and, on
iDRAC9, `Oem.Dell.DellSoftwareInventory.ComponentType` and `IdentityInfoValue[0]`. `Need` asks for a
document when the component is unknown, unnamed, named more than 30 days ago (`firmware.DocRefresh`) or its
running version changed (the release date belongs to the version). An absent (404) or undecodable document
leaves the ID-derived item (the driver's fallback name, its kind); other errors count as `DocsFailed`. A scan
cut by its budget returns what it read with `Complete=false`. Strings pass `textclean` and are capped (names
128, versions 64, identifiers 128 bytes). The repository policy test `TestNoFirmwareUpdatePath` fails the
build if any Go source names `SimpleUpdate`, `HttpPushUri`, `MultipartHttpPushUri`, `StartUpdate`,
`UpdateService/Actions` or the Dell update service; the driver tests and e2e assert the mocks saw GETs only.

**State merge (Dell; corrected in v0.8.1, see "Firmware states corrected" below).** An `Installed-` member
is what the device runs (iDRAC9 OEM `DellSoftwareInventory.Status` "Installed", with an installation date); a
`Current-` member is the image the BMC holds in its firmware store (OEM status "AvailableForInstallation",
installation date "NA", an image hash), usually the same version. Running = `Installed`, else the generic
version, else `Current` (nothing better is known); Previous = `Previous`; Staged = `Available`; when `Current`
and `Installed` both exist and differ, `Current` goes to `stored` (an image the BMC holds but never installed;
the iDRAC8 fixture's backplane runs `Installed-101434-2.23` and holds `Current-101434-2.25`). A stored image
newer than the running version flags the row **Not applied** (info); an older or incomparable one is shown
without a flag. The name and details come from the running state's document, else any read document; the
release date only from the running state's.
Generic Redfish has no states: the key is the member ID and the version is running.

**Kinds.** `bmc, bios, cpld, nic, storage, drive, enclosure, psu, lc, other` (the store's CHECK list). Dell
order: FQDD prefix (`iDRAC.` bmc, `BIOS.` bios, `CPLD.`, `NIC.`, `RAID.`/`AHCI.`/`NonRAID.` storage,
`Disk.` drive, `Enclosure.`, `PSU.`, `USC.`/`LC.`/`DriverPack`/`Diagnostics`/`OSCollector`/`ServiceModule` lc;
any other FQDD is other), the known component IDs (159 bios, 25227 bmc, 27763 cpld, 28897/18981/25806/
101734/104684 lc), `ComponentType` (`BIOS`, `APAC` → lc), Dell words (iDRAC, Lifecycle, PERC, HBA, BOSS,
BP13G–BP16G), then the generic keywords (BIOS, remote access controller, BMC, CPLD, disk/SSD/HDD/NVMe
before backplane/enclosure, power supply/PSU, ethernet/network, RAID/storage controller). Generic Redfish:
`RelatedItem` (Drives, PowerSupplies, EthernetInterfaces/NetworkAdapters, Storage, Processors → other,
Managers, the system or its Bios, a chassis), then the name. A stored row keeps the kind its document gave.

**Display names.** The member document's name; else `firmware.names[<component id>]` from config.yaml;
else the driver's known name (BIOS, iDRAC, the FQDD); else "Unnamed component (ID n)" (UX-10).

**Versions and the minimum (one source of truth).** `firmware.CompareVersions` splits on `.`, pads with
`0`, compares numeric segments as unbounded numbers and alphanumeric segments run by run (digits as
numbers, letters case-insensitively); a number against letters, runs that do not line up, an empty
segment or an empty version is incomparable. `bmcsec.CompareVersions` now delegates to it, so the
security check `fw.bmc` and the Firmware page judge a BMC alike. Rows of kind `bmc` are judged only
against `security.min_firmware.<kind>` (`MinimumSource` `security.min_firmware.idrac8`); `firmware.minimum`
rules never apply to them, and a rule with `kind: bmc` fails the load. For other rows, of the matching rules
(a rule that can only match the BMC's own row, component 25227 or an `iDRAC.` FQDD, fails the load too)
the first the running version is below wins, else the first it cannot be compared with (**Cannot compare**,
never "below"), else the highest that passes (**OK**); no rule: no flag. **Stale release** (info) when
`firmware.stale_after` > 0 and the release is older. Flags sort worst first: below minimum, not applied,
cannot compare, stale release, OK, none. The sidebar counts below minimum only (`Flag.Warn`).

**Data model: migration 0014.** `firmware_components` (as planned, plus `named`: the name came from a
document, and `doc_read_at`: when it was read; the plan's "last_seen older than 30 days" refresh became
`doc_read_at`, because `last_seen` moves at every scan), `firmware_changes` (plus `name`: the display name
at the time, so the history stays readable after the row is gone; CHECK `after <> before`) and a third table,
`firmware_scans` (one row per server: when, members listed, components, complete, documents read and
failed, and the system model at the time, so model rules apply before the inventory is read again after
a restart), so "last scan" and "64 of N" survive a restart without a scan. Strict tables, bounded strings. The
janitor prunes changes after 2 years (`fwinventory.ChangeRetention`). A browser-managed server's rows go
with it in `registry.Delete`'s transaction; every registry apply hands the service the registry's IDs
(enabled or not) and it deletes the rows of the others (a server removed from config.yaml).

**Recording a scan (`fwinventory.Record`).** Under the service's write lock: merge, sanitize, keep what
earlier documents taught (`firmware.Sticky`: name, kind, updateable, identity; the release date only while
the running version is the same), keep the stored states an incomplete scan did not list (a Dell component whose
Installed- member was not listed keeps its stored running version and takes a different Current- version as
the stored image, instead of reading as an upgrade; one whose Current- member was not listed keeps its stored
image while the running version is the same; `Component.Members`, set by the merge and never stored, tells a
missing member from two listed at one version), and keep stored components it did not list: the most
recently seen first, at most `MaxRowsPerServer` (128) rows per server, dropping those no scan has listed for
`UnlistedExpiry` (30 days); a complete scan that lists nothing while rows exist counts as incomplete (a
glitch is not every component disappearing). Components equal once cleaned are stored once (the Dell parser
cleans the FQDD too), and `last_seen` is never before `first_seen` (a clock step back). `firmware.Diff` compares running, previous and staged: a
component that appeared has `before ''`, one that disappeared (complete scans only) `after ''`; the first
scan of a server is no change. One transaction replaces the server's rows, appends the changes, upserts the
scan row and writes one audit row per stored change: `server.firmware.changed`, principal `system`, params
`component` (display name), `component_id`, `fqdd`, `field`, `before`, `after`. At most `MaxChangesPerScan`
(16) changes are stored and audited one by one; beyond that one summary row (`summary: true`, `changes`,
`components`, `recorded`) counts the rest (the metric counts every change). Then the in-memory copy is
replaced (`atomic.Pointer`; readers never lock), the cached sidebar count is cleared, and one notification
is sent for the scan (below).

**Firmware tier (`fleet/firmware.go`).** Enabled when the driver implements `bmc.FirmwareScanner` and a
`FirmwareSink` is wired (`ServerState.FirmwareEnabled`; IPMI servers have none). It runs after the inventory
tier, under its own cycle budget: at start, every `FirmwareEvery` (24 h), on `Fleet.Refresh(id,
TierFirmware)`, right after a BMC restart window ends with the BMC back (`restartCycle` zeroes it with the
inventory tier, and runs it only after `endRestart`, so the window is reported back promptly) and when the inventory tier's ID-derived list differs from the last good scan's signature
(members and versions), so a version change is noticed within the 6-hour inventory period at the cost of
the cheap list read. A failed scan (driver or sink) keeps the stored scan, sets `FirmwareError` and is
retried after `EventsEvery`; it never trips the breaker. `FirmwareRunning`, `FirmwareRequested`,
`FirmwareAsOf` (the last good scan since start), `FirmwareNext` and `FirmwareEvery` are published.
`Fleet.Refresh(id, TierPosture)` is `RequestPosture`. Deviation: the plan's 10-second wake-up timer is not
needed; `Refresh` wakes the poller at once through its wake channel (a request during an open restart
window waits for the BMC to come back).

**Authz.** `server.firmware.view` (viewer, token-readable): `/firmware`, the Inventory section, the API;
`server.firmware.export` (viewer, token-readable): the CSVs; `server.firmware.rescan` (operator, sessions
only, no step-up): `POST /servers/{id}/firmware/rescan` through `probe()` (session, CSRF, authorization,
refusals audited `denied`) plus 6/min/user (`rate_limited`, audited) and a 30-second cooldown per server
(`fwinventory.RescanCooldown`; `denied`/`cooldown`, 429 with `Retry-After`). The service is fail-closed like
the security re-run: `started` before it asks the poller (no row, no request), then `ok`, or `error` with
`paused`, `unavailable` or `refused`.

**UI.** `/firmware` ("Firmware" in the sidebar and the phone menu between Servers and Settings, with the
count of below-minimum rows, from the service's `WarnCount`, cached for 10 seconds and cleared
by every scan): a GET filter form (server and kind from closed lists, "Flagged
only", a text search of at most 64 characters; a value of the wrong shape is a 400 page), counts, the legend
("Running is the version the device runs; Previous is the rollback copy the BMC keeps; Staged waits for a
reboot; a version stored on the BMC is an image the BMC holds but never installed"), one stacked table (Kind · Component · Server ·
Running (with "(2.25 stored on the BMC, not installed)" when the BMC holds another image) · Previous · Staged · Released · Flag with the
minimum and the rule's note), columns empty on every row hidden, component IDs and FQDDs behind
"Show component IDs and FQDDs" (`?details=1`), Download CSV, and a Scans panel (per server: "Last scan 10:31
· next in 23 h", "Scanning…", "Not scanned yet.", the last failure's class, "64 of N firmware entries were
read", Re-scan for operators or the reason it is unavailable) with the catalog line and the lock badge for
the config.yaml minimums. The Inventory tab's Firmware section groups the server's rows by kind (one table,
group header rows), shows the scan line with Re-scan, and the 20 newest changes. Without the service the
Inventory tab keeps the poller's list (with the new legend). Help gains four glossary entries.

**CSV (`internal/csvx`).** RFC 4180 through `encoding/csv` with CRLF, streamed. Every cell: valid UTF-8
(invalid bytes become U+FFFD), capped on a rune boundary (512 bytes here), then guarded: a cell starting with
`=`, `+`, `-`, `@`, tab or CR, or the full-width `＝ ＋ － ＠`, also after leading spaces, gets a leading
apostrophe; plain numbers (`^[+-]?[0-9]+(\.[0-9]+)?$`) are left alone; leading white space is any Unicode
space (NBSP, ideographic space, a newline). A row cap (10 000 rows) and a byte cap (4 MiB for this export,
`csvx.ErrTooLarge`): the handlers render into a buffer first and answer 413 rather than a truncated file;
a fixed width, a safe file name
(`firmware_<fleet|server id>_<yyyymmddThhmmZ>.csv`, the scope reduced to `[a-z0-9_-]`). Rate: 6 exports a
minute per user (UI) or per token (API, on top of the token limit). Exports are not audited (like the other
API reads; plan 02's open question about auditing downloads covers both).

**API (additive).** `GET /api/v1/firmware` → `{data: [rows], meta: {total, matched, flagged, warn,
scanned_servers, generated, catalog}}` with the page's filters; `GET /api/v1/firmware.csv`; `GET
/api/v1/servers/{id}/firmware` → `{server_id, scan_enabled, scanning, last_scan, next_scan, scan_error,
members_listed, complete, truncated, components: [rows], changes: [last 20]}`. A row: `server_id,
server_name, bmc_kind, kind, component, component_id, fqdd, running, previous, staged, stored,
release_date, updateable, flag, flags, minimum_version, minimum_source, identity, first_seen, last_seen`.
Problem Details on errors (400 bad filter, 404 unknown server or no service, 413, 429).

**Notifications.** The service sends **one** message per scan with changes (`notify.FirmwareEvent`, class
`security`, severity **warning**: a deviation from the plan's "info", because the default subscription is
"warning and above"; the security class is sent at normal priority, so it never pages), key
`security/firmware/<server>`, title "<server>: firmware changed on N components", `Count` N. Title and message
carry no BMC text; the components and versions go in `Detail` (at most 16 lines, then "and N more"; only for
targets that include detail). Components whose only change is the rollback copy are not counted, and a scan
with nothing else raises nothing. The audit tap leaves `server.firmware.changed` rows alone, so a fleet-wide
update is one message per server, not one per component sharing the per-target bucket with critical
classes.

**Metrics (additive).** `oob_firmware_components{server}`, `oob_firmware_flagged{server,flag}`
(below_minimum, not_applied, cannot_compare, stale_release), `oob_firmware_last_scan_timestamp_seconds{server}`
(0: never), `oob_firmware_changes_total{server}` (since start). Versions stay behind
`metrics.include_inventory` (`oob_server_info` already carries `bios_version` and `bmc_firmware` there).

**Offline catalog: interface only.** `catalog.Catalog{Lookup(ctx, Key) (Release, bool, error); Info(ctx)
(Info, error)}`, `catalog.Null()` ("Catalog: none imported" on the page and in the API meta),
`KeyFromIdentity` (Dell `DCIM:firmware:VEN:DEV:SUBVEN:SUBDEV`, else the component and system IDs). The
"Newer available" flag and the import command are not built.

**Fixtures.** `testdata/redfish/synthetic-firmware/{idrac8-r730xd,idrac9-r240}/`: 19 SYNTHETIC member
documents written from the captured shapes (iDRAC8: `SoftwareInventory.v1_1_1`, no `ReleaseDate`, no OEM;
iDRAC9: `v1_9_0` with `ReleaseDate` and `DellSoftwareInventory`), documentation MACs, no serials, each
marked `SYNTHETIC` in its `Description` (a test checks the marker and that none shadows a captured file).
Members whose FQDD holds `:` (iDRAC9 drives, the driver pack, diagnostics, USC) have no document on purpose:
they exercise the 404 path. The e2e harness and the dev server serve them with `WithExtraFixtures`; the
dev server also loads the firmware e2e stack's `firmware.minimum` rule, so Playwright sees a flagged row.

**Tests.** Unit: the comparison table (fixture versions, padding, overflow, incomparable, antisymmetry), kinds,
merge (the 101434 stored image, Available, missing names), policy (every match key, globbed FQDD, the BMC minimum,
strictest rule), rows, filters, release age, diff and sticky/need; the generic and Dell scans against both mocks
(names, kinds, one document per component, "only unknown" reads, the 64 cap, budget, 404/500/undecodable
documents, GET only); the store (round trip, replace, changes, prune, CHECKs, transactions, registry delete);
config validation; the fleet tier with the fake clock (cadence, retry, refresh, refusals, inventory trigger, a
scan right after a BMC restart, none inside the window); the service (first scan, changes and audit rows,
sticky names, incomplete and empty scans, sanitising, flags and counts, restart persistence, re-scan audit,
registry sync, prune); csvx; API; UI (page, filters, details, sidebar count, re-scan roles, CSRF, rate limits,
CSV, Inventory section, CSP); notify tap; metrics golden scrape; the cmd wiring over the real runtime and
mock. e2e (Go, its own stack): both mocks scanned with document names, the not-applied backplane image and the
below-minimum BIOS flagged, a BIOS update on the mock plus Re-scan producing a change, its audit row and the `security`
webhook, both CSVs parsed, GET-only BMCs. Playwright: `firmware.spec.ts` (table, filter, Inventory section,
re-scan, axe at 1440/390) and `firmware`, `firmware-details`, `inventory-r240` in `pages.spec.ts`.

**Not done / open.** The maintainer's read-only capture of every member document per BMC (to replace the
SYNTHETIC documents; the Current/Installed semantics are confirmed, see below; deploy/README has the procedure), then the
`docs/hardware.md` cells. The catalog import, the "Newer available" flag and a Settings editor for the
minimums are later slices. The visual baseline is not refreshed on this branch (new page and sidebar item):
regenerate it after the merge as in §36, and add `/firmware` to `visual.spec.ts` then.

**Review fixes (2026-10-23).** Security S-M1 (incomplete scans bounded: 128 rows, 30-day expiry of unlisted
components), S-M2 (one notification per scan), S-M3 (16 change and audit rows per scan plus a summary), S-M4
(30-second re-scan cooldown per server), S-L1 (components equal once cleaned stored once; Dell FQDDs cleaned),
S-L2 (re-scan audited `started` first, fail-closed), S-L3 (the CSV guard skips any Unicode space), S-L4 (cached
sidebar count; the janitor prunes through the service), S-L5 (`last_seen` clamped), S-L7 (4 MiB export cap).
Code C-M1 (no false downgrade on an incomplete Dell scan), C-M2 (a mismatched component's Installed- member
does not re-read its document), C-M3 (only the minimum is kept on one line; a long note wraps, checked at 390
px), C-L1 (the console probe's refused case uses a refusing dialer), C-L2 (BMC-only rules refused), C-L3 (model
kept with the scan), C-L5 (the counts chip reads "N flagged" and links to that filter), C-L6 (the text filter
counts characters), C-L7 (the firmware scan follows the end of a BMC restart window), C-L8 (comments), C-L9 (row
groups for the kind separators, no empty `<strong>`, no Re-scan on a paused server). Migration 0014 gained
`firmware_scans.model` in place (never released).

**Review fixes, second round (2026-10-23).** N1: when the 128-row cap evicts, platform firmware (kinds bmc,
bios, cpld) is kept first, then the most recently seen, so a flood of junk IDs in incomplete scans cannot
push the BIOS out and lose its "before" version. N2: before the 16-change cap the changes are ordered with
the platform firmware and `running` fields first (the notification lists them first too). The CSV guard also
skips leading format characters (Cf: zero-width, bidi, BOM): BMC text passes `textclean` before it reaches
`csvx`, but the server name (config.yaml or the browser) does not, so the guard no longer relies on it.
**Known narrow case:** on a Dell BMC whose scans stay incomplete, a real install of a component's stored
image, while its Installed- member is beyond the member cap, reads as "unchanged" (C-M1 keeps the stored
running version); the next complete scan corrects it.
**Migration 0014 was edited in place** during the reviews (`firmware_scans.model`): it was never released
and no persistent database ran it.

**Firmware states corrected (v0.8.1, 2026-10-29).** Slices up to v0.8.0 took a Dell `Current-` member for
the running version and an `Installed-` member that differed for a stale Lifecycle Controller record (flag
**Mismatch**). That is the wrong way round. On a live iDRAC9 the OEM block of every `Current-` member says
`Status: "AvailableForInstallation"`, `InstallationDate: "NA"` and carries an image hash, while the `Installed-`
member says `Status: "Installed"` with a real installation date; on an iDRAC8 (no OEM block) racadm
`swinventory` lists the `Installed-` version as "Current Version" (with its install date) and the `Current-`
version as "Available Version". So `Installed` is what runs and `Current` is the image in the BMC's store.
Changes: running from `Installed` first (`firmware.Merge`; the driver's document preference is Installed,
Current, Available, Previous), `lc_installed` became `stored` (component field `Stored`, API and CSV column
`stored`), flag `mismatch` became `not_applied` ("Not applied", info, no longer counted in the sidebar; only a
stored image newer than the running one), metrics label `not_applied`, `NeedsDocument` never re-reads for a
`Current-` member of a component with a known stored image, and `keepUnlisted` covers both missing members
using the states the scan listed (`Component.Members`; review M1: two members listed at one version clear the
stored image, and a new `Current-` version in an incomplete scan is a new stored image, never a running change).
A component listed only as `Current-` whose version changes while scans stay incomplete shows the change at the
next complete scan.
**Migration 0016** swaps `running` and `lc_installed` on the rows that hold both, clears their release date and
`doc_read_at` (both came from the stored image's member, so the next scan reads the running member's document),
rewrites the "appeared" change row of such a component to the running version (later change rows are history
and stay as recorded), and renames the column to `stored`. The API field and CSV column rename is breaking for
any consumer of `lc_installed`; the API is not public yet. Fixtures: SYNTHETIC `Installed-` member documents
derived from the captured `Current-` ones (same names and identities; the iDRAC8 backplane at 2.23).

## 39. Implementation notes (sensor history, plan 02)

Branch `history-graphs`, from `main` @ `44cb0da` (2026-10-23). Plan: `docs/plans/02-history-graphs-csv.md`;
decisions are recorded in its §18. The app keeps every poll's readings, rolls them up
by the hour and the day, and draws them on a History tab, as sparklines on the server page, and as CSV
and JSON. Charts are server-rendered SVG: no script, no chart library, the strict CSP unchanged. Nothing
here contacts a BMC; nothing was run against real hardware.

**Decisions:** CSV downloads are plain reads, not audited (like the firmware export),
with the plan's rate limits; retention defaults kept (raw 7 d, hourly 90 d, daily 2 y; PSUs and voltages
sampled); fleet-table sparklines later (the chosen redesign puts a shared-axis 24 h recorder on the
desktop Overview: the query API below serves it as is, `Service.Chart` over many servers' keys); an API
point budget of 2000; "export every sensor" stays operator-level.

**Packages and files.**

| Where | What |
|---|---|
| `internal/store/history*.go`, `migrations/0015_history.sql` | the five tables, the writer repository (`Insert`, `RollupHourly/Daily`, `PruneBefore`, `KeepNewest`, `DeleteKey`, `DeleteIdleKeys`, `SetWatermarks`, `NoteClockJump`, `Stats`) and the reads (`Keys`, `Buckets`, `Raw`, `CountRaw`, `Earliest`, `Meta`); `Tx.History` |
| `internal/store/readonly.go` | `OpenReadOnly`: the read-only pool (`ReadDB.History`, `ReadDB.AuditSearch`) |
| `internal/store/auditsearch.go` | `AuditFilter.Actions` (≤ 32) and `.Since` for the event overlay |
| `internal/fleet/samples.go` | `HistorySamples`, `Sampling`, the sink and the clock-jump note |
| `internal/bmc/power.go` | `Voltage.IsPowerGood` (moved from the UI: sampler and UI share it) |
| `internal/history` | ranges and plans (`PlanFor`, `SparkPlan`, `ParsePlan`), `Segments`, `Merge`, `Summarize`, the overlay (`FromLogs`, `FromAudit`, `Collect`), the `Service` (reads, `Run`/`RunOnce`, `SyncServers`, `Status`) and the export (`PrepareExport`, `WriteCSV`, `ExportName`) |
| `internal/history/svg` | chart and sparkline geometry (`Build`, `Sparkline`); writes no markup |
| `internal/csvx` | extended: `FlushEvery`/`Flush`, `Slug`, `Number`, `Time`, `Stamp`, `FuzzField` |
| `internal/config/history.go`, `internal/settings/keys.go` | the five `history.*` General keys |
| `internal/api/history.go`, `internal/metrics/history.go` | three API resources; five metric families |
| `internal/web/ui/history_*.go`, `templates/history.html`, `history_partials.html` | the History tab, sparklines, CSV, Settings group |
| `cmd/oob-manager/history.go` | wiring: the pool, the service, the janitor, registry sync, UI, API, metrics |

**Data model: migration 0015.** As planned, plus CHECKs: `name` ≤ 128 bytes, `last_ts >= first_ts`,
hourly and daily buckets aligned (`bucket % 3600000 = 0`, `% 86400000 = 0`), watermarks aligned. The
old `sensor_samples` rows are copied (`temp:` → temp/celsius, `fan:` → fan/rpm, `power:consumed` →
power/watts; any other key, and keys without an ID part, are dropped; names come with the next poll) and
the table and its index dropped. `settings_kv` is rebuilt with every key of 0005, 0007 and 0012 (General
and the S4 Integrations keys) plus the five history keys; `TestSettingsKVAcceptsEveryKnownKey` stays the
guard. Bytes measured: about 18 B per raw row (6.0 MB for 326 000 rows), so the plan's table (30 B) is
conservative.

**Writer.** `Insert` stores one poll in one transaction: one `SELECT` of the server's keys, new keys
inserted (`RETURNING id`), a changed name, unit or kind updated, `INSERT OR IGNORE` per sample (a
duplicate timestamp after a clock step is ignored), `last_ts` moved forward. Invalid samples (no key,
over 160 bytes, unknown kind or unit, NaN, ±Inf) are skipped. `Behind` reports a timestamp older than a
key's newest sample. Measured: 0.46 ms per 32-sample poll (Mac SSD, WAL, `synchronous=NORMAL`).

**Two connections.** The writer stays one connection (the audit chain relies on it). New:
`store.OpenReadOnly` opens the same file `mode=ro` with `query_only(1)` and the writer's `busy_timeout`,
at most 2 connections; charts, exports and the overlay's audit search use it (WAL readers never block the
writer; tested with an open cursor while an audit append and an insert complete). The writer DSN gains
`journal_size_limit(67108864)` (the WAL shrinks back after checkpoints) and **`_txlock=immediate`**: the
e2e run caught `reset-totp` (a second process) failing with `SQLITE_BUSY` when serve's janitor committed
between its read and its write; a deferred transaction cannot upgrade a stale snapshot and SQLite returns
at once, without `busy_timeout`. With `BEGIN IMMEDIATE` the second process waits (test
`TestTwoWritersWaitInsteadOfFailing`, which fails with `deferred`). Inside the app nothing changes. No
`VACUUM` (§4.4 of the plan); `oob_history_db_freelist_pages` shows the reusable pages.

**Sampler.** Keys `temp:<id>`, `fan:<id>`, `power:consumed`, new `psu_in:<id>`, `psu_out:<id>` (the
measured input and output; never the rated input) and `volt:<id>` (analog rails; power-good signals
excluded through `bmc.Voltage.IsPowerGood`), one per key and poll, in the BMC's units (fans in RPM or %
by their `Units`). `history.sample_psus` and `history.sample_voltages` are read at every poll. A poll older
than stored samples logs one warning and records `history_meta.last_clock_jump` once per occurrence
(the poller remembers the last result); nothing is rewritten. The fleet no longer prunes (its
`Retention`/`PruneEvery` and the `SampleRepository` are gone; deviation: the plan kept them).

**Plans and tiers.** One plan per range, aligned to its step since the epoch (UTC), ending at the end of
the bucket holding now:

| Range | Step | Points | Served from |
|---|---|---|---|
| 24 h | 10 min | 144 | raw |
| 7 d | 1 h | 168 | hourly (deviation: the plan said raw; an hourly row is exactly one 1-hour bucket, so the points are identical and 60× cheaper) |
| 30 d | 3 h | 240 | hourly |
| 1 y | 1 d | 365 | daily |
| sparkline | 30 min | 48 | raw |

`Segments` splits a plan: the plan's tier where it has rows; after its watermark the finer tiers (the
hours not rolled up yet come from raw rows); before its first row the coarser tiers ("Hourly averages
before …" on the chart). A coarser tier ends at its own bucket boundary before the finer tier's first row,
and the janitor prunes raw rows by whole hours and hourly rows by whole days, so no sample is counted
twice and none is lost (the first version extended the coarse tier to the next boundary instead and drew a
daily row next to the hourly rows it summarized; the UI test caught the extra point). Buckets of the same
start from two segments merge (min, max, n-weighted average). Custom API windows: RFC 3339 `from`/`to`
(at most 2 years, not past tomorrow), optional `step` in seconds, raised to fit 2000 points and rounded
to its tier's granule (1 min raw under an hour, 1 h hourly under a day, else 1 d daily).

**Janitor (`Service.Run`).** A pass at start and at HH:02: hourly rollups for every complete hour from one
hour before the watermark (re-rolled, idempotent) or `raw_days` back, one `INSERT OR REPLACE … GROUP BY`
per hour (short transactions); daily rollups from the hourly rows for every complete UTC day likewise;
watermarks stored; then per key: raw rows older than `raw_days` (whole hours), the count rule
(`KeepNewest`: at most 1.5 × `raw_days` of polls at `config.PollFloor`, 30 240 rows per key for 7 days),
hourly older than `hourly_days` (whole days), daily older than `daily_days`, each in `DELETE`s of at most
5000 rows; keys with no rows left and `last_ts` older than `daily_days` are deleted; finally `Stats`
(row counts, `page_count × page_size`, freelist) on the **read-only pool** (counting reads every table;
it never holds the writer), cached in `Status` for Settings and `/metrics` (once an hour, never per
scrape). A failed pass leaves the watermarks and is retried next hour; its status keeps the last known
watermarks. A watermark ahead of now (the clock was ahead at an earlier pass and has been corrected)
makes the pass roll up the whole retention again instead of waiting for real time to catch up. Rollups
and prunes follow the retention clock, not the wall clock (second review round below). `SyncServers`
(every registry apply) deletes, batched, the rows of servers that left the registry once their last sample
is 30 days old. `EXPLAIN QUERY PLAN` tests pin every `sensor_raw` query to the primary key.

**Cost** (measured on a Mac SSD, 32 sensors, 7 days at 60 s, 326 000 raw rows, 6 MB): first pass after
an upgrade (168 hourly and 7 daily rollups, prunes, stats) 0.23 s; a steady pass 30 ms (prunes 20 ms);
a full History page read (32 sensors) 24 ms for 24 h, 8 ms for 7 d and 30 d, 3 ms for a year; a raw 7-day
export of one sensor (10 150 rows) 10 ms. **On an SD-card-class disk** the volume is what matters: a
steady pass reads one hour of readings (about 2 000 rows, under 100 KB), deletes about as many (a few
hundred KB through the WAL, no fsync per statement with `synchronous=NORMAL`) and counts every table (one
sequential read of the file, about 6 MB per server at the plateau, usually from the OS cache since it was
just written); expect well under a second per pass for a small fleet, a few seconds after an upgrade
(the first pass reads the whole raw tier once). Charts read only their range's rows. Inserts stay one
small transaction per poll.

**Rendering.** `internal/history/svg` turns buckets into strings with one decimal in a fixed viewBox
(600 × 140 for charts, 120 × 24 for sparklines; CSS scales them): the averages as a path (a gap of more
than 2.5 steps, or 150 minutes / 60 hours across a coarser tier, starts a new subpath; a lone point is a
dot), the focus's min/max envelope, threshold bands (the current snapshot's `WarnAbove`/`CritAbove`,
temperatures only, drawn when within 10 % above the data, which then extends the axis), event lines,
maintenance rectangles, 3–6 y ticks (1, 2, 2.5, 5 × 10^k) and 4–6 x ticks aligned to the viewer's
midnight or hour. The UI's `history_partials.html` draws them with `html/template` (every attribute and
text escaped; no `template.HTML`, no `style` attribute, no script). Colors are classes mapped to chart
tokens in `tokens.css` (`--chart-focus`, `--chart-muted`, `--chart-grid`, `--chart-text`, `--chart-plot`,
`--chart-band-warn`, `--chart-band-crit`, `--chart-mark`, `--chart-mark-crit`, `--chart-maint`, a
component layer over the semantic colors after the light-dark fallback), so the redesign's slices B–D
restyle charts in one place; `forced-colors` maps them to system colors. On a phone the chart keeps a
28 rem minimum width inside its own scrollable, focusable region (tick text stays legible; the page never
scrolls sideways). Golden files (`internal/web/ui/testdata/history_chart.svg`, `history_sparkline.svg`,
`go test -run Golden -update`) pin the markup.

**Accessibility.** Each chart is `<svg role="img" aria-labelledby="<id>-t <id>-d">` with a `<title>`
(kind, focused sensor, range) and a `<desc>` (minimum, average, maximum, sensors drawn, events); every
line and marker has its own `<title>`; a `<details>` data table lists every point of the focused series
(tested equal to the path's point count) with the CSV links; the events are repeated as a list with links
to the logs. Range and focus are links (`aria-current`), so everything works without a script and from
the keyboard. Values follow the viewer's °C/°F and formats; CSV stays in °C.

**UI.** History is a server tab after Logs (`server.history.view`). Panels: Temperatures, Fans, Power
draw, Power supplies (input and output together), Voltage rails, one per unit when a kind mixes units
(fans in RPM and %); sensors in a panel ordered by name; the focus is the requested key when it is in the
panel, else the first; at most 16 lines, the rest under "Also recorded" (the focus always drawn). Each
panel shows the focus's minimum, average, maximum and sample count and today's thresholds as text. The
data table names daily buckets by their UTC date ("2026-10-20 UTC": they are UTC days), the others in
the viewer's zone; day ticks step by calendar days, so they stay on local midnight across DST.
"Events in this period": warning and critical cached SEL/Lifecycle entries (acknowledged ones marked),
power requests, fan lease starts, ends and expiries, BMC restarts and their verification, maintenance
spans (an active window that began before the range is added from the maintenance service); at most 200
markers, the newest kept. The audit query reads at most the 1000 newest matching rows since the range
start (through the action index); older ones in a very busy year are not drawn. A clock step back inside the range adds a notice. The Hardware tab's Status
panel gains three sparklines (the hottest sensor, the inlet, the draw), read in one chart call, each
linking to the History tab focused on that sensor. Settings → General shows the history keys as their own
group (switches as On/Off selects, retention in days) with the size line from the janitor's status. Help
gains Sensor history, Bucket and Rollup.

**CSV.** `GET /servers/{id}/history.csv?sensor=&range=` (viewer) or `?all=1` (operator; a viewer gets a
403 page and a `denied` audit row), bucketed (`bucket_start_utc, bucket_end_utc, server, sensor, name,
kind, unit, min, avg, max, samples`) or raw (`raw=1`, 24 h and 7 d links; any window up to 31 days:
`timestamp_utc, server, sensor, name, kind, unit, value`). Deviation: a `name` column next to the key
(the plan had the key only; the name is what a person recognises and the reason for the guard). Times
RFC 3339 UTC, numbers `strconv` shortest round-trip with `.`. `bucket_end_utc` is one step after the
start, or the whole hour or day when a coarser tier served that bucket (`Series.BucketEnd`). A raw export
of a custom window covers exactly the asked window (not the step-aligned one), and the 31-day limit
applies to it. `PrepareExport` sizes the export first
(bucketed: reads the series; raw: `CountRaw`) and refuses over 100 000 rows (413) before a byte is
written; `WriteCSV` streams through `csvx` (64 MiB safety cap), flushing every 1000 rows, reading raw rows
in pages of 10 000 from the read-only pool. File name `<server>_<key slug>_<range|custom>[_raw]_<stamp>.csv`.
6 exports a minute per user (its own bucket); downloads are not audited (decision); refusals are.

**Authz.** `server.history.view` and `server.history.export` (viewer, tokens too);
`server.history.export_all` (operator). Deviation: export_all is **sessions only**: a token stays a
viewer-level reader whatever its role (the invariant `TestTokensAreReadOnlyRegardlessOfRole` keeps), so the
API's `all=1` answers 403 and tokens export one sensor per request.

**API (additive).** `GET /api/v1/servers/{id}/history/sensors` → `{data: [{key, kind, name, unit, first,
last}], meta: {total}}`; `GET …/history?sensor=&range=` or `&from=&to=&step=` → `{data: [{t, min, avg,
max, n}], meta: {sensor, kind, unit, tier, tiers, step_s, from, to, points, clock_jump}}` (`tier` is the
plan's, `tiers` the ones actually used); `GET …/history.csv` as above for one sensor. 404 unknown server
or no history, 400 unknown sensor or a bad window, 413, 429 (the per-token export bucket is shared with
the firmware CSV, 6/min). Tested: 50 history requests against a real, polled fleet add no driver call.

**Metrics (additive).** `oob_history_rows{tier}`, `oob_history_db_bytes`, `oob_history_db_freelist_pages`,
`oob_history_rollup_last_timestamp_seconds{tier}`, `oob_history_prune_duration_seconds`; left out until
the first pass; no per-sensor series.

**Tests.** Store: insert, keys and names, invalid samples, clock step, buckets per tier with weighting,
rollup idempotency and alignment, raw paging and counts, prunes (time, count, keys, idle), stats, query
plans, the migration copy, the read-only pool (writes refused, reads beside the writer), two processes.
History: ranges, plans and custom windows, segments (every tier mix, bucket edges), merge and summary,
markers, the janitor (rollups equal raw, retention, coarse note, sync, the loop's schedule, cancellation),
the overlay over a real audit log, exports (bucketed equals the chart, raw, flushes, caps, names). SVG:
point counts, gaps, envelope, bands, ticks, marks, spans, determinism. csvx: flush, slug, numbers,
`FuzzField`. Fleet: the samples of every family and the switches, the clock-jump note. API: lists,
series, custom, refusals, CSV, rate limit, no BMC calls. UI: the tab (panels, title/desc, data table
equal to the path, events, escaping, no `style`/script), ranges and focus, sparklines, hidden without the
service, CSV (headers, raw, refusals, audit of refusals, rate limit), export-all for operators, units and
formats, golden SVG, the Settings group. cmd: the runtime writes the mock's readings, a ghost server's rows
go, metrics state. e2e (Go, its own stack): 48 h seeded before serve (keys from a separate mock of the
same fixture, so the stack's mocks see no extra session), every kind's panel, sparklines, the first pass
rolled up the seed, CSV equals JSON bucket by bucket, a raw export, a burst of history requests adds no BMC
request. Playwright: `history.spec.ts` (sparkline link, tab, ranges, focus, data table, CSV download, axe in
both schemes at 1440 and 390) and `history`, `history-7d-focus`, `history-r240-1y` in `pages.spec.ts`.

**Review fixes (2026-10-23).** A code review of the branch found no critical or high issues. Fixed:
`Stats` moved to the read-only pool; watermarks ahead of now reset; daily bucket dates in UTC;
`bucket_end_utc` follows the serving tier; day ticks by calendar days; raw custom exports cover the asked
window; an `all=1` export is always named `all-sensors`; a failed pass keeps the last watermarks. Left as
documented: the overlay's 1000-row audit window.

**Review fixes, second round (2026-10-23, after the rebase onto `main` @ `2837081`).** The coordinator verified
migration 0015 on a copy of the real v0.7.2 database (schema 11, 28 814 samples, 17 keys: per server and
sensor count, sum and first/last timestamp identical; integrity ok). Fixed, tests first:
- *HIGH-1, key growth:* `store.MaxKeysPerServer` (512, archived keys included): new keys beyond it are
  refused and counted (`InsertResult.Refused`, `ServerState.HistoryRefused`,
  `oob_history_keys_refused_total{server}`), logged once per poller; the sampler caps each poll's families
  (128 temperatures, 32 fans, 16 PSUs, 64 rails); the legacy Thermal/Power decode now caps like the
  subsystem path (it kept every member); the History panel lists at most 48 "Also recorded" links and
  counts the rest. Tests: a fake BMC inventing 300 names a poll for 8 polls ends at 512 keys; a legacy
  document with 300 of each sensor is cut to the caps.
- *MEDIUM-1, forward clock:* the janitor prunes and rolls up by its own **retention clock**
  (`history/clock.go`, `history_meta.last_pass_at`, `janitor_clock`, `last_forward_jump`; migration 0015
  edited in place, unreleased). It follows the wall clock while the two agree and otherwise advances at
  most twice the real time that passed (the monotonic clock in the process; 3 hours, the hourly cadence
  plus two of slack, on the first pass after a start). A +60-day step therefore deletes nothing on its
  pass and catches up two hours an hour; a long downtime is caught up the same way. The step is recorded
  (`last_forward_jump`, a warning log) and the History tab explains the lag. A step back is followed at
  once. (The plan's "prunes early and is harmless" was wrong: one pass deleted everything.)
- *MEDIUM-2, cut downloads:* a stream that fails after the headers panics with `http.ErrAbortHandler`
  (UI and API), so the client sees a broken transfer (tested over a real server: the body read fails);
  raw exports read exactly the window counted up to the preparation time, and the writer allows the
  counted rows (plus two per sensor for a poll already in flight), never more than the cap.
- *MEDIUM-3, audit flood:* the UI export checks the rate limit before the role, and each refusal kind is
  audited once a minute per user (20 refused requests: 2 rows).
- *L1:* "every sensor" bucketed exports are refused by their upper bound (sensors × points) before any
  series is read. *L2:* power markers name the requester ("Graceful restart requested by alice") like the
  fan and BMC markers, and every viewer of the History tab sees them: deliberate, the same disclosure as
  the server page's power state cause (security.md §3j). *L3:* see deploy/README's
  upgrade note (old keys over 160 bytes and server IDs over 64 bytes are not copied).
- *Code M1:* `SyncServers` keeps the history of a server missing from the registry for
  `history.SyncGrace` (30 days) after its last sample (a typo or a commented-out entry loses nothing);
  the browser's server delete does the same (no immediate delete); the idle-key rule removes the rest.
- *Code L1–L6:* migration tests for a v0.7.2 database with samples and for a 0015 that fails after the
  copy (the transaction rolls back; `sensor_samples` survives); a unit or kind change archives the old key
  (`<key>#<old unit>#<id>`) and starts a new one instead of relabelling old rows; `first_ts` moves back
  with an older sample; buckets of a coarser tier are drawn at the middle of their own width and the line
  bridges gaps by each bucket's width; ticks are 11 viewBox units (13–18 px, the chart at most 60 rem) and
  18 units on phones on a 30 rem minimum width (14 px or more), with a 56-unit label column.

**Security re-check of round 2 (2026-10-23).** Earlier findings closed; fixed, tests first:
- *MEDIUM-N1, unit flips:* a fan alternating RPM and percent used up the key cap (600 flips, 512 keys).
  The ThermalSubsystem fan decode keeps RPM whenever the document has `SpeedRPM`, so a momentarily null
  RPM is no reading (the sample is skipped), not a switch to percent; a unit change at the cap is refused
  instead of archiving a key whose replacement cannot be stored. *Final confirm (MEDIUM):* the first fix
  bounded archives by deleting the oldest, so three flips deleted an RPM history. Now an archive whose
  unit and kind match the new reading is swapped back in (it becomes the live key, the current one is
  archived): flips between two states cost two keys and delete nothing. Archives are matched exactly by
  `sensor_keys.archived_from` (the live key they came from; 0015 edited in place, unreleased), never by
  name, so a real key containing `#` or sharing a long prefix is never taken for one. A sensor cycling
  through more than `store.MaxArchivesPerKey` (4) unit and kind combinations loses its oldest archive:
  logged every time and counted in `oob_history_keys_refused_total`. Tests: 600 flips keep all 600 readings
  in 2 keys and a real new sensor is recorded; 6 combinations keep 4 archives and report 1 dropped; keys
  with `#` and long shared prefixes are untouched. `parseBoot` accepts decimal uptimes only (no NaN, Inf,
  sign, exponent or hex).
- *MEDIUM-N2, crash loop:* a forward step followed by restarts advanced the retention clock 3 hours per
  restart. `history_meta` keeps the kernel boot ID and uptime of the last pass (`/proc/sys/kernel/random/
  boot_id`, `/proc/uptime`, plain file reads); on the same boot the advance is bounded by twice the uptime
  delta, whatever the restarts; a new boot gets the 3-hour allowance once. Without `/proc` (macOS, other
  kernels) the in-process monotonic clock and the 3-hour allowance per start remain. Test: a +60-day step
  and 40 restarts 10 s apart move the clock 13 minutes and prune nothing.
- *LOW-N3:* rollups run to the wall clock's hour (they only add summaries); only prunes follow the
  retention clock.
- *LOW-N4:* archive names are cut on a rune boundary (the key part keeps 32 bytes for the suffix).
- *LOW-N5:* deploy/README says a re-added server ID shows its old series for up to 30 days and how to
  clear it.

**Not done / open.** Fleet-table sparklines (later; the redesign's Overview recorder is plan 04).
SEL/Lifecycle CSV export (a separate follow-up, plan §1). The visual baseline is not refreshed on this
branch (new tab, sparklines on the server page): regenerate it after the merge as in §36 and add the
History tab to `visual.spec.ts` then. Thresholds are the current snapshot's, not historical ones.

## 40. Implementation notes (round-2 redesign, slice B: components, colour anchors, icon sprite, favicons)

Branch `redesign-slice-b` on `main` @ 479dd59. Plan 04 §10 slice B: components 1–7 of §5, the icon sprite
(§7) and the maintainer's decisions §11 items 2, 10, 11 and 12. Direction A, *Quiet signal*: healthy is quiet,
problems are loud and specific. No Go dependency, no migration, no route change; the CSP is unchanged (the
sprite is in the page, the favicons are `img-src 'self'`). Design reference: `docs/design/round-2.md`, which
now replaces `direction-b.md` for tokens and components (the shell sections of `direction-b.md` stay valid
until slice C).

### Colour anchors and the palette generator (`tools/themegen`)

- `themes.css` is **generated** by `go run ./tools/themegen -o internal/web/ui/static/themes.css`, a Go
  port (stdlib `math`) of the mockup package's `palettes.mjs`/`oklch.mjs` for direction A. Each palette is a
  neutral hue and chroma per mode, an accent hue and five status hues; every ink is then *fitted* (lightness
  stepped by 0.005 towards more contrast) until it meets its ratio on every surface and tint it is drawn on.
  Every fit step measures the colour **as written** (`written()`: gamut-mapped by chroma reduction, L
  rounded to 0.01 %, chroma truncated to 4 decimals, then L nudged by 0.01 % until no sRGB channel lies
  within 0.1 of an 8-bit rounding boundary, so Chromium's own conversion paints the same 8-bit value), and
  returns that colour, so the CSS says exactly what was checked. A fit that does not converge within 400
  steps, or a colour with no unambiguous value within ±1 % of L, is an **error** and the tool exits
  non-zero (no silent fallback). Products in the colour math are written `float64(x*y)` so the compiler
  never fuses them into multiply-adds (arm64 would otherwise generate different digits from amd64 CI).
  `TestThemesCSSIsGenerated` fails when the file and the generator disagree, and runs in CI's test job, so
  no separate regenerate-and-diff step is needed; the package is a maintainer tool (never shipped), 94 %
  covered. High contrast's inks on solid fills target 6:1 (black on the dark mode's critical fill cannot
  reach 7:1); the contrast test requires 4.5:1.
- **Graphite (default) uses the maintainer's anchors**: accent cyan-teal **H 198**; OK **158**, warning **78**,
  critical **24**, info **245**, stale **98**; a slate **off** tone (the neutral hue 250, chroma ≤ 0.03).
  The other palettes keep their identity hues (Solarized, Nord, Dracula, High contrast, and Okabe–Ito for
  Color-blind safe) with the same rule: the accent is at least **40°** from every status hue in every
  palette and mode (`TestAccentStaysFarFromStatusHues`; Graphite's closest pair is accent/OK, exactly 40°).
  `TestGraphiteUsesTheAnchors` holds Graphite to the anchors.
- Primitive steps: `neutral-0` canvas, `-1` surface, `-2` field, `-3` hairline border, `-4` raised
  surface (menus, meter track), `-6` field border, `-8` muted, `-9` text, `-10` focus; per family `-1`
  tint, `-5` **mark** (glyphs, outlines, meter fills, ≥ 3:1), `-7` **ink** (text, ≥ 4.5:1), `-8` solid fill
  (critical, off), `-0` the ink on a fill.
- Semantic names, Graphite light / dark (the 8-bit colour painted; every palette in `testdata/theme-hex.txt`):

  | Name | Primitive | Light | Dark |
  |---|---|---|---|
  | `--bg` | neutral-0 | `#eef3f8` | `#0b0f12` |
  | `--surface` | neutral-1 | `#ffffff` | `#14181c` |
  | `--surface-2` | neutral-2 | `#f2f8fe` | `#1d2125` |
  | `--surface-3` (new) | neutral-4 | `#e9eff6` | `#262b30` |
  | `--border` | neutral-3 | `#dde2e8` | `#272b30` |
  | `--field-border` | neutral-6 | `#717579` | `#898d91` |
  | `--muted` | neutral-8 | `#4a4d51` | `#b4b8bc` |
  | `--text`, `--btn-bg` (new) | neutral-9 | `#141618` | `#eef0f3` |
  | `--btn-fg` (new) | neutral-1 | `#ffffff` | `#14181c` |
  | `--focus` | neutral-10 | `#020202` | `#fafafa` |
  | `--accent` / `--accent-bg` (new) / `--on-accent` | accent-7 / -1 / -0 | `#007275` / `#c8f9fa` / `#ffffff` | `#38d6db` / `#002a2c` / `#020e0e` |
  | `--ok` / `--ok-bg` / `--ok-mark` (new) | ok-7 / -1 / -5 | `#005734` / `#d8fae5` / `#007d4d` | `#7ae4aa` / `#0d291a` / `#63d99b` |
  | `--warn` / `--warn-bg` / `--warn-mark` (new) | warn-7 / -1 / -5 | `#604100` / `#ffedd3` / `#ae7900` | `#f9bf60` / `#2f2006` / `#f9b73f` |
  | `--crit` / `--crit-bg` / `--crit-mark` (new) | crit-7 / -1 / -5 | `#7f2022` / `#ffebe9` / `#b71727` | `#ffb4af` / `#361a18` / `#ff6462` |
  | `--danger` / `--on-danger` | crit-8 / -0 | `#ad001e` / `#ffffff` | `#f45152` / `#100606` |
  | `--danger-hover` (new) | crit-9 | `#940018` | `#ff6a67` |
  | `--btn-bg-hover` (new) | neutral-7 | `#2a2c2e` | `#cfd1d4` |
  | `--info` / `--info-bg` / `--info-mark` (new) | info-7 / -1 / -5 | `#014b79` / `#e4f2ff` / `#296898` | `#9bd1ff` / `#0e2537` / `#7cbbf0` |
  | `--stale-fg` / `--stale-bg` / `--stale-mark` (new) | stale-7 / -1 / -5 | `#50481f` / `#f4f1de` / `#726940` | `#d5cc9f` / `#262315` / `#c8bf93` |
  | `--off` / `--off-bg` / `--off-fill` / `--on-off` (all new) | off-7 / -1 / -8 / -0 | `#4c5a69` / `#e6f1fd` / `#444e59` / `#ffffff` | `#a3b3c4` / `#1c242c` / `#525c67` / `#f8f8f8` |

  `--danger` was equal to `--crit` in v0.7; it is now the solid critical fill. Every existing name is kept.
- `TestThemeContrast` (all six palettes × both modes) now also checks: text, muted, links and every ink on
  `--surface-3` and on every tint including `--accent-bg` and `--off-bg`; marks ≥ 3:1 on every surface and
  their tint; `--on-off` on `--off-fill`; the neutral primary button at **7:1**, also hovered
  (`--btn-fg` on `--btn-bg-hover`), and `--on-danger` on `--danger-hover` (both hover fills are generated
  tokens: app.css uses no `color-mix()`); the focus ring ≥ 1.5:1 from both `--warn` and `--warn-mark`;
  `--warn-mark` at least **0.12** in OKLab lightness from `--danger` and **0.1** from `--crit-mark` (warning
  and critical differ in greyscale too; the critical mark starts darker for this, Graphite dark `#ff6462`).
  The accent is ≥ 40° from every status hue; Graphite's accent/OK pair is exactly 40° (the anchors), the
  other palettes keep ≥ 42°. `TestPalettesMatchV07Hex` and its golden are retired (the
  colours changed on purpose); `TestPalettesMatchGolden` holds the resolved values to `testdata/theme-hex.txt`
  (`-update` rewrites it), which `themes.spec.ts` still compares with what Chromium paints. The
  `light-dark()` fallback in `tokens.css` is the new Graphite dark, including plain values for the two
  shadow tokens (`--shadow-panel`, `--elev-2`), which otherwise use `light-dark()` too.
- Scale tokens added for the components: radii `--r-badge` .375rem, `--r-ctl` .5rem, `--r-panel` .75rem,
  `--r-pill`; `--fs-h3`; `--ctl-h` 2.5rem, `--ctl-h-sm` 2rem, `--tap` 2.75rem; `--lh-body` 1.5. `--elev-2`
  (menus) gains a soft shadow and `--shadow-panel` holds the panels' light-mode shadow. `--r-1/--r-2`
  (unused) are gone.

### Components 1–7 (`app.css`, same class names; markup changed only for icons)

1. **Base**: Inter with optical sizing, tabular slashed-zero numerals everywhere; h1 600 weight on the fluid
   `--fs-5`, h2 sentence case at `--fs-h3` in text colour (was small uppercase muted), links underlined at
   1 px with offset; `::selection` in the accent tint; focus ring unchanged (3 px, 4 px in High contrast);
   `.skip` is a neutral pill; `.nodata` is muted, no longer a synthesised italic; `.sr-only` hardened.
2. **Badges and chips**, by fill weight: OK quiet (text colour, green mark icon), warning tinted with a mark
   outline, critical the solid `--danger` fill, info/maintenance tinted outline, stale tinted and dashed,
   unknown dashed, **powered off a solid slate** (`.b-off`, was info blue). Sentence case, 600 weight,
   `--r-badge`. Chips are pills; Aging and Stale age chips keep their tints. Tags: critical outlined in the
   crit mark, plain tags muted.
3. **Buttons**: the primary is **neutral ink** (`--btn-bg`/`--btn-fg`); the accent is reserved for links,
   selection and focus halos so it is never read as a state. Secondary outlined, quiet ghost, danger solid
   critical, danger-outline and caution outlined in their marks; disabled dashed and muted with its "why"
   text; `--r-ctl` radius, 40 px (44 px on phones).
4. **Forms**: fields on `--surface-2` with `--field-border` (≥ 3:1), `--r-ctl`; invalid fields get a 2 px
   crit-mark border; radio and checkbox cards take the accent border **and** tint when chosen (not colour
   alone; Highlight outline in forced colours); code blocks are mono on `--surface-2`.
5. **Panels** at `--r-panel` with a hairline and (light mode only) a 1 px soft shadow; status panels keep a
   3 px inset stripe in the family mark; alerts are tinted with a full mark border (stale dashed); the
   summary strip uses eyebrow labels and 1.5rem numerals; the healthy strip line is quiet (surface + green mark).
6. **Tables**: sentence-case muted headers, hairline rows, a row hover tint (not on phones), row states as
   tint + 3 px inset mark (off rows in the slate tint); compact 36 px stays the default density. **Headroom
   meters** are rounded tracks on `--surface-3` with mark fills (warning amber, critical the solid fill)
   and the existing ticks.
7. **Lists**: dense, feed (muted times), kv, notes, acks and checks re-spaced on the new scale.

The status bar, sidebar, sheet, tabs, steppers, pager, sign-in and footer only received the new colours
and radii (their layout is slice C). Status tiles in the sidebar and the fleet pill follow the same fill
weights.

### Icon sprite (Lucide 1.53.0)

- Plan 04 §7 and §11 item 10. One `<svg class="sprite" width="0" height="0" aria-hidden="true">` right after
  `<body>` on every page, with a `<symbol id="i-<name>" viewBox="0 0 24 24">` per icon; the `icon` partial
  writes `<svg class="ic ic-<name>" … aria-hidden="true"><use href="#i-<name>"/></svg>`. Strokes come from CSS
  (`.ic`: `currentColor`, 1.8 on the 24 grid, round caps and joins). Same-document `<use>`: no fetch, no CSP
  change. About 7.8 KB per page before gzip.
- **Provenance**: Lucide release **1.53.0** (2026-10-08, 15 days old when vendored), asset
  `lucide-icons-1.53.0.zip` (SHA-256 `9b493937acd827896739aad925e2978731375fdca11233d663cfb1c48af53d3f`, equal
  to GitHub's recorded digest); 40 SVGs (43 since slice C, §41) copied unmodified to `iconsrc/lucide-1.53.0/icons/` (a separate `//go:embed`, read only to build the
  sprite, never served: `/static/…/icons/*.svg` is 404), and the
  repository `LICENSE` at tag `1.53.0` (tag commit `b56741cf…`, file SHA-256 `b495047b…0329c57`), all in
  `vendor.sha256`. Licence: ISC (Feather-derived icons also MIT, both texts in the file); NOTICE entry, §2 row,
  About credit.
- Icons: activity, check, chevron-down, chevron-right, circle-check, circle-question-mark, clock,
  clock-arrow-up, copy, cpu, external-link, fan, hourglass, info, layout-dashboard, life-buoy, lock, log-out,
  maximize, menu, monitor, octagon-x, plus, power, power-off, refresh-cw, rotate-ccw, scroll-text, search,
  server, settings, shield, shield-check, sliders-horizontal, square-terminal, sticky-note, thermometer,
  triangle-alert, wrench, x; plus the project's own **mark** (`static/mark.svg`). **Reserved** for slices C–D
  and not drawn yet: chevron-down, chevron-right, copy, log-out, plus, refresh-cw, rotate-ccw, search,
  shield-check, sliders-horizontal, thermometer (`reservedIcons` in `sprite_test.go`;
  `TestEverySpriteIconIsUsedOrReserved` fails on an icon that is neither used nor reserved, or reserved but
  used). Icons chosen in Go (`actionBtn.Icon`: fan, power, monitor) are checked too.
- `sprite.go` builds the sprite once in `newRenderer` and parses every file with `encoding/xml`: the root
  must be `<svg viewBox="0 0 24 24">`, children only `path`, `circle`, `ellipse`, `rect`, `line`, `polyline`,
  `polygon` with their geometry attributes (values limited to numbers and path commands), plus
  `fill`/`stroke` = `none`/`currentColor`; any element outside the SVG namespace, any namespaced attribute,
  text, nesting, `use`, `style`, handlers, xlink or directives fail start-up. Tests: the allow-list (20
  rejection cases), every page carries exactly one sprite and every `<use>` resolves, every icon named in a
  template or chosen in Go exists.
- A new `sicon` partial maps a state class to its icon (ok circle-check, warn triangle-alert, crit
  octagon-x, info info, pend hourglass, stale clock, live activity, aging clock-arrow-up, maint wrench, off
  power-off, otherwise circle-question-mark; `TestStatusIconsAreDistinct` keeps every shape different). It
  replaces the system-font glyphs (✓ ▲ ✕ ◆ ◷ ◔ ● ‖ ⏻) in badges, the fleet pill, sidebar tiles, age chips and
  event count chips (which gain a `Class` field). The view models' `Glyph` fields and methods
  (`healthView`, `pillView`, `chipView`, the user, token and audit rows, `maintGlyph`) are **deleted**; their
  tests assert the class instead. Only the steppers' ✓ stays a glyph (slice C).
- The Lucide sources live in `internal/web/ui/iconsrc/` (their own `//go:embed`), **not served**; only the
  licence is under `static/vendor/lucide-1.53.0/`, for the About page link.

### Brand mark and status favicons

- The **side-channel mark** (a power ring broken by the out-of-band dot) is the sprite's `mark` symbol in
  the top bar (neutral ink tile) and `static/logo.svg`.
- Five status favicons, `static/favicon-{ok,warn,crit,stale,off}.svg`: dark tile and the mark, with a
  badge that differs in **shape** as well as colour, like the status icons: ok a filled dot (ok mark),
  warn a triangle (warning mark), crit an octagon (danger fill), stale a hollow ring (stale mark), off a
  square (off ink); `TestFaviconShapesDiffer` holds that. Plus the plain `favicon.svg`.
  `pillView.Favicon()` picks one from the fleet's worst state: critical → crit, warning → warn, powered off →
  off, stale or unknown → stale, OK or maintenance only → ok, and an empty fleet ("No servers") keeps the
  plain mark. `layoutData.Favicon()` returns the plain mark whenever no user is signed in, whatever the
  pill. Signed-in pages link `/static/favicon-<state>.svg?v=<version>` (static files, the usual one-hour
  cache, versioned like the sheets); other pages keep `/static/favicon.svg` with no version.

### Tests and gates

- New: `sprite_test.go`, `favicon_test.go`, `theme_hue_test.go`, `TestStylesheetsStaySelfContained`
  (no `@import`, no other origin, `url()` only to the vendored fonts), the generator's tests; `themes.spec.ts`
  samples the new fill weights; `pages.spec.ts` asserts **no horizontal scroll at 320 px** on Overview,
  Server and Logs in both schemes (passed without shell changes). Markup assertions that named a glyph were
  updated to the icon (three tests); the glyph assertions of `power_rank_test.go`, `power_off_test.go` and
  `views_b_test.go` moved to the class with the glyph code's deletion.
- The **visual job is blocking** (no `continue-on-error`) and the `image` job needs it (the private repo has
  no branch protection); the baseline was refreshed in `[visual]` commits from `visual_update` CI runs on
  this branch.

**Deferred to slice C** (shell): top-bar layout and glass, the dimmed sidebar with sub-lines, the phone
bottom action bar, tabs as segmented grids on phones, steppers and pager, sign-in, footer, and the
Overview/Server page structures. Also left for slice C: alerts have no leading icon (it needs a body
wrapper in every alert's markup); the sidebar's maintenance wrench is announced only through its `title`
and `sr-only` text, as the old ‖ glyph was; disclosures (`details.more`, the Security tab's "Why it
matters" and "Accept as a risk") have no visible chevron; the steppers' ✓ glyph.

## 41. Implementation notes (round-2 redesign, slice C: shell, page structures, IA step)

Branch `redesign-slice-c` on `main` @ b9ed63b. Plan 04 §10 slice C: components 8–10 of §5, the page
structures of direction A with C's flight recorder and B's incident mode, the Security tab details of §11,
and the IA step of §11 items 8 and 9 as **one revertable commit** (`feat(ui)!: round-2 IA step`). No Go
dependency, no migration, no authz change; the CSP is unchanged (no `style=`, no inline script, no new origin).

### Determinism first (step 0, and the review's M3)

The e2e history seed now ends on the sparkline grid (`history.SparkStep`, 30 minutes since the epoch) and
indexes its wave from that end, so the 24 h sparklines and the Overview recorder draw identically in every
run. After the line, the seed carries the fixture's own values every five minutes up to a minute before now, so
no bucket is empty before the first live poll. The UI then draws its charts for that grid line: the test hook
`env.uiHistoryNow` (zero in production, like `stepUpWindow`) wraps the UI's history in one whose `Now()` is the
seed's end, while the sensor history itself keeps the real clock. A run that crosses a grid line therefore no
longer shifts the window; the visual spec also masks the recorder's axis labels.

### Stylesheets

`tokens.css` → `themes.css` → `app.css` (components, 554 lines) → `shell.css` (shell, 266) →
`pages.css` (page layouts, 151). `TestTokenLayers` and the sheet-order test cover all three; none
defines a colour; no `color-mix()` (glass and translucent glows are therefore not built: the bars are
opaque, the incident glow is a blurred shadow of `--danger`).

### Components 8–10 and the slice B deferrals

- **Shell**: top bar 3.5 rem (mark, wordmark with a dot in the fleet's worst state, pill, clock, account menu
  with an avatar initial and icons, About and licenses); sidebar 16.5 rem with each server's **sub-line in
  words** (`sideValue`: "47 °C", "Powered off", "Stale · 9 min", "Maintenance · 41 °C", "No data", "BMC
  restarting"), so the maintenance marker has a visible word; the Menu sheet below 1024 px; breadcrumbs as an
  ordered list; tabs with an ink underline, a 4-column segmented grid with icons on phones; footer.
- **Component 9**: steppers and the first-run checklist draw the sprite's `check` (no ✓ glyph left); pager
  steps are outlined controls; log-kind and range sub-navigation is a segmented control (`.seg`); every
  disclosure leads with `chevron-right`, turned 90° when open; lock badge as a pill.
- **Component 10**: confirm pages put the tier badge above the question (reading order and Cancel focus kept,
  audit R2-05); the authenticator box is headed by the shield; sign-in leads with the large mark.
- **Alerts** lead with their state icon (`sicon`) and a body wrapper (`.alert-b`, a `<div>` when the body
  holds paragraphs or forms); alerts that led with a lock icon keep it.
- Lucide 1.53.0 `ellipsis`, `hard-drive`, `sun-moon` vendored from the verified release zip (manifest);
  every previously reserved icon except `copy`, `plus`, `rotate-ccw` and `search` is now drawn.

### Overview

- **Hero** (`overview_hero.go`, `heroOf`): the verdict is the h1 ("All 2 servers healthy", else the worst
  non-maintenance server and its state, else "Warning or critical events in the last 24 h"); the worst
  attention item with its badge; counts, draw, 24 h event counts and the data age; auto-refresh; "Also needs
  attention" (`id="attn-h"`). Banners follow the hero.
- **Incident mode** (B): only while `Counts.Critical > 0` — display type for the verdict, the critical count
  as a display numeral, one static glow on the icon tile. Nothing animates.
- **Flight recorder** (C, `recorder.go`, `svg.RecorderRow`, `svg.AxisTicks`): one row per server, worst first,
  at most 24 (`maxRecorderRows`; the rest are counted, the Servers table lists all). Each row is the server's
  hottest sensor over `history.SparkPlan` (48 buckets of 30 minutes from raw rows). Cost: one read of each
  server's sensor list, then **one `Chart` call for all rows** not in the recorder cache (`reccache.go`: a
  minute per row, keyed by server, sensor key, temperature unit and the plan's start, at most 256 entries; when
  full, expired entries go first, then all). With no history wired, or a viewer without
  `server.history.view`, nothing is read. The series are
  drawn in a 720 × 40 viewBox with `preserveAspectRatio="none"` and non-scaling strokes, so every row shares
  the time axis; steps without a bucket are hatched; axis labels every sixth hour in the viewer's zone are
  placed with the existing `.tN` position classes. Accessibility: the SVGs are `aria-hidden`; each row has a
  text summary (minimum, average, maximum, gaps), a visible hint explains the drawing, and a "Data table:
  fleet, last 24 hours" disclosure repeats the numbers. Without history, or for a viewer without
  `server.history.view`, only the compact list is drawn.
- **Phones** keep the verdict-first layout: the hero, then a compact list (name, worst line, number, age).
  The fleet table with every column is on the Servers page (`layout.spec.ts` and the visual spec's
  "settled" wait read it there).
- 5-second test at 390 × 844: `#verdict .verdict`, `#verdict .worst` and `#verdict .dataage` in the first
  viewport.

### Server pages

The head carries state chips (power, health, data age) and, after the IA step, the action menus. The
Security tab (§11): viewers keep the summary only; operators and admins get the **posture map** (one cell per
check, fill weight carries the result, each group a link to its section: the jump list) and, inside each
group, passes and infos fold into "N more checks" ("Not checked" infos and accepted risks stay visible).

### IA step (one commit)

- **Header menus** Console ▾ · Power ▾ · More ▾ (`servermenus.go`, partials `hmenus`, `menutrio`,
  `menuitems`), `<details>` with links only; items that cannot be used stay visible with their reason
  (criterion 12); a viewer gets "Actions need the operator role." (audit R2-11). **Restart BMC…** is under
  Power ▾. The same menus form the **phone bottom bar** (`layoutData.ServerMenus`, `body.has-bottombar`;
  operators and admins). The pill shows the **short worst word** on phones (`pillView.short`).
- **Stable tabs**: Overview · Sensors · History · Events · Activity · Inventory · Security (History and
  Security where wired). Consoles are reached from Console ▾; their pages are unchanged (slice D).
- **Sidebar**: Overview, Servers, Firmware, Events, Activity, Settings, Help (About in the account menu and
  footer). Settings → Integrations already sat between Notifications and Audit log.
- **Redirects** (**302**, query re-encoded and kept; `moved` in `server.go`). 302 rather than 301 on purpose:
  browsers keep a 301 forever, which would defeat a `git revert` of the IA commit. An old Operations address
  with a fan lease notice (`?fan=started`) goes to the Fan boost page, which shows it.

  | Old GET path | New |
  |---|---|
  | `/servers/{id}/operations` | `/servers/{id}` (Overview tab; Now panel and the menus) |
  | `/servers/{id}/logs` | `/servers/{id}/events` |

  New GET pages: `/servers/{id}/sensors`, `/servers/{id}/events`, `/servers/{id}/activity`,
  `/servers/{id}/fan` (Fan boost: the lease card), `/activity`. POST routes and CSRF bindings did not move;
  only where a POST lands changed: power and BMC restart results on the Overview tab's Now panel (`#now-h`,
  `#pw-last`, `#bmc-last`), fan leases on the Fan boost page, acknowledgements on Events, maintenance and
  notes on Activity.
- **Activity privacy rule** (`activity.go`), for every role: the SQL reads only the action and result pairs of
  `activityMatches()` (`store.AuditFilter.Matches`, so a page of 50 is 50 shown rows): power actions and BMC
  restarts when requested (`started`) or failed (`error`), fan leases, lease expiries, BMC restart
  verifications and maintenance windows when they took effect (`ok`) or failed. These are the actions the
  history overlay draws for every History viewer, but one row per thing done: a power action's final `ok` row
  (which also covers an unconfirmed outcome) is not repeated. Never sign-ins, step-ups, tokens, users,
  settings or refusals; `activityRow` has no field for an address, role, method or parameter.
  `TestActivityShowsActionsOnlyToEveryRole` seeds those rows with a source IP and parameters, a final `ok`
  power row and a refusal, and checks a viewer sees none of them. Pages of 50, `?before=<seq>`.
  **Accepted disclosure (review L8):** the `before` cursor is the audit sequence number, so a viewer can tell
  how many audit rows of any kind exist between two actions. It is not opaque on purpose (the audit log's own
  pager uses the same cursor); the rows themselves stay hidden.

### Moved to slice D, or not built

- Motion, view transitions, the command palette and `/go`, the console frames (unchanged).
- Glass bars and an ambient glow (need colour arithmetic; see above).
- The recorder's power and health bands and "since your last visit" shading, and the Overview rail's Now
  and Since-your-last-visit cards: the app stores no state history and no per-user visit record.
- The server Overview keeps the Status panel (with sparklines) instead of vitals tiles; the native iDRAC
  console launch (a form) stays on the console card, not in Console ▾.

### Review fixes (2026-10-29)

A combined security and code review found no critical or high issue. Fixed: the Activity filter in SQL with one
row per thing done (above); the recorder's axis labels masked in the visual spec; the UI's history clock frozen
on the seed's grid line in e2e (above); axe scans with the Power menu open (header at 1440, bottom bar at 390)
and of the phone page scrolled to the bottom, where the footer must end above the bar (both clean; the disabled
items' reason text is `--muted` on the menus' `--surface-3`, a pair `TestThemeContrast` already holds to 4.5:1
in every palette and mode); the new pages in `TestPagesRequireSession`; the phone bar reuses the menus the page
head built; one `Chart` call and a bounded cache for the recorder (above); 302 redirects (above); stale
"Operations" copy and comments, dead fields and renamed tests; the sidebar says "Maintenance" whatever else is
true of the server; the Overview title names the first server of the pill's worst state (`fleetClass`, the rule
the counts, tone and incident mode use); axis ticks step in wall-clock hours so a DST change keeps them on 00,
06, 12 and 18; the posture map's cell row may wrap; power results land on the Now panel (`#now-h`), like a BMC
restart.

## 42. Implementation notes (firmware update checker, plan 08)

Plan: `docs/plans/08-update-checker.md` (decisions in its §21). Read-only: the app reads a vendor's signed
list of releases and compares versions. It never downloads a firmware package, never stages or applies
anything and never sends a request to a BMC for this feature (rule 11; the `firmwareUpdateWords` policy test
is unchanged). Slices: **U1** catalog core (this section, feature not wired into serve), **U2** matching and
the view, **U3** settings, notifications, upload and e2e; U2 and U3 ship together as v0.9.0.

### U1: catalog core

- **`internal/egress`** is the outbound destination policy, extracted from `internal/notify` so the
  notification transport and the catalog fetch share one implementation: a host is resolved once, every
  answer must be public unicast unless it is inside the setting's allowed networks, and the dial goes to the
  checked IP; the one-shot client has no proxy, no redirects, no keep-alive and bounded headers. Refusals
  name the setting (`notifications.allowed_networks`, `firmware.catalog.allowed_networks`). Notify keeps its
  classes (a `*egress.DNSError` is `dns`); its tests are unchanged.
- **`internal/firmware/catalog`**: the plan-03 interface extended. `Lookup` returns a `Match` (latest
  release, candidate count, how the system was identified); `Release` carries criticality (1 Recommended,
  2 Urgent, 3 Optional), name, details URL, package path (shown to a human, never fetched) and reboot flag.
  `UpdateSource` is the vendor seam (name, default URL, verify, parse); `Limits` and `Want` (system IDs plus
  normalised model names) bound and scope a parse; failure classes `download`, `size`, `signature`,
  `untrusted_key`, `parse` (`catalog.Class`).
- **`internal/firmware/catalog/dell`**:
  - **Signature first** (`verify.go`, `pgp_*.go`, standard library only, §2): the armor is at most 4 KiB
    with exactly one v3 or v4 signature packet over binary data; its issuer must be a trusted primary key
    (else `untrusted_key`, naming the key ID; subkeys never sign); the hash must be SHA-2, or SHA-1 from a key
    pinned as legacy (only Dell's embedded key is); an unknown critical hashed subpacket fails; then the
    RSA/DSA check over the **compressed** bytes plus the signature trailer. A hashed issuer fingerprint must
    name the key exactly and wins over an unhashed key ID; two trusted keys sharing a key ID are refused; a
    hashed signature expiration is honoured. Extra keys must be sane (RSA 2048–16384 bits with an odd
    exponent ≥ 3; DSA FIPS 186 domain checks). **Not covered:** freshness. An older catalog that Dell itself
    signed would verify again (replay needs a TLS break for the online fetch); the shrink hold (§15 of the
    plan) is the guard against a much smaller one. Dell signs with DSA-1024/SHA-1 (a v3 packet);
    TLS to a file-only https URL is the primary control and the signature defence in depth (threat T14).
    Verified on Dell's real catalog and signature, and a one-bit change is refused.
  - **Parser** (`parse.go`, `component.go`, `utf16.go`): one gzip member; a size reader fails at 128 MiB
    decompressed (`size`, not a silent truncation); UTF-16 LE/BE by BOM is transcoded by a small stdlib
    reader that refuses unpaired surrogates and odd byte counts (no `x/text`); a strict `xml.Decoder` on raw
    tokens with depth ≤ 16, attributes ≤ 4 KiB, text ≤ 64 KiB, no DTD or entity declarations, ≤ 20,000
    components, ≤ 256 devices, 512 models and 256 PCI identities per component, ≤ 100,000 kept entries and a
    60 s wall clock. Only top-level `SoftwareComponent` elements count; `Prerequisites`, bundles, inventory
    components and OS lists are skipped token-wise. **Only `FRMW` and `BIOS` components are kept:** Dell's
    driver packages (`DRVR`, 135 in the 2026-10-22 catalog) share component IDs with firmware (219 IDs
    overlap), so a NIC would otherwise be compared with its Windows driver version. Strings go through
    `textclean` with caps (names 160, versions 64, paths and URLs 512); invalid system IDs, component IDs or
    PCI IDs drop the entry. Measured on Dell's real catalog (22 MiB XML, 1,005 components): 0.2 s and a peak
    heap of 4.4 MiB; `TestParseMemoryIsBounded` holds a 5,000-component synthetic catalog under 32 MiB.
  - The real catalog keeps 845 releases for the iDRAC9 test system (`088F`). The iDRAC8 system (`0627`)
    appears only inside `<Prerequisites>` (one iDRAC 2.40.40.40 package from 2016), so the check will say
    the vendor catalog does not list it.
- **`internal/fwcatalog`**: `Stage` (≤ 16 MiB into a temp file), `Importer` (sha256, verify, parse, the
  **shrink hold**: a catalog that keeps fewer than half the active import's rows is stored `held` until an
  admin confirms, then the verified file is cached as `<data>/catalog/dell/<sha256>.xml.gz` + `.sign`, mode
  0600, and the import saved; `Reparse` re-reads the cached files for a changed fleet with no network) and
  `Fetcher` (conditional GET with the stored ETag/Last-Modified, a 3xx is a `download` failure naming the
  redirect, `Content-Length` and the streamed body capped, 30 s without a byte aborts, then `URL.sign` ≤ 4
  KiB; a missing signature is `signature`). Unsigned catalogs are refused unless `firmware.catalog.allow_unsigned`
  is set, and never online. Every check is a `catalog_checks` row; imports are audited as
  `firmware.catalog.imported` / `firmware.catalog.failed` (class only, never a response body).
- **Migration 0017**: `catalog_imports` (state active/held/replaced, one active and one held per source by
  partial unique index, newest 20 kept), `catalog_checks` (90 days, 500 rows), `catalog_releases` and
  `catalog_models` (the kept systems' catalog model names, for the iDRAC8 model fallback), the U2 tables
  `firmware_update_skips` and `firmware_update_notified`, `firmware_scans.system_id`, and the `settings_kv`
  rebuild with `firmware.catalog.enabled`, `.check_every` and `.notify` (U3 uses them).
- **Config** (file-only, `firmware.catalog`): `url` (https, no user info, query or fragment), `extra_keys_file`,
  `allowed_networks`, `allow_unsigned`, `systems` (server ID → 4 hex digits).
- **CLI:** `oob-manager catalog import <catalog.xml.gz> [<catalog.xml.gz.sign>]` runs the same pipeline
  (principal `cli`).
- **Tests:** a synthetic UTF-16 catalog built in `catalogtest` (the shapes of §4 of the plan, 39 components,
  a driver sharing a component ID, a prerequisite, filler systems), test keys (v4 RSA/SHA-256 and a
  hand-built **v3 DSA/SHA-1** packet like Dell's, all built with the standard library), every bound as its own case, `FuzzUTF16Reader`,
  `FuzzParseCatalog`, `FuzzVerifyArmored`, fetch cases against an httptest TLS server (304, redirect, 5xx,
  announced and streamed oversize, stall, missing and oversized signature, a private address refused before
  any request), the opt-in `-tags dellnet` live test (nightly, non-blocking).


### U2: matching and the view

- **System key.** The Redfish inventory reads `Oem.Dell.DellSystem.SystemID` (iDRAC9; the R240 fixture's
  2191 → `088F`) into `bmc.InventoryInfo.SystemID`; each scan stores it in `firmware_scans.system_id`.
  iDRAC8 reports none, so its model name must name exactly one system in the catalog's `catalog_models`
  (ambiguous names do not match); `firmware.catalog.systems` overrides both. Generic Redfish has no source.
- **Matching** (`fwcatalog.Index`, built from the store, cached 30 s and dropped at once on an import or a skip):
  candidates by system and component ID; a row with a 6-part Dell identity keeps the packages with its PCI
  identity, else those without one; latest = highest comparable version (`firmware.CompareVersions`;
  packages that do not order against running are left out; none → `cannot_compare`). States: `none` (up to
  date), `available`, `urgent`, `skipped` (exactly the skipped version; a newer one reopens), `cannot_compare`,
  `not_in_catalog`, and `""` without a catalog. "Already stored on the BMC" when `stored` is the latest.
- **Flags.** `update_urgent` (warn, rank after `below_minimum`; **counted in the sidebar badge**, decision 5)
  and `update_available` (info, after `not_applied`). Filter `updates=1` keeps rows with a newer, unskipped release.
- **Coverage line** per server: no source for the BMC kind, model not identified, not listed (end of support),
  only legacy entries (newest > 5 years old), or "N of M components matched · K updates (U urgent)".
- **Latest column** on /firmware and the Inventory section, shown while a catalog is in use. The vendor link is
  drawn only for `https` on `dell.com` or `*.dell.com` (`rel="noopener noreferrer"`, new tab); anything else is text.
- **Skip this version** (`server.firmware.skip_update`, admin, fresh step-up, CSRF, 10/min/user, audited with
  component, FQDD, version and comment): the form carries the version the admin saw; a different latest is a
  409. Unskip is the same action. A server leaving the registry drops its skips and notified rows.
- **Fleet changes** re-parse the cached catalog locally when a scan reads a new system ID or model (no network).
- **API (additive except one field):** rows gain `latest` (`{version, released, criticality, name, details_url,
  package_path, reboot_required, candidates, matched_by}` or `null`) and `update`; `meta` gains `updates` and
  `urgent`; **`meta.catalog` changes from a text line to an object** `{source, enabled, version, published,
  imported_at, signed, held, checked_at, last_result}`; the server view gains `coverage`; new
  `GET /api/v1/firmware/catalog` (viewer, tokens). CSV appends five columns (deploy/README).
- **Metrics (append-only):** `oob_firmware_updates_available{server,criticality}`, and the flagged family gains
  `update_urgent` and `update_available`; `oob_firmware_catalog_published_timestamp_seconds{source}`,
  `oob_firmware_catalog_last_check_timestamp_seconds{source,result}` and
  `oob_firmware_catalog_check_failures_total{source,class}` (wired in U3).

### U3: settings, the online check, upload, notifications

- **Runtime keys** (Settings › General, group "Firmware update check"; config.yaml wins with the lock badge):
  `firmware.catalog.enabled` (default off), `.check_every` (days, 1–30, default 7), `.notify` (urgent, all,
  off; default urgent). Migration 0017 already lists them in `settings_kv`. Every General change already
  needs admin + a fresh step-up; a change of `enabled` is audited twice (`settings.general.changed` and
  `firmware.catalog.enabled_changed` with before/after).
- **Scheduler** (`fwcatalog.Checker.Run`, one goroutine, no fleet or BMC handle): wakes every 30 s and reads
  the keys; nothing is fetched while off. First check 2–10 min after start (jitter), within 2 min of turning
  it on, then every `check_every`; failures retry after 1 h and 6 h, then the interval. Conditional GET with
  the stored ETag/Last-Modified of the last online import (`not_modified` is recorded, nothing parsed).
  Three consecutive failures send one `firmware` warning until a success.
- **Check now** (`firmware.catalog.check`, operator, sessions, CSRF, audited): one per 5 minutes globally
  (429 with Retry-After, audited `rate_limited`), refused while the check is off (409, audited `disabled`).
- **Upload** (`firmware.catalog.upload`, admin, fresh step-up, CSRF, 1/min/user): multipart, streamed part by
  part (no temporary copy: the container's `/tmp` is a 16 MiB tmpfs), in order CSRF token, signature, catalog;
  the body is capped at 16 MiB + 68 KiB (413). The role and step-up are checked before the body is read, and
  the panel shows the form only with a fresh step-up (a multipart form is not stashed across the step-up
  page). The same pipeline as the online check (origin `upload`, principal, role and address of the admin,
  failures audited); refusals name the class only. **Confirm** a held catalog: the same action; the form
  carries the held import's ID (a catalog replaced meanwhile is refused) and the audit row its version,
  sha256 and signer.
- **Notifications** (class `firmware`, never pages): after every online check (a 304 too), an upload, a
  confirmation and every recorded scan, the view's newer unskipped releases (servers in maintenance left out
  until their window ends; scans and uploads notify even while the online check is off, from the catalog
  in use) are marked in `firmware_update_notified` and the new ones sent in **one** message (16 lines and
  "and N more"); warning when any is urgent, else info; `notify` filters what is sent (everything seen is
  marked, so changing the level never floods). The config's class list gains `firmware` (file targets
  without a class list get it; browser targets choose it).
- **Settings panel** "Vendor firmware catalog": status, the file-only keys read-only (URL, trusted key
  fingerprints, allowed networks, `allow_unsigned`, overrides count), the upload form and the held-catalog
  button.
- **Metrics:** the three `oob_firmware_catalog_*` families are wired (failure counts since start, by class).
- **e2e:** the harness serves a signed synthetic catalog over TLS (test root, `allowed_networks:
  [127.0.0.0/8]`, the test key in `extra_keys_file`) and imports it with `catalog import` before serve; the
  check stays off (no request reaches the server) until the admin turns it on in Settings, then the first
  check imports, the urgent iDRAC9 update is notified once, and Check now re-checks with a 304.

## 43. Implementation notes (round-2 redesign, slice D: motion, view transitions, console frames)

Plan 04 §10 slice D with the maintainer's §11 items 5, 6 and 13. **Item 7, the command palette, is deferred** to a
later minor (decision); its §7 design stands. The IA step (item 8) shipped in slice C. No migration,
no authz change, no new script, no new origin; the CSP is unchanged.

### Motion (`static/motion.css`)

- **One file, opt-in.** Every transition, animation and view transition is in `motion.css`, inside
  `@media (prefers-reduced-motion: no-preference)`; the old "kill everything under reduce" rule in `app.css` is
  gone because nothing else moves. A `reduce` block there only switches off a vendored sheet's motion (the
  xterm.js scrollbar fade, 800 ms upstream, 200 ms here when motion is allowed). Deleting the file and its
  `<link>` removes all motion and changes nothing else.
- **Budget** (item 5): durations only from `--dur-1` (120 ms) and `--dur-2` (200 ms), ease-out `--ease`.
  Nothing on alarms or status changes: chips, pills, badges, banners and the console status chip appear as
  they are.
- **What moves:** colour fades on hover and focus of links, buttons, summaries and fields; chevrons turning;
  menus and the phone Menu sheet entering (`@starting-style`: fade and a 6 px drop); a disclosure's body fading
  in; and the **value-change tint**.
- **View transitions** (item 6): `@view-transition { navigation: auto }` with a 200 ms crossfade;
  `view-transition-name` on the top bar (`topbar`), sidebar (`sidebar`), server head (`server-head`, morphs
  between a server's tabs) and the current tab's ink (`tab-ink`, slides). The ink became an element of its own
  (`<span class="tab-ink" aria-hidden="true">` in `servertabs` and `settingstabs`; hidden on phones, where the
  current tab is filled). The main column is deliberately unnamed: a named column would stretch between pages of
  different heights. Same-origin navigations only (a form's 303 to a GET included); reloads and the
  auto-refresh never transition. Chromium and Safari animate; Firefox navigates instantly.

### Value-change cue

- `fleet.ServerState` keeps the successful snapshot before the current one (`Previous`, `HasPrevious`; a failed
  poll moves neither), passed through `fleetview` to `ui.ServerView`.
- `ui/valuechange.go`: on the Sensors tab, a temperature (matched by name and context, in the viewer's unit) or
  a fan (by name) whose reading shows another value than at the previous poll, at the shown precision, gets
  `chg chg-up` or `chg chg-down`. New, missing or unread readings are never marked; the rows are copied, not
  changed.
- `motion.css` tints `.chg` with `--accent-bg`, holds it for `--hold` (600 ms, an animation delay), then fades it
  in `--dur-2`. Under reduced motion there is no cue: the maintainer's item 5 is "all off under reduced motion", and a
  static ▲/▼ would make the visual baseline depend on the mock's last two polls.

### Console frames (item 13: restyled only)

- `console.css` is now the shared frame of both consoles (the serial page loads it before `serial.css`, which
  keeps only the terminal, its colours and the transcript; the duplicated rules are gone). One `.con-frame`:
  a toolbar strip on `--surface` over the always-black stage, radius `--r-panel`. The connection state is a
  chip: dashed and muted while connecting, a green outline and mark when connected, a red tint on an error (the
  `data-state` values `console.js` and `serial.js` already set). The transport line is a chip with the lock
  icon (the triangle when VNC is not encrypted) and wraps on a phone (it overflowed at 390 px). The xterm focus
  ring moved inside the frame.
- Unchanged: the layout with the session panels, every control, id and script hook, and the keyboard notes.
  The mockup's full-bleed focus mode would be a redesign, not a restyle.

### Settings › Servers › a server (follow-ups from v0.9.1)

- The panels' lead paragraphs get room below them (`.panel-intro`); each fingerprint is its own block with a
  separator, so "HTTPS certificate (Redfish)" no longer sits on the paragraph above.
- **Credentials:** the three cards share subgrid rows (heading, state, form) and stretch, and each form ends in
  its button, so the headings, the "Set" / "Not set" badges and the Store/Replace buttons line up across the
  row even though the VNC card has no username.
- **Features:** three labelled groups (Fans; Consoles; Power and polling) in a grid of 18 rem columns instead of
  one long column; the self-host box and the "What goes down with it" list span the row.
- The editable page is the one an install with browser-managed servers uses (file-managed servers move
  there with `settings import`), so the visual spec now adds a disabled browser-managed server in
  its setup and captures `settings-server-db` (its credential date is masked). A disabled server stays out of
  the sidebar and the fleet pages, so no other baseline gains a row except the Settings › Servers list.

### Tests

- `TestMotionOnlyWhenAllowed`: no other stylesheet declares motion; every `motion.css` block is a
  `prefers-reduced-motion` block; `no-preference` blocks use no literal durations; a `reduce` block may only set
  `none`; every `--dur-*` token is at most 250 ms.
- `TestPreviousSnapshotIsKept` (fleet), `TestReadingChange`, `TestSensorRowsMarkChanges`,
  `TestSensorTablesCarryTheChangeClass` (ui).
- `motion.spec.ts`: with motion allowed, no element on six pages has a transition or animation longer than
  250 ms, the four view-transition names are set and a menu has its entrance; with reduced motion every duration
  is zero and no name is set. `playwright.config.ts` now sets `reducedMotion: 'reduce'` for every spec (plan 04
  §7), so no spec clicks, scans or screenshots half-way through an entrance; `motion.spec.ts` opts back in.

### Review (2026-10-29)

One combined security and code review, done by the implementing agent (a worker that could not start separate
reviewer agents), then a re-check of the fix. Security: no new script, origin, inline style or input path; the
previous snapshot is internal state only (the JSON API and metrics build their own fields, so nothing new is
exposed); the console restyle keeps every id and data attribute the scripts and CSP rely on. One real bug, fixed:
**a `view-transition-name` makes its element a stacking context**, so with motion allowed the server head's
Power menu opened *under* the tabs and panels that follow it. `.shead` is now `position: relative; z-index: 5`
(below the top bar's 20 and the phone bottom bar's 15), and `motion.spec.ts` hit-tests every Power menu item with
motion on. Lows noted, not changed: the value-change cue tints again when a page reloads twice within one poll
(it compares polls, not page views); Firefox gets no view transitions (by design, plan 04 §7).

## 44. Implementation notes (store-ready install, plan 09)

v0.11.0, branch `store-ready-install`. Plan 07 §4.8 (first part), designed in docs/plans/09-store-ready-install.md.
No migration (schema stays 18). Threat rows S11, T15, I18, E6.

### What a container with only a data volume does

- **No config.yaml.** `loadConfig` falls back to `config.Defaults()` when no `-config` was given and neither the
  default nor the pre-rename file exists; it logs "running on built-in defaults". An explicit `-config` that is
  missing stays an error. `public_url` and the TLS pair are now optional in any config.yaml (both TLS files or
  neither). `TLSConfig.Defaulted` and `SecretsConfig.{Identity,AppKeys,Credentials}Defaulted` record what the file
  left out, like `Storage.DBPathDefaulted`.
- **Path resolution** (`storePaths`, cmd): a defaulted TLS pair is `<data>/tls/tls.{crt,key}`. Defaulted secrets use
  their mounted defaults (`/run/secrets/...`, `pathDefaults` so tests use temp dirs); only when the identity **and**
  the app keys are both defaulted and both absent do they become `<data>/keys/{age-identity,app-keys.age}`, and then
  a defaulted, absent credentials file means no file (an empty set; `loadCredentials`). `<data>` is
  `dir(storage.db_path)`.
- **First start** (`ensureStoreFiles`, before the certificate, the keys or the DB are opened): `firstrun.CheckWritable`
  (also in `openCore`, so the CLI gets the same message), then `firstrun.EnsureCert` and `firstrun.EnsureKeys` for the
  data-volume paths only. `EnsureKeys` generates only when the data volume has no key set and `dbIsFresh` (no DB file,
  or `store.DB.HoldsSealedData` false: no row in users, bmc_credentials, notify_targets, api_tokens). Sets are written
  in a temp sibling directory and renamed (`writeSet`); leftovers are cleaned on the next start; half a set refuses.
- **Setup code** (`newFirstRun`, serve): when the users table is empty, `firstrun.NewSetup` (20 random bytes,
  base32, grouped 8 × 4, 24 h) and one WARN log line with the code; audit `setup.code_issued` (expiry only).
  `firstrun.Service` backs the UI: `SetupOpen` (live code and zero users; a non-zero count burns the code), `Claim`
  (checks the input, then `Setup.Claim` reserves the code for one caller, `BootstrapAdmin`, then `Burn`, or
  `Release` on a fixable failure), `BackupPending` and `DismissBackup`.
- **UI** (`internal/web/ui/firstrun.go`): `GET/POST /setup` (pre-session, CSRF bound to the pre cookie, login rate
  limits, audit `setup.claim` ok/denied with `bad_code`, `csrf`, `rate_limited`, `closed`), then the existing reveal
  page and `/enroll` confirm. The sign-in page links to `/setup` only while it is open. The admin banner "Back up the
  encryption key" with `POST /keys/backup-notice` (admin, session CSRF, audit `keys.backup_acknowledged`).

### Decisions

- **No `PUID`/`PGID`.** The image is distroless, non-root and read-only; honouring them needs a root entrypoint
  that `chown`s and drops privileges, which the hardening forbids. Docker's `--user uid:gid` does the same job; the
  writability check names the uid/gid and the `chown` to run.
- **Credentials without a file.** An empty age file cannot be written (an empty credentials document is invalid)
  and is not needed: browser-added servers seal their logins in the DB.
- **The setup code stays in memory only** (its digest), so a restart issues a new one and nothing in the database
  or the data volume can be replayed.
- `/leases` is only needed for `host-lease` fans; a store install without that mount starts normally.

### Tests

- `internal/config/store_test.go`: defaults without a file, defaulted flags per secret, optional TLS and
  `public_url`, half a TLS pair refused.
- `internal/firstrun`: writability probe (missing, file, read-only), key generation (modes, reuse, refusal on a
  non-fresh DB, partial set, abandoned temp dir), certificate (modes, reuse, half pair), setup code (format,
  normalisation, expiry, burn, one winner among 20 concurrent claims, release), the service (one admin among 16
  concurrent claims, a failed creation keeps the code, closed once an account exists), the notice.
- `cmd/oob-manager/store_install_test.go`: no config file, explicit missing `-config`, mounted defaults win, **an
  install whose config.yaml names every file gets nothing generated and still fails on a missing file**, first
  start generates then reuses, sealed data without keys refuses (read-only check), an unwritable data directory
  stops before the database exists.
- UI: setup creates the admin then closes (404, no sign-in link), rejects (wrong code audited `bad_code`,
  mismatched passwords, bad username not echoed, forged CSRF), rate limit, absent without a first-run service,
  closed when an account exists; the backup banner is admin-only, CSRF-bound and audited.
- Go e2e `TestE2EStoreInstall`: an empty data directory and no config.yaml through the real `serve`: generated
  files and modes, code read from the log, wrong code 401, `/setup` → reveal → `/enroll` → sign-in → banner →
  acknowledge, `/setup` 404 afterwards, the code logged exactly once. `TestE2E` now also checks that the
  configured install generates no `keys/` or `tls/` and offers no setup.
- No visual baseline for `/setup`: the dev harness bootstraps its admin first, so the page never shows there.

### Review (2026-10-29)

One combined security and code review, done by the implementing agent (a worker that cannot start separate
reviewer agents), then a re-check of the fixes. Findings fixed: the freshness check migrated an existing database
before refusing to start (now read-only); the username rule was copied (now `auth.ValidUsername`); `Setup.Check`
was API used only by tests (unexported); the quick start did not say how to recover an unconfirmed first admin or
replace the generated certificate. Checked and kept: the setup code is never in a URL, audit row or page; claims
serialise in memory and `CreateFirst` guards the database; configured paths are never replaced (tested); the
banner's dismiss is admin, session-CSRF and audited; `redirectLocal` guards its target. Lows noted, not changed:
after the code expires (24 h) the sign-in page shows no hint (the README and the start log say to restart); a store
install that later mounts only the identity at `/run/secrets` fails until the app keys are mounted too (fail closed).

### Independent review and v0.11.1 (2026-10-29)

A separate security reviewer read the v0.11.0 diff: no critical or high finding, and none affecting an install whose
config.yaml names its files and has users. Fixed in v0.11.1 (plan 09 §8): **M1** a missing config.yaml ran on built-in
defaults; it now does so only for a fresh or marked store volume (`<data>/store-install`, written on a fresh volume's
first start, removed by any start with config.yaml), refuses an unmarked database holding sealed data, and accepts
`-config=none` as an ERROR-logged opt-in (`loadWithoutConfig`; start notes now carry a level). **L1** `Service.Claim`
releases an unsettled claim in a defer (a recovered panic no longer wedges `/setup`). **L2** `/setup` has its own
per-IP bucket (`setupRate`, 5/min) instead of the sign-in buckets. **L3** `firstrun.Cert` reports `NotAfter`;
`ensureStoreFiles` warns within 30 days of it. **L4** `dataKeys` requires both key paths defaulted. **L6**
`dbIsFresh` errors say why nothing is generated. **L8** the key-notice acknowledgement is audited before the marker is
removed and refused when the audit write fails; the `Dismiss` comment matches the code. Tests: unit tests per fix
(written first), and `TestE2EStoreInstall` now restarts the store install (no new setup code) and checks that the same
data without the marker is refused and left unchanged.

## 45. Implementation notes (plan 06 §3.5: fuzz targets, nightly)

Twenty Go native fuzz targets, all in `_test.go` files so the coverage gate and the binary are unaffected. Every
`func Fuzz…` must be listed in exactly one of the Makefile's `FUZZ_A` / `FUZZ_B` sets (`internal/repopolicy`
`TestFuzzTargetsListed`). `nightly.yml` job `fuzz` runs both sets in parallel, each target for 30 s (about 5 min per
set), and uploads the failing input on a failure. `make fuzz FUZZ_SET=A FUZZTIME=2m` runs them locally.

| Target | Package | Property |
|---|---|---|
| FuzzRFBFilter | console/rfb | only allowlisted client messages; type byte kept; encodings ≤ 64 and rebuilt; clipboard ≤ cap; other messages copied verbatim; no input forwarded in view-only; ends with EOF or ErrProtocol |
| FuzzRFBServerHandshake | console/rfb | BMC-supplied version, security and ServerInit bytes never panic; names > 1 KiB never accepted |
| FuzzParseVersion | console/rfb | only `RFB 003.yyy\n` (yyy ≥ 3) → 3, 7 or 8 |
| FuzzSerialControl / FuzzSerialInput | console | only the three control types with sane sizes; the quit key 0x1c never survives, nothing else is lost |
| FuzzLeaseAck | fan/hostlease | a hostile ack yields only bounded fields (owner set, pct ≤ 100, lease id and reason patterns) |
| FuzzRedact / FuzzGELFEncode | audit | no value under a secret key survives at any depth (lists included); the caller's map is untouched / one JSON object + exactly one NUL, GELF key set, no `_id` |
| FuzzCheckBMCAddr | netpolicy | accepted strings re-format to themselves, are inside the allowlist and never special |
| FuzzSetupCode | firstrun | only the real code (any case, spaces, dashes) claims; a wrong guess never blocks it |
| FuzzLogEntryDecode / FuzzSnapshotDecode | bmc/redfish | mutated log pages, legacy Thermal and subsystem Fan documents: no panic, text valid UTF-8 ≤ 1024 bytes, units in the closed set |
| FuzzCompareVersions | firmware | antisymmetric, reflexive, transitive on comparable triples |
| FuzzLinkify | web/ui | segments re-join to the input, links http(s) only, rendered HTML has no unescaped `<` and no `javascript:` href |
| FuzzPGPVerify (new) + FuzzParseCatalog, FuzzVerifyArmored, FuzzParsePackets, FuzzUTF16Reader (plan 08) | firmware/catalog/dell | changed data never verifies under a real signature; parser bounds |
| FuzzField (plan 02) | csvx | RFC 4180 round trip with the formula guard |

Not added here: `FuzzTOTPCode` / `FuzzBase32` (`internal/auth` belongs to the parallel lane-A slice; add them there).

**Found by fuzzing, fixed in this slice:**
- `rfb.ParseVersion` accepted a sign in either number (`RFB +03.007\n` as 3.7), because `strconv.Atoi` allows one.
  It now requires three ASCII digits on each side (regression `TestParseVersionRejectsSigns` + corpus entry).
- `audit.redact` recursed only into nested maps, so a secret-named key inside a list of maps
  (`{"items":[{"secret":"s"}]}`) reached the chain and GELF unredacted. `redactValue` now descends into `[]any` and
  `[]map[string]any` (regression `TestRedactListsOfMaps`). No current caller was found passing such a list. The fix
  closes the backstop's gap.

## 46. Implementation notes (P7 hardening, plan 06 lane A slice H1: reviews, limits, umask, CSP test)

Plan 06 §3.1 and §3.4. Decisions: `umask 077` yes; no CSP report endpoint.

- **Rate limits.** Every POST route reviewed into security.md §3k. Gaps found and fixed:
  - `/readyz` (unauthenticated): a 1 s render cache. The lock is held while computing, so
    concurrent requests share one ping. The shared answer is computed with
    `context.WithoutCancel` (still bounded by the 2 s `readyTimeout`), a cancelled ping is never
    cached, and the cache is stamped after the compute. No per-address limit: an earlier draft had
    a 60/min bucket, dropped after the independent review (M2) because Kuma and Homepage on the
    same host can share one masked source address and Kuma reads 429 as down; the cache already
    bounds the database to about one ping a second.
  - `/prefs/theme`, `/prefs/refresh`: the annotate rate (30/min) in their own `prefs:` bucket, not
    audited (cookie only).
  - `/keys/backup-notice`: the change limit, since every dismissal writes an audit row.
  - `/preferences` already used the change limit; now tested.
- **Fixation / CSRF checklist** (security.md §3l): new tests for demotion (403 on the next request,
  real store), disable (signed out on the next request), a planted session cookie never adopted, a
  cookie replayed after logout, and a WebSocket Origin on the same host with another port. The
  pre-session cookie `__Host-oob_pre` is now **cleared at sign-in** (`clearPreCookie`), so nothing
  set before login survives it. The TOFU "proof from another server's form" case already existed
  (`TestProofBoundToPurpose`).
- **Secrets at rest** documented in security.md §3m: the purposes table (CSRF, ui-resume, bmc-cred,
  tofu, notify; plans 08/09 added none), the master's double use, `oob-manager/totp/v2` reserved,
  and the missing `rekey` CLI as a known gap with its runbook consequence.
- **umask.** `main()` calls `restrictUmask()` (0o077, `golang.org/x/sys/unix`, linux and darwin;
  a no-op elsewhere) first, so every subcommand that may create the database (`serve`,
  `bootstrap-admin`, `token`, `settings`, the coming `backup`), the store-install marker, keys or TLS
  files gets owner-only modes (review L2; the first draft set it in `serveCmd` only). In `main`, not
  `run`, so in-process tests keep their umask. `TestProcessUmaskMakesDatabaseOwnerOnly` checks the
  DB, WAL and SHM are 0600. deploy/README "Upgrade" tells existing installs to `chmod 600` once.
- **CSP.** The page matrix in `tests/e2e/pages.spec.ts` (helpers in `csp.ts`) records `securitypolicyviolation` events on every page it visits (signed in
  and out, both widths and schemes) and fails on any outside the allowlist (xterm.js `style-src` on `/servers/*/serial`).
  A separate spec was tried first: its extra admin sign-in pushed the suite over the e2e harness's
  20/h per-account limit, so the check rides on a run that already signs in.
- **Review pass** over the tree (template trust conversions, unbounded reads, SQL built with
  `Sprintf`, `InsecureSkipVerify`, file modes): nothing new. Every body read is capped (the Redfish
  transport caps at 4 MiB), the `Sprintf` SQL uses fixed table and column names from `tierTable`,
  and each `InsecureSkipVerify` is replaced by a pin check or is the loopback healthcheck. Noted,
  not changed: a replayed logout form after logout writes an anonymous `auth.logout` audit row
  (bounded by the CSRF token's TTL; accepted); the `/setup` bucket keyed by peer address (plan 09
  follow-up N1).
- **Independent security review** (no critical or high): M1 (cache poisoned by a cancelled
  caller), M2 (429 locking out monitors), L1 (cache stamped before a slow compute), L2 (umask only
  in `serve`), L3 (stronger fixation and disable tests: `TestPendingTokenRejectedAfterLogin`, the
  re-enable case), L4 (§3k accuracy) all fixed. Noted, not changed:
  - L5: a replayed `/keys/backup-notice` form past the change limit gets 429 **and** writes a
    `denied`/`rate_limited` audit row per attempt (`allowChange` audits refusals); bounded by the
    form's CSRF TTL and the admin session, and consistent with every other settings refusal.
  - L6: the CSP check sees only the pages in the `pages.spec.ts` matrix, and reads the violations
    right after each load (`h1` present), so a violation from a later interaction (a menu opened,
    a console connected) or a page outside the matrix is not detected.

## 47. Implementation notes (P7 hardening, plan 06 lane A slice H2: backup, verify-audit, admin-recover, drills)

Plan 06 §3.6 (decision: build the `backup` CLI).

- **`backup [-config path] <dir>`** (`cmd/oob-manager/backup.go`): `store.Backup(src, dst)` runs
  `VACUUM INTO ?` on its **own** connection opened `mode=rw` (never creates the source, no migration,
  no pragma beyond `busy_timeout`). The read-only pool cannot be used: SQLite opens the destination
  with the source connection's flags, so `VACUUM INTO` from `mode=ro`/`query_only` fails with
  "attempt to write a readonly database". The destination must be absolute and new (checked, and
  SQLite refuses to overwrite). The file is chmod 0600 explicitly (the umask in `main` would do it,
  but a test or another caller may have a wider one), then reopened read-only: schema version and a
  full chain verification are printed. A copy that does not verify is kept and reported (exit 1).
- **`verify-audit [-config path] [db]`**: `store.OpenReadOnly` + `audit.Verify` over the new
  `ReadDB.Audit()` (query-only, so `Append` fails there by construction) and `ReadDB.SchemaVersion()`.
- **`admin-recover -username`**: the break-glass path settings_design.md §2 specified but never built.
  `admin.Service.RecoverAdmin` re-enables, sets admin, clears the `acct:` lockout row (new
  `Tx.Lockouts()`) and ends sessions in one transaction with its `admin.recover` row (principal `cli`).
  It bypasses the guarded account setters on purpose; it never touches the authenticator.
- **Drills** (deploy/README "Recovery runbook"): 1, 2 and 7 are new tests in `drills_test.go`; 8 is
  `TestAdminRecover`; 3, 4 and 6 point at the existing tests where the behaviour lives (fan
  `TestCrashRestart`, maint `TestOpenEndedReminder`, bmcreset
  `TestStartRearmsOpenWindowsAndClosesExpiredOnes`); 5 is a runbook reading (the orphan `started` row of
  `power.*`). Drill 2 also asserts that no `keys/`, `tls/` or `store-install` appears when a key file is
  lost (plan 09's fail-closed rule).
- **Independent review fixes (H2):**
  - M1: CLI audit rows were never shipped (the CLI core had no shipper), so the break-glass row never
    left the box and drill 7 would report false loss. Mutating commands now call
    `openMutatingCLICore` (or `startCLIShipping` in bootstrap/confirm), which builds the same
    integrations service as serve and runs it; `core.close()` flushes via the new
    `integrations.Service.Flush` for up to `cliShipFlush` (3 s) and only warns.
    `TestCLIAuditRowsReachTheLogServer` (checked to fail without shipping) and
    `TestCLIShippingFailureOnlyWarns`.
  - M2: the runbook restore moves the damaged files aside, copies the backup in, and `chown
    65532:65532` + `chmod 600` (a root `cp` left a file the app cannot open); a newer-schema backup is refused.
  - L1/L2: drill 8 is a table of what each tool fixes (admin-recover clears only the per-account
    lockout; not IP limits, stored settings or a lost password), plus the compromised-credentials follow-up.
  - L3: admin-recover shows the account's state, needs `-yes` or the name typed back, validates the
    name with `auth.ValidUsername` before any audit row, and records the shell user (`os_user`).
  - L5: `OpenReadOnly` runs with `trusted_schema(0)`; README and security.md say verify-audit cannot
    see a full rewrite or tail truncation, and that the log server's copy is the control.
  - L6: `?`, `#` and `%` are refused in database and backup paths (URI syntax); the backup is chmod-ed
    only after `Lstat` shows a regular file; README caution about `/data/keys` in volume backups.
  - L7: `TestBackupAndVerifyAudit` scans the copy for the identity, the sealed app keys and any
    `AGE-SECRET-KEY-` bytes.

## 48. Implementation notes (P7 hardening, plan 06 lane A slice H6: threat model, generic deploy docs)

Plan 06 §3.7, §3.10 and the §4 checklist. Docs only, apart from `deploy/compose.yaml`.

- **security.md §2:** new rows R6 (acknowledgements as evidence-hiding: they never delete an entry and
  suppress only that entry's notification), R7 (a full chain rewrite or tail truncation is invisible
  offline; the log server's copy is the control), I19 (file modes, backups, `/data/keys` on store
  installs) and E7 (the `admin-recover` break glass). D1 now covers `/readyz` (cache, deliberately no 429)
  and the unlimited sign-in GETs; E1 the per-request role and `disabled` re-read; R1 the CLI rows shipped
  to GELF with the shell user. A "no new threat" note covers display preferences, the read-only
  connection (`trusted_schema` off, shared `busy_timeout`) and the absent CSP report endpoint. Residual
  risks 6–9 added. Every threat ID checked unique (S1–S11, T1–T15 incl. T2a, I1–I19, D1–D12, R1–R7, E1–E7).
- **deploy/compose.yaml** is generic now (`/srv/oob-manager`, 192.0.2.20, no platform paths or real
  addresses); an install keeps its own copy with its real values.
- **deploy/README §3.10:** "Docker Compose with mounted keys", "Keeping the identity off the data volume"
  (the boot-hook staging pattern for any init system), "Unraid" (Compose Manager, the app-data share, the identity on
  the flash drive staged by the boot script, bridge network, update exclusions) and "Audit log server (GELF)".
  Notes about one specific install were moved out of the repository at the public cut (plan 07 §4.1).
- **Plan 06 §4** carries a dated status per line.
- **Final lows of the independent re-check (H6 commit):**
  - The GELF policy's deny set no longer depends on the registry: `core.storedBMCAddrs` reads the BMC
    addresses of config.yaml's servers and of every browser-managed row when no registry is loaded (the
    CLI), so a CLI command can never dial a BMC (`TestBMCAddrsWithoutRegistry`).
  - `store.Backup` now creates the destination itself with `O_CREATE|O_EXCL`, mode 0600 (fails on any
    existing path, a symlink included; `VACUUM INTO` accepts an empty existing file), and after the
    vacuum checks with `Lstat` + `os.SameFile` that it is still that regular file. Residual: SQLite
    reopens the path by name, so a writer of the backup directory could swap the file during the
    vacuum; the check afterwards reports it (the copy is then not trusted) but cannot prevent it.
    O_NOFOLLOW + Fchmod on SQLite's own open is not reachable through `database/sql`.
  - `admin-recover` with a username that does not exist returns before the service call, so it leaves
    no audit row (accepted: nothing changed; the shell user is accountable through the host).
  - `os_user` is the shell account: `uid 65532` inside `docker exec`, not a person.
  - CLI shipping waits up to about 6 s on exit (a 3 s flush, then the shipper's own close).
  - Docs: an upgrade note that `?`, `#` and `%` in `storage.db_path` are refused; security.md cells
    re-punctuated; residual 6 made generic; compose.yaml image tag a placeholder and the key-mount
    comment corrected (all key mounts go together, or none).

## 49. Implementation notes (plan 06 §3.2: ZAP and the OpenAPI document)

- **Image:** `zaproxy/zap-stable:20261008` pinned by its index digest in the Makefile (`ZAP_IMAGE`), at least 14 days old
  when pinned. A Renovate custom manager updates tag and digest together, and `internal/repopolicy`
  `TestZAPImagePinnedByDigest` keeps that form.
- **Every CI run (`ci.yml` job `zap`, about 3 min):** `make zap-quick`. The dev harness (mock BMCs, self-signed TLS),
  then `zap-baseline.py` from `/login`, unauthenticated, spider 1 min. Any WARN or FAIL not allowlisted fails the job.
- **Nightly (`nightly.yml` job `zap-full`):** `make zap-full`.
  - **Authenticated baseline:** `tests/zap/signin.mjs` signs in with the harness's throwaway account
    (password + TOTP) and writes a ZAP replacer rule carrying the session cookie into a config file in run.sh's private
    temp dir. The spider never submits forms (`spider.processform/postform=false`), and logout, step-up, power, fan,
    console, serial, WebSocket, BMC reset, delete, enable/disable, test and reset paths are globally excluded.
  - **API scan:** `zap-api-scan.py` against `docs/api/openapi.yaml` with the harness's read-only token, one request per
    second so the 60/min token limit is not the whole result.
  - **Reports:** HTML, JSON and Markdown are uploaded either way. The session and token never leave the temp dir.
- **Manual nightly runs:** `workflow_dispatch` now takes `only: all|soak|fuzz|zap-full|dell-catalog`, so proving one
  job does not run the 45-minute soak.
- **Allowlists:** `tests/zap/rules.tsv` (baselines) and `api-rules.tsv`, one line per rule:
  `<id> TAB <IGNORE|WARN|FAIL> TAB (<reason>; expires YYYY-MM-DD)`. `TestZAPAllowlistEntriesJustified` refuses a
  missing reason, a duplicate, an expired entry, or an expiry more than a year ahead. Entries: 90004 (COEP; COOP/CORP
  are sent and nothing is cross-origin), 10110 and 10027 (vendored xterm.js/noVNC), 10049 (versioned public assets;
  HTML/API no-store), 10109, 10111, 10112 (informational), and four found by the first CI runs: 10015 (`no-store` is
  sufficient under RFC 9111), 10029 (cookie poisoning heuristic; every cookie value is server-generated), 10031
  (reflected query values escaped by html/template, strict CSP). None needed an app change.
- The API scan is kept to `/api/`, `/healthz`, `/readyz` and `/metrics` (a global exclude): its first run probed `/WEB-INF/…`
  and `POST /`, got the UI's HTML 404 and tripped the API-only content-type rule 100001 (193 hits, none on an API path).
  The second run still hit it once, on the bare target URL (no path), which serves the UI page; the exclude now covers it.
- The API scan's active phase is capped with `scanner.maxScanDurationInMins=8` (zap-api-scan's `-T` does not bound it),
  and each scan's reports are saved before the next starts.
- **OpenAPI:** `docs/api/openapi.yaml` (OpenAPI 3.0.3, every operation GET) is the public API reference. Its
  `TestOpenAPICoversEveryRoute` parses `internal/api`'s `mux.Handle` registrations (literal paths and `Path*`
  constants) and fails on a served route missing from the document, a documented path that is not served, or a
  non-GET operation.
- **Doc drift noticed, not changed here:** §6's API table lists `/api/v1/servers/{id}/fan`, which `internal/api` does
  not register.
- **actionlint** was already in CI's lint job (P7-early), so nothing was added for it.

## 50. Implementation notes (plan 06 §3.3: release workflow, dry run until public)

- **`.github/workflows/release.yml`** has four jobs:
  - **gate** (read-only + `actions: read`): decides version and mode. It refuses a live release without a successful
    `ci.yml` run for the commit; in a dry run that is only a warning.
  - **build** (read-only): linux amd64/arm64 binaries + `checksums.txt`, and the multi-arch image as an OCI archive with
    buildx provenance (`mode=max`) and SBOM attestations. The arm64 Go stage runs under QEMU, because the Dockerfile
    stays buildable by a legacy (non-BuildKit) builder (no `$BUILDPLATFORM`). It also writes the Syft SPDX SBOM of
    the source, and uploads all of it as the `release-<version>` artifact (7 days).
  - **publish** (live only; the only job with `contents/packages/id-token/attestations: write`): `skopeo copy --all`
    pushes the very OCI archive that was built to `ghcr.io/<owner>/oob-manager:vX.Y.Z` and `:vX.Y`. Then a keyless
    `cosign sign`, a `cosign attest` with the SPDX predicate, `actions/attest-build-provenance` for the image (pushed to
    the registry) and for the binaries, and `gh release create` with the annotated tag's message as notes.
  - **verify** (live only): `cosign verify` (identity `^https://github.com/<repo>/`, GitHub OIDC issuer),
    `gh attestation verify` for the image and each binary, and `sha256sum -c` on the downloaded release.
- **Switch:** `env.RELEASE_LIVE: "false"`, one line, the maintainer's decision. While false:
  - a manual run is a dry run whatever its `dry_run` input says, and nothing is pushed or signed;
  - a pushed `v*` tag runs only the gate job, which logs that the tag was ignored (about one billed minute).
  Keyless signing would put the private repository's name in Rekor. A live manual run must be started on the tag it
  names.
- **Pins:** new actions are pinned by SHA with tag comments, each release at least 14 days old:
  - docker/setup-qemu-action v4.4.0
  - docker/login-action v4.6.0
  - actions/download-artifact v8.0.2
  - sigstore/cosign-installer v4.1.2
  - actions/attest-build-provenance v4.2.2

  `COSIGN_VERSION` v3.1.3 (v3.1.4 is under 14 days old) and `SYFT_VERSION` (same as ci.yml, `TestToolPinsAgree`) carry
  Renovate comments.
- **Docs:** deploy/README "Verifying a release" has the user-side commands and the going-live steps.
- **Not verified yet:** no run of the workflow, not even the dry run. Actions minutes ran out on 2026-10-30 (jobs
  refused for billing), so it has been checked with actionlint, `bash -n` on every `run:` block (shellcheck is not
  installed locally; CI's lint runs it) and the repopolicy workflow rules. The first dry-run dispatch should be the
  next Actions spend.

## 51. Implementation notes (plan 09 §8 follow-ups N1, N2, N3, L5)

- **N1, coalesced `/setup` rate-limit audit** (`internal/web/ui/firstrun.go`): `setupDenyRate` (1 a minute, the same
  window as `setupRate`) is a second per-address limiter, `setupDenyLimit`; `setupRateLimited` audits
  `setup.claim` denied `rate_limited` only when it grants a token, the pattern of the history export's
  `denyCoalesced`. The 5-a-minute bucket and the 429 response are unchanged; wrong codes and CSRF refusals inside the
  limit are still audited one by one, so the bound is 5 + 1 rows per address a minute.
- **N2, CLI start notes** (`cmd/oob-manager/paths.go`): `startNote.cli` marks a problem (a store marker that could not
  be written or removed: `problemNote`; `-config=none`, ERROR). `printStartNotes` prints only those to stderr as
  `oob-manager: warning|error: <msg>`, and `loadCLIConfig` (loadConfig + print) replaces the bare `loadConfig` in
  `openCLICore`, `backup` and `verify-audit`; `bootstrap-admin` and `confirm-totp` print what `parseFlags` returns.
  Deprecation notes and "running on built-in defaults" stay serve-only, so `TestLegacyInstallCLIIsQuiet` holds.
- **N3** is documentation only: deploy/README "Keep config.yaml when `storage.db_path` is not the default".
- **L5, serve needs a config.yaml to name its TLS pair** (`noTLSError`): `loadConfigFor(e, flag, serve)` is the body;
  `loadServeConfig` (serve, through `parseFlags`'s `configLoader` argument) refuses a loaded file whose
  `TLS.Defaulted` is true, right after `config.Load` and before the database path is resolved or the store marker
  is removed, so a refused start changes nothing on disk. `loadConfig` (every CLI subcommand, including the
  break-glass ones: `admin-recover`, `reset-totp`, `token`, `confirm-totp`, `backup`, `verify-audit`, `settings`,
  `catalog`) accepts such a file, since none of them uses the certificate (only serve calls `ensureStoreFiles` and
  `loadServeCert`). The store marker is cleared only for a config.yaml that names its pair, so a CLI command on a
  tls-less file leaves a store volume a store volume. `config.Parse` still accepts a file without `tls`
  (`config.Defaults` shares its validation, and many partial test configs in internal/config rely on it).
  `loadWithoutConfig` (no file, or `-config=none`) keeps the generated pair. No opt-in key was added: a store
  install that gains a config.yaml names `<data>/tls/tls.{crt,key}`, after which the pair is a configured file:
  no expiry WARN, no regeneration on removal, and the 825-day certificate must be replaced by hand. deploy/README
  ("Adding a config.yaml to a store install") shows `openssl x509 -enddate` for the end date and the `gen-tls`
  swap; the app itself does not display the UI certificate's expiry.
- **Tests:** `TestSetupRateLimitedAuditsOncePerWindow` (ui); `cli_notes_test.go` (every CLI path prints a blocked
  marker exactly once; only `cli` notes print; `-config=none` on the CLI); `config_tls_test.go` (serve's refusal with and
  without `-config` and before the database exists, marker kept on serve's refusal and on a CLI load, a store
  install naming its generated pair, and `admin-recover`, `token create` and `verify-audit` succeeding on a tls-less
  config.yaml that serve refuses). `TestConfiguredDataVolumeKeyPathIsNotGenerated` wrote a config.yaml without `tls` and so relied on the
  silent generation; it now names a (missing) pair, which its assertions never touched.

## 52. Implementation notes (round-2 redesign, plan 04 §11 item 7: the Go to palette, `/go`, shortcuts)

Plan 04 §7 ("Optional progressive JS behind the no-JS rule") and the maintainer's §11 item 7 (palette **on**, the `/go`
fallback, shortcuts `g o`, `g s`, `/`, `?`), deferred out of slice D (§43) and built on branch `command-palette`. No
migration, no new dependency, no authz change, no new origin; the CSP is unchanged.

### One destination list (`ui/golinks.go`)

- `layoutData.GoLinks()` builds the groups **Pages** (Overview, Servers, Firmware when `CanFirmware`, Events when
  `CanLogs`, Activity, Settings when `IsAdmin`, Help), **Servers** (the sidebar's entries: name, its sub-line and the
  state unless the sub-line already says it), **Settings** (the seven tabs, admin only) and **Account** (Display
  preferences, About). It reads only fields `layoutFor` filled from authz, so it shows exactly what the sidebar and the
  account menu already show: a viewer never sees a Settings path, and servers need `fleet.view`. A page without a user
  has no list.
- **`GET /go`** (`s.page(authz.ViewFleet, …)`, every role) renders it server-side with a GET filter (`q`: any Unicode space becomes one space, at most 64
  characters, printable only, else 400: `parseGoQuery`; every word must appear in the label, the hint or the group, case-insensitive:
  `filterGo`, which palette.js mirrors). It is the no-script form of the palette and holds the shortcut table
  (`#shortcuts`). Linked from the account menu and the phone Menu sheet ("Go to…", `data-palette`: with the script a
  plain click opens the palette instead; a modified click or no script follows the link) and from Help.
- Every signed-in page carries the same list in an inert `<template id="oob-go">` at the end of `<body>` (about 2 KB
  before gzip). A template's content is not rendered, focusable or exposed to assistive technology, so without the
  script nothing changes.

### `static/palette.js` (about 520 lines, plain ES5-style IIFE like `app.js`)

- Loaded with `defer` on signed-in pages only, by one line in `layout.html`; deleting it removes the palette, the
  shortcuts and the recent list and nothing else (the "Go to…" links then go to `/go`). It builds its DOM with
  `createElement` and `textContent` (no `innerHTML`, no style attribute), submits no form, fetches nothing, and
  navigates with `location.assign` only to paths that pass `^/(seg(/seg)*)?$` (no query, fragment, scheme or `//`).
- **Dialog:** a `<dialog class="pal">` opened with `showModal()` (top layer, the page behind is inert), plus
  `aria-modal="true"` and a label. A combobox field (`aria-controls`, `aria-activedescendant`, `aria-expanded` false when
  nothing matches) over a listbox whose groups are `role="group"` with an `aria-label` (the visible group heading is
  `aria-hidden`). Arrow keys move and wrap, Enter opens, Escape or Ctrl/Cmd+K closes, a click on an option opens it, a
  click on the backdrop closes. Tab is trapped between the field, the close button and the "All destinations and
  shortcuts" link. Focus returns to what had it; a "Go to…" link inside a menu returns it to that menu's summary (the
  menu closes when the palette opens). **Chromium queues the dialog's `close` event**, so a key pressed right after
  Escape still landed in the hidden field and counted as typing: focus is restored synchronously in `closePalette`,
  and when the palette was opened from the page itself the hidden field is blurred.
- **Sources:** the `<template>` list, the current server page's tab bar ("This server": its tabs, with the server's
  name as the hint), and **Recent**.
- **Recent pages:** `sessionStorage` key `oob.palette.recent`, `{u: username, items: [{p, l}]}`, at most 6 entries, the
  newest first, the current page left out when shown. `p` is `location.pathname` only (never the query string or
  fragment, which can hold filters or tokens), `l` the page title without the suffix (at most 120 characters). Only
  pages the server marks are recorded: `layoutData.Recent` (`recentOK`: a signed-in GET answered 200 with one of
  `recentPages`, which leaves out sign-in, enrollment, setup, step-up, confirm, reveal, error, console, new-item forms
  and `/go`) renders `<meta name="oob-recent" content="on">`. Read entries are re-validated one by one (path pattern,
  length, user), so a tampered store shows nothing it should not. The list is bound to the username (another user
  in the same tab gets an empty list), removed when the sign-out form is submitted, and removed by `app.js` on any
  page without the Go to list (sign-in after an expiry or a revoked session). A recent Settings page is shown only
  while the server's list still holds Settings (a role changed since). Every storage access is in
  `try`/`catch`; with storage blocked there is no recent list.
- **Motion:** `motion.css` gives the open dialog the menus' entrance (fade and 6 px drop, `--dur-2`, `@starting-style`)
  and the backdrop a fade, inside `prefers-reduced-motion: no-preference`; nothing moves under reduced motion. Colours
  are tokens only: the dialog is `--surface`, the active option `--accent-bg` with a 3 px `--accent` bar (text,
  muted and accent on `--accent-bg` are already checked by `TestThemeContrast` in every palette and mode); the
  backdrop is the new `--scrim` token (no text sits on it). Forced colors: a CanvasText border and a Highlight outline
  on the active option.

### Shortcuts: decisions

- **Ctrl+K and Cmd+K** both open the palette on every platform (Ctrl+K is the common palette key; Cmd+K is what a
  Mac user expects). Outside a field it takes Ctrl+K from the browser (in Chromium and Firefox it focuses the search
  bar); inside a field the browser keeps it. The account menu shows the right one (`⌘ K` on Apple platforms).
- **`/`** focuses the page's filter field when it has one (`main form.filters`: the search field first, else its
  first text field: Events, Firmware, the audit log, `/go`) and selects its text; on any other page it opens the
  palette. That reconciles plan 04 item 7 ("`/` = filters") with the palette: the key always lands in a filter.
- **`g o`** Overview, **`g s`** Servers (the second key within 1.5 s); **`?`** goes to `/go#shortcuts` (a page section,
  not an overlay: one place that works without the script too).
- **Never while typing:** no shortcut acts while focus is in an input, textarea, select or contenteditable, while a
  modifier other than Shift is held (except Ctrl/Cmd+K), during IME composition, in full screen, or on an event a
  page script already handled. The shortcuts that leave the page (`g o`, `g s`, `?`) also wait while a form on
  the page holds input not yet submitted (app.js's auto-refresh rule), so two stray keys never discard an edit.
- **Consoles:** both console scripts route keys to the remote host while their frame has focus (noVNC on the
  canvas, xterm.js on its textarea), and the release chord Ctrl+Alt+Shift hands focus to the toolbar. A shortcut there
  would navigate away and end the session, so **on a page with a connected console** (`[data-ticket]`, rendered only
  once a console session was granted) palette.js registers no shortcut at all, not even Ctrl+K, and focus inside a
  console frame (`.con-frame`, `.xterm`) is excluded on every page as well. The palette stays reachable from the
  account menu by pointer there.
- **WCAG 2.1.4 (character key shortcuts):** the single-key shortcuts (`/`, `?`, `g o`, `g s`) can be switched off per
  browser with a checkbox on `/go#shortcuts`, shown only when the script runs (`localStorage` key `oob.shortcuts` =
  `off`; when storage is blocked the switch lasts for that page). Ctrl/Cmd+K uses a modifier and stays on.

### Tests

- Go (`golinks_test.go`): `/go` needs a session; a viewer's list (pages, servers, account) holds no Settings or
  Firmware path, an admin's holds every settings tab; the page works without script (GET form with a label, the
  shortcut table, the script-only switch `hidden`); the filter (case, several words, group label, no match, too long,
  control characters, escaping); `filterGo` does not change its input; the palette script and the `<template>` only on
  signed-in pages (the sign-in page has neither); `oob-recent` only on plain views (`recentOK` table: POST, non-200,
  anonymous, confirm, reveal, step-up, consoles, `/go`, error, enrollment, new-item forms); `palette.js` is served as
  JavaScript and holds no `eval`, `Function`, `innerHTML`, `insertAdjacentHTML`, `document.write`, style attribute,
  `fetch`, XHR, form submission or `location.search`. `TestEveryPageIsCSPClean` (and the firmware page check) allow the
  two enhancement scripts; the console page now has three scripts; `search` left `reservedIcons` (now used).
- Playwright `palette.spec.ts`: a connected serial console receives `g`, `s`, `/`, `?` and Ctrl+K (checked at the
  fake BMC) with no navigation and no palette, and neither console page reacts with focus on its toolbar (no key is
  typed into the VNC canvas: the fake BMC keeps one key record per run, which `smoke.spec.ts` checks exactly); Ctrl+K
  and Cmd+K open, Escape restores focus, Tab stays inside, filtering, arrows (wrapping), Enter navigates, the
  no-match state; `g s`, `g o`, `/` on a page with and without a filter, `?`, and no shortcut while typing in a field;
  the per-browser switch; the account menu link and focus back to its summary, the backdrop click; axe (WCAG 2.2 AA
  and best practice) on the open palette and its no-match state in both schemes at 1440 and 390 px; the entrance within
  250 ms and 0 under reduced motion; the no-script `/go` page, its filter and the menu link; the recent list (server
  tabs, recent entries, no query string stored, error pages and `/go` not stored, tampered entries dropped, cleared at
  sign-out). `pages.spec.ts` adds `/go` and `/go?q=zzz` to the axe, reflow and CSP matrix. Its four tests now share one
  admin sign-in: the harness allows 20 sign-ins of an account an hour (the configuration maximum), and the extra spec
  pushed the full run past it.
- **Visual baseline:** `visual.spec.ts` adds `go`; Help (signed in) gains two list items (Finding your way, Keyboard),
  so the `help-*` images change. Both need a `visual_update` run (Linux container; see `tests/e2e/README.md`). The
  account menu and the Menu sheet gained a "Go to…" item, but both are closed in every baseline; `help-signed-out` is
  unchanged (the new items need a session).

### Review (2026-10-30)

One security and code review by a separate reviewer agent over the whole diff: no critical or high finding (no DOM
injection, every navigation through the path pattern, the destination list built only from authz-derived fields,
`recentOK` excluding every page that shows a secret). Lows fixed: the recent list is also dropped on any signed-out
page (`app.js`), not only at sign-out; a recent Settings page is hidden once the user no longer has Settings; the
`/go` filter counts characters, not bytes, and turns a pasted no-break space into a space; Enter and Escape ignore
an IME's last composing keydown (Safari's `keyCode` 229); the leaving shortcuts wait while a form holds unsaved
input; `option()` no longer fills the shown list as a side effect; `recentPages` and `settingsLinks` are functions,
not package-level variables. Kept as designed: Ctrl/Cmd+K does nothing while a text field has focus (the browser keeps
its own shortcut there, and "never while typing" applies to every shortcut).

### Second review fixes (2026-10-30)

An independent security review of the branch found no critical, high or medium issue. Its lows, fixed test-first:

- **Consoles:** on a page with a connected console the "Go to…" link is a plain link to `/go` (the click handler
  steps aside) and `openPalette` does nothing, so no path opens the palette over a live session. e2e: the link
  navigates to `/go` from the graphical console page and its key hint stays hidden.
- **Palette navigation and unsaved input:** `go()` applies the leaving shortcuts' rule. With unsaved input in a text
  field, text area, select or checkbox the palette stays open and shows "This page has unsaved input. Submit or clear
  it before you leave." (a `role="status"` note on `--warn-bg`; warn ink on its tint is in `TestThemeContrast`). No
  confirm dialog. e2e: each kind of control holds `g s`, `?` and the palette; axe on the note.
- **Recent pages are offered only while reachable:** an entry is shown when its path is one of today's destinations
  or tabs of the current server, or lies below one (a server's tab under `/servers/<id>`, a user under
  `/settings/users`). `/` and `/servers` are never prefixes, so a server that left the list does not come back
  through a recent entry. This replaces the Settings-only filter: a role that loses Events, Firmware or Settings
  loses those recents too. e2e: another user's list shows nothing; a gone server, an unknown path and (after
  removing them from the list, as a role change would) Settings and Events entries are hidden.
- **Server IDs and `PATH_RE`:** the registry accepts `^[a-z0-9][a-z0-9-]{0,31}$` for every server (config.yaml and
  browser-managed, `config.ValidateServer`), a subset of `PATH_RE`'s segment `[A-Za-z0-9._-]+`, so no server is
  dropped. `TestPalettePathPatternAcceptsEveryServerID` reads the pattern out of `palette.js` and checks server IDs at
  the limits, every destination path, and that `//host`, query strings, fragments, schemes, empty segments and a
  trailing slash are refused.
- **`/go` filter:** zero-width joiner and non-joiner (U+200D, U+200C: emoji sequences, Persian and Indic text) are
  accepted; bidi overrides and isolates, direction marks, the BOM and the soft hyphen are still refused.
- **Tests added:** `TestGoLinksFirmwareByRole` (firmware wired: viewer, operator and admin all get `/firmware`, only the
  admin Settings; the old viewer check was vacuous without firmware and now says so), `TestGoLinksMatchTheSidebar`
  (the Pages and Servers groups equal the sidebar's links, in order, for three role and firmware combinations),
  `TestGoLinksEscapeServerNames` (a name with markup is escaped on `/go` and in the `<template>`), the joiner cases,
  and in e2e a markup name injected into the list renders as option text and creates no element.

The re-check closed all of these and raised two more lows, also fixed:

- **Dot segments:** `PATH_RE` refuses a `.` or `..` segment (each segment needs a character other than a dot). A
  tampered recent such as `/servers/r240/../../settings/users` passed the "below `/servers/r240`" test and the
  browser would have normalized it to `/settings/users`. Real entries never hold one (`location.pathname` is
  already normalized), and the server still checks access; this only removes a misleading link. The pattern test
  refuses `/..`, `/.`, `/a/./b` and the escape above, and the e2e stores the escape and expects it hidden.
- **Joiners spelled out:** `golinks.go` writes them as `'\u200c'` and `'\u200d'` instead of the invisible characters.

## 53. Implementation notes (CI on self-hosted runners)

**What.** `ci.yml` and `nightly.yml` pick their runner from the repository variable `CI_RUNNER`:
`runs-on: ${{ github.event_name == 'pull_request' && 'ubuntu-24.04' || vars.CI_RUNNER || 'ubuntu-24.04' }}`.
With `CI_RUNNER` set to a runner label (for example `oob-ci`), push, dispatch and schedule runs use
self-hosted runners with that label; with it unset or empty, everything runs on GitHub-hosted
`ubuntu-24.04` as before. `release.yml` always uses GitHub-hosted runners, so release provenance is
built on GitHub's machines.

**Why pull requests stay hosted.** A self-hosted runner runs whatever the workflow checks out. Once
the repository is public, a pull request from a fork could run arbitrary code on that machine, so
`pull_request` events never use `CI_RUNNER`. Keep "Require approval for all outside collaborators"
on for fork workflows as well.

**Runner requirements** (what the jobs assume from `ubuntu-24.04`):
- **One job per machine.** e2e-ui, ZAP and visual bind port 18443, and ZAP runs with
  `--network host`, so two runners must not share a network namespace. Use one VM per runner.
- **Base:** Ubuntu 24.04 with passwordless `sudo`, because `npx playwright install --with-deps`
  runs apt.
- **Tools on the PATH:** `git`, `make`, `gcc`, `jq`, `curl`, `unzip`, `xz-utils`, `zstd`,
  `shellcheck` (the lint job fails without it) and `sqlite3`.
- **Docker** Engine with the buildx plugin, and the runner user in the `docker` group.
- **Node.js 22** on the PATH: e2e-ui calls `npm` without `setup-node`.
- **Fonts** matching the hosted image (DejaVu, Liberation, Noto Color Emoji), so the
  1366/1440 px layout checks measure the same widths. The visual job runs in a pinned Playwright
  container and does not depend on host fonts.
- **Fetched by the jobs themselves:** Go (`setup-go`, from `go.mod`), golangci-lint, actionlint,
  govulncheck, Trivy and Syft. On a persistent runner their caches survive between jobs.

- **Work folder `/home/runner/work`** (`config.sh --work /home/runner/work`), with the runner user
  `runner`: the same layout as GitHub-hosted runners. `actions/cache` stores paths relative to the
  workspace, so a cache saved on a hosted runner (for example the Trivy binary in
  `~/.local/bin/trivy-bin`) restores to the wrong place under any other layout.
- **Caches:** `setup-go` uses the GitHub cache only on hosted runners (`cache:` is false when
  `CI_RUNNER` is set). A self-hosted runner keeps `~/go/pkg/mod` and the build cache on disk, and
  unpacking the cache archive over them fails on every existing file.
- **CPU speed:** the timing-sensitive tests (power transitions, notification delivery, the web UI
  package within its 10 min `go test` timeout) assume a CPU that is not held at its lowest
  frequency. A host whose cpufreq governor pins cores at minimum speed fails them.
**Switching back.** Delete the `CI_RUNNER` variable (Settings › Secrets and variables › Actions ›
Variables). The next run uses GitHub-hosted runners; no workflow change is needed.
