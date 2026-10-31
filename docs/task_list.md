# Task list — oob-manager

TDD-first: every task starts with failing tests (RED), then the minimal implementation
(GREEN), then refactor. Coverage gate 80 % from P0 onward. Estimates are focused
working days (d) and include tests and review.

**Gate before any phase touches real hardware:** the hardware owner approves; no BMC, host or
firewall changes without explicit approval and a backup. Development runs against the mock BMCs.

## Prerequisites on the test hardware (outside this repo)

- [x] Retire any general-purpose IPMI tool that holds the iDRAC `root` password, rotate `root`, and
  turn IPMI over LAN off.
- [ ] Create `oob_ro` and `oob_op` (and `oob_kvm` where needed) on each iDRAC (security.md §4).
- [ ] Record each iDRAC's license tier and firmware (decides console features).
- [ ] Record each iDRAC's TLS SPKI hash and SSH host key (for pinning).

## P0 — Foundations (≈ 5 d)

| # | Task | Tests first | Est |
|---|---|---|---|
| 0.1 | Repo skeleton, `go.mod` with toolchain pin, Makefile, golangci-lint + gosec config | lint passes on empty packages | 0.25 |
| 0.2 | CI: lint, `go test -race -cover` (80 % gate), govulncheck, build, Trivy, Syft SBOM | pipeline green on skeleton | 0.5 |
| 0.3 | Dockerfile (multi-stage → distroless static nonroot, digest-pinned), `healthcheck` subcommand, `deploy/compose.yaml` with read-only/caps/secrets | container starts read-only as 65532; Trivy clean | 0.5 |
| 0.4 | `config` load + validation (fail fast) | table tests: unknown keys, bad fan mode, missing pin, floor < 20 | 0.5 |
| 0.5 | `secrets`: age file decrypt, redacting `Secret` type | Secret never prints; wrong key fails startup | 0.25 |
| 0.6 | `store`: SQLite + embedded migrations + repositories | migration up on empty DB; repo CRUD | 0.5 |
| 0.7 | `audit`: hash chain + GELF TCP shipper with bounded queue | tamper detected; log server down ≠ action blocked | 0.75 |
| 0.8 | `web` base: TLS, security headers, CSP nonce, CrossOriginProtection, limits, Problem Details | header snapshot tests; cross-origin POST rejected | 0.5 |
| 0.9 | `auth` local: argon2id, TOTP enrolment, sessions, lockout, step-up; first-admin bootstrap CLI | brute-force lockout, TOTP replay rejected, session rotation | 1.0 |
| 0.10 | `authz` matrix | every route × role table test, deny by default | 0.25 |

## P1 — MVP: sensors & health, read-only (≈ 4 d)

| # | Task | Tests first | Est |
|---|---|---|---|
| 1.1 | Record & sanitize Redfish payloads from both test iDRACs with `oob_ro` (GET only, approved session) | — (fixture capture) | 0.25 |
| 1.2 | `bmc` types + `redfish` driver: probe, snapshot (Thermal/Power + new subsystems), SEL, inventory; TLS pinning | decode iDRAC8 + iDRAC9 fixtures; pin mismatch refused | 1.0 |
| 1.3 | `dellredfish` probe extras: license tier, firmware, Lifecycle log | fixtures | 0.5 |
| 1.4 | `fleet`: per-server poller, jitter, breaker, atomic snapshots, sample retention | fake clock tests; one dead BMC doesn't stall others | 0.75 |
| 1.5 | UI: overview, server page, logs, inventory, staleness display | handler tests + Playwright smoke | 1.0 |
| 1.6 | API v1 read-only + tokens + `/healthz` `/readyz`; dashboard + uptime-monitor wiring docs | token scope tests; pagination | 0.5 |

**MVP release = P0 + P1 (≈ 9 d).** Deploy, then soak for a week alongside the current tools.

_Status 2026-10-20: P1 code complete and wired (UI, API, fleet); lint clean; `make e2e` (Go + Playwright) runs against
the in-repo mock BMCs. Remaining pre-deploy gaps are listed in tech_doc §14._

## P2 — Power control (≈ 2 d)

| # | Task | Tests first | Est |
|---|---|---|---|
| 2.1 | `power` service: enum, allowlist ∩ BMC AllowableValues, cooldown, verify transition | mock Redfish; denial paths; 429 on cooldown | 0.75 |
| 2.2 | IPMI chassis control fallback (generic driver) | go-ipmi reference BMC | 0.5 |
| 2.3 | UI confirm flow (typed name, step-up, critical-server warning) + audit/GELF | E2E: denied without step-up, success writes audit | 0.75 |

_Status 2026-10-21 (branch `p2-power`): 2.1 and 2.3 code complete against mocks (redfishmock `WithPowerControl`
with state transitions); `make check`, lint and `make e2e` (Go + Playwright incl. axe on the confirm pages) green.
**2.2 deferred:** go-ipmi is not a dependency yet (rule 10), so `kind: ipmi` servers get no power actions; the
service already takes any `power.Controller`, so an IPMI controller plugs in without UI changes. Real hardware
needs an operator account per iDRAC first (a BMC write, with the hardware owner's approval). Details: tech_doc §20._

## P3 — Fan control (≈ 4 d)

| # | Task | Tests first | Est |
|---|---|---|---|
| 3.1 | **Spike (read-only):** confirm the test iDRAC9's firmware, `ThermalSettings.1.*` attribute names/ranges, raw-fan block | — | 0.25 |
| 3.2 | `fan` lease model + arbiter + startup reconciliation | expiry, floor clamp, hostile values, crash-restart | 0.75 |
| 3.3 | `hostlease` applier: atomic write, ack reader, pending→applied UI | file contents golden tests; ack parsing | 0.5 |
| 3.4 | **Host script patch** in `deploy/host/` (lease reader in awk + ack) with bats tests; applied to a real host only with the maintainer's approval, with backup + `bash -n` | bats: valid/expired/oversized/garbage/guard/race | 1.0 |
| 3.5 | `redfishfloor` applier (iDRAC9) with original-value restore | mock Redfish PATCH; restore on expiry and on startup | 0.5 |
| 3.6 | `dellipmi` OEM applier (`ipmi-oem`, legacy, off by default) | go-ipmi reference BMC: re-assert, restore AUTO on shutdown | 0.5 |
| 3.7 | Fan UI: owner, countdown, End now | E2E lease lifecycle | 0.5 |

_Status 2026-10-21 (branch `p3-fans`): 3.2–3.5 and 3.7 built and tested against mocks (unit, bats, `make e2e`
incl. Playwright + axe); 3.6 `ipmi-oem` deferred (no go-ipmi yet). Nothing applied to a host or BMC: the
host-script patch and the iDRAC9 operator account with *Configure* wait for the hardware owner. Spike 3.1 found
`MFSMinimumLimit` 35 on the test R240 (the `redfish-floor` floor is configurable down to the BMC's limit). Details: tech_doc §21._

## P4 — Serial console (≈ 3 d)

| # | Task | Tests first | Est |
|---|---|---|---|
| 4.1 | `bmcssh` driver: pinned host key, exactly `console com2` | in-process SSH server; wrong host key refused; no other command possible | 0.75 |
| 4.2 | `console` broker: WS tickets, one session per server, idle/max timeouts, audit | ticket replay, timeout, takeover | 0.75 |
| 4.3 | IPMI SOL path (go-ipmi `sol_stream`) for generic BMCs | reference BMC SOL | 0.75 |
| 4.4 | xterm.js page under strict CSP | Playwright echo test | 0.5 |
| 4.5 | Host serial redirection how-to (BIOS COM2, Linux `console=ttyS1`, FreeBSD-appliance dual console) — doc only | — | 0.25 |

_Status 2026-10-21 (branch `p4-serial`): 4.1, 4.2, 4.4 and 4.5 done against mocks (in-process SSH server
`bmcssh/sshtest`, Playwright echo test + axe); `make check`, lint and `make e2e` green. 4.3 (IPMI SOL) deferred:
no vetted pure-Go SOL library in go.mod, interface `console.SerialOpener` defined, `serial: sol` shows "Not
supported yet". `console.serial` is now admin + step-up (was operator). Not yet tried on the real iDRACs; the host
side (BIOS redirection to COM2, `console=ttyS1`) waits for decision 6's reboots. Details and open points: tech_doc §22._

## P5 — Graphical console (≈ 5–5.5 d; see docs/research/console.md)

**Decision 2026-10-21: core console only.** noVNC → app relay → BMC VNC server (iDRAC7/8/9 with
Enterprise, TLS + pin, per-server quirk flags incl. the iDRAC8 black-screen workaround: Raw/CopyRect/
DesktopSize encodings, 8-bit colour) plus the iDRAC9 one-time native-console launch (`GetKVMSession`).
Java-only BMCs (iDRAC6, old iLO, …) get a clear "graphical console not supported on this BMC — use the
serial console" state. **No Java sidecar** (hard rule 11 stays; research option C rejected). Feature
detection: Redfish GraphicalConsole + licence + VNC settings + a harmless RFB banner read →
ready / in use / needs setup / licence / unsupported.

| # | Task | Tests first | Est |
|---|---|---|---|
| 5.1 | **Spike:** noVNC against iDRAC8 VNC server (known black-screen report), TLS mode, licence check | — | 0.5 |
| 5.2 | RFB auth terminator (VNC auth server-side, `None` to browser) + TLS to BMC | fake RFB server; password never on the WS | 1.5 |
| 5.3 | noVNC page (vendored, CSP incl. `wasm-unsafe-eval` only if required) | Playwright connects to fake RFB | 0.75 |
| 5.4 | iDRAC9 `GetKVMSession` launch (feature-detected) | mock Redfish; feature absent → hidden | 0.5 |
| 5.5 | Fallbacks: "open iDRAC UI" link when unsupported | — | 0.25 |

_Status 2026-10-21 (branch `p5-console`): 5.2–5.5 code complete against mocks (fake RFB server, redfishmock
GetKVMSession), with the detection matrix and card states; `make check`, lint and `make e2e` (Go + Playwright
incl. axe) green. 5.1 (spike on the real iDRAC8/iDRAC9) is still open and needs the hardware owner's approval: VNC server
settings are BMC writes. Details and open points: tech_doc §18._

## P6 — Cloudflare Access + integrations (≈ 2 d, optional)

| # | Task | Tests first | Est |
|---|---|---|---|
| 6.1 | CF Access JWT verifier + email→user mapping; header ignored in local mode | forged/expired/wrong-aud JWTs rejected | 0.75 |
| 6.2 | ~~Reverse-proxy host + Access app + firewall rule~~ dropped: decision 1 is LAN-only | — | 0 |
| 6.3 | Dashboard and automation read-only usage, `/metrics` (optional) | API contract tests | 0.75 |

## P7 — Hardening & release (≈ 2 d)

| # | Task | Est |
|---|---|---|
| 7.0 | **P7-early** (plan 06 §3.8 Renovate + dependency-doc test, §3.9 gates, actionlint): `renovate.json` with the 14-day rule, per-package 80 % coverage gate, actionlint in CI, nightly soak, `internal/repopolicy` tests (they fail on a dropped rule, an undocumented module or an unannotated tool pin) | 0.75 |
| 7.1 | security-reviewer + code-reviewer agents pass; fix CRITICAL/HIGH | 0.5 |
| 7.2 | ZAP baseline vs container with mock BMCs; Trivy/govulncheck clean; SBOM published | 0.5 |
| 7.3 | Restore drills: lost DB, lost age key, app crash during lease; runbook in README | 0.5 |
| 7.4 | First real deploy (compose project, bridge network on the Docker host's address per decision 7, kept out of auto-updaters, GELF stream) | 0.5 |

_Status 2026-10-22 (branch `p7-early`): 7.0 done. `make cover` gates the total and every package at 80 % each (in-repo test doubles excluded;
auth, authz, fan, power, audit, console, console/rfb, netpolicy, secrets/credstore, tofu and registry must be present); actionlint v1.7.12 runs in the lint job;
the nightly workflow runs `make soak`; Renovate needs the maintainer to install the Renovate GitHub app on the repository before
it opens any PR, and code-owner review on `main` needs branch protection (owner settings). Rest of P7 (ZAP, release signing, fuzzing, drills, threat-model refresh, `.trivyignore` policy, the
monthly cadence in deploy/README) is still open: plan 06. Details: tech_doc §33._

## Backlog — multi-vendor BMC support (research 2026-10-21, not scheduled)

From the multi-vendor BMC research note (2026-10-21, kept outside the repository): M0 generic Redfish core + per-vendor
adapters (3 d), M1 generic Redfish read-only (3–4 d), M2 Lenovo XCC (3 d), M3 IPMI driver with pinned
cipher suites 17/3 only (5–6 d), M4 IMM2 (2 d), M5 OpenBMC (4–5 d), M6 Supermicro (3 d), M7 HPE iLO (3 d).
No test hardware beyond Dell iDRAC8/9, so everything else ships marked **untested** (see 8.5a).

- **Optional: Intel AMT / vPro** (desktops without a BMC; ≈ 3–4 d): power via WS-Man, KVM over the
  standard RFB protocol (fits the existing VNC relay), SOL. AMT must be provisioned in MEBx at each
  machine first, and there is no test hardware for it yet. Security: current ME firmware, TLS, strong
  password, firewall to the app host only (INTEL-SA-00075 history).

## P8 — Public release (≈ 1.5–2 d, after P7 and a stable soak)

**Name: `oob-manager`** (renamed from `oob-console` on 2026-10-22: the name is free on GitHub and Docker Hub; `oob-console` was decided 2026-10-21, alternatives then: Racklight, Pilotlight, Rackside, BMCdeck). Compatibility notes: tech_doc §36.

Goal: publish a generic, safe-by-default project for anyone with Dell iDRAC 8/9 or Redfish/IPMI BMCs,
with no detail of the maintainer's own installation in the tree or its history. Plan:
[plans/07-public-release.md](plans/07-public-release.md).

**Decided (decision):**

- The public repository is a fresh `MrRonco/oob-manager` made by a **clean cut** (`scripts/public-cut.sh`: `git archive`
  of a tag, scanned, then one initial commit); the private working repository is renamed `oob-manager-private` and
  archived later. **Development continues in the public repository.**
- The first public version is the minor current at the cut, labelled **public beta**. `v1.0.0` comes after the first
  hardware reports and a month without a security fix.
- Support statement: **"As-is homelab project, issues and contributions welcome, security reports answered first."**
- Images on **GHCR only** (`ghcr.io/mrronco/oob-manager`).
- Contributions use the **DCO** sign-off (`git commit -s`); no CLA.
- Tested hardware: iDRAC8 2.86 on a Dell R730XD and iDRAC9 7.00 on a Dell R240; everything else is untested, and a
  hardware report is invited.

| # | Task | Est |
|---|---|---|
| 8.1 | **Split generic vs personal:** install-specific material (addresses, host paths, monitoring wiring, the maintainer's accounts and decisions narrative) moves to the maintainer's private notes, **outside the repository** (no `deploy/homelab/`, so the cut needs no exclusion list). Public docs describe a generic deployment. `internal/repopolicy` `TestPublicTreeHasNoNetworkDetails` fails on private addresses, host paths, real-looking MACs and home-network host names from then on. | 0.5 |
| 8.2 | **Make site-tied features optional:** the `host-lease` fan mode is documented as an opt-in integration with an example host script; Docker Compose is the default deploy with Unraid as one example; no hard-coded models, IPs or paths; config examples use RFC 5737 IPs (192.0.2.0/24). | 0.25 |
| 8.3 | **Safe defaults:** no default credentials (first-admin bootstrap only), LAN-only binding guidance, TLS required, all dangerous actions off until configured. Re-run the security-reviewer + ZAP baseline on the generic build. | 0.25 |
| 8.4 | **Release engineering:** turn on GitHub Actions CI; multi-arch image on GHCR, signed with cosign (keyless), SBOM + provenance attached; versioned releases + CHANGELOG; Renovate with the 14-day rule. | 0.5 |
| 8.5 | **Community files:** LICENSE (**Apache-2.0**), SECURITY.md (private vulnerability reporting via GitHub advisories), CONTRIBUTING.md (DCO), CODE_OF_CONDUCT.md, issue/PR templates, README with scope, tested hardware (iDRAC8 2.86, iDRAC9 7.00) and the support statement above. Check third-party licences (gofish BSD-3, go-ipmi Apache-2.0, xterm.js MIT, noVNC MPL-2.0 file-level) in a NOTICE file. | 0.25 |
| 8.5a | **Tested-hardware statement and call for testers** (2026-10-21): the release notes and README list exactly what was verified on real hardware (Dell iDRAC8 fw 2.86 on an R730XD, iDRAC9 fw 7.00 on an R240) and mark everything else **untested**: other Dell generations, generic Redfish, Lenovo/IBM, HPE, Supermicro, OpenBMC, IPMI. Ask users to try it and report results (working or broken) through a "Hardware report" issue template that collects BMC vendor, model, firmware, licence tier, which features worked, and sanitized error messages (no IPs, serials, licence IDs or credentials). Keep a `docs/hardware.md` compatibility table updated from those reports. | 0.25 |
| 8.6 | **Clean cut:** `scripts/public-cut.sh <tag> <outdir> --identifiers <file>` exports the tag with `git archive` (no history), runs gitleaks and trufflehog (filesystem mode), the repopolicy test, the maintainer's private identifier grep and exiftool over every image on that exact tree, and fails closed if a scanner is missing. The maintainer then makes one commit, pushes to the new repository while it is still private, reviews, and only then makes it public. | 0.25 |

Ongoing after release: triage issues and security reports, monthly dependency/base-image bumps.

## Totals

| Scope | Estimate |
|---|---|
| MVP (P0 + P1) | ≈ 9 d |
| + power + fans (P2 + P3) | ≈ 15 d |
| Full app (P0–P7) | ≈ 25–27 d |
| + public release (P8) | ≈ 27–29 d |
| Ongoing | ~1 h/month: dependency + base-digest bump, Trivy review |

## Decisions (2026-10-20)

The design's open questions, answered on 2026-10-20 from facts read over Redfish from the two test
iDRACs (an iDRAC8 on a Dell R730XD and an iDRAC9 on a Dell R240).
Where an answer is specific to that installation, the general rule it illustrates is given.

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Exposure | **LAN-only by default.** No tunnel or reverse-proxy route; remote use goes through a VPN into the LAN. Cloudflare Access mode exists for those who publish it anyway. | The app can power-cycle every server, often including the firewall and the Docker host. Keeping it off the internet costs nothing. |
| 2 | iDRAC licences | **Graphical console stays in scope** for iDRAC8 and iDRAC9 with an Enterprise (or Datacenter) licence; the app reads the tier and hides what the licence does not allow. | Read from `LicenseService` / `GraphicalConsole` on 2026-10-20. |
| 3 | IPMI-over-LAN | **Not needed for Dell servers** (Redfish + BMC SSH cover everything): keep it off, and turn it off once nothing else depends on it. | RAKP hash disclosure makes any reachable UDP/623 an offline password-cracking target (security.md §5). |
| 4 | Host script contract | **`host-lease`:** the host's fan script reads a lease file (example reader in `deploy/host/`) and runs **every minute**. | A lease should apply within a minute. The script is light (in-band FreeIPMI), and its stale-heartbeat watchdog is unchanged. |
| 5 | Fan floor | **30 % for any lease in `host-lease` mode** (the host curve keeps its own minimum when no lease is active). **iDRAC9: boost only.** | iDRAC9 7.00 exposes only Dell's *Minimum Fan Speed* (`ThermalSettings.1.MinimumFanSpeed`; 255 = auto, with a model-specific lower limit, `MFSMinimumLimit`) and offsets. It cannot pin a speed, so its mode is `redfish-floor` (raise only, revert to 255). |
| 6 | Serial redirection | **Host-side change, not an MVP blocker:** BIOS "Console Redirection via COM2" plus the OS console on the serial port (Linux `console=ttyS1,115200`; FreeBSD appliances: dual console). | Both need reboots; a firewall's reboot takes the internet down, and an Enterprise graphical console is a fallback meanwhile. |
| 7 | Container network | **Bridge network, published on the Docker host's address** (for example `192.0.2.20:8443`), not a macvlan address. | A bridge container egresses as the Docker host, so a BMC IP filter that admits only the Docker host keeps working; a macvlan address would be blocked, and iDRAC8 has a single filter range. |
| 8 | Secrets layout | **age identity off the data volume** (root-only storage, staged to a tmpfs at boot), not a typed passphrase. Store installs may generate it in `/data` instead (plan 09). | Unattended restart matters: after a power cut a passphrase would leave the app down exactly when it is needed. |
| 9 | Dashboards | **Point dashboard widgets at the app's read-only API** once it has run cleanly for a week, and remove their own iDRAC credentials. | Only one component should hold iDRAC credentials. |

**Follow-on (added):** the app uses **dedicated iDRAC accounts** (Operator role, not `root`). After that the iDRAC
root password can be rotated without breaking anything, and root is no longer used day to day.
