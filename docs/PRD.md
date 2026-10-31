# PRD — oob-manager

**Date:** 2026-10-20 · **Status:** Accepted (the product has shipped since; this is the original requirement set)

## 1. Problem

In a homelab or a small rack of Dell servers, out-of-band management is typically split between:

- the iDRAC web UIs (one per server, each with its own login, root accounts, and a
  Java/HTML5 console that varies by generation and license);
- host-side scripts that own fan policy in-band over FreeIPMI (common on Dell servers whose
  stock fan curve is loud);
- a NAS or hypervisor IPMI plugin for sensors, and dashboard widgets that poll Redfish for temperatures;
- general-purpose "IPMI web tool" containers, some unmaintained, with unauthenticated command
  execution and the iDRAC root password in their environment.

The goal is **one secure, fully functional web application** for fans, sensors, power and
remote console, that works on modern (Redfish) and **legacy (IPMI 2.0)** BMCs, and that
cannot become such a tool: it never holds a BMC root account and never runs shell commands.

## 2. Users and roles

| Role | Who | Can |
|---|---|---|
| `viewer` | A person checking from a phone; dashboards, automation and uptime monitors (API tokens) | Read sensors, health, SEL, inventory, audit of own actions |
| `operator` | The person who runs the servers day to day | Viewer + power on / graceful shutdown / graceful restart, fan override (lease) |
| `admin` | The administrator (a break-glass account) | Operator + force-off / power-cycle, graphical and serial consoles (step-up; serial moved from operator in P4, tech_doc §22), server and user management, audit export |

Machine clients (dashboards and automation tools, uptime monitors, vulnerability
inventories) get **read-only API tokens** only.
No machine token can ever hold `operator` or `admin`.

## 3. Goals

1. **G1 Sensors & health** for N servers on one page: temperatures, fan RPM, PSU status,
   power draw, overall health rollup, SEL/Lifecycle log, firmware/BIOS versions.
2. **G2 Power control** with confirmation, re-authentication and audit.
3. **G3 Fan control** that **coexists** with a host fan script where one exists: time-boxed override,
   enforced safe minimum, automatic revert, never leaves the BMC in sticky manual mode.
4. **G4 Remote console**: serial console everywhere; graphical console where the BMC and its
   license allow it; credentials never reach the browser.
5. **G5 Legacy support**: a generic IPMI 2.0 (RMCP+) driver for BMCs without Redfish.
6. **G6 Security bar** suitable for a tier-0 tool: own authN, roles, CSRF,
   CSP, rate limits, audit to a hash chain and optionally a log server (GELF), least-privilege BMC accounts, hardened container,
   Trivy-clean in CI.
7. **G7 Integrations**: read-only JSON for dashboards and automation, a health endpoint for
   uptime monitors, a version/inventory record for vulnerability scanners, optional Prometheus `/metrics`.

## 4. Non-goals (explicit)

- **Virtual media, firmware updates, BIOS settings, BMC user management, RAID config, OS
  deployment.** These are high-blast-radius and rarely needed; use the vendor UI for them.
- Replacing a host fan-control policy. Where a host script controls the fans (`host-lease` mode),
  it stays the **single writer**; this app only *requests* overrides.
- Internet exposure without an identity-aware proxy (Cloudflare Access) in front.
- Multi-tenant or multi-user collaboration features. This is a small-team, single-site tool.
- Java (JNLP/avct) console support.

## 5. Functional requirements

### 5.1 Servers and discovery
- FR-1 Servers are declared in config (name, BMC address, vendor hint, credential refs,
  TLS pin, fan policy). No network scanning.
- FR-2 On first contact the driver probes capabilities (Redfish service root, Dell OEM
  presence, iDRAC generation and firmware, license tier, IPMI availability) and stores a
  capability record. The UI hides or greys out unsupported features with the reason
  ("iDRAC8 Express license: no virtual console").

### 5.2 Sensors & health
- FR-3 Poll every 60 s (configurable, minimum 30 s) using the **read-only** BMC account.
- FR-4 Show per server: health rollup, power state, temperatures with thresholds, fans
  (RPM, %), PSUs (state, input watts, redundancy), current/peak power, SEL newest-first
  with severity, firmware inventory.
- FR-5 Keep sensor history in SQLite: 7 days of readings, hourly and daily rollups to 2 years
  (configurable); render charts and sparklines; export CSV. Not a TSDB (Prometheus stays the integration
  point).
- FR-6 Mark stale data clearly (last-successful-poll age) and never display a cached value
  as current.

### 5.3 Power control
- FR-7 Actions: On, GracefulShutdown, GracefulRestart (operator); ForceOff, PowerCycle,
  ForceRestart (admin).
- FR-8 Each action requires: role check, a step-up TOTP within the last 5 min, and typing
  the server name. ForceOff/PowerCycle on a server tagged `critical` (for example the Docker host
  itself) also shows a warning listing what goes down (configured per server: storage, containers, DNS, logging).
- FR-9 Per-server cooldown of 60 s between power actions; per-user rate limit.
- FR-10 Result is verified by re-reading `PowerState` and shown with the audit record ID.

### 5.4 Fan control
- FR-11 Fan override is a **lease**: target %, mode (`boost` or `pin`), duration
  (5–120 min, default 30), reason. It expires automatically.
- FR-12 Enforced safe minimum per server (default 30 %). Thermal guards cancel any lease:
  CPU or hottest-drive temperature at the AUTO threshold of the host curve.
- FR-13 Arbitration modes per server: `host-lease` (a host script applies the lease),
  `redfish-floor` (iDRAC9 — raise `MinimumFanSpeed`, BMC stays in AUTO), `ipmi-oem`
  (legacy Dell with no host controller — app applies and owns revert), `none` (read-only).
- FR-14 UI shows: current owner (host curve / lease / BMC AUTO), applied %, lease expiry
  countdown, and an "End now" button. Ending a lease is allowed for operator without step-up.

### 5.5 Remote console
- FR-15 Serial console in the browser (xterm.js) via the BMC's SSH `console com2` (Dell) or
  IPMI SOL (generic/legacy). Operator role. Session limit 1 per server, idle timeout 15 min,
  max 2 h, full session metadata audited (not keystrokes by default; optional transcript).
- FR-16 Graphical console (admin role, where supported):
  - iDRAC9 firmware with `GetKVMSession`: "Launch" opens the iDRAC HTML5 console with
    single-use temporary credentials (LAN only).
  - BMCs with a VNC server (iDRAC8/9 Enterprise): proxied through the app to noVNC;
    the app does the VNC authentication server-side.
- FR-17 Never expose permanent BMC credentials to the browser in any console mode.

### 5.6 Auth
- FR-18 Local accounts: argon2id password + mandatory TOTP. Optional passkeys (WebAuthn) later.
- FR-19 Optional Cloudflare Access mode: validate `Cf-Access-Jwt-Assertion` (signature,
  `aud`, `iss`, expiry) and map the email to a local user. Step-up TOTP still applies to
  dangerous actions.
- FR-20 API tokens: read-only scope, hashed at rest, per-token name and last-used.

### 5.7 Audit
- FR-21 Every login, step-up, failed auth, power action, fan lease change, console session
  start/end, config reload and token use is recorded: who, role, source IP, server, action,
  parameters, result, BMC response code, correlation ID.
- FR-22 Audit goes to a local hash-chained table **and**, when configured, to a log server (GELF over
  TCP or TLS, e.g. Graylog). Delivery failure never blocks the action, but raises a health warning.

## 6. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 | Idle footprint ≤ 40 MB RAM, ≤ 1 % of a core; one process, ≤ 30 threads (contrast: a typical general-purpose IPMI tool container runs over 100 processes) |
| NFR-2 | Page loads ≤ 500 ms on LAN from cached poll data; BMC calls never block page render |
| NFR-3 | A dead or slow BMC never affects other servers (per-server goroutine, timeouts, circuit breaker) |
| NFR-4 | Container image ≤ 30 MB, zero HIGH/CRITICAL Trivy findings at release |
| NFR-5 | ≥ 80 % test coverage, enforced in CI |
| NFR-6 | Works with no internet access (no CDNs, all assets embedded) |
| NFR-7 | Restart-safe: an app crash or restart cannot leave fans in manual mode (lease expiry is enforced by the host or BMC side, not only by the app) |

## 7. Success criteria

1. Everything a general-purpose IPMI tool was used for is covered without its risks.
2. Every configured server shows live sensors, power state and SEL within 60 s of start.
3. A fan lease in `host-lease` mode is applied within one host-script cycle and reverts on expiry,
   on app shutdown, on container kill, and on a thermal guard — verified by test.
4. A power action produces a matching log-server (GELF) record within 5 s.
5. Serial console works on both tested servers; graphical console works wherever the license allows.
6. Trivy and govulncheck are clean; an external scan (ZAP baseline) shows no HIGH findings.

## 8. Decisions (were open questions)

Answered 2026-10-20, see [task_list.md](task_list.md#decisions-2026-10-20). Originally open: exposure (LAN-only vs Cloudflare
Access), iDRAC license tiers, whether IPMI-over-LAN stays on, the host-script contract,
serial console redirection on the hosts, container networking.
