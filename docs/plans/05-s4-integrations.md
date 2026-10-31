# Plan 05 — Settings slice S4: Integrations

Status: plan, 2026-10-21. No code. Source: `docs/settings_design.md` §1 (scope row
"Integrations"), §5 (routes, hot reload "GELF: build the new shipper, swap, flush and close
the old one"), §6 (S4, 1 d), §8 decision 6 ("GELF over TLS: in S4"). Builds on tech_doc §9
(GELF TCP shipper), §16/§24/§25 (settings precedence, lock badges, TOFU), §26–§27
(notifications and `settings.locked: [integrations]`), §29 (`/metrics`), the `core.go`
sink wiring (`teeSink(shipper, lateTap)`).

## 1. Goal and non-goals

**Goal.** Finish the Settings area: the audit shipper (GELF) becomes configurable in the
browser with the same precedence and lock badges as General and Servers, can speak TLS with a
pinned certificate, can be swapped without a restart, shows its live state and can send a
test event; the page also gives copy-ready hints for the pull-style integrations
(Homepage `customapi`, Uptime Kuma `/readyz`, Prometheus scraping `/metrics`) with
`<token>` placeholders, never real tokens.

**Non-goals.** A settings JSON API (rule S4 of the design: `/api/v1` stays read-only and
tokens never reach `admin.*`); GELF over UDP or HTTP; shipping *application logs* to GELF
(audit rows only, as today; app logs stay on stderr — a separate item); editing
notification targets here (they have their own tab, §7); storing API tokens or showing
them again.

## 2. User stories

| Role | Story |
|---|---|
| admin | In Settings → Integrations I see whether audit rows reach my log server (connected since, queued, sent, dropped, last error class) and I can change the target without restarting. |
| admin | I turn on TLS for the GELF connection, fetch the server's fingerprint, compare it with my log server's certificate and confirm it; a wrong certificate later pauses shipping (queue) rather than sending to an impostor. |
| admin | "Send test" writes an audit row and tells me whether the frame was written to the connection. |
| admin | The page shows me the exact Homepage widget, Uptime Kuma monitor and Prometheus scrape snippets for this instance, with `<token>` where my own read-only token goes, and tells me where to mint one. |
| admin (file-managed install) | Keys set in config.yaml show the lock badge and cannot be changed in the browser; `settings.locked: [integrations]` makes the whole tab read-only. |
| viewer/operator | Nothing: the tab is admin-only (viewers never learn the log server's address). |

## 3. UX placement (direction B)

`/settings/integrations`, a new `settingstabs` entry after Notifications (Users · API tokens
· General · Servers · Notifications · **Integrations** · Audit log). Two columns (`g2`):

- **Left, "Audit shipping (GELF)"** panel: state line (badge `Connected`/`Disconnected`/
  `Disabled`/`Paused: certificate changed`), counters (queued, sent, dropped, last error
  class, since), then the form (C-15 fields): Enabled, Address (`host:port`), Transport
  (`tcp` / `tls`), Server name (TLS SNI, optional, defaults to the host part), Fingerprint
  (grouped hex, read-only, with "Fetch and confirm" → the TOFU confirm page, or paste),
  source/lock badge per field, Save (step-up line on top as every settings page), and a
  secondary "Send test". A locked section shows the notice and no buttons.
- **Right, "Dashboards and monitoring"** panel with three `<details>`-free subsections,
  each a `codeblock` (C-16 style, monospace, Copy button as enhancement): Homepage
  (`customapi` YAML for `/api/v1/servers/<id>` with the instance URL and `<token>`),
  Uptime Kuma (HTTP keyword monitor on `/readyz`, keyword `ok`, no token; plus the optional
  `/metrics` keyword monitor with `<token>` when metrics are enabled), Prometheus
  (`scrape_configs` with `bearer_token_file`, `scheme: https`, `tls_config.ca_file`
  placeholder; shown with a lock badge "metrics are file-only" and the current
  `metrics.enabled` state). A closing line: "Alerts to people (ntfy, Pushover, Gotify,
  webhook, email) are in Notifications" (link).
- **If the round-2 redesign** regroups Settings, the two panels become two sub-pages or an
  accordion; routes are unchanged.

## 4. Source of truth, keys and precedence

Runtime-managed keys (file > DB > default, lock badge when set in `config.yaml`):

| Key | config.yaml | Type / bounds | Default |
|---|---|---|---|
| `gelf.enabled` | `audit.gelf.address` non-empty | bool | off |
| `gelf.address` | `audit.gelf.address` | `host:port`; host = IP literal or DNS name ≤ 253 chars; port 1–65535 | — |
| `gelf.transport` | `audit.gelf.transport` | `tcp` \| `tls` | `tcp` |
| `gelf.server_name` | `audit.gelf.server_name` (new) | DNS name, optional | host part |
| `gelf.pin_sha256` | `audit.gelf.pin_sha256` (new) | 64 hex, required when `tls` | — |

File-only (never in the browser): `audit.gelf.allowed_networks` (CIDRs; default: the
private ranges plus loopback refused, see §8) and the shipper tuning (`queue`, timeouts).

`settings_kv` already lists `gelf.address` and `gelf.enabled` (0005/0007); the three new
keys need the CHECK list rebuilt (migration **`00NN_integrations.sql`**, NN ≥ 12 — the
same rebuild pattern as 0007; if plan 02's rebuild lands first, this one rebuilds again,
which is cheap). `settings.Resolve` gains an Integrations section with its own validator
(`config.ValidateGELF`, shared by file and browser), `Effective.Integrations`, `Diff` allow-
list (every key public: the pin and address are not secrets).

## 5. GELF over TLS with a pinned certificate (decision 6)

- **Dial**: `tls.Dial` over the existing `ShipperConfig.Dial` hook with `MinVersion`
  TLS 1.2, `ServerName` = `gelf.server_name`, and `VerifyConnection` that accepts the
  handshake when **any certificate in the presented chain** has the pinned SPKI (leaf or
  issuing CA). That is the "CA pin" the brief asks for: pinning the issuer lets the log
  server rotate its leaf without touching the app; pinning the leaf (self-signed servers)
  also works. No system-roots verification is attempted when a pin is set (the pin is the
  trust anchor, as for BMCs); without a pin `tls` is refused by validation. Same constant-
  time compare and fail-closed shape as `redfish.pinnedTLSConfig` (shared helper
  `internal/tlspin`).
- **TOFU**: reuse `tofu.FetchTLS(ctx, addr, port)` (handshake-only, zero application bytes,
  5 s bounds) to show subject, issuer, validity, SANs and the SPKI of the leaf **and** of
  the issuer when the server sends its chain; the admin picks which to pin (default: leaf
  when self-signed, issuer when a chain is present). The confirm page carries the
  `Prover` proof (purpose = this form's path, bound to session, address and value, 5 min),
  exactly like server pins. Manual paste is allowed and audited as `pin_via: manual`.
- **Mismatch at run time**: the shipper records `tls_pin` as the last error class, stops
  dialling for 5 min, keeps queueing (bounded, 1 024, then drops with the counter), the
  Integrations page shows "Paused: certificate changed" with "Fetch and confirm", Overview
  shows a system banner (like a failing notification target), `/readyz` reports
  `degraded`, and a `trust` notification event is emitted
  (`notify.TrustEvent("audit-shipper", "GELF server", "TLS certificate")`, resolved on the
  next successful write).
- **Plain TCP stays available** (`tcp`) for a server on a trusted segment; the page says
  "unencrypted" next to it.
- Graylog's GELF TCP input accepts TLS (`tls_enable`); the frame format is unchanged (NUL-
  terminated JSON). Nothing vendor-specific is added.

## 6. Hot swap of the shipper

- `audit.Logger` receives its sink once. Add `audit.SwitchSink` (an `atomic.Pointer[Sink]`
  that implements `Sink`; `Enqueue` loads and forwards; a nil target drops with the
  counter). `core` builds `c.sink = &audit.SwitchSink{}` and installs
  `teeSink(c.sink, c.notifyTap)` as today.
- `internal/integrations.Service.Apply(cfg)`: build the new shipper (lazy dial), start its
  `Run` under its own context, `c.sink.Swap(new)`, then cancel the old shipper's context so
  its `Run` flushes (3 s) and closes. **Order of the change itself**: the audit row
  `admin.integrations.update` is written and shipped through the **old** sink before the
  swap, so the previous log server records who redirected the audit stream and where to;
  then the swap; then a second row `admin.integrations.applied` (principal `system`)
  travels through the new one. `/readyz`, `/metrics` (`oob_audit_shipper_*`) and the page
  read the current shipper's `Stats()` through the switch.
- Startup: the runtime resolves the effective GELF settings (file or DB) exactly like
  General keys; `serve` no longer reads `Audit.GELF` directly.
- Disabling: swap in `nil`; the old one flushes and closes; the state line says Disabled.

## 7. Boundary with notifications and tokens (document on the page and in deploy/README)

| Channel | What it carries | Where it is configured |
|---|---|---|
| GELF (push) | every audit row, machine-readable, for a log system | Integrations |
| Notifications (push) | human alerts: health, reachability, logs, actions; webhooks for automation | Notifications |
| API / `/metrics` / `/readyz` (pull) | current state for dashboards and monitors | tokens in API tokens; hints in Integrations |

The generic webhook stays a notification target (it is an *event* channel with filtering
and retries); Integrations never duplicates it.

## 8. Security

- **Authz**: `admin.integrations.view` (admin) and `admin.integrations.manage` (admin,
  step-up) — already named in settings_design §3; added to the matrix tests. `settings.
  locked: [integrations]` locks this tab **and** the notification targets (the existing
  meaning; documented as the union).
- **Destination policy (new threat row T10)**: an admin pointing the audit stream at a
  host of their choosing exfiltrates principals, server IDs, actions and parameters
  (never secrets: params are redacted fail-closed). Controls: the address must be inside
  `audit.gelf.allowed_networks` (file-only; default = RFC 1918 + ULA, i.e. a LAN log
  server, because that is where log servers live; loopback, link-local, multicast,
  unspecified and the app's own listen address are refused always); DNS names are
  resolved per dial and every answer must pass the policy (the notifications transport
  already does this); TLS + pin recommended by the UI copy; every change audited **before**
  it takes effect (§6). The fingerprint fetch is a dial to an admin-supplied address:
  admin + step-up + 6/min (`fpLimit`, shared with server fingerprints) + audited
  (`admin.integrations.gelf.fingerprint`, address, port, result class), handshake-only,
  5 s bounds — the same T8 reasoning as Settings → Servers.
- **Secrets**: none (GELF has no credential). The pin and address are public values.
- **CSRF / step-up / rate**: `change()` (10/min/user), `probe()` for the fetch (6/min),
  `Send test` 3/min/user (its own limiter), forms carry `rev` → 409 on conflict.
- **Test event**: writes `admin.integrations.gelf.test` (ok/error + class, the shipper's
  connected flag before and after a synchronous single write attempt bounded to 5 s). A
  TCP write without an error is the only signal GELF gives; the page says so ("the server
  accepted the bytes; check your log server for the row").

## 9. Audit events

| Action | Result | Params |
|---|---|---|
| `admin.integrations.update` | ok / denied (`locked`, `conflict`, `invalid` not audited) | `target: "gelf"`, `rev`, `changes[{field,before,after}]` (address, transport, server_name, pin, enabled) |
| `admin.integrations.applied` | ok / error (class) | principal `system`; `address`, `transport` — shipped through the new sink |
| `admin.integrations.gelf.fingerprint` | ok / error | `address`, `port`, `class` |
| `admin.integrations.gelf.pin` | ok | `pin_via: fetched\|manual`, `pinned: leaf\|issuer` |
| `admin.integrations.gelf.test` | ok / error | `connected_before`, `connected_after`, `class` |

## 10. Notifications and metrics

- Trust event on pin mismatch (§5), resolved on recovery; `notify` class `trust` (existing).
- Metrics (additive): `oob_audit_shipper_tls` (1 when TLS), `oob_audit_shipper_pin_mismatch`
  (1 while paused), `oob_audit_shipper_reconnects_total`, `oob_audit_shipper_last_success_
  timestamp_seconds`. The existing connected/queued/dropped families now read the active
  shipper through the switch.
- `/readyz`: `degraded` while disconnected or paused (unchanged semantics, now also for
  the pin case).

## 11. API

None (settings have no JSON API). The hints embed `public_url` (or the request host) so the
snippets are copy-ready.

## 12. Failure modes and safety

- Log server down: queue, drop with counters, banner; never blocks an action (unchanged).
- Swap while frames are queued: the old shipper flushes for 3 s then drops the rest with
  the counter; the page warns "N rows were queued; they are sent now or dropped" before
  Save when `queued > 0`.
- Address resolves to a disallowed IP after save (DNS change): dial refused, class
  `policy`, page shows it; nothing is sent.
- App restart: the effective settings are re-resolved (DB row or file); the switch is
  rebuilt; no state to persist beyond `settings_kv`.
- Rule 11: nothing here touches a BMC.

## 13. Test plan

- **Unit, `audit`**: `SwitchSink` swap under concurrent `Enqueue` (no frame lost beyond the
  queue bound, old flushed, counters move), nil sink drops; TLS shipper against an
  in-process TLS GELF receiver: leaf pin ok, issuer pin ok with a chain, wrong pin refused
  with zero application bytes sent and `tls_pin` recorded, plain-TCP server with `tls`
  configured → `tls` class (no fallback), reconnect backoff.
- **Unit, `integrations`**: validator (bounds, `tls` requires pin, server name shape),
  policy table (hostile addresses, DNS answer outside the allowlist refuses the name, the
  app's own address), `Apply` ordering (update row via old sink, applied row via new;
  fakes record which sink got which), disable, conflict 409, locked 403.
- **Unit, `tofu`**: issuer SPKI extraction from a chain; no bytes after the handshake
  (existing property, new assertion for the GELF port).
- **UI**: page sources/lock badges, viewer/operator 403 audited, stale step-up redirect,
  Save/Reset, fetch → confirm → pin (proof purpose bound), manual pin, Send test (3/min →
  429), hints contain `<token>` and never an `oobk_` string (grep the rendered page against
  every token the test minted), `settings.locked` notice, `copy_test`/`security_test`.
- **authz** matrix rows; `settings` precedence tests for the new section.
- **e2e (Go)**: the stack starts with a plain-TCP fake GELF receiver (exists for the e2e
  webhook pattern? if not, a 60-line receiver), the admin switches to a TLS receiver with a
  generated certificate via fetch-and-confirm, the `update` row arrives at the **old**
  receiver and `applied` at the new, Send test lands, a wrong pin pauses shipping and the
  Overview banner + `trust` webhook appear, `/readyz` says degraded then ok, no token text
  on the page.
- **Playwright + axe**: `/settings/integrations` and its TOFU confirm page at 1440/390 in
  both schemes; `pages.spec.ts` entries; Copy buttons with JS.

## 14. Docs to update

settings_design.md ("S4 as built" subsection), tech_doc (new §: switch sink, TLS pin
semantics, keys), security.md (new **T10** audit-stream redirection row; §3 "Web controls"
mention; §6 nothing), deploy/README ("Settings → Integrations" with the TLS/pin steps, the
Homepage/Kuma/Prometheus hints now generated by the page, `audit.gelf.allowed_networks`),
the `config.yaml` example (`audit.gelf: {address, transport, server_name, pin_sha256}`).

## 15. Effort

| Part | Days |
|---|---|
| Keys, validator, migration, `SwitchSink`, service `Apply`, runtime wiring | 0.5 |
| TLS shipper + pin (leaf/issuer), TOFU reuse, trust event, metrics | 0.5 |
| UI page (form, state, hints, TOFU confirm), authz, tests, e2e, docs | 0.75 |
| **Total** | **1.75** (design said 1 d for TCP-only; TLS + pin + hints add the rest) |

## 16. Risks

- Pinning the issuer requires the log server to send its chain; many self-hosted setups
  send only the leaf — the UI defaults to the leaf in that case and says what happens on
  rotation (shipping pauses until re-confirmed).
- The default `allowed_networks` (private ranges) is the opposite of the notifications
  default (public only). It is deliberate (log servers live on the LAN) and documented;
  an admin with a hosted log service lists its range.
- Two branches rebuilding `settings_kv` (plans 02 and 05): harmless, but the second to
  merge must re-list the first's keys in its CHECK (the dense-version test does not
  catch a dropped key; a store test `TestSettingsKVAcceptsEveryKnownKey` should).

## 17. Open questions

1. Default `audit.gelf.allowed_networks` = private ranges (plan) — agree?
2. Offer UDP GELF for log servers that only listen on UDP? (Plan: no; TCP/TLS only, as
   today.)
3. Should the Prometheus hint also show the `metrics.allow_networks` value and the
   per-token advice, or just the scrape block?
