# Plan 01 — BMC reset (`Manager.Reset`, `GracefulRestart`)

Status: plan, 2026-10-21. **Implemented 2026-10-23** on branch `bmc-reset` (from `main` @ `3358e51`, rebased onto `93befdf`),
tested against the Redfish mock only: implementation notes in tech_doc §37 (migration **0013**, threat
rows **T11**, **D9**, **R4** in security.md, notification class `bmc`). The decisions on §18 are
recorded there. Research input: feature research item 6 (F6a).
Builds on tech_doc §17 (sessions), §20 (power service), §21 (fan leases), §25 (hot apply),
security.md §3a (transport allowlist) and §3c (power controls).

## 1. Goal and non-goals

**Goal.** Let an admin restart a hung BMC from the app ("the console will not launch", "the
BMC web UI is sluggish", "SSH stopped answering") with the same safety model as a forced
power action, and have the app behave sensibly while the BMC is away: no false
"unreachable" alarms, consoles closed cleanly, fan leases restored when the BMC returns.

**Non-goals (rule 11 and blast radius).**

- `Manager.ResetToDefaults`, Dell `DellManager.ResetToDefaults`, `SetCustomDefaults`: never
  sent. The action policy regex excludes them by construction.
- `ForceRestart` of the manager: neither tested iDRAC offers it; the closed set is
  `GracefulRestart` only. A BMC that offers only `ForceRestart` shows the action as "Not
  offered by this BMC".
- Host power: a BMC restart never touches `ComputerSystem.Reset`.
- IPMI `mc reset` for `kind: ipmi` servers: out of scope (no go-ipmi dependency yet).
- Firmware updates, "reset and clear SEL", BMC network reconfiguration.

## 2. User stories

| Role | Story |
|---|---|
| viewer | I see on the server page that the BMC is restarting (not "stale", not "unreachable") and when the app expects it back. |
| operator | Same as viewer; the Restart BMC button is visible but disabled with "needs the admin role". |
| admin | From Operations I can restart the BMC after typing the server name and a fresh code; I am told what it costs (consoles close, monitoring blind for minutes, fans may run loud); afterwards I see "BMC back after 2 min 10 s" and the audit record. |
| admin | I cannot restart a BMC while a power action is still being verified, while another reset is in progress, or inside the cooldown; the reason is visible. |
| admin (notifications) | My targets get "BMC restart requested/done/failed" and do **not** get a spurious "unreachable" for the restart window. |

## 3. UX placement (direction B)

- **Operations tab** (`/servers/{id}/operations`): a new panel **"BMC"** under the Power
  panel in the left column. Contents: BMC model + firmware (from capabilities), "Last BMC
  restart" (iDRAC9 `LastResetTime`; iDRAC8 has none, so the app's own last reset row is
  shown, else "Not reported"), the button `Restart BMC…` (`btn-danger-outline btn-small`,
  icon `power`), and the disabled reason when not available (closed list, see §9).
- **Confirm page** (`GET/POST /servers/{id}/bmc/reset`): reuses `confirm.html` (C-11):
  title "Restart the BMC of <server>?", consequences panel (danger): "Every console on this
  server closes now", "Sensors, logs and power control are unavailable for about 2–5
  minutes", "Fans may run at full speed until the BMC is back" (see §13, unverified), "The
  host keeps running", plus the self-host warning when `power.self_host` (the app itself is
  not affected, but say so). Typed server name always; step-up inline; Cancel is the
  default focus; the button says "Restart BMC of <server>".
- **While restarting**: the server page verdict panel shows a `role=status` line "BMC
  restarting · requested 01:12 by alice · expected back by 01:17" with the stale (dashed)
  chip style, the sidebar glyph uses the stale class with text "BMC restarting", the fleet
  table's Data column shows "BMC restarting". The fleet pill counts it as "1 restarting"
  (new count, not "stale").
- **Server page action bar**: unchanged (the bar stays short; the action lives on the
  Operations tab like power actions).
- **If the round-2 redesign moves Operations** into an actions sheet or a split button, the
  BMC panel becomes one group ("BMC ▾ → Restart BMC…") and the confirm page is unchanged.
  Nothing here depends on the tab existing: the route is `/servers/{id}/bmc/reset`.

## 4. Data model and migration

Migration **`00NN_bmc_resets.sql`** (NN ≥ 12: the security-panel branch may take 0011 and
tech_doc §30 reserves "0011" for a metrics token scope; assign the number at merge,
`TestMigrationVersionsAreDense` catches collisions):

```sql
CREATE TABLE bmc_resets (
    id             INTEGER PRIMARY KEY,
    server_id      TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    correlation_id TEXT    NOT NULL,
    requested_at   INTEGER NOT NULL,                 -- unix ms UTC
    requested_by   TEXT    NOT NULL CHECK (requested_by <> ''),
    reset_type     TEXT    NOT NULL CHECK (reset_type = 'GracefulRestart'),
    result         TEXT    NOT NULL CHECK (result IN ('sent', 'refused', 'verified', 'timeout')),
    back_at        INTEGER,                          -- first successful poll after the reset
    deadline_at    INTEGER NOT NULL,
    error_class    TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX bmc_resets_server ON bmc_resets (server_id, requested_at);
```

Why a table and not only audit rows: the cooldown and the "restarting" window must survive
an app restart (the BMC may still be rebooting when the app comes back), and "Last BMC
restart" on the panel must not scan the audit log on every page view. Rows older than
400 days are pruned daily (same janitor as acks).

No change to `settings_kv`, `servers` or `capabilities`. The capability JSON gains
`manager_reset_types` (additive, from the probe; old rows without it mean "not probed yet").

## 5. Redfish / BMC specifics

Facts read from the captured fixtures (tested firmware; everything else is marked):

| | iDRAC8 2.86 (13G) | iDRAC9 7.00 (14G) |
|---|---|---|
| Action | `Actions["#Manager.Reset"].target` = `/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset` | same URI |
| `ResetType@Redfish.AllowableValues` | `["GracefulRestart"]` | `["GracefulRestart"]` |
| Other manager actions present (never used) | `OemManager.ExportSystemConfiguration` | `#Manager.ResetToDefaults` (`ResetAll`, `PreserveNetworkAndUsers`), Oem `DellManager.ResetToDefaults` (`All`, `Default`, `ResetAllWithRootDefaults`), `DellManager.SetCustomDefaults`, export/import |
| `LastResetTime` | absent | present (`2026-04-03T01:18:54-04:00` in the capture) |
| `PowerState` on the Manager | absent | `On` |
| Session behaviour after the POST | **unverified**: expect every session invalid, HTTPS down for 1–5 min | **unverified**: expect 1–3 min |
| Privilege needed by the operator account | **unverified** (Dell documents `racreset` under "Configure iDRAC", bit 0x2); the account used for `redfish-floor` already has it on iDRAC9, the iDRAC8 operator account may not | same |

**Discovery (read-only, on the inventory tier).** The probe already decodes the Manager. Add
to `managerLinksDoc`: `Actions["#Manager.Reset"].{target, ResetType@Redfish.AllowableValues}`.
`CapabilityFlags` gains `ManagerReset bool` and `Capabilities` gains `ManagerResetTypes()`;
the flag is true only when the target equals `<manager>/Actions/Manager.Reset` **and**
`GracefulRestart` is advertised. Absent action → "Not offered by this BMC".

**Transport allowlist: sixth exception.** `redfish.IsManagerResetActionURI(p)`:
`^/redfish/v1/Managers/[A-Za-z0-9._-]{1,64}/Actions/Manager\.Reset$` with the `..` guard, as
`IsResetActionURI`. `redfish.OpenManagerResetter(ctx, cfg)` mirrors `OpenResetter`: a fresh
driver with the **operator** login and `WithActionPolicy(IsManagerResetActionURI)`, walks
service root → first system → `Links.ManagedBy[0]` (fallback: first Manager, exactly like
the probe) → manager doc; the advertised target must equal `<manager>/Actions/Manager.Reset`
or `ErrUnsupported`. `Reset(ctx)` sends exactly `{"ResetType":"GracefulRestart"}` (one-field
struct, closed set of one value, must also be in the advertised list). A 401 is not retried.
Pollers never get this policy (test: the poller's driver refuses the POST before a byte is
sent). The DELETE of our own session after the POST will usually fail (the BMC is going
away): treat `unreachable`/`timeout`/5xx on logout as success for this action only.

**Expected response.** 204 or 200 on both (unverified; Dell samples show 204). Anything
2xx = `sent`. 403 → `error` class `auth` and the panel says "The operator account lacks
the privilege for this action" until the next successful reset (sticky per server, cleared
by hot apply or restart). 409/400 → `error` class `bmc`. Timeout → `sent_unconfirmed`:
treat as sent (the BMC may well be restarting) and let verification decide.

**Verification.** After `sent`, the fleet enters the *restarting* window (§6). The reset is
`verified` on the first successful snapshot after `requested_at + quiet`; on iDRAC9 the
poller also records the new `LastResetTime` (must be ≥ `requested_at`; if unchanged after
the window, the row still says `verified` but notes `last_reset_time_unchanged`, which is
shown as "the BMC answered again but did not report a restart"). `timeout` when the
deadline passes without a successful poll (iDRAC8 5 min, iDRAC9 3 min, both constants per
kind in code, not config).

## 6. Effects on the rest of the app

**Fleet: a "BMC restarting" state (new).** `fleet.Fleet.ExpectRestart(id, since, until)` sets
`ServerState.Restarting{Since, Until, By}` on the poller (published through the existing
atomic pointer). While `Restarting` is set and `now < Until`:

- the poller sleeps `quiet` (60 s) after the request, then polls every 30 s (not the
  interval) until a snapshot succeeds or `Until` passes;
- failures are **not** counted for the breaker and `FailingSince` is not set;
- `Stale` is still computed honestly (data **is** old) but the UI maps "stale + restarting"
  to the restarting wording; the API keeps `stale: true` and adds `bmc.restarting`;
- the slow tiers are skipped; after the first good snapshot the inventory tier runs
  immediately (firmware version may have changed, `LastResetTime` must be re-read);
- on success the state is cleared and the reset row becomes `verified`; past `Until`
  the state is cleared, the row becomes `timeout`, and normal failure accounting starts
  from that poll (so "unreachable since" is the deadline, not the request time).

`fleet.Apply` keeps a running poller's `Restarting` state when the fingerprint is unchanged
and drops it when the server is rebuilt (a changed address is a different BMC). At startup
the runtime re-reads open `bmc_resets` rows (`result = 'sent'`, `deadline_at > now`) and
re-arms the window, so an app restart during a BMC restart does not raise alarms.

**Notifications.** The detector's reachability signal ignores a server while `Restarting`
(no "unreachable", no "stale" event); if the window ends in `timeout` the next detector pass
reports unreachable as usual. New tap mappings for `bmc.reset`: `started` → warning "BMC
restart requested" (`ClassBMC`, see §10), `ok`/`verified` → info "BMC back after N s",
`error`/`timeout` → warning/critical. `health` is not judged on a stale snapshot already.

**Consoles.** Before the POST, the broker ends every graphical and serial session on the
server with reason `bmc_reset` (audited `console.*.stop`, `reason=bmc_reset`); the VNC
banner probe and serial "last attempt" state are reset to "Not checked yet" and re-probed
on the first good poll. The iDRAC9 native console (launched in a new tab) dies on its own;
the confirm page says so.

**Fan leases.**

- `host-lease`: unaffected (the host script reads a file). But a host fan script that
  talks to the BMC in-band (IPMI/KCS) cannot read sensors while the BMC restarts; the
  confirm page reminds the admin that such scripts must fail safe (the shipped reader
  snippet does nothing BMC-side, so the lease file is simply still there afterwards).
- `redfish-floor` (iDRAC9): `ThermalSettings.1.MinimumFanSpeed` is an iDRAC attribute and
  is **expected** to persist across a graceful BMC restart (**unverified**). After the
  first good poll the fan service re-runs `Apply` for the active lease (idempotent by
  contract) and audits `fan.lease.reapply` with `reason=bmc_reset` when the read value had
  reverted. The lease's expiry does not move. `End now` during the window fails to release
  (`ErrRelease`, the BMC is away) and the reconciler retries every 15 s as today; the UI
  shows "Will be released when the BMC is back".
- `ipmi-oem` (deferred mode): would need an explicit re-assert; noted for when it exists.

**Power service.** A reset is refused while `power.Service.Last(id)` is not `Final()`
(`denied:power_pending`). Symmetrically, `power.Request` refuses while the server is
`Restarting` (`denied:bmc_restarting`), because the operator login and the verification
read would both fail. The 60 s power cooldown and the BMC cooldown are independent.

**Settings → Servers.** A connection change, disable or delete during the window ends the
window (the row becomes `timeout` with `error_class=config_changed`).

## 7. Authorization and step-up

- New action `bmc.reset`: **admin + fresh step-up**, sessions only (tokens never), in
  `RequiresStepUp`, covered by `TestMatrixCoversEveryAction` and `TestRequiresStepUp`.
- Typed server name **always** (the blast radius is "monitoring blind + consoles closed",
  the same class as a forced power action).
- Order of checks on POST, mirroring §3c: session → server from the path → CSRF (form
  `bmc`) → availability (capability flag, operator login, no power pending, not
  restarting, cooldown) → `confirm=yes` → typed name → step-up (fresh or inline code) →
  authorization → 10/min/user (`changeLimit`, key `bmc:<user>`) → service.
- Cooldown: **10 minutes per server** after a `sent` (constant; the BMC takes minutes to
  come back and repeated resets achieve nothing). 429 + `Retry-After` on the POST and the
  reason on the confirm page. Persisted in `bmc_resets` (survives restarts).

## 8. Audit events

All rows carry `server_id`, the request's correlation ID, principal, role, source IP.

| Action | Result | Params |
|---|---|---|
| `bmc.reset` | `denied` | `class`: `confirm_mismatch`, `stepup_required`, `cooldown`, `power_pending`, `restarting`, `not_offered`, `no_operator`, `rate_limited`, `csrf` |
| `bmc.reset` | `started` | `reset_type`, `deadline` (RFC 3339), `consoles_ended` (count). **Fail-closed**: no row, no POST. |
| `bmc.reset` | `ok` | `bmc_status` (HTTP class), `outcome: sent` |
| `bmc.reset` | `error` | `error_class` (`auth`, `bmc`, `timeout`, `unreachable`, `unsupported`) |
| `bmc.reset.verified` | `ok` | principal `system`; `downtime_s`, `last_reset_time` (iDRAC9) or `last_reset_time_unchanged: true`, `firmware_version` |
| `bmc.reset.verified` | `error` | principal `system`; `error_class: timeout` (deadline passed), or `config_changed` |

Consoles ended by the reset keep their own `console.*.stop` rows (`reason=bmc_reset`);
fan re-application keeps `fan.lease.reapply`.

## 9. Disabled reasons (closed list, visible text per C-10)

`Not offered by this BMC` · `Needs an operator BMC account` · `Needs the admin role` ·
`BMC is restarting (back by HH:MM)` · `A power action is still being verified` ·
`Cooling down for N min` · `The operator account lacks the privilege (last attempt)` ·
`Not determined yet` (no probe yet).

## 10. Notifications

New class **`bmc`** ("BMC restarts"), not suppressed by maintenance (`Mutable()` false: it
is an action with a trail), default-subscribed for new targets. Existing targets: not
subscribed until edited (their `subs_json` lists classes explicitly); the Notifications
page shows the new class with a "new" hint. Alternative considered and rejected: folding
into `power` (wrong semantics; a "power" subscriber expects host power only).

Events: requested (warning), done (info, recovery of the requested event's key so the
pair reads as problem/resolved), failed (warning), timed out (critical: the BMC did not
come back; this is the one that should wake someone).

## 11. Metrics (additive)

- `oob_server_bmc_restarting{server,name}` gauge: 1 during the window.
- `oob_server_bmc_last_reset_timestamp_seconds{server,name}`: from iDRAC9 `LastResetTime`
  when reported, else the app's last verified reset, else 0.
- `oob_bmc_resets_total{server,name,result}` counter since start (`sent`, `refused`,
  `verified`, `timeout`).

## 12. API (read-only, additive)

- `/api/v1/servers` summary gains `bmc_restarting: bool`.
- `/api/v1/servers/{id}` gains
  `bmc: {reset_supported: bool, restarting: bool, restart_requested_at, restart_deadline,
  last_reset_time (null when the BMC does not report it), last_app_reset: {at, by, result}}`.
  `stale` keeps its honest value.

## 13. Failure modes and safety

- **POST accepted, BMC never restarts**: `timeout` after the deadline, breaker resumes,
  reachability alert fires. The row says `timeout`, the panel "The BMC did not come back
  by HH:MM; open the BMC web UI".
- **POST times out but the BMC did restart**: handled by the window (treated as sent).
- **403**: sticky "lacks the privilege" reason; cooldown kept; no retry loop.
- **App crash mid-window**: the row (`sent`, open deadline) re-arms the window at startup.
- **Credentials or address changed mid-window**: window ended as `config_changed`.
- **Fans during the restart**: on Dell servers the fans are commonly reported to run at
  full speed while the iDRAC reboots and settle when it is back [reported, unverified on
  the tested hardware]. The confirm page states it; it is not a fault.
- **Host-side effects**: none on the host OS. In-band BMC access (host tools, host fan
  scripts over KCS) is unavailable for the window.
- **Rule 11**: only `GracefulRestart` to the exact manager action URI; every other manager
  action is refused by the regex and by the closed value set before a byte is sent.
- **No bypass for tests**: the mock BMC simulates the reset (§14).

## 14. Test plan

- **Unit, `redfish`**: `IsManagerResetActionURI` table (exact match, `..`, query/fragment,
  other actions incl. `ResetToDefaults` and the Oem paths refused); `OpenManagerResetter`
  against `redfishmock`: discovery via `ManagedBy`, foreign target refused, body exactly
  `{"ResetType":"GracefulRestart"}`, unlisted type refused before sending, 401 not retried,
  logout failure tolerated; the poller's driver cannot POST it.
- **`redfishmock.WithManagerReset(downtime)`**: operator sessions only (403 otherwise),
  canonical body only (400), answers 204, invalidates every session, sets the server
  "down" (connection refused or 503, option) for `downtime`, then comes back; the iDRAC9
  fixture variant updates `LastResetTime`; counted in `ManagerResetStats`, not in
  `OtherWrites`. `FailNextManagerReset(code)`.
- **Unit, `fleet`**: window semantics with the fake clock (quiet, 30 s retries, no breaker,
  no `FailingSince`, verified on success, timeout at the deadline, inventory tier
  immediately after return, state kept/dropped by `Apply`, re-armed from open rows).
- **Unit, service (`internal/bmcreset`)**: fail-closed audit, cooldown reserve/return,
  `power_pending` and `restarting` refusals both ways, consoles ended before POST (fake
  broker records order), fan re-apply after return (fake applier with a reverted value),
  config_changed, crash restart (rows only).
- **Unit, `notify`**: tap mapping; detector silent during the window, loud after timeout.
- **Unit, `metrics`**: new families in the golden scrape.
- **Unit, `ui`**: Operations panel reasons, confirm page (typed name, warnings, self-host),
  POST order, 429 with `Retry-After`, restarting wording on server page, sidebar and
  fleet table; `authz` matrix rows.
- **e2e (Go)**: iDRAC9 mock with `WithManagerReset(3s)`: wrong name → 422, exact name →
  303, consoles ended, no "unreachable" webhook, verified row and `bmc.reset.verified`
  within the window, power action refused during the window (409 + reason), cooldown
  429 afterwards; iDRAC8 mock shows the action offered (fixture advertises it) and a 403
  injection shows the privilege reason. Shutdown accounting: one extra operator
  login/logout per reset.
- **Playwright + axe**: Operations tab with the BMC panel, the confirm page (1440/390,
  dark/light), the restarting server page; added to `pages.spec.ts`.
- **Race**: `go test -race -count=3 -shuffle=on` on fleet, bmcreset, notify.
- **Hardware (by the maintainer, after merge)**: one real reset per iDRAC with the operator
  account; record privilege result, HTTP status, downtime, whether `MinimumFanSpeed`
  survived (iDRAC9), fan behaviour, `LastResetTime`; update §5 and the hardware table.

## 15. Docs to update

tech_doc (§3a-style note on the sixth exception; a new §, which became §37), security.md (§3a sixth
exception; new rows, numbered at implementation after the security checks and S4 took T9, T10 and D8:
**T11** "BMC reset body or target altered", **D9** "repeated BMC resets
as denial of service / monitoring blinding", **R4** "BMC reset without a trace"; mention in
D4 that a reset drops the session table), deploy/README ("Enabling BMC reset": privilege
for the operator account per iDRAC generation, what to expect), Help page (glossary: BMC
restart vs host restart), docs/hardware compatibility table (verified cells), notification
class list in deploy/README, metrics list, API docs.

## 16. Effort

| Part | Days |
|---|---|
| Redfish resetter + policy + mock | 0.5 |
| Fleet restarting window + runtime re-arm + migration | 0.5 |
| Service (audit, cooldown, consoles, fans, power interlock) | 0.5 |
| UI (panel, confirm, states), authz, notifications, metrics, API | 0.5 |
| e2e + Playwright + docs | 0.5 |
| **Total** | **2.5** (research said 1.5 for the bare action; the restarting state and fan re-apply are the difference) |

## 17. Risks

- The operator account may lack the privilege on iDRAC8 (the plan degrades to a visible
  reason, not an error page), and granting "Configure iDRAC" widens what the app's account
  can do (document in security.md §4: it is the same privilege `redfish-floor` already
  needs on iDRAC9).
- A BMC that answers 204 and does nothing looks like `timeout`; the plan says so.
- A restart window hides a real outage for up to 5 min; the deadline is per kind and
  the API keeps `stale` honest.

## 18. Decisions

Implemented as decided (tech_doc §37):

1. **Cooldown:** 10 minutes per server (the plan's default).
2. **Another admin's console:** the reset ends it and audits it (`console.*.stop` with
   `reason=bmc_reset`), as proposed: the admin has takeover rights anyway. The confirm page names
   whose console is open.
3. **Notification class:** a new class `bmc`, as proposed. A target with an empty class list
   subscribes to every class (existing behaviour), so such targets also receive `bmc` events; this is
   documented in deploy/README's upgrade notes. Targets saved with an explicit list are not subscribed
   until edited (the form marks the class as new).
4. **iDRAC8 privilege:** keep the plan's approach: a 403 is detected and the panel says the operator
   account needs *Configure iDRAC*. Whether to grant it on hardware waits for the maintainer's one-time
   hardware test.
5. **Hardware verification:** the maintainer's, after merge (one reset per BMC). The procedure (downtime,
   fan behaviour, `MinimumFanSpeed` persistence on the iDRAC9, the fleet "restarting" state,
   re-login) is in deploy/README, "Enabling BMC restart"; it was not performed.

The original questions:

1. Cooldown 10 min per server: fine, or longer?
2. Should a BMC reset be allowed while **another admin's** console is active (the plan
   ends it and audits, since the admin has takeover rights anyway), or refused with "in
   use by X"?
3. New notification class `bmc` (existing targets must opt in) versus folding into
   `power` (no opt-in needed, muddier semantics)?
4. Grant "Configure iDRAC" to the iDRAC8 operator account if the hardware test shows it is
   required, or leave BMC reset iDRAC9-only?
5. Approve the one-time hardware verification (one reset per BMC) once the code is merged.
