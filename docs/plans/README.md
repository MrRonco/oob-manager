# Roadmap plans — sequencing, dependencies, estimate

Written 2026-10-21 on branch `roadmap-plans` from `main` @ `eaa154f`.

**Status 2026-10-22 (merged into `main` after v0.7.2):** the two branches mentioned below have
shipped: the BMC security checks took migration **0011** (v0.7.0/0.7.1) and the round-2 audit
fixes shipped in v0.7.2 (no migration). New migrations start at **0012**. Next free threat IDs in
docs/security.md are now S10, T10, I15, D9, R4, E5; the security checks added the `security`
notification class, which plan 03 can use for firmware posture.

**Status 2026-10-23:** S4 (plan 05) took threat ID T10 and migration 0012. Plan 01 (BMC reset) is
implemented on branch `bmc-reset`: migration **0013** (`bmc_resets`), threat rows **T11**, **D9**, **R4**,
notification class `bmc`, tech_doc **§37**. Next free after it: migration **0014**; threat IDs S10, T12,
I15, D10, R5, E5.

**Status 2026-10-23 (later):** Plan 03 (firmware view) is implemented on branch `firmware-view`:
migration **0014** (`firmware_components`, `firmware_changes`, `firmware_scans`), threat rows **T12**,
**I15**, **D10**, **R5**, tech_doc **§38**, notification class `security` (no new class), the shared
`internal/csvx` helper for plan 02. Next free after it: migration **0015**; threat IDs S10, T13, I16,
D11, R6, E5.

**Status 2026-10-23 (history):** Plan 02 (history graphs and CSV) is implemented on branch
`history-graphs`: migration **0015** (`sensor_keys`, `sensor_raw`, `sensor_hourly`, `sensor_daily`,
`history_meta`, and the `settings_kv` rebuild that re-lists every General and S4 key), threat rows
**T13**, **I16**, **D11**, tech_doc **§39**, authz actions `server.history.view`, `.export`,
`.export_all`, five `oob_history_*` metric families, `internal/csvx` extended. Next free after it:
migration **0016**; threat IDs S10, T14, I17, D12, R6, E5.

**Status 2026-10-29 (update checker):** Plan 08 (firmware update checker: Dell's signed enterprise catalog,
read-only, opt-in online fetch or uploaded file) is merged with v0.8.1 done (migration 0016, `stored`). The maintainer
wants it built **before redesign slice D**, after v0.8.1 (`fix-firmware-states`, which takes migration
0016 and renames `lc_installed`). Plan 08 then takes migration **0017**, threat rows **T14**, **I17**,
**D12**, **S10**, **E5**, and a new notification class `firmware`. Decisions (plan §21): the check is off by
default and an admin turns it on in Settings (step-up, audited; URL and keys stay file-only); the
deprecated `golang.org/x/crypto/openpgp` package is used, wrapped in one file (no new module).

**Status 2026-10-29 (store-ready install):** Plan 09 (plan 07 §4.8, first part) is built as v0.11.0: a container
started with only a data volume generates its certificate and keys there on first start, offers `/setup` with a
one-time code from the log, and shows a backup notice. No migration (next free stays **0019**). Threat rows **S11**,
**T15**, **I18**, **E6**; next free S12, T16, I19, D13, R6, E7. tech_doc **§44**.

Six implementation plans, one per item, each with goal, roles, UX placement (direction B, with a note for the
round-2 redesign), data model and migration, BMC specifics, authz, audit, notifications,
metrics, API, failure modes, test plan, docs, effort, risks and open questions.

| # | Plan | Days | Migration | New authz actions |
|---|---|---|---|---|
| 01 | [BMC reset](01-bmc-reset.md) | 2.5 | `bmc_resets` | `bmc.reset` (admin, step-up) |
| 02 | [History graphs + CSV](02-history-graphs-csv.md) | 3.5 | history tables + `settings_kv` rebuild | `server.history.view`, `server.history.export`, `server.history.export_all` |
| 03 | [Firmware view](03-firmware-view.md) | 3.25 | `firmware_components`, `firmware_changes` | `server.firmware.view`, `.export`, `.rescan` |
| 04 | [Round-2 design implementation](04-round2-design-implementation.md) | 6.5–7 (+0.5 baseline) | none | none |
| 05 | [S4 Integrations](05-s4-integrations.md) | 1.75 | `settings_kv` rebuild | `admin.integrations.view`, `.manage` |
| 06 | [P7 Hardening](06-p7-hardening.md) | 6.75 | none | none |
| 07 | [Public release (P8) + Unraid CA listing](07-public-release.md) | ≈ 3.75 + 7-day soak | none | none |
| 08 | [Firmware update checker](08-update-checker.md) | 3.0 | `catalog_imports`, `catalog_checks`, `catalog_releases`, `firmware_update_skips`, `firmware_update_notified` + `settings_kv` rebuild | `firmware.catalog.check` (operator), `firmware.catalog.upload` (admin, step-up), `server.firmware.skip_update` / `.unskip_update` (admin, step-up) |
| 09 | [Store-ready install](09-store-ready-install.md) (plan 07 §4.8, first part) | 1.0 | none | none (`/setup` is pre-session, gated by the one-time code) |
| | **Combined** | **≈ 24.5–25.5 d** | | |

Two other branches are in flight and were not read: a BMC security-check panel
(`bmc-security`, may take migration **0011**) and the round-2 UX audit (its output drives
plan 04). Every plan here numbers its migration **0012 or later**, by name, and assigns the
number at merge; `TestMigrationVersionsAreDense` catches collisions. tech_doc §30 also
reserves "0011" for a metrics token scope — whichever lands first takes it.

## Recommended sequencing

```
P7-early (0.75)  →  05 S4 (1.75)  →  01 BMC reset (2.5)  →  03 Firmware (3.25)
→  02 History (3.5)  →  04 slice A (1.5) + baseline (0.5)  →  [round-2 direction chosen]
→  04 slices B–D (5–5.5)  →  06 P7 rest (6)  →  P8
```

Why this order:

1. **P7-early first** (Renovate with the 14-day rule, per-package coverage gate, actionlint,
   the dependency-documentation test): 0.75 d that protects everything after it.
2. **S4** closes the Settings design (the last open slice), is small, and its `SwitchSink`
   and TLS pin helper are reused by nothing else — no reason to wait.
3. **BMC reset** is the highest value per day (research F6a) and introduces the fleet
   "restarting" state that plan 02's event overlay and plan 03's tier skipping consume.
4. **Firmware before History**: firmware is pre-release in the research ranking; it also
   introduces the shared `csvx` helper that history reuses (history is the larger CSV user,
   but firmware's is simpler to build first).
5. **History** last of the features: largest schema change, second SQLite connection.
6. **Redesign slice A** (fonts, OKLCH tokens, visual baseline) only once the feature UIs
   exist, so the baselines are taken over the final page set; slices B–D wait for the
   audit's direction decision.
7. **P7** at the end, because its threat-model refresh, fuzz targets and ZAP allowlist
   must cover the final surface; its drills include plan 01's crash case.

If the round-2 direction is decided early, slice A can move to right after P7-early (it is
invisible except for the font) and the baselines are then updated by each feature PR — the
visual policy allows that.

## Dependencies and merge hotspots

| Shared thing | Plans | Rule |
|---|---|---|
| Migration numbers | 01, 02, 03, 05 (+ bmc-security, metrics scope) | assign at merge; keep `TestUpgradeFromProductionSchema` and the dense test green |
| `settings_kv` CHECK list rebuild | 02, 05 | the second to merge re-lists the first's keys; add `TestSettingsKVAcceptsEveryKnownKey` |
| `internal/csvx` | 03 (creates), 02 (extends) | firmware first |
| Fleet `Restarting` state and `Fleet.Refresh(tier)` | 01 (creates), 02 overlay, 03 tier | BMC reset first |
| `authz.go` matrix + `TestMatrixCoversEveryAction` | 01, 02, 03, 05 | one row block per plan; trivial conflicts |
| `partials.html` (`servertabs`, `settingstabs`, `sidenav`), `pages.spec.ts` list | 02 (History tab), 03 (Firmware page), 05 (Integrations tab), 04 (everything) | features before the redesign; or rebase |
| `metrics/specs.go` family list, golden scrape | 01, 02, 03, 05 | append-only; regenerate the golden file once per merge |
| security.md threat IDs | 01 (T9, D8, R4), 02 (I12), 03 (I13), 05 (T10), 06 (refresh) | next free today: S10, T9, I12, D8, R4, E5; never renumber |
| notification classes | 01 adds `bmc`; 03 may need a posture class from the security panel | decide the class question before 01 ships |
| `redfishmock` options | 01 `WithManagerReset`, 03 member overlays | additive |
| `deploy/README.md` | all | one section per feature, generic text only (rule 12) |

## What each item needs from the maintainer

| Plan | Decisions | Hardware / approvals |
|---|---|---|
| 01 | cooldown length; reset while another admin's console is open; new `bmc` notification class vs `power`; grant "Configure iDRAC" to the iDRAC8 operator account if required | one real BMC reset per iDRAC after merge (privilege, downtime, fan behaviour, `MinimumFanSpeed` persistence) |
| 02 | answered 2026-10-23 (plan §18): downloads not audited; defaults kept; fleet sparklines later; 2000 points; export-all operator | none |
| 03 | firmware flags on Overview or not; notification mapping for `server.firmware.changed`; `firmware.minimum` file-only vs Settings editor; age-flag default; the first minimum list | one read-only capture of every firmware member document per BMC (sanitised) |
| 04 | the §11 decision checklist (fonts and licence, OKLCH anchors, palettes, motion, view transitions, command palette, IA changes, phone nav, icons, tolerance); ship slice A early? | screen-reader pass owner |
| 05 | default `allowed_networks` for GELF = private ranges; UDP GELF (no); Prometheus hint contents | a TLS-capable GELF input on the log server to verify the pin flow |
| 06 | ZAP on PR vs nightly; keyless cosign; `backup` CLI in P7; per-package coverage list; `umask 077` | approval to run the eight drills on a real install (drills 1, 2 and 8 touch the live database and keys: do them on a copy) |

## Rules every plan follows

CLAUDE.md 1–12: TDD with the 80 % gates; no `os/exec`; nothing user-supplied reaches a
BMC (closed enums, exact action URIs, one-field bodies); immutable values; small files; no
secrets in logs/fixtures; dangerous actions = role + step-up + audit + rate limit; fan
control stays cooperative with an enforced revert; rule 11's out-of-scope list is untouched
(plan 03 reads firmware and never updates it; plan 01 sends exactly one `GracefulRestart`);
no new Go dependency anywhere in the six plans (fonts are vendored assets with a tech_doc §2
row); generic docs with RFC 5737 addresses only.
