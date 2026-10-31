# Plan 03 — Firmware view (read-only)

Status: plan, 2026-10-21. **Implemented 2026-10-23** on branch `firmware-view` (migration 0014, threat
rows T12, I15, D10, R5, tech_doc §38); decisions in §18. No code. Research input: feature research item 9 (F7), UX audit
UX-10 ("Dell component-ID-to-name map" deferred). Builds on tech_doc §11 (Dell firmware
parsing), §17 (poll tiers), §25 (registry), §29 (metrics, `include_inventory`).
**Firmware updates stay out of scope forever** (CLAUDE.md rule 11); this plan reads, names,
compares and exports.

## 1. Goal and non-goals

**Goal.** Answer "what firmware runs where, is anything behind, is anything half-applied"
for the whole fleet in one table and per server: readable component names instead of
`Component 101068`, running vs previous (rollback) vs staged, the release date and its age
when the BMC exposes one, a per-kind "minimum known good" list in config that flags old
versions without any internet access, a slow poll tier with a Re-scan button, and a CSV
export. Prepare the interface (only the interface) for a later offline vendor-catalog check.

**Non-goals.** Pushing updates, staging images, rebooting into Lifecycle Controller,
contacting any vendor site (NFR-6), parsing or importing `Catalog.xml` (that is the later
item; here only the Go interface and a null implementation), BIOS/RAID settings, warranty.

## 2. User stories

| Role | Story |
|---|---|
| viewer | On Inventory I read "BIOS 2.19.0 (running) · previous 2.18.1", "iDRAC 2.86.86.86", "Backplane 0 2.25", grouped by kind, with a legend; no "Component 101068". |
| viewer | On the Firmware page I see every server's BIOS, BMC, NIC, storage controller, drive, PSU and CPLD versions in one table, oldest and inconsistent first, and the release age where known. |
| operator | I press Re-scan on a server after an update and the table refreshes within a minute instead of 24 h. |
| admin | I keep a short list of minimum known-good versions in config.yaml and the page flags "below minimum" rows; I export the table as CSV for a change ticket. |
| integrator | `GET /api/v1/firmware` returns the same rows as JSON for an inventory tool. |

## 3. UX placement (direction B)

- **New top-level page `/firmware`** ("Firmware" in the sidebar between Servers and Settings,
  with a count badge of flagged rows; phone Menu sheet gets the same entry). Content: a
  filter toolbar (C-19, GET form: server, kind, "flagged only", text) and one data table
  (C-06, stacked on phones): Kind · Component · Server · Running · Previous · Released /
  age · Flag. Rows sort problems first (below minimum, mismatch, cannot compare, then by
  kind, component, server). Flags are badges (C-01): `Below minimum` (warn), `Mismatch`
  (warn), `Cannot compare` (info), `OK` (quiet). A legend line explains Running / Staged /
  Previous. "Download CSV" in the page tools.
- **Server › Inventory**: the Firmware section is restructured the same way (grouped by
  kind; one row per component with Running, Staged when different, Previous muted; the
  flag; release date), with "Re-scan firmware" (operator+) in the panel header and a
  "Last scan HH:MM · next in N h" meta line; the Component ID and FQDD columns stay hidden
  unless `?details=1` (link) since the names now carry the meaning.
- **Overview**: nothing new (firmware is not a health signal); the Needs attention list is
  **not** extended with firmware flags (question §17).
- **If the round-2 redesign collapses the sidebar**, `/firmware` becomes a Servers
  sub-view ("Servers › Firmware") with the same route; the table partial is reused.

## 4. Data model and migration

Migration **`00NN_firmware.sql`** (NN ≥ 12; numbering per plan 01 §4):

```sql
-- One row per component per server, as last read. States are merged here: running is
-- what the device reports now, previous the rollback copy, staged an image waiting for
-- a reboot (Dell "Available"/"Installed" that differs from "Current", see §5.3).
CREATE TABLE firmware_components (
    server_id       TEXT    NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    component_id    TEXT    NOT NULL CHECK (length(component_id) BETWEEN 1 AND 64),  -- vendor id or member id
    fqdd            TEXT    NOT NULL DEFAULT '',
    kind            TEXT    NOT NULL CHECK (kind IN ('bmc','bios','cpld','nic','storage','drive',
                                                    'enclosure','psu','lc','other')),
    name            TEXT    NOT NULL DEFAULT '',          -- vendor name from the member document
    running         TEXT    NOT NULL DEFAULT '',
    previous        TEXT    NOT NULL DEFAULT '',
    staged          TEXT    NOT NULL DEFAULT '',
    lc_installed    TEXT    NOT NULL DEFAULT '',          -- Dell "Installed-" when it differs from running
    release_date    INTEGER,                              -- unix ms, NULL when not reported
    updateable      INTEGER NOT NULL DEFAULT 0 CHECK (updateable IN (0, 1)),
    identity        TEXT    NOT NULL DEFAULT '',          -- e.g. "DCIM:firmware:14E4:165F:1028:088F" (catalog key)
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    PRIMARY KEY (server_id, component_id, fqdd)
) STRICT;

-- Version changes between scans ("who updated the BIOS and when"); pruned after 2 years.
CREATE TABLE firmware_changes (
    id           INTEGER PRIMARY KEY,
    server_id    TEXT NOT NULL, component_id TEXT NOT NULL, fqdd TEXT NOT NULL DEFAULT '',
    field        TEXT NOT NULL CHECK (field IN ('running','previous','staged')),
    before       TEXT NOT NULL, after TEXT NOT NULL,
    seen_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX firmware_changes_server ON firmware_changes (server_id, seen_at);
```

Rows of servers that leave the registry are deleted on the registry sync hook. The fleet
page reads these tables (not the poller cache), so a restarted app shows the last scan at
once and a never-polled server shows "not scanned yet".

## 5. Redfish / BMC specifics

### 5.1 What the captured fixtures show

| | iDRAC8 2.86 | iDRAC9 7.00 |
|---|---|---|
| Collection | `/redfish/v1/UpdateService/FirmwareInventory`, 21 members | same, 25 members |
| Member ID shape | `<State>-<ComponentID>-<Version>` (no FQDD) | `<State>-<ComponentID>-<Version>__<FQDD>` |
| States seen | `Current`, `Installed`, `Previous` | same |
| Member document | `Name` ("Backplane 0"), `SoftwareId`, `Version`, `Updateable`, `Status` — **no `ReleaseDate`**, no Oem block | `Name` ("Broadcom Gigabit Ethernet BCM5720 - <MAC>"), `Version`, `Updateable`, **`ReleaseDate`** (`2025-09-27T00:00:00Z`), `Oem.Dell.DellSoftwareInventory` (`ComponentID`, `ComponentType` FRMW/BIOS/APAC, `IdentityInfoValue` = PCI identity, `InstallationDate` "NA", `Status` e.g. `AvailableForInstallation`, `MajorVersion`/`MinorVersion`) |
| Manager link | — | `Links.ActiveSoftwareImage` → the running iDRAC image |
| Cost of one member GET | 1–3 s (session auth) | well under 1 s |

Today the Dell parser derives everything from the member IDs (one GET) and names only the
seven component IDs confirmed by FQDDs; everything else is "Component <id>". The member
documents carry the human names, so **names cost one GET per member, once**.

### 5.2 Reads (all GET, read-only account; no new transport exception)

- Collection as today; then, for members whose `(component_id, fqdd)` is **not yet named**
  in `firmware_components` (or whose `last_seen` is older than 30 days), GET the member
  document: `Name`, `Version`, `Updateable`, `ReleaseDate`, `Oem.Dell.DellSoftwareInventory`
  (`ComponentType`, `IdentityInfoValue`, `Status`). Bounded to 64 members per scan (the
  existing `maxFirmwareItems`), each with the per-request timeout; a scan that cannot finish
  in the tier budget keeps what it got and continues next time (names are sticky).
- Generic Redfish (`kind: redfish`) already fetches `SoftwareInventory` per member; it gains
  `ReleaseDate`, `Updateable`, `SoftwareId` and `RelatedItem` (to classify by the linked
  resource type: `Processors`, `EthernetInterfaces`, `Storage`, `Drives`, `PowerSupplies`).
- Nothing else: no `UpdateService.SimpleUpdate`, no `Actions`, no `MultipartHttpPushUri`.
  A test asserts the firmware scan issues only GETs (mock request log).

### 5.3 Dell state semantics (marked, because the tested data conflicts)

The iDRAC8 capture has `Current-101434-2.25` **and** `Installed-101434-2.23` for the same
backplane. Working interpretation [inference, to confirm against Dell's Redfish guide]:
`Installed-` is the version the Lifecycle Controller recorded at the last update job or
inventory, `Current-` the version the device reports now, `Previous-` the rollback image.
Rules: **running** = `Current` when present, else `Installed`; when both exist and differ
the row gets flag `Mismatch` ("the device reports 2.25, the Lifecycle inventory says 2.23;
collect a system inventory from the BMC UI") and the LC value is kept in `lc_installed`;
`Available` (not in the captures, documented by Dell as a staged image) becomes **staged**.
The inventory page legend says "Running is what the device reports now; Previous is the
rollback copy the BMC keeps; Staged waits for a reboot". The current legend text ("Installed
is what runs now") is replaced.

> **Correction (v0.8.1, 2026-10-29): this interpretation was the wrong way round.** On the
> hardware, `Installed-` is what the device runs (iDRAC9 OEM status "Installed" with an
> installation date; on the iDRAC8, racadm's "Current Version") and `Current-` is the image the
> BMC holds in its firmware store (OEM status "AvailableForInstallation", no installation date;
> racadm's "Available Version"). The backplane above runs 2.23 and holds a 2.25 image that was
> never installed. Running is now `Installed`, the other version is `stored`, and the flag is
> **Not applied** (info, only when the stored image is newer). Details: tech_doc §38 "Firmware
> states corrected"; migration 0016 fixes stored rows.

### 5.4 Component kinds and names

Kind classification, in order: (1) FQDD prefix on iDRAC9 — `iDRAC.`→bmc, `BIOS.`→bios,
`CPLD.`→cpld, `NIC.`→nic, `RAID.`/`AHCI.`/`NonRAID.`→storage, `Disk.`→drive, `Enclosure.`→
enclosure, `PSU.`→psu, `USC.`/`LC.`/`DriverPack`/`Diagnostics`/`OSCollector`/
`ServiceModule`→lc, else other; (2) the known Dell component IDs (159 bios, 25227 bmc,
28897 lc, 27763 cpld, 18981/25806/101734/104684 lc); (3) `DellSoftwareInventory.ComponentType`
(`BIOS`, `FRMW` + name keywords); (4) keywords in `Name` for iDRAC8 ("BIOS", "iDRAC",
"Lifecycle", "CPLD", "Backplane", "PERC"/"HBA"/"BOSS"→storage, "Power Supply"→psu,
"Ethernet"/"Network"→nic, "Disk"/"SSD"→drive); (5) `other`. Names come from the member
`Name`; the known-ID switch stays as the fallback for a member whose document could not be
read; the last fallback is "Unnamed component (ID <id>)" (UX-10 wording). A file-only map
`firmware.names: {"<component id>": "<name>"}` lets an admin name what no document names.
Nothing here is Dell-specific beyond the FQDD/ID tables, which live in `dellredfish`.

### 5.5 Release date and age

`ReleaseDate` (iDRAC9, generic Redfish when present) → "Released <year-month> (<age> ago)".
iDRAC8 reports none → the column reads "Not reported" and is hidden when empty for every
row of the page (UX-19 rule). The age is **information, not a flag**: old firmware on
end-of-life hardware is normal. A file-only `firmware.stale_after: 3y` (0 = off, default
off) turns it into the `Stale release` info flag for owners who want it.

### 5.6 Minimum known good (config, no internet)

```yaml
firmware:
  stale_after: 0            # e.g. 3y; 0 = never flag by age
  names: {}                 # component id → display name (iDRAC8 members without a document)
  minimum:
    - { bmc_kind: idrac8, kind: bmc,  version: "2.86.86.86" }
    - { bmc_kind: idrac9, kind: bmc,  version: "7.00.00.182" }
    - { bmc_kind: idrac9, kind: bios, model: "PowerEdge R440", version: "2.20.0" }
    - { component_id: "105897", version: "23.31.1", note: "BCM5720 fix for …" }
```

Match keys (all optional, all must match when present): `bmc_kind`, `kind`, `model`
(system model, exact), `component_id`, `fqdd` (glob `*` allowed at the end). Validation at
load: closed enums, version non-empty, ≤ 200 rules. Comparison: `firmware.CompareVersions`
splits on `.`, compares numeric segments numerically and non-numeric segments as strings,
pads the shorter with zero segments; a mixed pair (numeric vs alphanumeric in the same
position, e.g. `RS03` vs `2.5`) returns **incomparable** → flag `Cannot compare`, never
"below". The fixture versions (`2.86.86.86`, `7.00.00.182`, `25.5.9.0001`, `00.24.7A`,
`4239A37`, `E013`, `RS03`, `23.31.1`) are the table test. The flag is `Below minimum` when
running < minimum, `OK` when ≥, `No rule` (quiet, not shown) when nothing matches.
Later, the same rule list could be editable in Settings (lock badge, step-up); file-only in
this slice keeps the surface small.

### 5.7 Poll tier and Re-scan

- New **firmware tier**: every `FirmwareEvery` = 24 h (the inventory tier keeps the cheap
  collection read every 6 h for the version list; the member-document pass runs on the
  24 h tier or when new IDs appear), its own cycle budget, retried after 5 min on failure
  like the other slow tiers, never trips the breaker, skipped while the BMC is restarting
  (plan 01) and run right after it returns (firmware may have changed).
- `fleet.Fleet.Refresh(id, tier)` marks a tier due now (the poller reads the request on its
  next loop; a 10 s wake-up timer bounds the wait). UI: `POST /servers/{id}/firmware/rescan`
  — operator (`server.firmware.rescan`, no step-up: read-only), CSRF, the `probe()` 6/min
  limit, audited `server.firmware.rescan` (ok). The page then shows "Scanning…" until
  `last_seen` moves.

### 5.8 Change detection

On every scan the upsert compares running/previous/staged with the stored row; a change
writes a `firmware_changes` row and an audit row `server.firmware.changed` (principal
`system`, params `component`, `field`, `before`, `after`). Unexpected firmware changes are
a compromise indicator; the audit row reaches GELF and the audit tap. Notification: **not in
this slice** (see §10).

## 6. Authorization

- `server.firmware.view` (viewer; token-readable) for `/firmware`, the Inventory section and
  the API; `server.firmware.export` (viewer; token-readable); `server.firmware.rescan`
  (operator, sessions only, no step-up). Rows in `TestMatrixCoversEveryAction`.
- Disclosure: firmware versions describe the vulnerability posture of the BMCs. The pages
  need a session, the API a token, exactly like inventory today; `/metrics` keeps hiding
  versions unless `metrics.include_inventory` (unchanged).

## 7. CSV export and API

- `GET /firmware.csv?<same filters>` (UI) and `GET /api/v1/firmware.csv` (token), via the
  `internal/csvx` helper of plan 02 (RFC 4180, injection guard, streaming, 6/min). Columns:
  `server_id,server_name,bmc_kind,kind,component,component_id,fqdd,running,previous,staged,
  lc_installed,release_date,updateable,flag,minimum_version,identity,last_seen_utc`.
  Filename `firmware_<scope>_<yyyymmddThhmmZ>.csv` (`scope` = `fleet` or the server id).
- JSON: `GET /api/v1/firmware` → `{data:[rows], meta:{total, flagged, scanned_servers,
  generated}}`; `GET /api/v1/servers/{id}/firmware` → the server's rows plus
  `{last_scan, next_scan, changes:[last 20]}`. Problem Details on errors.

## 8. Metrics (additive)

`oob_firmware_components{server}` gauge, `oob_firmware_flagged{server,flag}` gauge,
`oob_firmware_last_scan_timestamp_seconds{server}`, `oob_firmware_changes_total{server}`
counter (since start). Versions themselves stay behind `include_inventory` (existing
`oob_server_info` gains `bmc_firmware` and `bios_version` labels there — it already carries
identity labels in that mode).

## 9. Offline catalog: interface only

```go
// internal/firmware/catalog
type Key struct{ VendorID, DeviceID, SubVendorID, SubDeviceID, ComponentID, SystemID string }
type Release struct{ Version string; Date time.Time; Severity string; Note string }
type Catalog interface {
    Lookup(ctx context.Context, k Key) (Release, bool, error)
    Info(ctx context.Context) (Info, error)   // name, imported at, entry count; zero when none
}
```

`nullCatalog` ships now (`Info` says "no catalog"). The flag `Newer available` and the
page's "Catalog: none imported" line are wired against the interface so the later CLI
import (`oob-manager catalog import <file>`: gzip cap 64 MiB, streaming `encoding/xml`,
no DTD, table `firmware_catalog`, never fetched online, signature check as an open item)
needs no UI or schema change beyond its own table. `Key` is filled from
`DellSoftwareInventory.IdentityInfoValue` and the system SKU/model on iDRAC9; iDRAC8 gives
only `ComponentID`, which the catalog can still match. **No update is ever pushed**; the
interface returns versions, not images or URLs.

## 10. Notifications

None in this slice. `server.firmware.changed` is an audit row; if the bmc-security panel
branch introduces a posture/finding notification class, firmware changes and "below
minimum" join it there; otherwise a follow-up maps the audit row to an info event on a
class the maintainer picks (question §17).

## 11. Failure modes and safety

- A member document that fails to decode or is absent leaves the row with its ID-derived
  version and the fallback name; the scan is not an error.
- A BMC with 100+ members: the collection is capped at 64 members (existing), the page
  says "64 of N components shown".
- Hostile names/versions: `html/template`, the CSV guard, label sanitising in metrics;
  version strings are ≤ 64 bytes, names ≤ 128 (truncated on a rune boundary).
- The tier never writes to a BMC (test on the mock request log).
- Rule 11: there is no code path that references `SimpleUpdate` or any update action; a
  lint-style test greps the firmware packages for those identifiers.

## 12. Test plan

- **Unit, `firmware`**: `CompareVersions` table (fixture versions, padding, incomparable),
  rule matching (every key, globbed FQDD, ≤ 200 rules, validation errors), kind
  classification table (FQDD prefixes, IDs, ComponentType, name keywords, generic
  `RelatedItem`), state merge (Current/Installed/Previous/Available combinations incl. the
  101434 mismatch), release age formatting, change detection.
- **Unit, `dellredfish`/`redfish`**: member document decoding against the three captured
  member fixtures per BMC plus SYNTHETIC overlays (an `Available-` member, a member without
  `Name`, a missing member → 404 tolerated), only-GET assertion, 64 cap, "unknown IDs only"
  fetch logic (second scan issues zero member GETs).
- **Store**: upsert/compare/changes rows, prune, registry sync deletion.
- **Fleet**: firmware tier cadence with the fake clock, `Refresh` wakes the poller within
  10 s, retry after failure, skip while restarting.
- **UI**: `/firmware` sorting and filters (closed values), stacked rows, flags, legend,
  hidden empty columns, Inventory restructure, Re-scan (operator; viewer 403 audited; 6/min),
  CSV headers; `copy_test`/`security_test`.
- **API**: fleet and per-server JSON, CSV, token limits, 404.
- **e2e (Go)**: both mocks scanned at startup; names appear from the member documents
  (fixtures: "Backplane 0", the BCM5720 NIC), the iDRAC8 mismatch row is flagged, a config
  `minimum` rule flags the iDRAC8 BIOS 2.19.0 against "2.20.0", an overlay changing a
  version plus Re-scan produces a `firmware_changes` row and the audit row, CSV parses with
  the expected columns, zero non-GET requests.
- **Playwright + axe**: `/firmware` and the Inventory page at 1440/390 in both schemes;
  `pages.spec.ts` entries.
- **Hardware (by the maintainer, read-only)**: capture one full set of member documents from
  each BMC with the read-only account (sanitised: MACs → `00:00:5E:00:53:xx`, serials out)
  to replace the SYNTHETIC overlays; confirm the Current/Installed semantics on the iDRAC8
  by comparing with its web UI.

## 13. Docs to update

tech_doc (new §: tiers, schema, state semantics, config), deploy/README ("Firmware view":
the `firmware:` block with examples, the CSV columns, the catalog interface note), Help
(glossary: FQDD, Lifecycle Controller inventory, rollback image, staged), security.md
(**I13** disclosure of firmware posture via pages/API/CSV; the catalog import threat row is
written when the import exists), API docs, metrics list, `docs/hardware.md` cells (names
verified per BMC).

## 14. Effort

| Part | Days |
|---|---|
| Member documents, kinds, names, state merge, compare, rules (with fixtures) | 1.0 |
| Schema, tier, Refresh, change detection, registry sync | 0.5 |
| `/firmware` page, Inventory restructure, Re-scan, CSV, API, metrics | 1.0 |
| Catalog interface + null implementation | 0.25 |
| e2e, Playwright, docs | 0.5 |
| **Total** | **3.25** |

## 15. Risks

- The Dell state semantics may be the other way round (`Installed` running, `Current`
  staged). The merge rule is one function with a table test; the hardware check decides.
  **It was** (confirmed 2026-10-29, fixed in v0.8.1; see the correction in §5.3).
- Per-member GETs on iDRAC8 are slow (≈ 21 × 2 s). They run once per unknown ID on a 24 h
  tier within the 150 s budget; a slow BMC just finishes naming on a later pass.
- Version comparison across vendors is heuristic; the plan refuses to call anything "below
  minimum" when it cannot compare.

## 16. Inputs needed

- The first `firmware.minimum` list (or "none, just names and the matrix").
- Approval for a read-only fixture capture session on both BMCs.

## 17. Open questions

1. Should "below minimum" and "mismatch" rows appear in Overview › Needs attention (they
   are posture, not health)? The plan keeps them off Overview and on the Firmware page
   with a sidebar count.
2. Notification for `server.firmware.changed`: wait for the security panel's class, or map
   it to `trust` now?
3. Keep `firmware.minimum` file-only, or plan a Settings editor (step-up, lock badge) in
   the same slice (+0.5 d)?
4. Age flag default: off (plan) or 3 years?

## 18. Decisions

1. **Overview:** "below minimum" and "mismatch" rows stay off Overview › Needs attention. They are on
   the Firmware page, and the sidebar entry counts them (the plan's default).
2. **Notification:** `server.firmware.changed` maps to the existing `security` class (it shipped with
   the BMC security checks). Implementation note: the events are warnings (the default "warning and
   above" subscription receives them; the security class is sent at normal priority and never pages);
   a change of the rollback copy alone raises nothing.
3. **`firmware.minimum`** stays file-only (config.yaml; a lock badge where it is shown); no Settings
   editor in this slice. It is reconciled with `security.min_firmware`: the BMC's own firmware is
   judged only against `security.min_firmware.<kind>` (one source of truth, shared with the `fw.bmc`
   security check, and one comparison: `bmcsec.CompareVersions` delegates to
   `firmware.CompareVersions`); a `firmware.minimum` rule of kind `bmc` is refused at load, and rules
   never apply to rows of kind `bmc`.
4. **Age flag:** off by default (`firmware.stale_after: 0`).

The read-only capture of every firmware member document per BMC (sanitised) is the maintainer's step
later; until then the tests use SYNTHETIC member documents written from the documented shapes
(`testdata/redfish/synthetic-firmware/`), and deploy/README describes the capture procedure.
