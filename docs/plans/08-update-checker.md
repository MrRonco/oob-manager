# Plan 08 — Firmware update checker (vendor catalog, read-only)

Status: plan, 2026-10-29; **decisions in §21**. v0.8.1 merged (main @ 0ea60b3,
migration 0016); implementation in slices U1–U3 (§18). A request the same day: "is there a way we can introduce an
update checker into this app?". Answer: yes, ahead of redesign slice D. Builds on plan 03 (firmware
view; tech_doc §38), its `internal/firmware/catalog` interface (§9 there) and **v0.8.1** (branch
`fix-firmware-states`). v0.8.1 corrected the Dell state semantics: `Installed-` is what runs, and
`Current-` is an image stored on the BMC that may not be installed. This plan uses v0.8.1's names: the
renamed `lc_installed` field/column, now **`stored`** (`firmware.Component.Stored`), and its
`not_applied` flag ("Not applied", info).

**Rule 11 still holds.** This plan reads a vendor's list of releases and compares versions. It never
downloads a firmware image, never stages, schedules or applies anything, and never sends a request
to a BMC for this feature.

## 1. Goal and non-goals

**Goal.** For every firmware component the firmware view already knows, show the newest version the
vendor publishes for that server model, its release date and its criticality ("Urgent",
"Recommended", "Optional"). Flag components that are behind. Say plainly when the vendor no longer
lists the model at all (end of support). Notify on new urgent updates. Get the data either from the
vendor's signed online catalog (opt-in, weekly) or from a catalog file the admin supplies (air-gapped
sites, private mirrors, older catalogs for end-of-life systems).

**Non-goals.**
- Updating firmware in any way: no `InstallFromRepository`, no `SimpleUpdate`, and no fetching of
  update packages (the `path` attribute is shown as a link for a human).
- iDRAC's own "check for updates" (it needs BMC internet egress and a write-capable account, and
  its action names are on the rule-11 deny list).
- Vendors other than Dell (only the interface, §11).
- Drivers and OS packages (`SupportedOperatingSystems` entries are ignored).
- Warranty.
- Dell security advisories (DSA/CVE) mapping (a later item, §19).

## 2. User stories

| Role | Story |
|---|---|
| viewer | On Firmware I see "BIOS 2.20.0 → **2.25.2** · Recommended", and "iDRAC 7.00.00.182 → 7.00.00.185 · **Urgent**", with a link to the vendor's details page. |
| viewer | On an end-of-life server I read "The vendor catalog no longer lists this model (newest entry 2016); updates can't be checked", not a wall of "no update". |
| operator | I press **Check now** after the vendor publishes a fix and the page updates within a minute. |
| admin | I turn the online check on or off, upload a catalog + signature on an air-gapped install, and skip one specific version for one component (with a comment) so it stops flagging until a newer one appears. |
| admin | An urgent update appearing for any server reaches my notification target once, not every week. |
| integrator | `GET /api/v1/firmware` rows carry `latest` and `update` fields; the CSV has matching columns. |

## 3. What this plan changes from earlier decisions

| Earlier text | Change | Why it is still within the rules |
|---|---|---|
| plan 03 §1 non-goal "contacting any vendor site (NFR-6)"; §9 "never fetched online"; the `catalog` package doc comment | An **opt-in** online fetch of one public file, off by default, switched on by an admin in Settings (decision 1, §21) | NFR-6 is "works with no internet access": everything still works offline (upload/CLI import, or the feature off). No CDN or asset dependency is added. |
| plan 03 §9 `Catalog.Lookup` returns one `Release` | Returns a `Match` (latest release + how it was matched + candidate count), §8 | The interface had no implementation yet; the null catalog changes with it |
| plan 03 §9 "signature check as an open item" | Mandatory detached-signature check against a pinned key, §5 | Verified feasible with an existing dependency |

## 4. Source: Dell enterprise catalog (verified 2026-10-29)

| Fact | Value | How verified |
|---|---|---|
| URL | `https://downloads.dell.com/catalog/Catalog.xml.gz` (also served as `Catalog.gz`) | HTTP 200, `content-type: application/x-gzip`, **no redirect** |
| Size | 1,506,587 bytes gzip → 22,194,078 bytes XML | downloaded |
| Encoding | **UTF-16 LE** with BOM; prolog `<?xml version="1.0" encoding="utf-16"?>` | `file`, first bytes |
| Conditional GET | `ETag` and `Last-Modified` present (`Thu, 22 Oct 2026 13:00:59 GMT`) | response headers |
| Signature | `Catalog.xml.gz.sign`, 194 bytes, ASCII-armored detached OpenPGP **v3** signature over the **.gz bytes**, DSA (algo 17), SHA-1 (digest algo 2), issuer key ID `CA77951D23B66A9D`, created 2026-10-22 08:04 UTC | `gpg --list-packets`; `gpg --verify` → "Good signature" |
| Signing key | `dsa1024` created 2001-04-16, fingerprint `4172 E2CE 955A 1776 A5E6 1BB7 CA77 951D 23B6 6A9D`, uids "Dell, Inc. (Product Group) <linux-security@dell.com>" and "Dell Computer Corporation (Linux Systems Group)" | identical key from `https://linux.dell.com/files/pgp_pubkeys/0xca77951d23b66a9d.asc` (Dell-operated) and from public keyservers |
| Go verification | `golang.org/x/crypto/openpgp` `CheckArmoredDetachedSignature` (module already a direct dependency, v0.57.0) verifies it and rejects a one-bit change ("hash tag doesn't match") | spike program, real files |
| Manifest | `<Manifest baseLocation="downloads.dell.com" dateTime="2026-10-22T14:39:35+05:30" version="26.10.22" releaseID="XFW33" identifier=… predecessorID=… baseLocationAccessProtocols="HTTPS">` | parsed |
| Content | 1,008 `SoftwareComponent`, 116 `SoftwareBundle`, 2 `InventoryComponent` | parsed |
| `SoftwareComponent` attributes (all 1,008) | `vendorVersion`, `dellVersion`, `releaseDate` ("September 24, 2026"), `dateTime` (RFC 3339), `path`, `packageType` (e.g. `LW64`), `releaseID`, `packageID`, `hash` + `hashAlgorithm` (SHA256), `hashMD5`, `size`, `rebootRequired`, `identifier`, `schemaVersion` | parsed |
| Children | `Name/Display`, `ComponentType@value` (BIOS, FRMW, …), `Criticality@value` with `Display`: **1 Recommended, 2 Urgent, 3 Optional**, `ImportantInfo@URL` (a `www.dell.com/support/...driverId=…` page), `SupportedDevices/Device@componentID` (+ optional `PCIInfo@vendorID/deviceID/subVendorID/subDeviceID`), `SupportedSystems/Brand/Model@systemID` + `Display` | parsed |
| Coverage of the two tested servers | iDRAC9 server (systemID `088F`): **207** components, newest 2026; iDRAC8 server (systemID `0627`): **1** component (iDRAC 2.40.40.40, 2016), older than what it runs | parsed |
| Ambiguity | for systemID `088F`, 703 component IDs, **73** of them with more than one version (older packages kept, or per-PCI-variant packages); every Device has a `componentID` | parsed |
| What it would flag today on the iDRAC9 server | BIOS 2.20.0 → 2.25.2 (Recommended); iDRAC 7.00.00.182 → 7.00.00.185 (Urgent) | parsed against the live inventory |

**Assumed, not verified:** how often Dell republishes (the manifest has a `predecessorID` chain, but
the cadence is unknown, so a weekly check is a guess that is cheap to be wrong about); that Dell will
keep this key (§5.3); that `Catalog.xml.gz` is the right catalog for every Dell server generation
(Dell also publishes per-platform catalogs through Repository Manager, which the upload path covers).

## 5. Signature verification

### 5.1 Order of operations (fail closed)

1. Download the `.gz` to a temp file under the data directory and the `.sign` into memory. Both
   are bounded (§6.3).
2. Verify the signature over the **compressed bytes** with a keyring that holds only the pinned
   key(s) (§5.2). Before calling the library:
   - the armor is at most 4 KiB;
   - it contains exactly one signature packet;
   - its issuer key ID is one of the pinned keys;
   - the hash is SHA-1 or SHA-2 (SHA-1 is accepted only for a key flagged `legacy` in the pin table).
3. Only after success: decompress and parse. On any failure the previous good catalog stays
   active. The check is recorded as failed with a closed class (`signature`, `untrusted_key`,
   `download`, `size`, `parse`, `not_modified` is not a failure), and the status line says so.
4. On success, atomically replace the cached files with the newly verified ones
   (`<data>/catalog/dell/Catalog.xml.gz` and `.sign`, mode 0600). Re-parsing later never needs
   the network again (§7.3).

### 5.2 Trusted keys

- Dell's public key is embedded in the binary (`internal/firmware/catalog/dell/dell-ca77951d.asc`)
  with its full fingerprint as a constant. A test fails if the embedded key's fingerprint differs.
  It is a public key, fine for the public repo, and its source is noted in tech_doc.
- File-only `firmware.catalog.extra_keys_file` (a path to armored public keys) adds keys. It serves
  three cases: key rotation by Dell before a release ships, catalogs re-signed for a private mirror,
  and the e2e test key. It cannot be changed from the browser: a browser-editable trust root would
  let a stolen admin session make any catalog "verified".
- `firmware.catalog.allow_unsigned: false` (file-only) controls whether an unsigned **upload** is
  accepted, for Dell Repository Manager custom catalogs, which are unsigned (decision 3: refused unless the switch is set).
  When it is true, an unsigned import is labelled "Unsigned catalog (accepted by configuration)"
  wherever its data is shown. The online fetch never accepts an unsigned catalog.

### 5.3 Crypto strength and library choice

- **DSA-1024 with SHA-1 is weak by today's standards.** The signature is defence in depth. The
  primary trust is TLS to a fixed public host (§6.1). A forgery would need a SHA-1 second preimage
  against Dell's signed file, or breaking DSA-1024. SHA-1 chosen-prefix collisions don't apply,
  because Dell would have to sign attacker-chosen content. The threat row records this (§16).
- **Library:** `golang.org/x/crypto/openpgp`. It is already in the module graph, so no new module.
  It is **deprecated** ("unsafe by design" refers mainly to its encryption and key-handling APIs).
  Only `ReadArmoredKeyRing` and `CheckArmoredDetachedSignature` are used, behind a ~60-line wrapper
  with the pre-checks above, in one file, with a `//nolint:staticcheck // SA1019: …` and a
  tech_doc §2 row. Alternatives considered:
  - `github.com/ProtonMail/go-crypto`, the maintained fork: a new dependency, and whether it still
    verifies v3 DSA/SHA-1 signatures is **not verified**.
  - A stdlib-only verifier on deprecated `crypto/dsa`: about 150 lines of hand-written packet
    parsing, which is more risk than the library.
  decision 2: `x/crypto/openpgp`, wrapped in one file. **Changed at U1 merge (2026-10-29):** govulncheck
  flags the whole `x/crypto/openpgp` tree as GO-2026-5932 (no fix), which fails the CI gate, so the
  stdlib-only verifier was built instead (three small files, verification only, tech_doc §2 and §42).

## 6. Fetching

### 6.1 Egress policy

- **URL:** file-only `firmware.catalog.url`, default the Dell URL. The `.sign` URL is the same URL
  plus `.sign`. Only `https` is accepted. It is not editable in the browser, because a
  browser-editable outbound URL is an SSRF primitive.
- **Transport:** the same policy as the notification transport (`notify.Policy`/`Transport`,
  tech_doc §26). It is extracted to a shared `internal/egress` package so both use one
  implementation:
  - the host is resolved once, and every answer must be public unicast unless it is inside
    `firmware.catalog.allowed_networks` (for a LAN mirror);
  - the connection goes to the checked IP;
  - TLS 1.2 or later with system roots;
  - no proxy;
  - **no redirects**: a 3xx is a `download` failure that names the redirect and tells the admin to
    set the final URL;
  - no cookies, no keep-alive, bounded headers.
- **HTTP proxy support** (common on locked-down networks) is a later item: a file-only
  `firmware.catalog.proxy`, not in this plan.
- **Request:** `User-Agent: oob-manager/<version>`, `If-None-Match` / `If-Modified-Since` from the
  last good fetch. A 304 is recorded as `not_modified` and nothing is parsed. The whole catalog is
  downloaded, so **the request reveals nothing about the fleet** (no model or component in the URL
  or headers).

### 6.2 Schedule

- `firmware.catalog.enabled`: default **false**. **Runtime-managed** (decision 1): DB-backed in
  `settings_kv`, shown in Settings › General. A `firmware.catalog.enabled` key in config.yaml wins
  and shows the lock badge ("Managed by config.yaml"). The settings precedence is
  config.yaml > database > default. Changing it from the browser needs **admin + a fresh step-up**
  (stricter than the other General keys, because it opens outbound traffic). Every change is
  audited (`settings.general.changed` with before/after, plus `firmware.catalog.enabled_changed`
  carrying the principal). Turning it on queues a first check within 2 minutes; turning it off
  stops scheduling but keeps the last imported catalog and its flags, labelled "check off, data
  from <date>".
- What the toggle enables is fixed by the file: the URL, the extra trusted keys, the allowed
  networks and `allow_unsigned` stay **config.yaml-only**. So a browser session can at most turn on
  traffic to the configured, signature-checked source, never point it elsewhere.
- `firmware.catalog.check_every`: default **7 days**, range 1–30 days, runtime-managed (General
  section).
- The first check runs 2–10 minutes after start, with jitter so a fleet of installs doesn't hit Dell
  at once.
- A failure retries after 1 h, then 6 h, then the normal interval.
- **Check now** (§10) queues an immediate check. There is one global limiter: one check per
  5 minutes, whoever asks.
- The worker is one goroutine owned by the firmware service. It never touches the poller or a BMC.

### 6.3 Bounds (untrusted input)

| Bound | Value | On breach |
|---|---|---|
| `.gz` download size | 16 MiB (the real file is 1.5 MiB) | `size`, temp file deleted |
| `.sign` size | 4 KiB | `signature` |
| Download time | 120 s total, 10 s connect/TLS, 30 s without a byte | `download` |
| Decompressed size | 128 MiB (the real file is 22 MiB) via `io.LimitReader` on the gzip stream, single gzip member only | `size` |
| XML | Strict decoder, **no DTD/entities** (`Directive` token → error), depth ≤ 16, attribute ≤ 4 KiB, text ≤ 64 KiB, ≤ 20,000 `SoftwareComponent`, ≤ 256 devices and ≤ 512 models per component | `parse` |
| Parse time | 60 s | `parse` |
| Memory | streaming `xml.Decoder.Token` + `DecodeElement` per `SoftwareComponent`; only the fleet's systems are kept (§7.3) | target < 32 MiB peak under the container's `GOMEMLIMIT`; a test measures it |

## 7. Parsing

### 7.1 UTF-16

There is no `golang.org/x/text` in the module graph, so it isn't added. Instead, a small
`utf16Reader` (stdlib `unicode/utf16` + `unicode/utf8`) transcodes UTF-16 LE/BE to UTF-8 by BOM,
handles surrogate pairs, and turns an unpaired surrogate into an error (not U+FFFD, since a catalog
that isn't well-formed is refused). The decoder's `CharsetReader` accepts only `utf-16`/`utf-8`
labels after transcoding (the identity). A catalog without a BOM is parsed as UTF-8 when its prolog
says so. It is unit-tested and fuzzed (§17).

### 7.2 What is read

The `Manifest` attributes (`version`, `releaseID`, `dateTime`, `identifier`, `baseLocation`).
Per `SoftwareComponent`:
- `vendorVersion`, `dateTime` (fallback `releaseDate`), `path`, `packageType`, `rebootRequired`,
  `releaseID`;
- `Name/Display` (lang `en`), `ComponentType@value`, `Criticality@value`, `ImportantInfo@URL`;
- each `Device@componentID` with its `PCIInfo` tuples;
- each `Model@systemID` + `Display` under `Brand`.

`SoftwareBundle`, `InventoryComponent`, `Prerequisites`, `RevisionHistory`, `FMPWrappers` and OS
lists are skipped token-wise. Every kept string goes through `textclean.Clean` with a length cap
(names 160, versions 64, paths 512, URLs 512).

### 7.3 What is stored

Only rows for **system IDs present in the fleet** (§8.1), replaced in one transaction per import.
On a registry change (server added or model changed), the cached, already-verified `.gz` is
re-parsed locally, with no network. For the two tested servers that is about 1,400 rows (207
components × devices) rather than tens of thousands.

## 8. Matching

### 8.1 The server's system key

- **iDRAC9:** `Systems/System.Embedded.1` `Oem.Dell.DellSystem.SystemID` (integer, e.g. 2191) →
  hex, upper case, 4 digits (`088F`). This is in the captured fixture, and both `Chassis` and
  `Systems` carry it. The inventory tier gains a `SystemID` field in `bmc.Inventory`, and
  `firmware_scans` gains `system_id`.
- **iDRAC8 (fw 2.86):** the Redfish system document has **no Oem block** (fixture). Fallback is the
  `Model` ("PowerEdge R730xd") matched against the catalog's `Brand/Display` + `Model/Display`
  ("PowerEdge" + "R730XD"), case-insensitive, whitespace-normalised. It must match exactly one
  `systemID` in the catalog, or there is no match. Rows matched this way say "matched by model
  name".
- **Override:** file-only `firmware.catalog.systems: {<server id>: "<systemID>"}` for anything the
  first two get wrong.
- **Generic Redfish** (`kind: redfish`): no system key, so the server shows "No vendor catalog for
  this BMC type".

### 8.2 Component match

1. Candidates are catalog devices with `componentID == component.ComponentID` and the server's
   `systemID` in the component's supported systems.
2. **PCI narrowing** applies when the row has a 6-part Dell identity (iDRAC9
   `IdentityInfoValue`, already stored in `identity`, parsed by `catalog.KeyFromIdentity`) and some
   candidates carry `PCIInfo`. Candidates whose PCI tuple matches are kept. If none matches, the
   PCI-less candidates are kept. iDRAC8 rows have no identity, so no narrowing, and the row says
   "N packages; chosen by version" when N > 1. Fuller PCI-only matching (devices without a
   component ID) is a **later item**: every device in today's catalog has one.
3. **Latest** is the maximum of the candidates under `firmware.CompareVersions`. Candidates that
   can't be compared with the others are dropped from the maximum. If nothing is comparable, the
   flag is `cannot_compare`.
4. **Verdict** of the running version against latest:
   - `running < latest` → **update available**, criticality from latest;
   - `running ≥ latest` → up to date (quiet);
   - incomparable → `cannot_compare` (info);
   - no candidates → **not in catalog** (quiet per row, summarised per server, §8.3).
5. If v0.8.1's `stored` (the image on the BMC) equals latest, the row says "2.25.2 is already
   stored on the BMC, not installed" instead of only "update available".

### 8.3 Server-level coverage

| Situation | Server line |
|---|---|
| system key unknown | "Model not identified; set `firmware.catalog.systems`" (admin hint) |
| 0 catalog components for the system | "The vendor catalog doesn't list this model. Updates can't be checked (end of support or a model the catalog omits)." |
| components exist but none newer than 5 years and none matched | "Only legacy entries (newest 2016). Likely end of support." |
| normal | "N of M components matched · K updates (U urgent)" |

## 9. Data model and migration

Migration **`0017_firmware_catalog.sql`** (v0.8.1 took 0016). It also
rebuilds the **`settings_kv` CHECK list** for the new runtime keys (`firmware.catalog.enabled`,
`.check_every`, `.notify`), re-listing every existing key. `TestSettingsKVAcceptsEveryKnownKey`
covers it.

```sql
-- One row per import attempt that produced a catalog (online or upload), newest kept active.
CREATE TABLE catalog_imports (
    id            INTEGER PRIMARY KEY,
    source        TEXT    NOT NULL CHECK (source IN ('dell')),
    origin        TEXT    NOT NULL CHECK (origin IN ('online','upload','cli')),
    version       TEXT    NOT NULL CHECK (length(version) <= 64),     -- Manifest@version
    release_id    TEXT    NOT NULL DEFAULT '' CHECK (length(release_id) <= 64),
    published_at  INTEGER,                                            -- Manifest@dateTime, unix ms
    imported_at   INTEGER NOT NULL,
    sha256        TEXT    NOT NULL CHECK (length(sha256) = 64),       -- of the .gz
    signer        TEXT    NOT NULL DEFAULT '' CHECK (length(signer) <= 64), -- fingerprint, '' = unsigned
    etag          TEXT    NOT NULL DEFAULT '' CHECK (length(etag) <= 256),
    last_modified TEXT    NOT NULL DEFAULT '' CHECK (length(last_modified) <= 64),
    components    INTEGER NOT NULL CHECK (components >= 0),           -- in the whole catalog
    kept          INTEGER NOT NULL CHECK (kept >= 0),                 -- rows kept for the fleet
    imported_by   TEXT    NOT NULL DEFAULT 'system'
) STRICT;

-- Every check, including 304s and failures (pruned to 90 days / 500 rows).
CREATE TABLE catalog_checks (
    id INTEGER PRIMARY KEY, source TEXT NOT NULL, at INTEGER NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('imported','not_modified','download','size',
                                           'signature','untrusted_key','parse','disabled')),
    detail TEXT NOT NULL DEFAULT '' CHECK (length(detail) <= 256), import_id INTEGER
) STRICT;

-- The active import's releases for the fleet's systems (replaced per import).
CREATE TABLE catalog_releases (
    import_id INTEGER NOT NULL, system_id TEXT NOT NULL, component_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL DEFAULT '', device_id TEXT NOT NULL DEFAULT '',
    sub_vendor_id TEXT NOT NULL DEFAULT '', sub_device_id TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL, released_at INTEGER, criticality INTEGER NOT NULL CHECK (criticality IN (1,2,3)),
    name TEXT NOT NULL, package_path TEXT NOT NULL DEFAULT '', details_url TEXT NOT NULL DEFAULT '',
    reboot_required INTEGER NOT NULL DEFAULT 0 CHECK (reboot_required IN (0,1))
) STRICT;
CREATE INDEX catalog_releases_key ON catalog_releases (system_id, component_id);

-- "Skip this version": one component, one latest version; a newer version reopens it.
CREATE TABLE firmware_update_skips (
    server_id TEXT NOT NULL, component_id TEXT NOT NULL, fqdd TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL, comment TEXT NOT NULL CHECK (length(comment) BETWEEN 1 AND 500),
    skipped_by TEXT NOT NULL, skipped_at INTEGER NOT NULL,
    PRIMARY KEY (server_id, component_id, fqdd)
) STRICT;

-- Which (server, component, version) updates were already notified (once each).
CREATE TABLE firmware_update_notified (
    server_id TEXT NOT NULL, component_id TEXT NOT NULL, fqdd TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL, notified_at INTEGER NOT NULL,
    PRIMARY KEY (server_id, component_id, fqdd, version)
) STRICT;

ALTER TABLE firmware_scans ADD COLUMN system_id TEXT NOT NULL DEFAULT '' CHECK (length(system_id) <= 16);
```

- `catalog_imports` keeps the last 20 rows.
- Registry sync deletes a removed server's skip and notified rows (like `firmware_components`).
- The cached files sit next to the database (`<data>/catalog/`), so a backup of the data volume
  includes them. They are public data.
- The verdict is **computed at read time** from `firmware_components` and `catalog_releases`, not
  stored per row. A new scan or a new import changes the page with no backfill.

## 10. UX placement (direction B, after slice C)

- **Firmware page:**
  - A new **Latest** column after Running: "2.25.2 · Recommended · <release month>". The vendor link opens
    the `ImportantInfo` page in a new tab with `rel="noopener noreferrer"`. A link is drawn only for
    `https` with host `dell.com` or `*.dell.com`; anything else is text.
  - New flags, worst-first order extended: **Urgent update** (warn; counted in the sidebar badge)
    and **Update available** (info). Both are compared with `below_minimum`, `not_applied` and the
    others in one rank table.
  - Filter: "Updates only".
  - Page meta line: "Dell catalog 26.10.22 (published 2026-10-22) · checked 3 h ago · **Check now**"
    (operator+). Other states: "Update check is off (Settings › General)", "Last check failed:
    signature (previous catalog 26.09.30 in use)", "Unsigned catalog (accepted by configuration)".
- **Server › Inventory › Firmware section:** the same column and flags, plus the server coverage
  line (§8.3).
- **Row actions** (admin): **Skip this version…** opens a form for the comment (1–500 chars) and
  needs a fresh step-up, like a security-check acceptance. A skipped row shows "Skipped (2.25.2) by
  <user>: <comment>" and **Unskip**.
- **Settings › General:** "Firmware update check" (on/off, interval, notify level), each with the
  lock badge when set in config.yaml. Saving a change to **on/off** asks for a fresh step-up (the
  step-up stash keeps the form, v0.7.2). The help text names the destination host read from the
  file ("Checks https://downloads.dell.com weekly; nothing about your servers is sent"). File-only keys (URL, keys file, allowed networks, systems map,
  allow_unsigned) are shown read-only with their values.
- **Settings › General › Upload catalog** (admin + step-up): two file inputs (`.gz` up to 16 MiB,
  `.sign` up to 4 KiB). The same pipeline (§5–7) runs, and the result appears inline.
- **Overview:** nothing, in line with plan 03's answer 1. The sidebar badge already counts urgent
  rows.
- **Help/glossary:** "Vendor catalog", "Criticality", "End of support".

## 11. Pluggability: `UpdateSource`

```go
// internal/firmware/catalog
type SystemKey struct{ Source, SystemID, Model string; ByModel bool }

type UpdateSource interface {
    Name() string                                     // "dell" (closed set)
    DefaultURL() string
    // SystemKey maps the BMC's inventory to the source's system key (false: unknown).
    SystemKey(inv bmc.Inventory) (SystemKey, bool)
    // Verify checks the artifact's signature against the trusted keys.
    Verify(artifact io.ReaderAt, size int64, sig []byte, keys KeyRing) (Signer, error)
    // Parse streams the (verified) artifact and returns the releases for the wanted systems.
    Parse(ctx context.Context, r io.Reader, want []SystemKey, lim Limits) (Snapshot, error)
}

type Catalog interface {      // the plan-03 interface, extended (read side, store-backed)
    Lookup(ctx context.Context, k Key) (Match, error)   // Match{Latest Release; Candidates int; By string}
    Info(ctx context.Context) (Info, error)
}
```

- Fetching (§6) is source-independent. A source supplies only a URL, the verify step and the parse
  step.
- Dell is the only implementation. Supermicro, HPE and Lenovo publish no comparable public signed
  catalog, so they stay backlog items, and the public release notes say "Dell only".
- `SystemKey` lives in the source, so `dellredfish` doesn't import the catalog package. The
  dependency direction is catalog → bmc types only.

## 12. Authorization and audit

| Action | Role | Notes |
|---|---|---|
| view Latest/flags/status | viewer (`server.firmware.view`, token-readable) | no new action |
| `firmware.catalog.check` (Check now) | operator, session, CSRF | global 1/5 min; audited `firmware.catalog.check` |
| `firmware.catalog.upload` | admin, step-up, CSRF | 1/min/user; audited with sha256, version, signer |
| `server.firmware.skip_update` / `.unskip_update` | admin, fresh step-up (like `server.security.accept`) | 10/min/user; audited with component, version, comment |
| `firmware.catalog.enabled` (Settings toggle) | admin, **fresh step-up**, CSRF | General change limit; audited by the settings service + `firmware.catalog.enabled_changed`; refused with the lock message when config.yaml sets it |
| other firmware settings keys (`check_every`, `notify`) | admin (existing General rules) | audited by the settings service |

System audit rows: `firmware.catalog.imported` (principal `system`; version, sha256, signer,
kept) and `firmware.catalog.failed` (class only, never the response body). New rows go in
`TestMatrixCoversEveryAction`.

## 13. Notifications

- New class **`firmware`** ("New firmware updates"), subscribable, listed after `security`.
  decision 4: a new class, not `security`.
- **One message per import** that finds newly available updates (server, component, version
  triples not in `firmware_update_notified` and not skipped). It lists at most 16 lines and
  "and N more".
- Severity is **warning** if any triple is Urgent, else **info**. Every existing target's default
  subscription is "warning and above", so **by default only urgent updates notify**. An admin who
  wants all of them sets the target to info. No extra "urgent only" switch is needed, but
  `firmware.catalog.notify: urgent|all|off` (default `urgent`) caps what is ever sent for installs
  with info-level targets.
- A failed check notifies only after **3 consecutive failures** (class `firmware`, warning), and
  says so once until a success.
- Never pages: normal priority, like `security`.
- Maintenance mode suppresses it like other classes.

## 14. API, CSV, metrics

- `GET /api/v1/firmware`:
  - rows gain `latest` (`{version, released, criticality: "urgent"|"recommended"|"optional",
    name, details_url, package_path, reboot_required, candidates, matched_by}` or `null`);
  - rows gain `update` (`none|available|urgent|skipped|cannot_compare|not_in_catalog`);
  - `meta.catalog` = `{source, version, published, imported_at, checked_at, last_result,
    signed}`.
- `GET /api/v1/firmware/catalog`: status plus the last 20 checks (token, viewer).
- No API write endpoints: Check now, upload and skip are UI-only (sessions, step-up). This follows
  the precedent of other admin actions.
- CSV (`/firmware.csv`, `/api/v1/firmware.csv`) appends `latest_version, latest_released,
  latest_criticality, update, catalog_version`. The column order of existing fields is unchanged.
- Metrics (append-only, `metrics/specs.go`):
  - `oob_firmware_updates_available{server,criticality}` gauge;
  - `oob_firmware_catalog_published_timestamp_seconds{source}`;
  - `oob_firmware_catalog_last_check_timestamp_seconds{source,result}`;
  - `oob_firmware_catalog_check_failures_total{source,class}`.
  Versions appear only with `metrics.include_inventory`, unchanged.

## 15. Failure modes and safety

- Dell unreachable or down: last good catalog in use, the status says "checked … failed:
  download", and the next retry is per §6.2. The page never blanks.
- A catalog shrinks drastically (e.g. a partial or truncated upload that still verifies, which is
  unlikely): if the new import keeps fewer than 50 % of the previous `kept` rows for the same
  systems, it is **held**. The status says "new catalog lists far fewer components; still using the
  previous one", until an admin confirms from Settings (step-up). This guards against silent loss
  of urgent flags.
- Clock skew: release dates are informational. Nothing depends on the signature creation time
  except display.
- Hostile strings (names, URLs, versions): `html/template`, the CSV injection guard, the URL
  allowlist (§10), length caps and `textclean`.
- Never reaches a BMC: the worker has no fleet or BMC handle (constructor-level). A test asserts
  zero BMC requests in the mock log during a check.
- Never fetches a package: the HTTP client is constructed with the configured catalog URL only.
  A test asserts that `package_path` is never passed to any client (the fetcher API takes no URL
  argument). The rule-11 repo policy test (`firmwareUpdateWords`) still passes unchanged.

## 16. Threat model rows (security.md; next free S10, T14, I17, D12, R6, E5)

| ID | Threat | Controls |
|---|---|---|
| **T14** | Tampered or substituted catalog (network attacker, compromised or misconfigured mirror) hides an urgent update or invents one | HTTPS to a file-only URL with system roots, no redirects, detached signature over the `.gz` against pinned keys before parsing, fail closed with the last good catalog kept, the shrink hold (§15), signer and sha256 audited. Residual: DSA-1024/SHA-1 key strength (§5.3), accepted, with TLS as the primary control. |
| **I17** | Outbound request discloses the fleet | Whole-catalog download, no model or component in any request, opt-in, generic User-Agent |
| **D12** | Decompression or XML bomb, huge or slow response exhausts memory/CPU | §6.3 bounds, streaming parse, single worker, global limiter |
| **S10** | Admin-set URL used for SSRF into the LAN | URL file-only, https only, `internal/egress` policy (public unicast unless allowlisted; resolve once, dial the checked IP) |
| **E5** | Stolen admin session uploads a crafted catalog, or turns the online check on to create outbound traffic | upload: step-up, signature required unless `allow_unsigned` is set in the file, audit, parse bounds; worst case is wrong flags, never an action on a BMC. Toggle: fresh step-up, audit, config.yaml lock available. The destination, keys and allowed networks are file-only, so enabling reaches only the configured, signature-checked host |

## 17. Test plan

- **Unit, `catalog/dell`:**
  - `utf16Reader` (LE/BE BOM, surrogate pairs, unpaired surrogate error, odd byte count).
  - Parser against a **synthetic UTF-16 LE catalog** (`testdata/catalog/synthetic-dell.xml.gz`,
    about 40 components written from the shapes in §4: BIOS with 4 systems, an iDRAC entry, a NIC
    with two PCI variants of one component ID, drives with alphanumeric versions, an OS-driver
    entry to skip, a `SoftwareBundle` to skip).
  - Every bound in §6.3 as its own test (gzip bomb, multi-member gzip, depth, attribute, DOCTYPE
    with an entity, component count, time limit with a slow reader).
  - System key derivation (2191 → `088F`, model fallback, ambiguous model → no match, override).
- **Signature:**
  - a test key generated at test time signs the synthetic fixture (v4, SHA-256): valid, one bit
    flipped, wrong key, two signature packets, oversized armor, SHA-1 on a non-legacy key refused;
  - a **v3 DSA/SHA-1 signature built by a test helper** (`crypto/dsa` + manual v3 packet bytes,
    the format verified in §4) so the legacy path Dell uses is covered offline;
  - the embedded Dell key's fingerprint constant.
- **Opt-in live test** (`-tags dellnet`, never in the blocking CI): download the real catalog and
  signature, verify, parse, assert `088F` and `0627` exist. It also runs in the nightly job as
  non-blocking.
- **Fuzz:** `FuzzUTF16Reader`, `FuzzParseCatalog` (seeded with the synthetic fixture),
  `FuzzVerifyArmored`. These join plan 06 §3.5's fuzz set.
- **Fetch** (httptest TLS server + test root):
  - 200 → imported, 304 with ETag → `not_modified`;
  - 302 → `download` (not followed), 5xx → retry schedule (fake clock);
  - slow body → time cap, oversize `Content-Length` and oversize chunked → `size`;
  - `.sign` 404 → `signature`, private-address URL refused by policy;
  - last good catalog kept on every failure;
  - shrink hold.
- **Matching:** table over the synthetic catalog and v0.8.1-shaped components:
  - update available, up to date, running newer than the catalog (the iDRAC8 iDRAC case: catalog
    2.40.40.40 < running 2.86);
  - PCI narrowing, multiple packages, incomparable;
  - not in catalog, stored-equals-latest note, skipped then a newer version reopens.
- **Store:** migration dense/upgrade tests, `settings_kv` keys, prune, registry sync, the
  computed verdict, `firmware_scans.system_id`.
- **Notify:** one message per import, dedup across imports, severity mapping, `notify: off|all`,
  3-failure rule, maintenance suppression.
- **UI/API/CSV/metrics:**
  - columns, flags, filter, link allowlist, status line states;
  - Check now (operator ok, viewer 403 audited, limiter 429), upload (admin + step-up, size caps),
    skip/unskip (step-up);
  - the enable toggle: admin with a fresh step-up saves, a stale step-up is sent to the step-up
    page and returns with the form kept, operator 403 audited, config.yaml key → lock badge and a
    refused POST, both audit rows written, on → a check is queued, off → scheduling stops and
    data is kept and labelled;
  - `copy_test`/`security_test`, golden scrape.
- **e2e (Go):** the e2e harness serves a signed synthetic catalog over TLS. Config points
  `firmware.catalog.url` there, with `allowed_networks` and `extra_keys_file` for the test key,
  and leaves `enabled` unset. The test starts with the check **off** (no request reaches the
  catalog server), then an admin turns it on in Settings through step-up, and the first check
  follows. Both mock BMCs are scanned; the iDRAC9 mock shows the BIOS update with Recommended and the iDRAC
  update with Urgent; the iDRAC8 mock shows the "only legacy entries" line. An urgent notification
  reaches the fake target once. Zero non-GET BMC requests.
- **Playwright + axe:** Firmware page with the Latest column at 1440/390 in both schemes, the skip
  form, the Settings firmware-check section (on, off, locked) and upload form, and a visual baseline refresh.

## 18. Slices and effort

| Slice | Content | Days |
|---|---|---|
| **U1 — catalog core** | `internal/egress` extraction (notify keeps its behaviour, existing tests green), Dell source: fetch, signature wrapper + pinned key, UTF-16 reader, bounded streaming parser, migration, import pipeline with cached files, `oob-manager catalog import <gz> <sig>` CLI, unit + fuzz | 1.25 |
| **U2 — matching and view** | `SystemID` in inventory and `firmware_scans`, matching and verdicts, Latest column, flags and rank, coverage lines, skip/unskip, API/CSV/metrics | 1.0 |
| **U3 — settings, notify, upload, e2e** | General keys + `settings_kv` rebuild, Check now, upload form, `firmware` class, e2e + Playwright, docs (tech_doc §, deploy/README "Firmware update check", security.md rows, Help) | 0.75 |
| | **Total** | **3.0** (+ the combined review per slice, project rule) |

U1 can merge on its own (feature off, CLI only). U2 and U3 should ship together as one release
(**v0.9.0**), so the UI never shows a half-wired check.

## 19. Risks and later items

- **The iDRAC8 server gets almost nothing.** Dell's current catalog has dropped it (1 entry, from
  2016). The plan says so honestly instead of implying "all up to date". An admin can upload an
  older or archived catalog that still lists it. Whether Dell publishes one isn't verified.
- **Version ordering across packages** relies on `CompareVersions`. Dell's own drive firmware
  versions (`EM05`, `EM06`) compare as strings, which is correct for these but is a heuristic.
  Mixed shapes become `cannot_compare`, never a false "update".
- **Key rotation:** if Dell re-signs with a new key, every check fails with `untrusted_key` until a
  release embeds it or the admin adds it through `extra_keys_file`. The status line names the new
  key ID so the admin can check it against linux.dell.com.
- **Deprecated OpenPGP package:** a future x/crypto release could remove it. The wrapper isolates
  it to one file, and the fallback is ProtonMail/go-crypto (a new dependency, to be checked then).
- **Later:** HTTP proxy, Dell security advisory (DSA/CVE) links per release, PCI-only matching,
  other vendors, per-model catalogs from Dell's per-platform catalog index.

## 20. Verified vs assumed (summary)

**Verified 2026-10-29:**
- the URL, size, encoding, headers and absence of a redirect;
- the signature format, the key and its fingerprint from two sources, and Go verification with the
  existing module (good and tampered cases);
- the manifest and component schema, the criticality values and the `ImportantInfo` URL;
- the system IDs and coverage of both tested models, the multi-version ambiguity count, and today's
  would-be flags;
- that iDRAC9 exposes `Oem.Dell.DellSystem.SystemID` and iDRAC8 2.86 has no Oem block on the
  system.

**Assumed:**
- Dell's publishing cadence and key longevity;
- that ProtonMail/go-crypto would also verify v3 DSA;
- that archived catalogs for end-of-life models are obtainable;
- that the parse stays under 32 MiB peak (to be measured in U1).

## 21. Open questions (answered)

1. ~~Default in the generic build: online check off or on?~~ **Off by default; the user can turn it
   on in Settings** (browser), not only in config.yaml. It follows the settings pattern: DB-backed,
   a config.yaml key wins with the lock badge. The toggle needs admin + a fresh step-up, and every
   change is audited. The source URL / mirror override and the extra trusted keys stay
   config.yaml-only (no SSRF via the browser). Applied in §3, §6.2, §10, §12, §16 (E5) and §17
   (unit, e2e, Playwright).
2. ~~Signature library?~~ **`golang.org/x/crypto/openpgp`**, wrapped in one file (§5.3).
3. ~~Unsigned uploads?~~ **Refused unless the file-only `firmware.catalog.allow_unsigned` switch is
   set** (§5.2).
4. ~~Notification class?~~ **A new `firmware` class** (§13).
5. ~~Sidebar badge?~~ **Urgent updates only** (§10).
