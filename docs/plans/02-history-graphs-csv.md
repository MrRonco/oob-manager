# Plan 02 — Sensor history graphs and CSV export

Status: plan, 2026-10-21. **Implemented 2026-10-23** on branch `history-graphs` (migration 0015, threat
rows T13, I16, D11, tech_doc §39); decisions in §18. Research input: feature research item 8 (F5); PRD FR-5
("7 days of sensor history in SQLite; render sparklines. Not a TSDB"). Builds on
tech_doc §12 (samples), §17 (poll tiers), §24 (display preferences), §29 (metrics) and the
store notes in §9 (one SQLite connection, WAL, STRICT, unix ms).

## 1. Goal and non-goals

**Goal.** Answer "what did this sensor do last night / last week / since the fan change"
inside the app, with no JavaScript, from the samples the pollers already collect: inline
sparklines on the server page, a History tab with a range picker, threshold bands,
min/avg/max and the events of the period overlaid, and a CSV export per sensor and range
from the UI and the read-only API. Bound the database growth with raw retention plus
hourly and daily rollups.

**Non-goals.**

- A time-series database. Prometheus (via `/metrics`, tech_doc §29) remains the real TSDB;
  the boundary is §13. No PromQL, no alerting on history, no backfill into `/metrics`.
- Client-side charting libraries (uPlot was listed in tech_doc §1; it is **not** needed:
  server-rendered SVG keeps the strict CSP and the no-JS rule). Remove the uPlot mention.
- Exporting SEL/Lifecycle logs as CSV (a separate, small follow-up; the plan reuses the CSV
  helper).
- Cross-server comparison charts, annotations typed by users, data import.

## 2. User stories

| Role | Story |
|---|---|
| viewer | On the server page I see 24 h sparklines next to the hottest temperature, the inlet and the power draw, so I know whether "47 °C" is normal or a spike. |
| viewer | On the History tab I pick 24 h / 7 d / 30 d / 1 y with links, pick a sensor, see the warning and critical bands, min/avg/max, and the SEL events, power actions, fan leases and maintenance windows of the period drawn over the chart. |
| viewer | I can download the data of a sensor and range as CSV (the same numbers as the chart), and read the chart's numbers in a table when I cannot see the picture. |
| operator | Same, plus "export every sensor of this server for the range" for a ticket. |
| admin | In Settings → General I set the raw, hourly and daily retention and whether PSU and voltage rails are sampled; I see how big the history is. |
| integrator (API token) | `GET /api/v1/servers/{id}/history?sensor=…&range=7d` (JSON) and `.csv` give me the bucketed series with the unit and the tier that served it. |

## 3. UX placement (direction B)

- **Server › Hardware**: three sparklines (C-04 stat tile variant) in the Status panel:
  Hottest temperature, Inlet (when reported), Draw. 24 h, 48 points (30 min buckets), width
  of the value column, no axes; the `title`/`<desc>` carry min/avg/max; each links to the
  History tab focused on that sensor. Fans and PSUs get no sparkline on the Hardware tab.
- **Server › History** (new tab in `servertabs`, after Logs: Hardware · Logs · History ·
  Inventory · Operations): page head + range picker (links `?range=24h|7d|30d|1y`, current
  one `aria-current`), then one panel per sensor kind present: Temperatures, Fans, Power
  draw, Power supplies, Voltage rails (analog only). Each panel: a chart (all series of the
  kind, ≤ 16, muted; the focused one accented with its min/max envelope), a legend list
  whose entries are links `?focus=<key>` (so focusing needs no JS), min/avg/max of the
  focused series for the range, the threshold bands when the current snapshot has
  thresholds, event markers, and a `<details>` "Data table" with the bucketed rows plus the
  "Download CSV" link. On phones the chart is full width and the legend stacks.
- **Events overlay**: vertical markers for warning/critical log entries (from the cached
  logs), power actions (`started`), fan lease start/end, BMC resets (plan 01), and shaded
  spans for maintenance windows; each marker has a `<title>`; the list under the chart
  repeats them as text with links (Events page, audit).
- **Settings › General**: a "History" group (retention keys, sampling switches, a read-only
  "History size: 38 MB, 1.2 M raw rows, last rollup 02:00" line).
- **If the round-2 redesign changes the tab model**, History stays a server-scoped page at
  `/servers/{id}/history`; sparklines move with the Status tiles. The chart partials are
  self-contained (`history_partials.html`) so a new look restyles them through tokens only.

## 4. Data model, growth math, migration

### 4.1 Today

`sensor_samples(server_id TEXT, ts INTEGER, sensor_key TEXT, value REAL)`, PK
`(server_id, sensor_key, ts)` WITHOUT ROWID, plus an index on `ts`; keys `temp:<id>`,
`fan:<id>`, `power:consumed`; written per poll, pruned hourly to 7 days; read by nothing.
PSUs and voltages are not sampled. The text key and server id are repeated in every row
and in the `ts` index: about 90 bytes per sample.

### 4.2 New schema (migration `00NN_history.sql`, NN ≥ 12; see plan 01 §4 on numbering)

```sql
CREATE TABLE sensor_keys (
    id        INTEGER PRIMARY KEY,
    server_id TEXT NOT NULL CHECK (length(server_id) BETWEEN 1 AND 64),
    key       TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 160),   -- "temp:<member id>"
    kind      TEXT NOT NULL CHECK (kind IN ('temp','fan','power','psu_in','psu_out','volt')),
    name      TEXT NOT NULL DEFAULT '',                               -- last display name seen
    unit      TEXT NOT NULL CHECK (unit IN ('celsius','rpm','percent','watts','volts')),
    first_ts  INTEGER NOT NULL,
    last_ts   INTEGER NOT NULL,
    UNIQUE (server_id, key)
) STRICT;

CREATE TABLE sensor_raw (
    key_id INTEGER NOT NULL REFERENCES sensor_keys (id) ON DELETE CASCADE,
    ts     INTEGER NOT NULL,              -- unix ms UTC, Snapshot.TakenAt
    value  REAL    NOT NULL,
    PRIMARY KEY (key_id, ts)
) STRICT, WITHOUT ROWID;                 -- no secondary index: prunes run per key

CREATE TABLE sensor_hourly (
    key_id  INTEGER NOT NULL REFERENCES sensor_keys (id) ON DELETE CASCADE,
    bucket  INTEGER NOT NULL,             -- unix ms of the hour start (UTC)
    min     REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL,
    n       INTEGER NOT NULL CHECK (n > 0),
    PRIMARY KEY (key_id, bucket)
) STRICT, WITHOUT ROWID;

CREATE TABLE sensor_daily ( -- same shape, bucket = day start UTC
    key_id INTEGER NOT NULL REFERENCES sensor_keys (id) ON DELETE CASCADE,
    bucket INTEGER NOT NULL, min REAL NOT NULL, avg REAL NOT NULL, max REAL NOT NULL,
    n INTEGER NOT NULL CHECK (n > 0), PRIMARY KEY (key_id, bucket)
) STRICT, WITHOUT ROWID;

CREATE TABLE history_meta (  -- single row: rollup watermarks and the last clock-jump seen
    id INTEGER PRIMARY KEY CHECK (id = 1),
    hourly_done INTEGER NOT NULL DEFAULT 0, daily_done INTEGER NOT NULL DEFAULT 0,
    last_clock_jump INTEGER
) STRICT;
INSERT INTO history_meta (id) VALUES (1);
```

The migration copies the existing `sensor_samples` (≤ 7 days) into `sensor_keys` +
`sensor_raw` (kind and unit derived from the key prefix; names filled by the next poll) and
drops `sensor_samples` and its index. `settings_kv` is rebuilt (as 0007 did) with the keys
of §9. `store.SampleRepository` keeps `Insert/Range/Prune` for the fleet and gains
`Keys(server)`, `Buckets(key, from, to, step)`, `RollupHourly(hour)`, `RollupDaily(day)`,
`PruneKey(key, before, keepAtMost)`, `Size()`.

### 4.3 Growth math

Bytes per row (SQLite record + cell overhead, 70 % page fill): raw ≈ 30 B, hourly/daily
≈ 55 B. `K` = sampled keys per server (temperatures + fans + 1 power + 2 per PSU + analog
rails; power-good rails are excluded). Plateau per server:

| Poll interval | K | Raw 7 d rows / MB | Hourly 90 d MB | Daily 2 y MB | Plateau |
|---|---|---|---|---|---|
| 60 s | 16 | 161 k / 4.8 | 1.9 | 0.6 | **≈ 7 MB** |
| 60 s | 32 | 323 k / 9.7 | 3.8 | 1.3 | **≈ 15 MB** |
| 30 s | 32 | 645 k / 19 | 3.8 | 1.3 | ≈ 24 MB |
| 150 s (iDRAC8 default cycle) | 32 | 129 k / 3.9 | 3.8 | 1.3 | ≈ 9 MB |

A fleet of 10 servers at 60 s with K = 32 plateaus near 150 MB; 30 servers near 450 MB. The
Settings page shows the real size (`page_count × page_size`) so the administrator can trim
retention. The old schema would have used about 3× the raw space.

### 4.4 SQLite considerations (read-only rootfs, `/data` mounted, one writer connection)

- **No `VACUUM`.** It needs a temp file the size of the database; the container's `/tmp` is a
  16 MiB tmpfs and the rootfs is read-only. A steady-state ring buffer does not need it:
  freed pages go to the freelist and are reused by the next inserts, so the file reaches
  its plateau and stays. `PRAGMA freelist_count` becomes a metric; `incremental_vacuum` is
  not available (`auto_vacuum` cannot be enabled on an existing database without a VACUUM).
- **Keep the WAL bounded:** add `_pragma=journal_size_limit(67108864)` to the DSN so the
  WAL shrinks back after checkpoints; the default `wal_autocheckpoint` (1000 pages) stays.
- **The store has one connection** (`SetMaxOpenConns(1)`, the audit chain relies on it).
  Every history query would hold the writer. Therefore: (a) inserts stay one transaction
  per poll (≤ K rows); (b) prunes run per key in batches of ≤ 5 000 rows with short
  transactions; (c) **chart and export reads use a second, read-only connection**
  (`store.OpenReadOnly`: `mode=ro`, `_pragma=query_only(1)`, same `busy_timeout`; WAL lets
  readers run beside the writer). The `-shm` file must stay writable, which it is under
  `/data`. Tests assert that a 300 k-row export never blocks an audit append for more than
  `busy_timeout`.
- **Rollups** are `INSERT OR REPLACE … SELECT … GROUP BY key_id` over one hour (≤ K × 120
  raw rows per server), run from a janitor at HH:02 for every hour between
  `history_meta.hourly_done` and the last complete hour (bounded by the raw retention, so
  a long downtime cannot queue days of work); daily at 00:10 UTC from the hourly rows
  (min of mins, max of maxes, `n`-weighted average). Idempotent by primary key.
- **Prune** runs hourly after the rollup: `sensor_raw` older than `raw_days` **and** more
  than `1.5 × raw_days × 86 400 / interval` rows per key (whichever rule deletes less is
  irrelevant: both run), `sensor_hourly` older than `hourly_days`, `sensor_daily` older than
  `daily_days`; keys with no rows in any tier and `last_ts` older than `daily_days` are
  deleted; keys of servers no longer in the registry are deleted on the registry sync hook
  (same place maintenance windows of removed servers are closed).

### 4.5 Clock jumps

Samples carry the app's wall clock at poll time. A forward jump (NTP after a cold boot
without RTC) leaves a gap and, as first written, would prune early: one janitor pass deleted every
reading (corrected in implementation: the janitor prunes by its own retention clock, tech_doc §39). A backward jump makes new samples
older than existing ones: the insert is `INSERT OR IGNORE` (no crash on a duplicate `ts`),
rollups put each sample in the bucket of its own `ts`, and the row-count prune rule keeps
growth bounded while time catches up. The sampler detects `ts < last_ts` per key, records
`history_meta.last_clock_jump` once, logs a warning and the History tab shows "The clock
moved back on <time>; samples around it may overlap". Nothing is rewritten.

## 5. Sampling changes (`internal/fleet/samples.go`)

- Keys: `temp:<id>`, `fan:<id>`, `power:consumed` (unchanged), new `psu_in:<id>`,
  `psu_out:<id>`, `volt:<id>`. IDs are the BMC member IDs (stable across polls); the name
  is the fallback, as today. Display names are written to `sensor_keys.name` when they
  change (cheap upsert once per poll).
- Power-good rails are **not** sampled: move the predicate from `ui/voltages.go` to
  `bmc.Voltage.IsPowerGood()` (`(^|\s)PG(\s|$)`), shared by sampler and UI.
- `history.sample_psus` and `history.sample_voltages` (General) switch the new kinds off.
- Values are stored in the BMC's units (°C, RPM or %, W, V). The UI converts °C→°F for
  display per user preference; CSV is always °C with the unit in the header.

## 6. Rendering without JavaScript (strict CSP)

- Package `internal/history` (model: ranges, tiers, bucketing, series, markers) and
  `internal/history/svg` (deterministic path builder: `strconv.FormatFloat(…, 'f', 1, 64)`,
  `viewBox="0 0 600 140"` for charts and `0 0 120 24` for sparklines, scaled by CSS
  `width:100%; height:auto`). Colours come from CSS classes mapped to the tokens
  (`.ser-focus{stroke:var(--accent)}`, `.ser-muted{stroke:var(--muted)}`,
  `.band-warn{fill:var(--warn-bg)}`, `.band-crit{fill:var(--crit-bg)}`, `.mark-ev{stroke:var(--warn)}`,
  `.span-maint{fill:var(--stale-bg)}`), so palettes, dark/light and `forced-colors`
  (`stroke: CanvasText`) apply automatically. **No `style=` attributes** (the existing
  `security_test` keeps passing) and no `<script>`.
- Accessibility: `<svg role="img" aria-labelledby="<id>-t <id>-d">` with `<title>` (sensor,
  range) and `<desc>` (min/avg/max, number of events); the `<details>` data table is the
  text equivalent (1.1.1); markers are repeated as a list. Axis labels are `<text>` in the
  viewer's time zone and formats (tech_doc §24), 4–6 ticks.
- Point budgets: 24 h → 10 min buckets (144), 7 d → hourly (168), 30 d → 3 h (240), 1 y →
  daily (365). Served tier: raw for 24 h and 7 d (bucketed in SQL), hourly for 30 d, daily
  for 1 y; when raw retention is shorter than the range the hourly tier fills the rest and
  the chart says "hourly averages before <date>". A chart has ≤ 16 series; a kind with
  more lists the rest under "Also recorded" as focus links. Page weight for a full History
  tab ≈ 60–120 KB of HTML.
- Thresholds: from the current snapshot's `WarnAbove`/`CritAbove` (temperatures only); the
  band is drawn only when the threshold is inside the plotted range plus 10 %.
- Range picker and focus are GET parameters with closed values (`range` ∈ 4 values; `focus`
  must be an existing key of that server, else ignored). Nothing from the query reaches a
  BMC or SQL unparameterised.

## 7. Events overlay

Sources, all already in memory or indexed: cached SEL/Lifecycle entries of the server with
severity ≥ warning inside the range (≤ 200 markers; "N more" otherwise); audit rows for the
server with actions `power.*` (`started`, `ok`), `fan.lease.create|end|expire`,
`bmc.reset` (plan 01), `server.maintenance.start|end`, through `AuditSearcher.Search`
extended with an `Actions []string` filter (bounded list, fixed fragments) and a `since`
bound; maintenance spans from start/end pairs. The acknowledged state of entries is shown
in the marker list (not on the chart).

## 8. CSV export

- **UI**: `GET /servers/{id}/history.csv?sensor=<key>&range=…` (one sensor) and
  `GET /servers/{id}/history.csv?all=1&range=…` (every sensor of the server, operator+;
  one file, `sensor` column). **API**: `GET /api/v1/servers/{id}/history.csv` with the same
  parameters, bearer token.
- **Format (RFC 4180)**: UTF-8, CRLF, fields quoted when needed with `"` doubled, header
  row first. Bucketed: `bucket_start_utc,bucket_end_utc,server,sensor,kind,unit,min,avg,max,samples`;
  raw (24 h / 7 d within raw retention, `raw=1`): `timestamp_utc,server,sensor,kind,unit,value`.
  Timestamps RFC 3339 UTC (the viewer's zone is a display matter; CSV is for machines).
  Numbers with `.` decimal separator, no thousands separators.
- **Formula injection**: any text field (sensor name) starting with `=`, `+`, `-`, `@`, tab
  or CR gets a leading `'`; server IDs and keys are already restricted alphabets.
- **Filename**: `Content-Disposition: attachment; filename="<server-id>_<sensor-slug>_<range>_<yyyymmddThhmmZ>.csv"`
  where `sensor-slug` is the key reduced to `[A-Za-z0-9._-]` (≤ 64); `all` exports use
  `all-sensors`. `Content-Type: text/csv; charset=utf-8`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff` (already global).
- **Bounds and streaming**: written with `encoding/csv` to the response through
  `http.Flusher` every 1 000 rows; rows ≤ 100 000 per response (a 7 d raw single-sensor
  export at 30 s is 20 160 rows; `all` at K = 32 is 645 k raw → refused with 413 unless
  bucketed, or the user picks 24 h); reads come from the read-only connection in pages of
  10 000 rows. Per-user limit 6/min (new `exportLimit`); API tokens: a per-token 6/min
  bucket for `.csv` on top of the general 60/min.
- **Audit**: none for reads (consistent with every other read of data the role may see);
  the request log has it. Open question §17.
- A shared helper `internal/csvx` (writer with the injection guard, filename slug, bounded
  row count) is reused by plan 03 (firmware CSV) and a later SEL export.

## 9. Settings (General section, same precedence and lock badges as S2)

| Key | Range | Default | Applies |
|---|---|---|---|
| `history.raw_days` | 1–30 | 7 | next prune |
| `history.hourly_days` | 7–730 | 90 | next prune |
| `history.daily_days` | 30–1825 | 730 | next prune |
| `history.sample_psus` | on/off | on | next poll |
| `history.sample_voltages` | on/off | on | next poll |

Lowering retention deletes data on the next prune (the form says so, with the current size).
File keys live under `history:` in config.yaml and win with the lock badge.

## 10. Authorization, API

- Actions: `server.history.view` (viewer; token-readable), `server.history.export` (viewer;
  token-readable; the `all=1` form needs operator). Retention: `admin.general.manage`.
- API (additive): `GET /api/v1/servers/{id}/history/sensors` → `{data:[{key, kind, name,
  unit, first, last}]}`; `GET /api/v1/servers/{id}/history?sensor=&range=` or
  `?sensor=&from=&to=&step=` → `{data:[{t, min, avg, max, n}], meta:{sensor, kind, unit,
  tier, step_s, from, to, points, clock_jump}}` with `points ≤ 2000` (the server raises
  `step` to fit), ranges ≤ 2 years, 400 on unknown sensor/range; `.csv` as §8. Problem
  Details on errors. Response caching: `no-store` like the rest.

## 11. Metrics (additive)

`oob_history_rows{tier=raw|hourly|daily}` gauge, `oob_history_db_bytes` and
`oob_history_db_freelist_pages` gauges, `oob_history_rollup_last_timestamp_seconds{tier}`,
`oob_history_prune_duration_seconds` (last run). No per-sensor series from history: the
live sensor families already exist.

## 12. Failure modes and safety

- Rollup or prune failure: logged, retried next hour; never affects polling (the sampler
  swallows insert errors already) or page views (charts degrade to "no history yet").
- Database full / disk pressure: inserts fail → warning log, metric gap; the app keeps
  running (history is best-effort).
- A hostile sensor name reaches the chart only through `html/template` and the CSV guard.
- Nothing in this feature talks to a BMC: tests assert zero BMC requests while rendering
  the History tab and exporting (same harness check as `/metrics`).
- Rule 11: read-only feature; the only writes are to the app's own database.

## 13. Boundary with Prometheus (to document in deploy/README)

The built-in history answers "what happened recently on this box" with no extra service:
days of raw data, two years of daily extremes, inside the app, exportable. Prometheus plus
Grafana is for real dashboards, alerting rules, cross-system correlation and long raw
retention; `/metrics` is the integration point and the history store never feeds it. Advice:
with Prometheus scraping every 60 s, set `history.raw_days: 1` and keep the rollups (they
are a few MB) so the in-app sparklines still work.

## 14. Test plan

- **Unit, `history`**: bucketing (boundaries at UTC hour/day edges, DST irrelevant because
  UTC), tier selection per range vs retention, point budget, min/avg/max weighting, clock
  jump detection, marker merging and the 200 cap; `svg`: golden SVG files for a sparkline
  and a chart (deterministic formatting; `-update` flag), no `style=`, one `<title>` and
  `<desc>` per chart, path point count equals the bucket count.
- **Unit, `csvx`**: RFC 4180 round trip with `encoding/csv` reader; injection guard table
  (`=1+1`, `+cmd`, `-x`, `@SUM`, `\tx`, `\rx`); filename slug; row cap; a `FuzzField`
  target (any input survives a write/read round trip unchanged except the guard).
- **Store**: migration from a seeded `sensor_samples` database (rows copied, kinds and
  units derived, old table gone, `TestMigrationVersionsAreDense` updated); key upsert;
  per-key prune (time and count rules); rollup idempotency; read-only connection
  (`query_only` refuses writes; a long read beside a writer: audit append completes under
  `busy_timeout`); `Size`.
- **Fleet**: sampler emits PSU/voltage keys, excludes power-good rails, honours the
  switches, upserts names, records a clock jump.
- **UI**: History tab per range and focus (closed values, unknown focus ignored),
  `<details>` table equals the chart points, markers from fake logs and audit, °F
  conversion of labels, sparklines on the server page, CSV download headers, `all=1`
  needs operator, 6/min → 429; `copy_test` and `security_test` still pass.
- **API**: sensors list, JSON series (`points ≤ 2000`, step raised), CSV, 400s, token
  limit; no BMC calls during 50 history requests (counting driver).
- **e2e (Go)**: the harness seeds 48 h of synthetic rows for both mock servers straight
  into the store before `serve` (it owns the install directory), then checks the History
  tab renders every kind, the sparklines exist, a CSV download parses and has the expected
  row count, the API JSON matches the CSV, a rollup produced hourly rows, and the mocks saw
  no request during the whole check.
- **Playwright + axe**: History tab at 1440/390 in both schemes (the SVG text contrast is
  checked by axe), the server page with sparklines, Settings → General history group;
  screenshots for the visual baselines of plan 04.
- **Race**: janitor vs sampler vs read-only reads under `-race -count=3`.

## 15. Docs to update

tech_doc (new §: schema, tiers, read-only connection, boundary; §5 table; §6 API; §12
samples), deploy/README (History settings, size expectations table, the Prometheus
boundary text, CSV format), security.md (new **I12** row: history export discloses sensor
history to any viewer/token — same data as the pages, rate-limited; note the second
connection in the store description), Help (glossary: bucket, rollup), PRD FR-5 wording
("7 days raw, rollups to 2 years"), tech_doc §1 (drop uPlot).

## 16. Effort

| Part | Days |
|---|---|
| Schema, migration, repositories, read-only connection, rollup/prune janitor | 1.0 |
| Sampler changes, history model, SVG builder, markers | 1.0 |
| UI (History tab, sparklines, settings group), authz, API, CSV helper and endpoints | 1.0 |
| Tests (golden SVG/CSV, e2e seeding, Playwright), docs | 0.5 |
| **Total** | **3.5** |

## 17. Open questions

1. Audit CSV downloads from the UI (`server.history.export` rows) or treat them as plain
   reads like every page? The plan says plain reads.
2. Defaults: raw 7 d, hourly 90 d, daily 2 y, PSU and voltages sampled. Keep?
3. Sparklines in the fleet table's Draw column (one extra query per server per Overview
   render) — later, or never?
4. Is a `points ≤ 2000` API budget enough for your dashboard use, or should raw JSON for
   24 h at 30 s (2 880 points) be allowed?
5. Should "export every sensor" be viewer-level too (the plan says operator, only because
   of its size)?

## 18. Decisions and implementation notes

Answers to §17, recorded 2026-10-23:

1. **CSV downloads from the UI are plain reads, not audited** (consistent with the firmware export);
   the rate limits stay as §8 says (6 a minute per user, and per token on top of the token's 60).
   Refusals (role, rate limit) are audited.
2. **Retention defaults kept:** raw 7 d, hourly 90 d, daily 2 y; PSUs and voltages sampled.
3. **Fleet-table sparklines: later.** The chosen redesign (direction A with C's recorder and B's incident
   mode, plan 04) puts a shared-axis 24 h recorder on the desktop Overview; the query API is built so that
   slice reuses it (`history.Service.Chart` takes any sensors and one plan; `SparkPlan` is the 24 h, 48
   point plan). No fleet sparklines now.
4. **API point budget `points ≤ 2000`** (the step is raised to fit).
5. **"Export every sensor" stays operator-level.** Implemented as sessions only: API tokens stay
   viewer-level readers whatever their role (the authz invariant), so `all=1` on the API answers 403 and a
   token exports one sensor per request.

Numbers taken at implementation (plans/README status note): migration **0015** (not "00NN ≥ 12"), threat
rows **T13**, **I16**, **D11** (the plan's "I12" was taken by the security checks), tech_doc **§39**.

Deviations from the plan, each explained in tech_doc §39: the 7-day chart is served from the hourly
rollups (identical points, far cheaper); the fleet no longer keeps a `SampleRepository` or prune loop (the
history service owns retention); the CSV gains a `name` column; raw exports cover any window up to 31
days; coarser tiers end on their bucket boundary and prunes are bucket aligned; the writer begins its
transactions IMMEDIATE (found by the e2e run: a CLI command beside serve could fail with SQLITE_BUSY).
