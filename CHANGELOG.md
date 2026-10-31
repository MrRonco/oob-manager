# Changelog

All notable changes to oob-manager, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (0.x: minor versions may break things; breaking
changes are called out below).

Versions up to v0.13.0 were pre-release builds, tested on one iDRAC8 (Dell R730XD) and one
iDRAC9 (Dell R240). The first public version is a **public beta**; `v1.0.0` follows once
hardware reports have come in and a month has passed without a security fix. The public
repository starts from a clean cut, so these pre-release versions have no tags or releases there.

**Migrations are one-way.** A release that lists a migration upgrades the database on its first
start and cannot be rolled back by downgrading the image alone. Back up first
(`oob-manager backup <dir>`, see deploy/README.md "Backups and verifying the audit chain").

## [Unreleased]

## [0.14.1] - 2026-10-31

Documentation and tests only; the application binary is unchanged from 0.14.0.

### Added

- README screenshot tour (light and dark) made from the mock BMCs: `make showcase` and the
  hand-run `showcase` workflow regenerate `docs/screenshots/`, including the social preview.
- `.github/FUNDING.yml` and a support link in the README.

### Internal

- The end-to-end authenticator-reset check no longer races a 30-second TOTP step boundary on slow
  runners.

## [0.14.0] - 2026-10-30

Public release candidate.

### Added

- `serve` warns at start when `listen` or `public_url` in config.yaml is a public IP address: the
  console is meant for a management LAN only.
- The image carries `LICENSE` and `NOTICE` in `/usr/share/doc/oob-manager/` and is labelled
  `org.opencontainers.image.licenses=Apache-2.0`.

### Security

- Starting a fan lease now fails closed on the audit log, like power, BMC restart and the consoles:
  when its "started" audit row cannot be written, nothing is changed and the page says so (503).
- Every fan lease start that fails after its "started" audit row now writes a closing error row, and
  each fan audit write gives up after 10 seconds, so one stuck write cannot hold the server's lease lock indefinitely.
- Notification, catalog and integration egress no longer treats site-local (`fec0::/10`), Teredo
  (`2001::/32`) or IPv4-compatible (`::/96`) addresses as public, and judges an IPv4-mapped address by
  the IPv4 address it carries.
- Release images carry a signed SBOM of the image itself (it used to describe the source tree).

### Fixed

- Settings › Servers › **Test connection** writes its audit row before the result is shown, so the
  audit log never lags behind what the page reports.

### Internal

- CI can run on self-hosted runners; the browser end-to-end tests run in two parallel parts.

## [0.13.0] - 2026-10-30

### Added

- **Go to** palette: `Ctrl`+`K` (`⌘`+`K` on a Mac) opens a list of every page and server to
  filter as you type. Single-key shortcuts (can be turned off per browser): `/` jumps to the page's
  filter field, `g` `o` opens Overview, `g` `s` Servers, `?` lists the shortcuts. Without JavaScript
  the same list is the `/go` page. Shortcuts are off on a connected console page.

## [0.12.0] - 2026-10-30

### Added

- `oob-manager backup <dir>` makes a consistent copy of the live database; `oob-manager verify-audit`
  checks the audit hash chain; `oob-manager admin-recover -username <u> -yes` restores access when
  every admin is locked out. All three are audited, and their rows reach the GELF log server too.
- A recovery runbook with tested drills (deploy/README.md).
- An OpenAPI description of the read-only API: `docs/api/openapi.yaml`.

### Changed

- Every POST route has a rate limit. `/readyz` answers from a one-second cache and is never rate
  limited, so an uptime monitor cannot lock itself out.
- New files are created with `umask 077`.

### Security

- Fuzz targets for every parser that reads BMC, catalog or user input, and an automated ZAP scan of the
  UI and API, run in CI.

### v0.12.1 - 2026-10-30

- `serve` refuses a config.yaml that does not name a TLS certificate and key (other CLI commands still
  run). A store install's marker is only cleared once the pair is named.
- Configuration start problems are printed to stderr by the CLI commands too.
- Rate-limited `/setup` attempts write at most one audit row per address a minute.

## [0.11.0] - 2026-10-29

### Added

- **Install from a data volume alone** (for app stores such as Unraid Community Applications): on a
  fresh volume with nothing configured, the first start generates the app keys and a self-signed TLS
  certificate in `/data` and logs the certificate fingerprint and a "back up these files" notice.
- **First-run setup page** `/setup`: exists only while no user exists, protected by a one-time code
  printed to the container log; creates the first admin with TOTP enrolment, like `bootstrap-admin`.
- The data directory is checked for write access at start, with a clear error instead of a failed
  migration. Run the container as another user with Docker's `--user`.

### v0.11.1 - 2026-10-29

- **Changed:** running without config.yaml is allowed only on a fresh or marked store volume
  (`-config=none` is the explicit opt-in). If config.yaml goes missing on an existing install, the app
  refuses to start ("restore config.yaml") instead of starting on defaults.
- `/setup` has its own rate limit and releases a claim that was not completed; keys are generated only
  for paths that are not configured; a warning before the generated certificate expires.

## [0.10.0] - 2026-10-29

### Changed

- Motion and view transitions between pages (only when the system does not ask for reduced motion), a
  short highlight on sensor values that changed, restyled console frames, and a server edit page that
  matches the other settings pages.

## [0.9.0] - 2026-10-29

### Added

- **Firmware update check** against Dell's signed enterprise catalog: a Latest column, "Urgent update"
  and "Update available" flags, per-server coverage, and Skip this version. The online check is **off by
  default**; turn it on in Settings › General (step-up, audited). The catalog can also be uploaded or
  imported with the CLI. Its signature is checked before it is parsed. The app still never downloads,
  stages or installs firmware.
- Notification class `firmware`; `GET /api/v1/firmware/catalog`.
- `oob-manager settings import -servers id1,id2` moves file-managed servers into the database (their
  credentials re-sealed), and `settings export` prints the effective settings without secrets.

### Changed (breaking for API and CSV consumers)

- API: `meta.catalog` is now an object; firmware rows gain `latest` and update fields. The firmware CSV
  gains five columns at the end.
- Migration 0017, one-way: back up before upgrading.

### v0.9.1 - 2026-10-29

- Settings pages line up field by field. The instance name shown in the header is a General setting
  (`ui.instance_name`). Migration 0018, one-way.

## [0.8.0] - 2026-10-29

The project was called **oob-console** up to v0.7.2 and is **oob-manager** from this release. Existing
installs keep working: the old config path (`/etc/oob-console/config.yaml`) and database file name
(`/data/oob-console.db`) are still found, with a deprecation warning. Tokens, sessions, sealed
credentials, the audit chain, metric names (`oob_*`) and `OOB_*` variables are unchanged.

### Added

- **BMC restart** (admin, step-up, audited, 10-minute cooldown per server). While the BMC restarts the
  app shows "BMC restarting" instead of "unreachable", and checks that it came back.
- **Firmware view:** readable component names, running, previous and stored versions, release dates
  where the BMC reports them, an optional "minimum known good" list, Re-scan and CSV export.
- **Sensor history:** a History tab with server-rendered charts, sparklines on the server page, CSV and
  JSON export. Retention defaults: raw 7 days, hourly 90 days, daily 2 years.
- **Settings › Integrations:** GELF audit shipping over TCP or TLS with a pinned certificate, managed in
  the browser; ready-to-copy snippets for Homepage, Uptime Kuma and Prometheus. GELF targets must be on
  private networks unless `audit.gelf.allowed_networks` says otherwise.
- New palettes and icons; Overview shows a recent-events recorder and an incident view when something is
  wrong; a global Activity page.

### Changed

- Server pages have stable tabs (Overview, Sensors, History, Events, Activity, Inventory, Security) and
  Console ▾ · Power ▾ · More ▾ menus. The Operations tab is gone: `/servers/{id}/operations` and
  `/servers/{id}/logs` redirect (302) to the server's Overview and Events pages.
- Migrations 0012–0015, one-way: back up before upgrading.

### v0.8.1 - 2026-10-29

- **Fixed:** Dell firmware states were inverted. A Dell "Installed" entry is the running version; a
  differing "Current" entry is an image stored on the BMC but never installed, now shown as "stored,
  not installed" with the flag **Not applied**.
- **Breaking:** JSON field and CSV column `lc_installed` → `stored`; flag `mismatch` → `not_applied`
  (also the `oob_firmware_flagged{flag}` label: alert rules on `flag="mismatch"` stop matching).
- Migration 0016, one-way: back up before upgrading.

## [0.7.0] - 2026-10-22

### Added

- **BMC security checks:** 31 read-only checks per server (TLS, enabled services such as IPMI over LAN,
  accounts, firmware, network settings), a Security tab, a posture column on the fleet table, the
  `security` notification class, accepted risks with a comment (step-up required) and re-runs.
  Migration 0011, one-way.

### v0.7.1 - 2026-10-22

- **Fixed:** the checks never open an iDRAC8's VNC port (its VNC server serves one client and stays busy
  for minutes, which made runs time out). A VNC timeout no longer fails a run.

### v0.7.2 - 2026-10-22

- A powered-off server is its own state ("off") in the fleet, UI, notifications and metrics, not an
  error.
- Typing is safe from auto-refresh; a form survives the step-up page; power transitions show at once;
  the fleet table fits laptop widths; confirm pages work on phones; danger styling only for
  irreversible actions.
- Compressed HTML responses (only for successful GETs without a query string).

## [0.6.0] - 2026-10-21

### Added

- **Maintenance mode** per server (replaces the per-server mute), server notes and event
  acknowledgements.
- **Prometheus metrics** at `/metrics`, off until `metrics.enabled` is set, limited to
  `metrics.allow_networks`.
- Migrations 0009–0010, one-way.

## [0.5.0] - 2026-10-21

### Added

- **Settings › Servers:** add servers in the browser, with sealed credentials, trust-on-first-use
  certificate and host-key pins, Test connection and hot apply. Browser-added BMC addresses must sit
  inside `settings.bmc_networks` (default: the private ranges).
- **Notifications:** ntfy, Pushover, Gotify, webhook and email targets.
- App-wide display defaults.
- Migrations 0006–0008, one-way.

## [0.4.0] - 2026-10-21

### Added

- **Settings › General** in the browser; a key set in config.yaml wins and shows a lock.
- **Display preferences** per user (click the clock): time zone, six themes in dark and light, date
  format, 12/24-hour clock, °C/°F, density.
- Migration 0005, one-way.

## [0.3.0] - 2026-10-21

### Added

- **Power control** (on, graceful shutdown, graceful restart, force off, power cycle): operator role,
  step-up TOTP, audit and a confirm page that lists what goes down, including the app's own host.
- **Fan leases:** a time-boxed minimum fan speed. `host-lease` mode writes a lease file for a host fan
  script; `redfish-floor` sets the iDRAC9 minimum fan speed and reverts it.
- **Serial console** through the BMC's SSH (`console com2`), with a pinned host key.

## [0.2.0] - 2026-10-21

### Added

- **Graphical console:** the BMC's VNC server proxied in the browser (noVNC), with TLS and a pinned
  certificate; iDRAC9 native console launch.

### Changed

- Redesigned interface.

## [0.1.0] - 2026-10-20

### Added

- First release: health, sensors, power draw, system event and lifecycle logs and inventory for Dell
  iDRAC8 and iDRAC9 over Redfish (IPMI 2.0 as a legacy path), polled per server.
- Local accounts with TOTP; the first admin is created with `oob-manager bootstrap-admin`; `reset-totp`
  and `gen-tls` commands.
- A read-only JSON API with bearer tokens (`oob-manager token create`).
- Audit log with a hash chain, optionally shipped to a GELF log server.
- Users, tokens and the audit log in the browser.
- Migrations 0001–0004.

### v0.1.1 - 2026-10-20

- Redfish sessions instead of Basic auth (iDRAC8 answered each Basic-auth request in 5–10 s), timeouts
  per BMC kind, and poll tiers (sensors every cycle, logs every 5 minutes, inventory every 6 hours).
- More memory headroom: run with a 256 MB container limit.
