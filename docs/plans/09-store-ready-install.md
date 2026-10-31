# Plan 09 — Store-ready install (plan 07 §4.8, first part)

Status: built 2026-10-29 as v0.11.0 on branch `store-ready-install`; the independent security review's
findings are fixed in v0.11.1 (§8), and the re-check's LOW follow-ups after v0.12.0 (§8, branch
`p9-followups`). Decision 13 (plan 07 §6) is
accepted: a store install keeps its age identity in its data volume, with a "back this up" notice.

## 1. Goal

A container started with nothing but a data volume and a published port reaches a working,
signed-in app: no host script, no config.yaml, no `docker exec`. An existing install (identity
mounted from outside the data volume, app keys and credentials mounted, config.yaml present) behaves
exactly as before: nothing is generated, moved or overwritten.

## 2. What counts as "not configured"

The rule everywhere: **a path written in config.yaml is never replaced by a generated file.** A
configured file that is missing is a startup error, as today. Only a *defaulted* path (key absent
from config.yaml, or no config.yaml at all) may fall back to the data volume, and only when its
mounted default (`/run/secrets/...`) is absent too.

| Item | Configured or mounted | Neither |
|---|---|---|
| config.yaml | loaded (default path, then the pre-rename path); a store-install marker in `<data>` is removed | built-in defaults, **only for a store install**: a fresh data volume (no database, or one without sealed data) is marked with `<data>/store-install` on its first start, and a marked volume starts on defaults again (one log line says so). An existing database with sealed data in an unmarked volume (a configured install that lost its config.yaml, e.g. an empty mount) is refused. `-config=none` is the explicit opt-in (ERROR-level log line). An explicit `-config` that is missing stays an error |
| `tls.cert_file` / `key_file` | loaded; one without the other is a validation error | without config.yaml: `<data>/tls/tls.crt` + `tls.key`, generated once with `certgen` (ECDSA P-256, 825 days), fingerprint logged. A config.yaml that sets neither is refused by serve (§8 L5; the CLI commands still run on it): a store install that adds one names the generated pair |
| `secrets.identity_file` / `app_keys_file` | loaded from the configured or mounted default path | `<data>/keys/age-identity` (0400) + `app-keys.age` (0400) |
| `secrets.credentials_file` | loaded | no file: an empty set (only config.yaml servers use it; browser-added servers keep their logins sealed in the database). Only when the keys are in `<data>/keys` |
| `public_url` | used for links and as a trusted origin | optional now: links use the request host, CSRF keeps its same-origin check (Origin vs Host), the console websocket keeps allowing the request host |

`<data>` is the directory of `storage.db_path` (default `/data`).

The generated key paths are used only when both key paths are *defaulted* (left out of config.yaml):
a config.yaml that names `<data>/keys/age-identity` itself is a configured path, never generated into.

**Key generation is first-start only.** Keys are generated only when `<data>/keys` holds neither
file **and** the database is new: no database file, or one with no users, BMC credentials,
notification targets or API tokens. A database that already holds sealed data and no reachable keys
refuses to start ("mount the original keys"): generating would make every sealed value unreadable.
If only one of the two key files exists, startup also refuses. Files are written with `O_EXCL`, fsynced
and chmod-ed. Each set (keys, TLS pair) is written in a temporary sibling directory and renamed into place,
so a crash never leaves half a set; leftover temporary directories are removed on the next start.
A marker `<data>/keys/BACKUP-PENDING` drives the UI notice.

## 3. Running as another user

The image stays distroless and non-root (65532) with a read-only root filesystem, so it has no root
entrypoint that could `chown` and drop privileges, and `PUID`/`PGID` cannot be honoured from inside.
Instead the container is run with Docker's own `--user 99:100` (compose `user:`, Unraid
`ExtraParams`). Nothing in the image depends on uid 65532: the files it writes live in the data
volume. Before anything else (keys, TLS, migrations) serve and the CLI check that `<data>` is a
writable directory by creating and removing a probe file, and fail with the uid/gid and the fix
(`chown -R <uid>:<gid> <host path>` or `--user`) instead of failing mid-migration.

## 4. First admin in the browser

- `/setup` exists only while the users table is empty. At startup with no users, serve creates a
  one-time setup code (20 random bytes, base32, shown in groups of four) and logs it once with the
  expiry. Only its SHA-256 is kept, in memory. A restart makes a new one. A claim that ends without
  settling (an error, or a panic the HTTP middleware recovers) releases the code, so `/setup` never
  stays wedged.
- The code is never in a URL (no history, no Referer). Comparison is constant-time on the digests.
  It expires after 24 hours and is burned when the admin is created. `/setup` has its own per-IP
  limit (5 a minute), separate from the sign-in limits: setup floods never lock out sign-in and failed
  sign-ins never block the claim. Every attempt is audited (`setup.claim` ok/denied with a class); a
  rate-limited refusal only once per address a minute (§8 N1).
- The form takes the code, a username and the password twice. It calls the same
  `Authenticator.BootstrapAdmin` as the CLI; `CreateFirst` inserts only `WHERE NOT EXISTS (SELECT 1
  FROM users)`, so two concurrent claims cannot create two admins (the loser sees "already set up").
- Then the page shows the TOTP secret and QR once (the existing reveal page) and the existing
  enrolment form confirms a code, exactly like `bootstrap-admin` + `confirm-totp`. The account cannot
  sign in until that succeeds; an interrupted setup is finished on `/enroll` or with `confirm-totp`.
- Once a user exists `/setup` answers 404 and the sign-in page stops linking to it.

## 5. Backup notice

While `BACKUP-PENDING` exists, admins see a banner on every page: the keys were generated in the
data volume, where to find `age-identity`, and that losing it loses every stored password and
authenticator. "I have a backup" removes the marker (admin, CSRF, audited `keys.backup_acknowledged`).
The log repeats the warning at every start while the marker exists.

## 6. Threats (docs/security.md)

| # | Threat | Control |
|---|---|---|
| S11 | A LAN neighbour claims a fresh install before its owner | Setup needs the one-time code from the container log (owner-only); 160-bit code, constant-time compare, rate limits, 24 h expiry, single use, audited; `/setup` gone once a user exists |
| T15 | A broken mount makes an existing install start "fresh" with new keys | Generation only for defaulted paths whose mounted defaults are absent **and** a database with no sealed data; otherwise refuse to start |
| I18 | Generated keys readable by others or lost | 0400 files in a 0700 directory owned by the app user, written atomically; backup banner until acknowledged; documented trade-off: keys in the data volume travel with backups of that volume |
| E6 | The setup code leaks through URLs or logs beyond the first start | Code only in a POST body; logged once per start while no user exists; never stored in clear |

## 7. Tests

Unit: config optional TLS/public_url and defaulted flags; config-less load; data-dir probe; key
generation (modes, atomicity, refuse on partial set or non-fresh DB, never touch configured paths);
TLS generation; setup code (expiry, single use, constant-time, wrong code); UI (setup only while no
users, CSRF, rate limit, concurrent claims, notice dismiss). Go e2e: an empty data directory and no
config.yaml → serve → code read from the log → `/setup` → TOTP confirm → sign-in → backup notice →
dismiss; and the existing harness (mounted keys, config.yaml) proves nothing is generated.

## 8. Independent review fixes (v0.11.1)

An independent security review of v0.11.0 found no critical or high issue. Fixed in v0.11.1:

| # | Finding | Fix |
|---|---|---|
| M1 | A missing config.yaml started the app on built-in defaults, so an install whose config mount came up empty would serve a new self-signed certificate and drop its file-only settings | Defaults only for a store install (fresh volume, or `<data>/store-install`); an unmarked volume with sealed data refuses; `-config=none` opts in at ERROR level; a start with config.yaml removes the marker |
| L1 | A panic after a claim left `/setup` wedged until a restart | Deferred release, cleared only when the claim settles |
| L2 | `/setup` shared the sign-in buckets, so a flood for `admin` could block sign-in and the real claim | Own per-IP bucket (5/min); the sign-in buckets are not charged |
| L3 | The generated certificate is never checked for expiry | WARN at startup within 30 days of its end (or after it), with how to replace it |
| L4 | A config.yaml naming `<data>/keys/age-identity` could be generated into | Generation needs both key paths defaulted |
| L6 | An uncheckable database refused with a bare store error | "refusing to generate keys: the database could not be checked" |
| L8 | The key-notice comment described a mode restore the code does not do; the acknowledgement's audit row was written after the dismissal | Comment corrected; the acknowledgement is audited first and not done when the audit write fails |

Not changed: the setup code in the container log (L7) is by design (owner-only access, documented in
S11/E6); a stray write-probe file after a kill, and audit rows from wrong setup codes (bounded by the
rate limit), are noted only.

### Follow-ups (LOW, fixed after v0.12.0)

From the independent re-check of v0.11.1. All four are fixed on branch `p9-followups` (tech_doc §51):

- **N1, fixed.** The `/setup` bucket is keyed by the peer IP. Behind Docker's userland proxy every client can share
  one address, so one client can hold the bucket for everyone, and each rate-limited request wrote an audit row.
  Now only the first rate-limited refusal per address and window (a minute, the bucket's own) is audited; the
  limiter itself is unchanged, and allowed attempts (wrong code, bad CSRF) are still audited one by one.
- **N2, fixed.** CLI subcommands dropped the config start notes (`openCLICore`, `parseFlags` callers, `backup`,
  `verify-audit`), so a failed store-marker removal was invisible there. Now the notes that report a problem (a
  store marker that could not be written or removed, `-config=none`) are printed to stderr as
  `oob-manager: warning: …` / `oob-manager: error: …`. The routine notes (pre-rename paths, running on built-in
  defaults) stay serve-only, so a healthy install's CLI output is unchanged.
- **N3, documented.** A start without config.yaml looks for the database at the default `storage.db_path`. An
  install whose database lives at a non-default path, started without its config.yaml, finds no database there
  and treats the volume as fresh (new keys and certificate next to an empty database; the real database is
  untouched). deploy/README ("No config.yaml is a store-install property") now says that an install with a
  non-default `storage.db_path` must keep its config.yaml.
- **L5, fixed.** Removing the `tls:` block from a config.yaml silently generated a self-signed certificate in the
  data volume. Now `serve` refuses a config.yaml that sets neither `tls.cert_file` nor `tls.key_file`, before the
  database is opened or the store marker is touched, naming `gen-tls` and how a store install keeps its generated
  pair: `tls: { cert_file: <data>/tls/tls.crt, key_file: <data>/tls/tls.key }`. The CLI subcommands never use the
  certificate, so they still run on such a file (break-glass commands such as `admin-recover` keep working while
  the administrator fixes it); they leave the store marker in place, since only a config.yaml serve would start with ends a
  store install. No new opt-in key: the generated certificate stays a property of an install without config.yaml,
  like the defaults themselves (`-config=none` remains the only explicit opt-in). Once the pair is named it is a
  configured file (no expiry WARN, no regeneration), so deploy/README tells the administrator to note its end date and
  replace it with `gen-tls` before then.
