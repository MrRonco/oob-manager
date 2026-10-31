# Security — oob-manager

This app holds credentials that can power off and take over the console of every server it
manages (often including the Docker host it runs on, and the firewall). Treat it as a tier-0
asset: compromise of the app ≈ physical access to every managed server.

## 1. Assets

| Asset | Impact if lost |
|---|---|
| BMC operator credentials | Power off / console on every managed server |
| BMC read-only credentials | Recon only (inventory, SEL) |
| VNC passwords | Graphical console (equivalent to physical access); 8 bytes of DES key at most |
| App session cookies, TOTP secrets, API tokens | Act as that user (an admin) |
| Audit chain | Ability to hide abuse |
| Fan lease channel | Thermal impact on the server's disks and CPUs (bounded by floor + guards) |

## 2. STRIDE

| # | Threat | Where | Control |
|---|---|---|---|
| S1 | Attacker on the management LAN logs in as an admin | Login | argon2id + mandatory TOTP; lockout with exponential backoff per account and per IP; no username enumeration |
| S2 | Forged `Cf-Access-Jwt-Assertion` header from LAN | CF mode | Verify RS256 signature against team JWKS (cached, refreshed), `aud` tag, `iss`, `exp`/`nbf`; header ignored entirely in LAN-only mode |
| S3 | Spoofed BMC (ARP/DNS) harvesting credentials | App → BMC | TLS certificate pinned per BMC (SHA-256 of SPKI); SSH host key pinned; IPMI RMCP+ mutual HMAC (still see §5). A certificate that stops matching pauses that server's polling (no retries) until an admin confirms a new fingerprint |
| S4 | Stolen API token used for actions | API | Tokens are read-only by type; no code path maps a token to operator/admin |
| T1 | CSRF triggers power action | Web | `http.CrossOriginProtection` (Go 1.25+, Sec-Fetch-Site/Origin) **plus** synchronizer token; `SameSite=Strict` cookie; actions only on POST |
| T2 | Lease file tampered (host-side write) | Lease dir | App writes `<id>.lease` atomically (temp + fsync + rename, 0640) with a 128-bit random `lease_id`. The host reader (`deploy/host/`) validates strictly: 512-byte cap, byte alphabet `[a-z0-9_=-]`, exactly six keys, no duplicates, no symlink, optional owner uid, `expires_at` enforced on the host, duration ≤ `FAN_LEASE_MAX_SECS`, floor clamped to the host's own minimum, never below its computed curve; thermal guards override. Directory owned by 65532, 0755 |
| T2a | Ack file forged or hostile (app-side read) | Lease dir | App reads `<id>.ack` through `os.Root`, refuses non-regular files and symlinks (Lstat and the opened file must be the same), caps at 512 bytes, strict key=value grammar, expected server id. A forged ack can only change what the UI *shows* (pending vs applied); it cannot start, extend or end a lease |
| T3 | Audit rows edited to hide actions | SQLite | Hash chain (`row_hash = SHA256(prev_hash ‖ canonical_row)`), verified on startup and via `/admin/audit/verify`; the optional GELF copy on a log server is off-box |
| T4 | A server pointed at a rogue BMC (config edited, or an admin session misused in Settings → Servers) | Config, Settings | config.yaml is a read-only mount; its changes take effect on restart and are audited with a config hash. Since slice S3 an admin can add and move servers in the browser, applied without a restart: each change needs the admin role, a fresh step-up, CSRF and the change limit and is audited in its transaction (no secrets); the address must be an IP literal inside `settings.bmc_networks` (not loopback, link-local, multicast or the app itself); the certificate is pinned by TOFU (fetched handshake-only, compared and confirmed by the admin with a session-bound 5-minute proof, or pasted and audited as manual) before any credential is sent; stored credentials are AES-256-GCM sealed and bound to server, slot, kind, address, port and version, so a moved server loses them (they can never be redirected to another host). `settings.locked: [servers]` makes the section read-only |
| T8 | Settings → Servers used as a port scanner or SSRF (fingerprint fetch, Test connection) | Settings | Admin + fresh step-up; the address may not be any local interface of the app; only the validated address and port are dialled (no host names, no redirects, no proxy); the TLS fetch sends no HTTP byte and the SSH fetch stops before authentication; 5 s dial and handshake bounds; class-only errors (`unreachable`, `timeout`, `not_tls`, `bad_cert`, `not_ssh`); 6 fetches and 6 tests per minute per user; every fetch audited with address, port and result. Test connection only reads (Redfish GETs, the session login every poll also does) |
| I10 | BMC credentials stored in the database | SQLite | Sealed with a key derived from the app keys (`DeriveKey(PurposeBMCCred)`), never in clear on disk or in backups of the DB; additional data binds each to its server, slot, kind, address, port and a version that only grows; replace-only, never displayed (UI shows "set · v3 · date by user"), never logged or audited; decrypted only when drivers are built. Losing the app keys loses them (re-enter) |
| R1 | "I didn't do that" | All actions | Audit: principal, auth method, source IP, CF-Ray (if any), correlation ID, BMC response. CLI actions carry principal `cli` and, for `admin-recover`, the shell account (`os_user`: inside `docker exec` that is `uid 65532`, not a person; the host shell history or Docker's logs say who ran it); mutating CLI commands ship their rows to the GELF target like serve does (best effort; up to about 6 s on exit), so the break-glass trail leaves the box (plan 06 §3.6). |
| I1 | BMC credentials in `docker inspect`/template/env | Deploy | Never env. Age-encrypted file via compose `secrets:` (ro); identity key separate; process reads once, keeps in memory |
| I2 | Credentials in logs or argv | Code | No shell-outs exist; logger has a redaction layer; struct types for secrets implement `String()`/`LogValue()` returning `[redacted]` |
| I3 | Credentials reaching the browser | Console | SSH/SOL/RFB auth terminated server-side: the app answers the BMC's VNC challenge and offers the browser security type None, so the VNC password is never sent to it (tested: no password bytes on the WebSocket); the serial console logs in to the BMC's SSH with the operator password server-side and relays only terminal bytes (tested the same way). Only exception: iDRAC9 KVM launch's single-use temp creds (admin + step-up, LAN, shown once on a no-store page, never logged or audited) |
| I4 | Error messages leak internals | Web | Generic user messages, detailed server logs; Problem Details JSON for the API |
| I5 | Backups leak secrets (volume backups, snapshots, off-site copies) | Storage | Secrets file is age-encrypted; on the hardened layout the age identity lives off the data volume (root-only storage, staged to a tmpfs at boot, 0400) and is excluded from backups that leave the box; a store install keeps its generated identity in `/data` and says so (deploy/README.md) |
| D1 | Login brute force / request floods | Web | Per-IP and per-user token buckets; request body cap 64 KiB (no route needs more); server timeouts (read header 5 s, read 15 s, write 30 s, idle 60 s). **Unauthenticated endpoints (plan 06 §3.1, 2026-10-30):** `/readyz` answers from a 1 s cache, so the database is pinged at most about once a second whatever the rate, and it has deliberately **no** per-address 429 (monitors on one host share a source address; uptime monitors such as Uptime Kuma read 429 as down); the shared answer ignores a caller's cancellation so a client that hangs up cannot cache "unavailable". The sign-in GETs mint HMAC form tokens and at most look up a session or count users, unlimited by design; every POST is limited (§3k). There is no unauthenticated report endpoint (no CSP reporting, §3) to flood. |
| D2 | Slow BMC exhausts goroutines | Fleet | Per-call timeouts, per-server breaker, bounded worker per server |
| D3 | Console sessions left open | Console | One per server per console type; serial and graphical share `console.idle_timeout` (15 min) and `console.max_session` (4 h); ended on logout, session expiry or rotation, role loss and app shutdown |
| S5 | Graphical console = physical access (keyboard, power button via the OS, BIOS) | Console | Admin role + fresh step-up (`console.vnc`, `console.vnc.takeover`), CSRF form, 10 starts/min/user, one session per server, audit of start/stop/takeover with duration and byte counts, idle/max timeouts (§3b) |
| S7 | Serial console = physical access (BIOS setup, boot loader, OS login) | Console | Admin role + fresh step-up (`console.serial`, `console.serial.takeover`; operator before P4), CSRF form, shared 10 starts/min/user, one session per server, audit of start/stop/takeover with duration, byte and break counts, idle/max timeouts (§3d) |
| S6 | Cross-site WebSocket hijacking of the console | Console | WS upgrade needs the session cookie (SameSite=Strict), a same-origin `Origin` (or `public_url`), the role with a fresh step-up, and a single-use 30 s ticket bound to that session and server (§3b) |
| T5 | Browser (or XSS) sends arbitrary RFB bytes to the BMC | Console | The relay parses every client→server message and forwards only SetPixelFormat (8/16/32 bpp), SetEncodings (allowlisted; pseudo-encodings that enable other client messages are removed), FramebufferUpdateRequest, KeyEvent, PointerEvent and ClientCutText ≤ 64 KiB; any other type ends the session |
| T6 | Browser (or XSS) runs commands on the BMC through the serial console | Console | The app runs exactly `console com2` (one exec request; the session type exposes no other command, shell or request, pinned by a test); browser text messages are a closed JSON enum (resize, break, quit) decoded strictly; the iDRAC quit key (Ctrl-\) is stripped from typed input and the app closes SSH right after its own quit, so nobody reaches the iDRAC's racadm shell (§3d) |
| I7 | Operator password sent to a spoofed BMC SSH service | App → BMC | Exact host key pin (`ssh_host_key`, from config.yaml or confirmed by an admin in Settings → Servers after a fetch that stops before authentication), host key algorithms limited to the pinned type; a mismatch fails before authentication, so the password is never sent (tested), and the server page offers to fetch and confirm the new key (never accepted automatically) |
| I6 | VNC password or session sniffed on the management network | App → BMC | VNC auth is DES with ≤ 8 password bytes (offline-crackable from one challenge/response); the relay dials the TLS-wrapped VNC port with an SPKI pin by default and warns when `tls: false` |
| D4 | Hammering the BMC (it has tiny session tables) | Fleet | One Redfish session per server (reused, deleted at shutdown, §3a), min poll interval 30 s, slow data (logs, inventory) on its own slower tiers, cooldown on power actions. A BMC restart (§3h) drops the BMC's whole session table: the poller logs in once again when the BMC answers, and the resetter's own logout is skipped, so a restart costs one extra session, not a churn |
| S8 | A power action against the wrong server, or by mistake | Power | Server from config by ID, action from a closed enum; confirm page (Cancel focused) naming action, server, effect, critical/self-host warnings and the configured "What goes down" list; typed server name for forced actions and for any take-down of a `critical` or `self_host` server (§3c) |
| T7 | Power action body or target altered (user input reaching the BMC) | App → BMC | The only POST target is the system's own `ComputerSystem.Reset` URI (exact regex, must equal `<system>/Actions/ComputerSystem.Reset` as advertised); body is built from a constant: `{"ResetType": X}`, X in the six-value enum ∩ the BMC's AllowableValues (§3a) |
| D5 | Power flapping (repeated cycles damage hardware, BMC overload) | Power | 60 s cooldown per server reserved before the BMC is contacted (429 + Retry-After), one operation per server at a time, 10 actions/min/user; a refusal before the POST gives the cooldown back |
| R2 | Power action with no trace, or a trace that claims success wrongly | Power | Audit fail-closed: no `started` row, no request. Then exactly one final row: `ok` (verified or unconfirmed restart), `error` (BMC refused, not reached in time, superseded, stopped) or `denied`; refusals in the UI (CSRF, role, typed name, step-up, rate limit, cooldown) are `denied` rows with the server ID; all shipped to GELF |
| E1 | Viewer escalates to operator actions | AuthZ | Central `Allowed()` matrix with table-driven tests covering every route × role; deny by default. Role and `disabled` are re-read from the user row on **every** request (`Authenticate` → `activeUser`), so a demotion applies on the next request (403) and disabling deletes the sessions (the old cookie stays refused after re-enabling); the pending password-stage cookie is refused once sign-in completes (§3l, plan 06 §3.1). |
| E2 | App compromise → host compromise | Container | uid 65532, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, no docker.sock, no host network, no `/dev/ipmi0`, only two writable mounts |
| E3 | App compromise → BMC admin | BMC accounts | App holds Operator-level (not Administrator) BMC accounts; no user management, firmware or virtual media privileges |
| E4 | XSS via BMC-supplied strings (SEL messages, sensor names) | Web | `html/template` auto-escaping; strict CSP with nonces; no `innerHTML` in our JS |
| S9 | Admin-entered notification URL used for SSRF (cloud metadata, LAN services, the BMCs) | Notifications | Closed `kind` enum; https only (http and plaintext SMTP only with a per-target opt-in **and** an address in the file-only `notifications.allowed_networks`); private, loopback, link-local, CGNAT, documentation, NAT64/6to4 and reserved ranges refused unless allowlisted; host names resolved once, every answer checked, the checked IP dialled (no DNS rebinding); no proxy, no redirects, 10 s timeout, response read to 4 KiB and discarded; admin + fresh step-up, audited (§3e) |
| I8 | Notification secrets (tokens, user keys, SMTP passwords, HMAC keys) leak | Notifications | AES-256-GCM with an HKDF-derived key (`oob-console/notify/v1`), AAD = target id, kind and URL (a changed destination cannot reuse them); replace-only, never rendered, logged or audited (versions only); file targets read them from the age credential file (§3e) |
| I9 | Data leaks to third-party push services | Notifications | Messages carry server name, signal and severity only; no addresses, serials or URLs; BMC log text only for targets that opt in (`include_detail`, off by default); the ntfy topic/webhook path is shown to admins only and audited as host |
| D6 | Notification floods or a dead receiver stall the app | Notifications | Health/PSU changes debounced (90 s default), one event per change plus its recovery, auth alerts with a 15 min cooldown; per-target bounded queue and token bucket (10, then 1/30 s); bounded retries (4, exponential backoff); a failing target raises a self-alert to the others and a banner on Overview; events never block the audit path |
| R3 | Alerts muted to hide an attack | Notifications | Maintenance mode (operator, audited, timed windows ≤ 7 days or until ended, start and end announced to the targets; an open-ended window is flagged on Overview after 24 h and re-announced once per 24 h while it lasts) suppresses only health, reachability, log and PSU classes; power, BMC restart, console, fan, sign-in, audit-chain and trust events are always sent; acknowledging a log entry is audited and never acknowledges a later entry |
| I11 | /metrics discloses fleet details to a scraper or token thief | Metrics | Off by default (`metrics.enabled`); read-only API token (bearer only, never a session cookie) plus optional file-only `metrics.allow_networks` checked on the TCP peer before the token; labels carry server IDs and names, BMC sensor IDs and names, notification target IDs and build version only. No BMC addresses, URLs, user names, serials, service tags, firmware or licence data unless `metrics.include_inventory: true` (§3f) |
| D7 | Scrapes used to hammer the BMCs or the app | Metrics | A scrape reads cached snapshots only (tested: a real fleet with a counting driver sees no call during 50 scrapes); renders serialised and reused for 1 s; per-token 60/min bucket; per-server lists capped at 64, targets at 64, families at 4096 series (§3f) |
| T9 | The security checks write to a BMC, or are turned into writes (a check "fixing" what it found) | Security checks | The checks read only: Redfish GETs on the poller's own driver (the transport allowlist is unchanged, §3a) and handshake-only probes that send no credentials and no application data (§3g). There is no remediation code path: every "what to do" is text. Tests assert the mock BMCs saw only GET/HEAD and the poller's login, no SSH authentication and no VNC authentication |
| I12 | The probes used as a port scanner, or to reach other hosts (SSRF through a BMC-reported port or redirect) | Security checks | Only the configured BMC address is ever dialled, on the configured Redfish, VNC (never an iDRAC8's: its single-client VNC server stays busy for minutes after each connection) and SSH ports and on the HTTP and SSH ports the BMC reports for itself (any other value falls back to 80/22); redirects are never followed; host names never dialled; dial 5 s, handshake 5 s bounds; the dialer is injected (`env.probeDial`) and refuses every address in tests (§3g) |
| I13 | BMC secrets in the attribute registry (IPMI encryption key, SNMP community strings, password hashes) copied into the app | Security checks | The Dell attribute document is decoded through an allowlist (`attrKeep`); everything else is dropped while decoding and never stored, shown, logged or audited. Fixtures carry `FIXTURE-SECRET-*` markers that tests assert never reach a posture, a finding, a page or the log (§3g) |
| I14 | Security findings (a BMC's weaknesses) read by a viewer, a token or a push service | Security checks | Findings need `server.security.view` (operator); a viewer sees the summary only. The API and `/metrics` carry counts by result, never findings. Notifications name check titles and results from the app's own catalog, never BMC strings, addresses or account names (§3g) |
| T10 | An admin (or a misused admin session) redirects the audit stream to a host of their choosing, to read it or to hide actions from the real log server; or an impostor answers at the log server's address | Settings → Integrations, GELF | Changing the GELF target needs the admin role, a fresh step-up, CSRF and the change limit; `settings.locked: [integrations]` and any key written in config.yaml make it read-only. The address must be inside the file-only `audit.gelf.allowed_networks` (default: the private ranges) and is never loopback, link-local, multicast, broadcast, unspecified, one of the app's own listen endpoints or the address of a managed BMC; a host name is resolved on every dial and refused if any answer fails, and the checked address is the one dialled. **The change is audited before it takes effect**: the `admin.integrations.update` row is committed to the local hash chain first; before the swap the app waits up to 2 s for the previous destination to receive what is queued for it (that row included), and `admin.integrations.applied` (sent to the new destination) records `previous_confirmed`. This is best effort: "received" means written to the connection (GELF has no acknowledgement), and a previous destination that is down never sees it (the page warns before Save). Every target change also raises an `audit` notification (critical when shipping is turned off, TLS is dropped, or the address, pin or server name changes, except a first value set while shipping is turned on, which is a warning; the message carries those public values to the push services), and `oob_audit_shipper_enabled` exposes a switched-off shipper. A refused destination is audited `denied`/`policy`; a fetch and a test write a `started` row before any dial. Rows never carry secrets (params redacted fail-closed). TLS with a pinned SPKI (the leaf, or an issuing CA only when the leaf verifiably chains to it and is valid for the configured server name or address; a publicly trusted CA is not preselected) refuses an impostor before any frame is sent; a mismatch pauses shipping (rows queue, banner, critical `trust` notification, `/readyz` degraded). The fingerprint fetch is handshake-only, policy-checked, 6/min and audited (same reasoning as T8); a host name is fetched at every answer and refused when they present different certificates, so the confirmed pin holds whichever answer the shipper uses. The database copy and its hash chain are unaffected |
| T11 | BMC restart body or target altered (user input reaching the BMC), or turned into a reset to defaults | App → BMC | The only POST target is the manager's own `Manager.Reset` URI (exact regex `^/redfish/v1/Managers/<id>/Actions/Manager\.Reset$`, no `..`, no query or fragment), and it must equal `<manager>/Actions/Manager.Reset` as advertised by the manager that manages the first system; the body is marshalled from a one-field struct with the constant `GracefulRestart`, which the BMC must also list. `Manager.ResetToDefaults`, Dell `ResetToDefaults` and `SetCustomDefaults` never match the policy and nothing in the code names them; only the BMC reset service builds a driver with this policy (§3a sixth exception, §3h) |
| D9 | Repeated BMC restarts used as a denial of service or to blind monitoring and alerting | BMC restart | Admin role + fresh step-up + typed server name + CSRF + 10/min/user; a 10-minute cooldown per server reserved before the BMC is contacted and persisted in `bmc_resets` (survives a restart; kept after a refusal at the BMC, given back only when nothing was sent); one window per server; refused while a power action is being verified and power refused while the BMC restarts. The restart window hides only the expected silence and only until a per-kind deadline (iDRAC8 5 min, iDRAC9 3 min); `stale` stays honest in the API and `/metrics`, the `bmc` notification class (never muted by maintenance) announces the request, and a BMC that does not come back raises a critical `bmc` event and, from the next pass, the usual reachability alarm (§3h) |
| R4 | A BMC restart with no trace, or a trace that claims it came back wrongly | BMC restart | Audit fail-closed: no `bmc.reset` `started` row, nothing happens (no console ended, no login, no POST). Then exactly one final `bmc.reset` row (`ok` with `outcome` sent or `sent_unconfirmed`, `error` with the class, or `denied` for every refusal in the UI and the service), and one `bmc.reset.verified` row by `system` when the window ends (`ok` with the downtime and, on iDRAC9, the BMC's own `LastResetTime`, flagged when it did not move; `error` with `timeout`, `config_changed`, `tls` or `unobserved`). Consoles ended by it keep their own `console.*.stop` rows (`reason=bmc_reset`); all shipped to GELF |
| D8 | The checks hammer the BMC (a run is a few dozen reads and handshakes) | Security checks | One run per server every `security.every` (default 6 h, floor 1 h) on the poller's own session and budget; a re-run needs the admin role, is rate-limited (10/min/user), has a 5-minute cooldown per server and is audited fail-closed (a `started` row before the request, like power); a service the BMC reports off is not probed; the VNC port is left alone while a console session is open, and always on an iDRAC8; a privilege refusal (401/403) is final, so it never churns the session table, and in Basic auth mode it ends the run's optional reads (§3g) |
| T12 | The firmware view turned into a firmware update (an update action called, an image staged or pushed), or BMC text in its CSV executed by a spreadsheet | Firmware view | The scan reads only: `UpdateService/FirmwareInventory` and its member documents with GET on the poller's own driver (transport allowlist unchanged, §3a); no code names `SimpleUpdate`, `HttpPushUri`, `MultipartHttpPushUri`, `StartUpdate` or any `UpdateService/Actions` target, and `internal/repopolicy` fails the build if one appears; the offline catalog interface returns versions, never images or URLs. Every CSV cell goes through `internal/csvx`: valid UTF-8, capped, and a cell starting with `=` `+` `-` `@`, tab or CR (or their full-width forms, also after any Unicode white space) gets a leading apostrophe; plain numbers are left alone; an export is capped at 10 000 rows and 4 MiB and refused (413) rather than truncated (§3i) |
| I15 | Firmware versions (the vulnerability posture of the BMCs and hosts) read by someone without a session, exported in bulk, or exposed by /metrics | Firmware view | Pages need a session with `server.firmware.view` (viewer), the API a read-only token; the CSV needs `server.firmware.export` (viewer, tokens too) and is limited to 6 exports a minute per user or token and 10 000 rows; `/metrics` carries counts by flag and the last scan time only (versions stay behind `metrics.include_inventory`); notifications carry no BMC text outside `Detail`, which only opted-in targets receive (§3i) |
| D10 | Firmware scans hammer a slow BMC (one member document per component) | Firmware view | One scan per server every 24 h (plus at start, after a BMC restart and when the 6-hour inventory lists different versions), under the tier's own cycle budget; at most 64 members; a member document is read once per component (the running state's member), only when the component is new, unnamed, named more than 30 days ago or its running version changed; a scan cut by its budget keeps what it read and continues later; incomplete scans keep at most 128 rows per server and drop components unlisted for 30 days; Re-scan is operator-only, CSRF, 6/min/user, 30 s cooldown per server and folded into one request per server; one notification per scan, not per component; the tier never trips the breaker (§3i) |
| R5 | A firmware change on a BMC (an attacker's implant, an unplanned update) goes unnoticed | Firmware view | Every scan compares running, previous and staged versions with the stored row; a change writes a `firmware_changes` row and an audit row `server.firmware.changed` (principal `system`) in the same transaction, shipped to GELF, and one `security`-class warning notification per scan (staged images too; the rollback copy's change follows the running one and raises nothing of its own). At most 16 changes are stored and audited one by one per scan, plus a summary row with the full count, so a hostile BMC cannot flood the audit chain. An incomplete or empty scan never records a removal (§3i) |
| R6 | Acknowledgements used to hide evidence (an operator acks the entry that shows the attack, before anyone looks) | Event log, notifications | Acknowledging needs the operator role, CSRF and the 30/min annotate limit, and is audited (who, which entry, reason); removing an acknowledgement is audited too. An acknowledgement never deletes or alters the BMC log entry or an audit row: the entry stays listed, marked with who acknowledged it and when. It suppresses the log notification for that exact entry only (log, id and creation time); any new entry still alerts. Maintenance windows (the bigger mute) are R3 |
| R7 | The audit chain rewritten or cut short by someone with write access to the database or a backup | Audit chain, backups | The startup check and `verify-audit` detect an edited row, a gap or a broken link; they cannot detect a full rewrite with every later hash recomputed, or the newest rows removed. The control is off-box: GELF audit shipping (serve and the mutating CLI commands), and comparing the head with the log server's last `row_hash` (runbook drill 7). Without a log server this residual stays (§7 item 6) |
| I19 | The database, its WAL or a backup read by another local user or a backup set (sealed secrets, token hashes, the audit log) | Files under /data, backups | The binary sets `umask 077` first thing in `main`, so the database, `-wal`/`-shm`, the store-install marker and generated keys are owner-only; `backup` writes 0600 explicitly after checking it created a regular file; the runbook restores with `chown 65532:65532` and mode 0600. Secrets inside stay sealed with the app keys, which no backup contains (the age identity never), and tests check the copy for key bytes. Store installs keep `/data/keys` next to the database: the README says to keep it out of volume-level backups (§7 item 8) |
| E7 | The CLI break glass (`admin-recover`) used to take over the app | CLI | Shell access to the container is already full control (the same trust as `bootstrap-admin` and `reset-totp`), and there is no web route. It validates the name before writing anything, shows the account's current state, needs `-yes` or the name typed back, and writes `admin.recover` (with the shell user) in the same transaction, shipped to GELF. It never resets a password or an authenticator |
| T13 | Sensor names (BMC text) in the history's CSV evaluated by a spreadsheet, or in its charts injected into the page | Sensor history | Every CSV cell goes through `internal/csvx` (valid UTF-8, capped, the formula guard of T12); charts are geometry computed in Go (numbers formatted with one decimal) drawn by `html/template`, which escapes every attribute and text; no `template.HTML`, no `style` attribute, no script; names are capped at 128 bytes in the database (§3j) |
| I16 | Sensor history (temperatures, power, fan speeds over two years) read by someone without a session, or exported in bulk | Sensor history | Pages need a session with `server.history.view` (viewer); the API a read-only token; one sensor's CSV needs `server.history.export` (viewer, tokens too), every sensor at once `server.history.export_all` (operator, sessions only). The data is what the pages already show, over time. 6 exports a minute per user (UI) or per token (API, shared with the firmware CSV) on top of the token's 60/min; 100 000 rows per export, refused before writing (413). Downloads are plain reads, not audited (decision); refusals are (§3j) |
| D11 | History growth fills the disk, or long chart and export reads stall the app (one SQLite writer holds the audit chain); a BMC inventing sensor names, or a clock stepped forward, used to grow or wipe it | Sensor history | At most 512 sensors per server (new ones refused, counted in `oob_history_keys_refused_total`, logged once) and per poll 128 temperatures, 32 fans, 16 PSUs and 64 rails, in the sampler and in both Redfish decode paths. Raw samples kept `history.raw_days` (default 7) and at most 1.5 × that many polls at the fastest allowed interval per sensor (a stepped-back clock cannot grow it), hourly rollups 90 days, daily 2 years; prunes run per sensor in statements of at most 5 000 rows, so an audit append waits for one batch at most. Charts, exports and their audit markers read a separate read-only pool (`query_only`, WAL readers never block the writer); exports are sized before writing and streamed in pages of 10 000 rows; requests are bounded (2000 points, 2 years, 16 lines a chart, 200 markers). The WAL is capped back to 64 MiB after checkpoints; no `VACUUM` (freed pages are reused). Prunes and rollups follow the janitor's retention clock, which advances at most twice real time, so a forward clock step or a restart after downtime is caught up gradually and never deletes everything in one pass. Nothing here contacts a BMC (tested: 50 history requests against a polled fleet add no driver call) (§3j) |
| T14 | Tampered or substituted vendor firmware catalog (network attacker, compromised or misconfigured mirror) hides an urgent update or invents one | Firmware update check (plan 08) | https to a file-only URL with system roots, no redirects, the `internal/egress` policy; detached OpenPGP signature over the compressed file checked **before** anything is decompressed, against Dell's pinned key (fingerprint constant) and the file-only `extra_keys_file`; a stdlib-only verifier (one v3/v4 signature packet, issuer must be a trusted primary key, SHA-1 only for the legacy Dell key, sane key parameters); fail closed with the last good catalog kept; a catalog keeping far fewer rows than the one in use is held until an admin confirms (step-up); signer and sha256 audited. Residual: DSA-1024/SHA-1 key strength (TLS is the primary control) and no freshness (an older Dell-signed catalog would verify; replaying it online needs a TLS break) |
| I17 | The outbound catalog request discloses the fleet | Firmware update check | Off by default (Settings toggle, admin + fresh step-up, audited; a config.yaml key locks it); the whole catalog is downloaded, no model or component in the URL or headers; generic User-Agent; conditional GET with the server's own ETag |
| D12 | Decompression or XML bomb, huge, slow or malformed catalog exhausts memory or CPU | Firmware update check | 16 MiB compressed (announced and streamed), one gzip member, 128 MiB decompressed (fails, never truncates), 1 MiB between markup, depth 16, attributes 4 KiB, text 64 KiB, 20 000 components, 256 devices / 512 models / 256 PCI IDs per component, 100 000 kept entries, 60 s parse, 120 s download, 30 s stall; no DTD or entities; strict UTF-16 transcoding; one worker, Check now once per 5 minutes globally; measured 4.4 MiB peak heap on Dell's 22 MiB catalog; fuzzed |
| S10 | An admin-set catalog URL used for SSRF into the LAN | Firmware update check | The URL, trusted keys and allowed networks are config.yaml-only (a browser session can only switch the configured, signature-checked source on or off); https only; `internal/egress` (public unicast unless allowlisted, resolved once, the checked IP dialled); the fetcher takes no URL argument, so a package path from the catalog can never be fetched (rule 11) |
| E5 | A stolen admin session uploads a crafted catalog, skips an urgent update, or turns the online check on | Firmware update check | Upload, held-catalog confirmation, skips and the toggle need admin + a fresh step-up, CSRF, rate limits, and are audited; an upload is signature-checked unless the file-only `allow_unsigned` is set (then labelled "unsigned catalog" everywhere); worst case is wrong flags, never an action on a BMC (the update check has no BMC handle) |
| S11 | A LAN neighbour claims an install with no account yet (a fresh store-style install, or a configured one whose admin was never bootstrapped) before its owner | First-run setup (plan 09) | `/setup` exists only while the users table is empty and needs the one-time code printed in the container log (owner-only access): 160 random bits, only its SHA-256 kept in memory, constant-time compare, 24 h expiry, single use (burned when the admin exists; a claim is held while the account is created, released on any unsettled exit, including a recovered panic), its own per-IP limit separate from the sign-in limits (a setup flood cannot lock out sign-in, nor failed sign-ins the claim), CSRF, every attempt audited (`setup.claim`; a rate-limited refusal once per address a minute, so a flood behind a shared proxy address cannot fill the audit log); `CreateFirst` inserts only `WHERE NOT EXISTS`, so concurrent claims make one admin |
| T15 | A broken mount makes an existing install start "fresh" with new keys, orphaning every sealed value, or start on built-in defaults (a new self-signed certificate, file-only settings dropped) | Store install (plan 09) | A path set in config.yaml is never replaced (missing = startup error), even one naming the data volume's own key file; a missing config.yaml runs on defaults only for a fresh or marked store volume (`<data>/store-install`), an unmarked database with sealed data refuses, `-config=none` is the explicit, ERROR-logged opt-in; `serve` refuses a config.yaml without a `tls` block (a generated certificate is only for an install without config.yaml; the CLI never uses the certificate and still runs); keys are generated only for defaulted paths whose mounted defaults are absent, when the data volume holds no key set **and** the database holds no users, BMC credentials, notification targets or API tokens; otherwise startup refuses; half a key set or certificate pair also refuses |
| I18 | Generated keys readable by other local users, half-written, or lost | Store install | Identity and app keys 0400 in a 0700 directory owned by the app user, written in a temporary directory and renamed into place (fsynced); an admin banner and a log warning at every start until the backup is acknowledged (`keys.backup_acknowledged`); documented trade-off: an identity in the data volume travels with its backups, so installs that can keep it elsewhere mount it instead; the acknowledgement is audited first and not done if the audit write fails |
| E6 | The setup code leaks beyond the administrator | First-run setup | Logged once per start, only while no account exists; never in a URL (no history or Referer), never audited or echoed back into the page; restart rotates it; harmless once the first admin exists. Residual: anyone with `docker logs` (or a log driver forwarding container output) sees it for up to 24 h; the audit shipper (GELF) carries audit rows only, not this line |

**No new threat, recorded for completeness (plan 06 §3.7):** per-user display preferences (time zone,
theme, formats) only change rendering and are validated against closed sets; the second, read-only
SQLite connection (history charts, the audit page, `verify-audit`) is `query_only` with `trusted_schema`
off and shares the writer's `busy_timeout`, so a long read can delay a write by at most that timeout,
never corrupt it; the decision to have no CSP report endpoint (§3) removes an attack surface rather than
adding one.

## 3. Web controls (concrete)

- **CSP:** `default-src 'none'; script-src 'self' 'nonce-{n}'; style-src 'self'; img-src 'self' data:;
  connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`.
  noVNC and xterm.js are served from `'self'`. **noVNC 1.7.0 needs neither `unsafe-eval` nor
  `'wasm-unsafe-eval'`** (no eval, no WebAssembly; its H.264 decoder uses WebCodecs), so the CSP
  is unchanged on the console page: the page loads one module script from `/static/console.js`
  (no inline script), noVNC sets element styles through the CSSOM (allowed by `style-src 'self'`),
  and `connect-src 'self'` covers the same-origin `wss:` WebSocket.
- **Go to palette** (`palette.js`, tech_doc §52): the one script with free-text input outside a console. It
  reads only the destination list the server rendered for this user (an inert `<template>`), the page's tab bar
  and its own recent list; it navigates to same-origin paths that pass a strict pattern and nothing else: no form
  submission, no `fetch`, no `innerHTML`. The recent list is in `sessionStorage` (paths without query strings,
  titles, at most six, bound to the username, removed at sign-out) and only for pages the server marks
  (`<meta name="oob-recent">`: never a reveal, confirm, step-up, console or error page). CSP unchanged.
- **Headers:** HSTS (when TLS), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` empty set, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`.
- **Cookies:** `__Host-oob_sid`, `Secure; HttpOnly; SameSite=Strict; Path=/`; server-side
  sessions (random 256-bit ID, stored hashed); idle 30 min, absolute 12 h; rotated on login
  and step-up.
- **Step-up ("sudo mode"):** dangerous actions require a TOTP entered ≤ 5 min ago: power, a BMC
  restart (`bmc.reset`, admin), fan leases, the consoles, every Settings change (users, tokens, general, servers, notifications, integrations) and
  accepting a BMC security finding as a risk or taking that back (`server.security.accept`, §3g). TOTP
  codes are single-use (last accepted step stored).
- **Rate limits:** login 5/min/IP and 10/h/account; actions 10/min/user; power cooldown 60 s
  per server; BMC restart cooldown 10 min per server; API tokens 60/min. Every route is in the
  table in §3k.
- **No CSP report endpoint (plan 06 §3.4).** A `report-to`/`report-uri` receiver would be the
  app's first *unauthenticated POST endpoint* that any LAN client can flood or spoof, and D1 values
  having none. The CSP is static and tested instead: the page matrix in `tests/e2e/pages.spec.ts` (helpers in `csp.ts`) listens for
  `securitypolicyviolation` on every page and fails on any violation outside its allowlist (only
  xterm.js's injected `<style>` on `/servers/*/serial`). Rejected alternative, if telemetry is ever
  wanted: `Content-Security-Policy-Report-Only` with a receiver capped at 4 KiB, 5/min/IP, counting
  only (no storage, no body logging).
- **Tokens, enrolment and TOTP resets (settings S1):** an admin with a fresh step-up (TOTP
  within 5 min) can mint and revoke API tokens and invite users or force an authenticator reset
  in Settings; the CLI (`token create|revoke`, `reset-totp`) stays as the shell path. A token is
  shown once on a `no-store` 200 page (never a redirect) and only its hash is stored. Users are
  invited by a one-time link (`/enroll/<token>`, 256-bit, SHA-256 stored, 24 h, single use in
  SQL, 5/min/IP); the link is the credential: it sets the password and shows the new TOTP secret
  once, after which the user confirms a code. Tokens are read-only, revocable and may expire
  (≤ 730 days). Every change commits in one transaction with its audit row; refusals are audited;
  audit params are redacted fail-closed; link tokens are redacted from logged paths. The last
  enabled admin cannot be demoted or disabled and no admin can change their own role, disable
  themselves or reset their own authenticator in the browser (enforced in the SQL UPDATE).
- **Compression and BREACH (tech_doc §32):** text responses are gzipped (`web.Compress`). BREACH
  needs a secret and attacker-chosen text in the same compressed response, many requests sent with
  the victim's cookies, and the response sizes observed. Here the secret is weak to begin with: the
  CSRF token is `ts ‖ HMAC(form ‖ session ‖ ts)` with `ts` in seconds, so it changes every second
  and cannot be recovered byte by byte across requests; the session cookie is `SameSite=Strict`,
  so a cross-site request carries no session and its page holds no token; and
  `http.CrossOriginProtection` refuses cross-origin POSTs. As defence in depth, **HTML is compressed only
  when it is a successful answer to a GET without a query string**: a query can be echoed next to a
  CSRF token (the Events search box and its acknowledgement forms' `back` field, the step-up page's
  `next`), an error page can echo the request path (the 404 for an unknown URL renders the signed-in
  layout, whose theme form carries the path and a token), and a POST answer can hold a one-time
  secret (enrolment, API token, console ticket). Static assets and JSON stay compressed; `Vary:
  Accept-Encoding` is always set.
- **Integrations (tech_doc §34, threat T10):** the GELF target is changed through the same
  `change()` chain (admin, fresh step-up, CSRF, 10/min); Fetch and confirm is a probe at 6/min
  (refused while the section is locked) and Send test 3/min; the confirm page is `no-store` and each
  offered pin carries its own session-bound 5-minute proof for the address and value. The page's
  dashboard snippets carry a `<token>` placeholder, never a token.
- **UI TLS:** `serve` fails fast without a certificate pair and serves only TLS on one port
  (no plain-HTTP listener, no redirect port). `gen-tls` makes a self-signed ECDSA P-256 pair
  (≤ 825 days, key 0600) until it is replaced with your own CA's certificate.
- **Input validation:** every route has a typed request struct with explicit validation
  (enums, ranges, server IDs from config only). Nothing user-supplied reaches a BMC URL
  path, IPMI raw byte, or SSH command. Server IDs are looked up, never interpolated.

## 3a. BMC transport (Redfish)

- **Method allowlist (enforced in the HTTP transport, before any byte leaves the app):**
  GET to any `/redfish/v1/...` path; **POST only** to the sessions collection named by the
  service root's `Links.Sessions` (for example `/redfish/v1/Sessions` on iDRAC8 or
  `/redfish/v1/SessionService/Sessions` on iDRAC9), and only after it was discovered;
  **DELETE only** to the exact URI of the session this app created (`Location` or
  `@odata.id`, validated as `<collection>/<one segment>` on the same host). Every other
  method, path, query string or fragment is refused with `ErrMethodNotAllowed`. These two
  exceptions to "read-only" exist only so the app can log in once and log out. They write
  nothing else on the BMC.
- **Third exception (P5): POST to Dell `GetKVMSession`.** Only the iDRAC9 native console launcher
  builds a driver with an action policy (`redfish.WithActionPolicy(dellredfish.IsKVMActionURI)`),
  using the **operator** account. The policy accepts exactly
  `/redfish/v1/Managers/<id>/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.GetKVMSession`
  (or the older `/redfish/v1/Dell/Managers/<id>/…` form), and the launcher posts only to the target
  the card service itself advertises under that service. The pollers' drivers have no policy, so
  they still cannot POST anything but their login. The launcher logs in, posts once, logs out.
  Admin role + fresh step-up + CSRF + 10/min/user, audited as `console.kvm_launch`.
- **Fourth exception (P2): POST to `ComputerSystem.Reset`.** Only the power service builds a
  driver with the reset policy (`redfish.WithActionPolicy(redfish.IsResetActionURI)`), with the
  **operator** account. The policy accepts exactly `/redfish/v1/Systems/<id>/Actions/ComputerSystem.Reset`
  (`<id>` = 1–64 of `[A-Za-z0-9._-]`), and the resetter posts only to the target the system
  advertises, which must equal `<system URI>/Actions/ComputerSystem.Reset`. The body is
  marshalled from a one-field struct, so it is exactly `{"ResetType":"<value>"}`, with the value
  from the closed set `On, GracefulShutdown, GracefulRestart, ForceOff, PowerCycle, ForceRestart`
  that the BMC also lists in `ResetType@Redfish.AllowableValues`; anything else is refused
  before a byte is sent. It logs in, posts once, reads `PowerState` while verifying, and logs
  out. A 401 on the POST is not retried.
- **Fifth exception (P3): PATCH of the iDRAC9 fan floor.** Only the `redfish-floor` fan applier
  builds a driver with `redfish.WithAttributePatch(/redfish/v1/Managers/System.Embedded.1/Attributes,
  ThermalSettings.1.MinimumFanSpeed)`, using the **operator** account (needs *Configure*). The
  transport allows PATCH to that one URI only, and `PatchAttributes` refuses any key but that one
  attribute and any value but 255 or 1–100 before a byte is sent; the value is clamped to the
  iDRAC's own `MFSMinimumLimit`..`MFSMaximumLimit` and to `safe_min_pct`. Each read or PATCH logs
  in, does one request and logs out. The pollers never get this option. Operator role + fresh
  step-up + CSRF + 10/min/user, audited as `fan.lease.create` / `fan.lease.end`, with the restore
  at expiry audited as `fan.lease.expire` (principal `system`).
- **Sixth exception (tech_doc §37): POST to `Manager.Reset`.** Only the BMC reset service builds a
  driver with the manager reset policy (`redfish.WithActionPolicy(redfish.IsManagerResetActionURI)`),
  with the **operator** account. The policy accepts exactly
  `/redfish/v1/Managers/<id>/Actions/Manager.Reset` (`<id>` = 1–64 of `[A-Za-z0-9._-]`, no `..`), and
  the resetter posts only to the target advertised by the manager that manages the first system
  (`Links.ManagedBy[0]`, else the first Manager, as the probe), which must equal
  `<manager URI>/Actions/Manager.Reset` and list `GracefulRestart`. The body is marshalled from a
  one-field struct with a constant, so it is exactly `{"ResetType":"GracefulRestart"}`; `ForceRestart`
  is never sent. It logs in, posts once and logs out; the logout is allowed to fail when the BMC is
  already restarting (unreachable, timeout, 5xx, or the 401/404 of a dropped session). A 401 is not
  retried; a 403 is reported as a privilege refusal. The pollers, the power resetter and every other
  driver cannot POST this URI (tested: refused before a byte is sent).
- **Why sessions:** HTTP Basic makes the BMC authenticate every request. Measured on an iDRAC8
  (fw 2.86), that took 5.5–9.5 s per GET, so every poll timed out. A session login takes
  about 6.6 s once, and then GETs take 1–3.4 s. One session per server also keeps the
  BMC's small session table free (D4).
- **Credentials and the token:** the password is read from the age file into a
  `secrets.Secret`. It leaves the Secret only in the login body (sent once over the
  pinned TLS connection) or, in `bmc.auth: basic` mode, in the Basic header. The
  X-Auth-Token is also a `secrets.Secret`, so it is redacted in every format, log and JSON
  path. Neither the token nor the password appears in errors (error strings carry the method,
  URI and status class only).
- **Lifecycle:** the app logs in on first use. After a 401 it logs in again once per request
  (500 ms backoff, then one retry; a second 401 is returned as an auth failure, so the
  app never retries in a loop). It DELETEs the session at shutdown (bounded at 10 s) and
  when credentials change. If the app is killed, the BMC's session timeout reclaims the
  session.
- **Basic fallback:** set `bmc.auth: basic` per server for a BMC without a SessionService.
  In that mode no session POST or DELETE is sent; the action POSTs above (KVM launch, power)
  are the only writes and carry Basic auth.
- **Security checks (§3g) added no exception.** Their Redfish reads are GETs on the poller's own
  driver and session. `ReadOptional` is a GET whose 401/403 is final (no re-login, no retry), so a
  resource the read-only account may not read costs one request and no session.

## 3b. Graphical console (P5)

- **Model:** noVNC (browser) ⇄ WSS ⇄ app relay ⇄ TCP+TLS (SPKI pin) ⇄ BMC VNC server. The app
  performs RFB VNC authentication with the BMC (RFC 6143 §7.2.2, stdlib `crypto/des`) and runs a
  None-only handshake towards the browser.
- **Tickets:** `POST /servers/{id}/console` (CSRF, admin, fresh step-up, rate limit) mints a
  256-bit ticket, stored only as SHA-256, valid 30 s, single use (a failed redemption burns it),
  bound to a hash of the session cookie and to the server. It is rendered once on a `no-store`
  page and read by the page script. The WebSocket upgrade re-checks cookie, role, step-up and
  Origin before the broker redeems the ticket.
- **One console per server.** A second request is refused with "in use by <user> since <time>";
  an admin can take over (`console.vnc.takeover`, audited with the previous user and duration).
- **Running session:** every 10 s the relay re-authenticates the session (logout, idle/absolute
  expiry and rotation end the console), re-checks the role, and, with
  `console.close_on_stepup_expiry: true`, ends it when the step-up window lapses (default off:
  a 5-minute console would be unusable; the step-up is required to open or take over). Idle
  = no keyboard, pointer or clipboard input. App shutdown ends every console and writes its
  stop row before `app.stop`.
- **BMC protection:** a rejected VNC password starts a 60 s cooldown (no retry loop that could
  lock the account); the banner probe never authenticates; a server with an active console is
  not probed.
- **VNC DES weakness:** anyone who records one challenge/response pair can brute-force the
  ≤ 8-byte password offline, and plain RFB carries screen and keystrokes in clear. TLS to the
  VNC port with a pin is the default and is required on any network that is not trusted end to
  end. The password is per BMC and exactly 8 random characters.
- **No downgrade:** with `console.vnc.tls: true` the relay and the banner probe only ever
  speak TLS. Some BMCs (iDRAC8) answer a client that sends no ClientHello with a plain RFB
  banner even when VNC SSL is on; the app never falls back to that, so a TLS failure is
  reported as a TLS mismatch, never as "ready", and no plaintext session is opened.
- **iDRAC8 VNC TLS has no forward secrecy:** iDRAC8 2.8x offers only TLS 1.2 RSA
  key-exchange suites on the VNC port. The `idrac8_rsa_kex_tls` quirk (iDRAC8 default) allows
  RSA-kex AES-GCM after the ECDHE suites, on the VNC dial only (never the web/Redfish
  transport), and is logged once per server at startup. The SPKI pin still authenticates the
  BMC, but anyone who later obtains the iDRAC's private key can decrypt recorded console
  traffic. Keep the management network restricted.
- **Fail closed:** no console starts without its `console.vnc.start` audit row.

## 3c. Power control (P2)

- **Authorization:** safe actions (`power.on`, `power.graceful_shutdown`, `power.graceful_restart`)
  need the operator or admin role; forced actions (`power.force_off`, `power.cycle`,
  `power.force_restart`) the admin role. Both need a fresh step-up (inline code on the confirm
  page, which names the action and server). API tokens never reach them (authz matrix test).
- **Order of checks on POST** `/servers/{id}/power/{action}`: session → server and action from
  the path (404 otherwise) → CSRF (form `power`, bound to the session) → availability (BMC lists
  the reset type, operator login configured, role, cooldown) → `confirm=yes` → typed name →
  step-up → authorization with the fresh step-up → 10/min/user → service. The service then
  audits `started` (fail-closed), reserves the cooldown, logs in, re-reads AllowableValues and the
  live `PowerState` (refuses `On` when on and the others when off), posts, and verifies.
- **Credentials:** the operator login is used only for the reset session; it is never the
  read-only poller account. Without it the actions are disabled with that reason.
- **Long requests:** the reset runs detached from the page's 25 s deadline so a slow BMC login
  cannot cut it in half; if the page deadline passes first the browser is sent to the
  Operations tab, which shows the operation as "Sending".
- **Self-host:** the server oob-manager runs on (`power.self_host`) gets an explicit warning,
  and every take-down needs the typed name; after it is off the app cannot power it back on.
- **Residual:** a BMC that accepts a reset and then does nothing is reported as failed after
  the timeout, but the app cannot know whether the host OS ignored a graceful request or the
  BMC lied. A restart faster than the poll interval is reported as unconfirmed.
- **Not built:** IPMI chassis control (task 2.2); `kind: ipmi` servers have no power actions.
## 3d. Serial console (P4)

- **Model:** xterm.js (browser) ⇄ WSS (subprotocol `oob-serial.v1`) ⇄ app broker ⇄ SSH (pinned host
  key) ⇄ BMC `console com2`. The app logs in with the operator account; the browser never sees it.
- **Tickets, one session, running-session checks, takeover, shutdown and fail-closed audit** work as in
  §3b, with separate tickets and slots (a serial ticket cannot open a graphical console). Actions:
  `console.serial`, `console.serial.takeover` (admin + fresh step-up); audit `console.serial.start/stop/takeover`.
- **What the browser can send:** keystrokes (≤ 4 KiB per message, Ctrl-\ removed) and three control
  messages. Anything else ends the session (`protocol`). The quit control writes Ctrl-\ and the app closes
  the SSH connection immediately, so even if a firmware returned to a shell after `console com2`, no input
  would reach it.
- **SSH algorithms:** x/crypto's non-insecure sets only. `idrac8_legacy_ssh` (iDRAC8 default) adds
  `ssh-rsa` (SHA-1 host signature, RSA pins only) and `diffie-hellman-group14-sha1`; it is logged per server
  at startup and shown on the card. Both are weak but not broken for this use: the host key is still pinned,
  and the management network is restricted.
- **BMC protection:** a rejected login starts a 60 s cooldown. The only periodic SSH connection is the
  security checks' probe (§3g, every `security.every`): it reads the banner and KEXINIT and closes before
  any authentication, so it costs no login and cannot count against the BMC's session table or lockout.
- **CSP:** unchanged. xterm.js's injected `<style>` elements are blocked by `style-src 'self'`; the same
  rules ship in `serial.css`.

## 3e. Notifications (tech_doc §26)

- **Sources:** the poller state (read every 15 s from the published snapshots, never a BMC call) and the
  audit trail (a tap on the audit sink). Nothing a request supplies reaches a receiver except an admin's
  target configuration.
- **Destination policy (SSRF):** see S9. `notifications.allowed_networks` is file-only, so a browser
  session cannot widen it. The dialer gets only the policy-checked IP literal; TLS still verifies the
  certificate against the URL's host name (system roots, TLS 1.2+). A redirect is a failure.
- **SMTP:** STARTTLS is required when chosen (a server that does not offer it fails; no downgrade);
  implicit TLS on 465; plaintext only on an allowlisted LAN relay and never with AUTH.
- **Changes:** admin + fresh step-up (`admin.notifications.manage`), CSRF, 10 changes/min, test sends
  3/min/user; every create, update, delete and test is audited with the target id, kind,
  host and changed field names. Secrets appear only as `[redacted] vN`.
- **Webhook signing:** `X-OOB-Signature: sha256=HMAC(secret, timestamp + "." + body)` with
  `X-OOB-Timestamp`; receivers should reject old timestamps (replay) and compare in constant time.
- **Residual:** a receiver controlled by an attacker learns the server names and event timing of the
  targets it receives; a maintenance window hides health alerts for its duration (by design; its start and end are
  announced, and an open-ended one is shown on Overview after 24 h and reminded once a day, so it cannot be
  forgotten silently). `/metrics` keeps reporting the real health of a server in maintenance. Server notes are plain text rendered through html/template (links: http(s) only,
  `rel="noopener noreferrer"`); their text is not audited.

## 3f. Prometheus metrics (tech_doc §29)

- **Off by default.** `metrics.enabled` lives in config.yaml only; a disabled endpoint answers 404 like
  any unknown path.
- **Auth model.** A scrape needs an active read-scope API token as `Authorization: Bearer`. The route is
  authorized as `fleet.view` for a token principal, which the matrix already grants every read token
  and which can never reach an operator or admin action. Session cookies are not read on this path, so
  a browser (or a CSRF from one) cannot scrape. A dedicated `metrics` token scope was considered and
  deferred: `api_tokens.scope` has `CHECK (scope = 'read')`, so it needs a migration. Mint a separate
  token named for the scraper so it can be revoked on its own.
- **Network allowlist.** `metrics.allow_networks` (CIDRs or IPs, file-only) is checked against the TCP
  peer before any token is looked at, so a token cannot be guessed from outside it. `X-Forwarded-For`
  and similar headers are ignored. Empty means any address.
- **What the labels expose.** Server IDs and display names; BMC sensor/fan/PSU member IDs, display
  names and physical context; notification target IDs (not names, URLs or hosts); login stage names;
  app version, commit and Go version. No BMC addresses, credentials, user names, URLs, SEL message
  text, serial numbers, service tags, firmware versions or licence data. Those identifiers appear only
  with `metrics.include_inventory: true`, as `oob_server_info` labels. Counts that a token holder learns
  beyond the JSON API: failed sign-ins by stage, audit chain state, console sessions open now,
  notification delivery counters, whether a server is in maintenance (and until when) and how many
  log entries are unacknowledged. None names a user or an address; maintenance reasons, notes and
  acknowledgement comments are never exported.
- **Hostile BMC strings.** Label values from BMCs are sanitized (invalid UTF-8 replaced, control
  characters removed, 64-byte cap on a rune boundary) and escaped (`\`, `"`, line feed), so a sensor
  name cannot inject series or break the format. Tested with a strict line parser.
- **Cost bounds.** No BMC call (cached state only); renders serialised and reused for 1 s; the token's
  API rate limit applies; cardinality caps, with `oob_scrape_series_dropped` reporting anything left out.
- **Residual:** a stolen scrape token reveals server names, sensor values and the timing of sign-in
  failures until it is revoked. Use `allow_networks` and an expiry.

## 3g. BMC security checks (tech_doc §31)

- **Read-only by construction.** The Redfish part of a run is GETs on the poller's driver (§3a: the
  method allowlist did not change). The network part (`internal/secprobe`) never sends a credential or a
  byte of application data: on the web port a TLS handshake with the app's own settings and seven
  variants (TLS 1.0, 1.1, 1.2, 1.3 alone; RC4/3DES, RSA key exchange and ECDHE suites alone), spaced 150 ms
  apart; on the VNC port one handshake only (the certificate is all that is read there, and the BMC takes
  one VNC client), stopped if a console session opens meanwhile, and none at all on an iDRAC8; the SSH banner and KEXINIT, then close,
  before any authentication; `HEAD /` on the plain-HTTP port (`GET` only after a 405/501) with redirects
  not followed; `HEAD /wsman` and `HEAD` of a control path, only over a TLS connection whose key matched
  the pin. The HTTP client's transport refuses every method but HEAD and GET before a byte is sent
  (tested). Offering a weak suite or an old TLS version is the point of a probe (it learns whether the BMC
  accepts it); nothing is exposed because no data follows the handshake. A variant counts as refused only
  on a TLS alert that means refusal (protocol_version, handshake_failure, insufficient_security); any other
  alert, a reset, a closed connection or a timeout leaves it unknown, and a port
  that will not accept, alone, the version it had just negotiated has every variant marked unknown, so a
  web server that drops connections can never produce a false pass.
- **Only the configured BMC is dialled.** Address and Redfish port from the validated config; the VNC port
  and its pin from `console.vnc` (only when the graphical console is VNC over TLS, never on an iDRAC8); the serial console's
  SSH port, else the SSH port the BMC reports, else 22; the HTTP port the BMC reports, else 80. A port
  the BMC reports outside 1–65535 falls back to the default. Host names are never dialled and redirects
  never followed, so a BMC cannot point the app elsewhere. The dialer is injected (`env.probeDial`); every
  env built without one refuses all addresses, and the e2e harness maps the TEST-NET addresses to fakes.
- **No IPMI, SNMP or Telnet packets, no login attempts.** IPMI cipher suite 0 is reported as unknown on
  iDRACs; factory passwords are never tested (`acct.default_names` says so in its evidence).
- **Privilege refusals are final.** A 401/403 on an optional resource marks the section "can't read with
  the read-only account" without a re-login, so a ReadOnly account that may not read AccountService or
  the attribute registry costs one request per run and no session. In Basic auth mode (`bmc.auth: basic`),
  where every request carries the password and a BMC may count each refusal as a failed login, the first
  401/403 ends the run's optional reads: the sections after it are skipped, with the reason, and nothing
  else is requested until the next run. Whether iDRAC8 2.86 and iDRAC9 7.00 allow those reads is untested
  on hardware; the app never asks for more privileges. A lockout duration over a year (or one that would
  overflow a duration) is not taken as a fact.
- **What is kept from the BMC.** The Dell attribute document is decoded through an allowlist; the IPMI
  encryption key, SNMP community strings and password hashes are dropped while decoding and never stored.
  Every string from the BMC (user names and roles, NTP and syslog servers, certificate names, firmware,
  BIOS and licence text, the SSH identification string and algorithm lists) goes through the one sanitizer
  `internal/bmc/textclean.Clean`: invalid UTF-8, control characters (Cc), format characters (Cf: zero-width
  spaces and joiners, bidirectional embeddings and overrides, the byte order mark, soft hyphens) and the
  line and paragraph separators (Zl, Zp) are removed, the result is trimmed and capped on a rune boundary
  (64 bytes for account names, roles and Dell attribute strings, 200 for certificate names, 1024 for other
  Redfish fields), then rendered through `html/template`. Look-alike letters (a Cyrillic о in "root") are
  graphic characters and stay: the account evidence shows any name that is not plain ASCII in Go's quoted
  form (`"rоot"`) so it cannot pass for the real one, and the factory-name check compares the
  sanitized name. Catalog text (titles, why, what to do) is the app's own.
- **Who sees what.** The tab needs `server.view`; the findings need `server.security.view` (operator), a
  viewer gets the summary (verdict and counts). Re-run and accept need the admin role, go through
  `annotate()` (session, CSRF, 30 changes/min/user, refusals audited) and are audited with the check,
  result and comment (`server.security.accept`, `.unaccept`, `.rerun`); accepting a risk or removing an
  acceptance also needs a **fresh step-up** (it silences a finding; a stale step-up is sent to `/stepup`
  and audited `stepup_required`), the re-run does not (it only reads) and has a 5-minute cooldown per
  server. `/metrics` exports counts by result and certificate expiry timestamps only. Notifications
  (class `security`, normal priority, never paused by maintenance) name check titles and results from the
  catalog, with no BMC strings, addresses or account names; `security_notified` stores subject hashes, not
  subjects. New findings are sent as **warnings** (every new finding is a warning or a failure) so a target
  at the default `min_severity: warning` receives them; the 14-day certificate reminder is info (the 7- and
  1-day ones are warnings). An accepted risk raises a `security` **warning** naming who accepted which check
  (`security/accept/<server>/<check>`), and an acceptance that ends (removed, resolved, changed, server
  changed) an **info** event, both through the audit tap, so an acceptance can never be silent. The admin's
  comment is free text: like BMC text it travels in the event's `Detail`, which only targets with
  `include_detail` receive, and `CleanComment` rejects control characters and strips format characters
  (zero-width, bidirectional) before it is stored, audited or sent.
  **Subscriptions:** a target whose `classes:` list is empty or absent in config.yaml (or that has every
  box ticked in the browser form, the default) receives *every* class, which now includes `security`:
  new findings per run, the certificate reminders and the acceptance events, filtered only by its
  `min_severity`. To keep a target out of it, list the classes it should get without `security` (file) or
  untick the class (browser); that semantics did not change, only the set of classes grew.
- **Accepted risks** bind to the check, the result, the SHA-256 of the whole subject (a certificate
  fingerprint, the account list, a firmware version; the stored `subject` is a clipped display copy) and
  the BMC address and port the server had when the risk was accepted. The accept form carries the finding
  as the page showed it (`seen`: result and subject hash); the service re-evaluates under its write lock
  and refuses a finding that changed since, re-rendering the tab with a notice, so an admin never accepts
  what they did not look at. A changed or resolved finding, or a server moved to another address, ends the
  acceptance automatically (audited as `system`, reason `changed`, `resolved` or `server changed`), and
  removing a browser-managed server deletes its acceptances and notification state in the same
  transaction, so an acceptance cannot silently cover a different problem or a different BMC.
- **Residual:** a BMC may log each probe as a failed TLS handshake or an SSH connection closed before
  authentication (per run, every 6 h: eight handshakes on the web port, up to one on the VNC port (none on an iDRAC8), one SSH
  connection, one or two plain-HTTP requests and two `HEAD`s). The checks observe; they cannot repair a BMC
  or detect a factory password.

## 3h. BMC restart (tech_doc §37)

- **Authorization:** `bmc.reset`, admin + fresh step-up, sessions only (an API token never reaches it,
  authz matrix test). The typed server name is always required: the blast radius (monitoring blind
  for minutes, every console closed) is that of a forced power action.
- **Order of checks on POST** `/servers/{id}/bmc/reset`: session → server from the path (404
  otherwise) → CSRF (form `bmc`, bound to the session) → availability (the probe saw the manager's
  own `Manager.Reset` with `GracefulRestart`, operator login configured, role, no restart window open,
  no power action still being verified, no sticky privilege refusal, the cooldown) → `confirm=yes` →
  typed name → step-up → authorization with the fresh step-up → 10/min/user (key `bmc:<user>`) →
  service. The service checks again (target, operator, power interlock, window, another request in
  flight, cooldown reserved and the server marked busy, so power requests are refused from here on,
  during the login and discovery too), writes `started` (fail-closed), logs in, opens the fleet's
  restart window and stores the `bmc_resets` row (both stamped just before the POST, so a crash keeps
  them), ends every console on the server, then posts once. A POST that gets no answer (timeout, or
  the connection lost after the request was written) is treated as sent but marked unconfirmed: only
  a newer `LastResetTime` then confirms the restart.
- **While the BMC is away:** the poller waits 60 s, then polls every 30 s; failures are not counted
  for the breaker and set no "unreachable since"; the detector raises no reachability event. The
  window ends when a poll succeeds (the inventory tier runs at once, the row becomes `verified`), at
  the per-kind deadline (`timeout`: normal failure accounting starts, so the alarm follows), when the
  server's connection settings change (`config_changed`) or when its certificate no longer matches the
  pin (`tls`, polling pauses). An app restart during the window re-arms it from the row.
- **Privilege refusal (403):** sticky "the operator account lacks the privilege" until a reset
  succeeds, a hot apply (any registry or settings change) or an app restart; the cooldown is kept, so
  there is no retry loop. Granting *Configure iDRAC* to the operator account widens what the app's
  account can do; it is the same privilege the `redfish-floor` fan mode already needs on iDRAC9 (§4).
- **Hostile or broken Manager documents:** the reset action and `LastResetTime` are read field by
  field; a wrongly typed value means "not offered" / "unknown" and never breaks discovery or polling.
- **Residual:** a BMC that answers 204 and does nothing is reported as verified at the next poll
  unless it reports `LastResetTime` (iDRAC9, judged only on a probe taken after the POST), where an
  unchanged value is flagged; on iDRAC8 the app cannot tell. The window (at most 15 minutes, also a
  database CHECK) hides a real outage that starts at the same moment for up to the deadline.

## 3i. Firmware view (tech_doc §38)

- **Read only, no new privilege:** the scan runs on the poller's driver and session with the
  read-only account: GET of `UpdateService/FirmwareInventory` (one request) and, for the components
  that need it, one member document each. No transport exception, no write, no Lifecycle Controller
  job; firmware updates stay out of scope (CLAUDE.md rule 11) and a repository policy test refuses
  any update identifier in the Go sources. Tests assert the mocks saw only GETs besides the login.
- **Nothing user-supplied reaches a BMC:** Re-scan takes only the server ID from the path (looked up in
  the fleet) and marks the poller's firmware tier due; the filter values (server, kind, flagged, text)
  only select rows in memory and are checked by shape (400 otherwise).
- **Authorization:** `server.firmware.view` and `server.firmware.export` (viewer, tokens too, like the
  inventory); `server.firmware.rescan` (operator, sessions only, CSRF, 6/min/user plus 30 s per server,
  refusals audited, no step-up because it changes nothing). Re-scans are audited fail-closed: `started`
  before the poller is asked, then `ok` or `error` with the class.
- **Hostile BMC strings:** names, versions, FQDDs and identities pass `internal/bmc/textclean` and are
  capped (names 128, versions 64, identifiers 128 bytes; the database has the same CHECKs);
  `html/template` escapes them; the CSV guard neutralises formulas; metrics never carry them.
- **Minimums are file-only:** `firmware.minimum` and `security.min_firmware` come from the read-only
  config.yaml; nothing in the browser changes what counts as acceptable.
- **Residual:** the Dell `Current`/`Installed` semantics are a working interpretation until the
  the maintainer's read-only capture confirms them; a version string the vendor formats inconsistently
  compares as "Cannot compare", never as "below"; a BMC that lies about its versions is believed.

## 3j. Sensor history (tech_doc §39)

- **No BMC traffic, no new privilege:** the history is written by the poller from the readings it
  already has (valid values only, power-good signals never) and read from the app's own database.
  The History tab, the sparklines, the API series and the CSV never reach a BMC.
- **Nothing user-supplied reaches SQL unbound:** the range is a closed enum (24h, 7d, 30d, 1y); a
  custom API window is parsed as RFC 3339 times and an integer step, bounded (2 years, 2000 points)
  and aligned before it reaches the store; the sensor and the focus must be keys the server already
  has (an unknown focus is ignored, an unknown sensor is a 400). Table and column names in the
  store's tier queries come from a fixed switch.
- **A second, read-only connection:** `store.OpenReadOnly` opens the same file with `mode=ro` and
  `query_only(1)` (at most 2 connections): a write through it fails (tested). Charts, exports and
  the audit rows of the event overlay use it, so a slow download never holds the writer that the
  audit chain needs. The writer begins its transactions IMMEDIATE, so a CLI command run beside serve
  waits on `busy_timeout` instead of failing with SQLITE_BUSY.
- **Exports:** RFC 4180 through `internal/csvx` (formula guard, valid UTF-8, capped cells), 100 000
  rows and 64 MiB at most, sized first and refused with 413 rather than cut; raw samples for at most
  31 days; `Cache-Control: no-store`; file names from the server ID, a slug of the sensor key
  (`[A-Za-z0-9._-]`) and a UTC stamp. Every sensor at once is operator-only and sessions-only;
  tokens export one sensor per request.
- **Hostile BMCs and clocks:** a server keeps at most 512 sensors in the history (archived ones
  included); a BMC that invents names every poll gets its new keys refused (counted and logged once),
  and every poll is capped per family in the sampler and in both Redfish decode paths. A sensor that
  changes unit or kind starts a new key, so a series never mixes units; a change back to an earlier unit
  reuses that unit's archived key (flips between two units cost two keys and delete nothing), archives
  are matched by a stored relation, not by name, a sensor keeps at most four archives (deleting the oldest
  is logged and counted), a null RPM reading never flips a fan to percent, and at the cap a unit change is
  refused rather than archived. Retention runs on the janitor's own clock, which advances at most
  twice real time: the kernel uptime on the same boot (a crash loop gains nothing), the monotonic clock
  in the process, 3 hours once per new boot; so a clock stepped forward cannot wipe the history in one
  pass. Rollups follow the wall clock (they only add). The History tab says when retention is catching
  up.
- **Exports never look complete when cut:** a stream that fails after the headers aborts the response
  (`http.ErrAbortHandler`), so the client sees a broken transfer. Refusals of an export are rate
  limited first and audited once a minute per user and kind.
- **Markers name people:** power, fan and BMC restart markers carry the requester's user name, and every
  viewer of the History tab sees them (the same disclosure as the server page's power cause).
- **Retention is an admin setting:** Settings → General (admin, fresh step-up, audited) or
  config.yaml; lowering it deletes data at the next hourly prune, and the page says so.
- **Residual:** history is best-effort (a failed insert is logged and polling goes on); a clock that
  moved back leaves overlapping samples that are kept, not rewritten (the History tab says so); the
  threshold bands are the current snapshot's, not the thresholds at the time.

## 3k. Rate limits per route (plan 06 §3.1, reviewed 2026-10-30)

Every POST route has a limit; buckets are in-memory token buckets (burst = the per-window count),
bounded where keys come from the network (IP, typed username). "Per user" buckets are keyed by
user ID; a refusal answers 429 with `Retry-After` and is audited unless noted. The unauthenticated
GETs of the sign-in flow (`/login`, `/login/totp`, `/enroll`, `/setup`) have **no** limit: at most
they look up the session a sent cookie names (`/login`, `/login/totp`) or count users (`/setup` while
first run is open), then mint HMAC form tokens (and the pre-session cookie); a flood costs CPU and
single indexed reads, and the POSTs behind them are limited.

| Route(s) | Limit | Notes |
|---|---|---|
| `POST /login`, `/enroll`, `/enroll/reveal` | 5/min/IP (live setting, 1–10) and 10/h/account (3–20) | per-account only for well-formed usernames |
| `POST /login/totp` | the live login-IP setting (default 5/min, 1–10), own key | |
| `POST /stepup`, inline step-up on confirm pages | the live login-IP setting (default 5/min, 1–10), own key | |
| `GET`/`POST /enroll/{token}` | 5/min/IP | link pages |
| `POST /setup` (first run) | 5/min/IP, own bucket | does not charge sign-in buckets (plan 09 L2) |
| `POST /logout` | CSRF (session-bound) only | deletes the caller's own session; a replay after logout only writes an anonymous audit row (accepted) |
| `POST /prefs/theme`, `/prefs/refresh` | 30/min/user (annotate rate, own `prefs:` bucket) | cookie-only, not audited; added 2026-10-30 |
| `POST /preferences` | 10/min/user (change limit) | `TestDisplayPrefsRateLimited` |
| `POST /keys/backup-notice` | 10/min/user (change limit) | each dismissal writes an audit row; added 2026-10-30 |
| Settings changes (users, tokens, general, servers, notifications, integrations, catalog confirm, resets) | 10/min/user (change limit) | plus admin + fresh step-up |
| `POST /settings/servers/fingerprint`, `…/pin/fetch`, `…/connection/fingerprint`, `/settings/integrations/gelf/fingerprint` | 6/min/user | probes: reach a BMC or log server |
| `POST /settings/servers/{id}/test` | 6/min/user | |
| `POST /settings/notifications/{id}/test` | 3/min/user | |
| `POST /settings/integrations/gelf/test` | 3/min/user | |
| `POST /settings/audit/verify` | 1/min global | |
| `POST /settings/catalog/upload` | 1/min/user | 16 MiB body cap, streamed |
| `POST /firmware/catalog/check` | one manual check per 5 min, global (`CheckNowEvery`) | service-side cooldown |
| `POST /servers/{id}/firmware/rescan` | 6/min/user | |
| `POST /servers/{id}/firmware/skip`, `…/unskip` | 10/min/user | |
| `GET /firmware.csv`, history CSV (UI) | 6/min/user | refusals audited once a minute per user and kind |
| `POST /servers/{id}/power/{action}` | 10/min/user + 60 s cooldown per server | |
| `POST /servers/{id}/bmc/reset` | 10/min/user + 10 min cooldown per server | |
| `POST /servers/{id}/fan/lease`, `…/end` | 10/min/user | |
| `POST /servers/{id}/console`, `…/console/kvm-launch`, `…/serial` | 10/min/user | |
| WebSocket upgrades | single-use 30 s ticket | plus cookie, role, step-up, Origin |
| maintenance, notes, acks, security rerun/accept | 30/min/user (annotate rate) | |
| `GET /healthz` | none | static answer, no I/O |
| `GET /readyz` | none; the answer is cached 1 s (database pinged at most about once a second) | added 2026-10-30 (D1). Deliberately no 429: monitors on the same host can share one source address and uptime monitors (Uptime Kuma, for one) read 429 as down. The shared answer ignores the caller's cancellation, so a client that hangs up cannot cache "unavailable" |
| `/api/*`, `/metrics` | 60/min/token | CSV exports 6/min/token; `/metrics` also limited to `allow_networks` |

## 3l. Session fixation and CSRF checklist (plan 06 §3.1)

Each line has a test.

| Control | Test |
|---|---|
| Session ID rotated on login and on step-up; the pending (password-stage) cookie is refused once the code is accepted | `internal/auth` session tests, `TestStepUp*`, `TestPendingTokenRejectedAfterLogin` |
| Role and `disabled` read from the user row on every request: a demotion applies at once (403), a disabled user is signed out (session deleted, sent to `/login`; the old cookie stays refused after re-enabling) | `TestDemotedAdminLosesAccessOnNextRequest`, `TestDisabledUserSignedOutOnNextRequest`, `TestDisabledUserSessionKilled` |
| A session cookie planted before sign-in is never adopted; the pre-session cookie (`__Host-oob_pre`) is cleared at sign-in | `TestPlantedCookiesReplacedAtLogin` |
| Every cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict` (theme/refresh included) | `prefs.go`, cookie tests |
| `CrossOriginProtection` + synchronizer token on every POST | `TestCrossOriginPostRejected`, `csrf_test.go` |
| TOFU proof bound to session + purpose + value, 5 min; another server's proof refused | `TestProofBoundToPurpose`, `internal/tofu` |
| Enrolment link single use in SQL | enrolment tests |
| WebSocket `Origin` checked against the request host and `public_url` host, port included | `TestConsoleWebSocketRefusals`, `TestConsoleWebSocketOriginPortMismatch` |
| `rev` compare-and-set on every settings form | settings tests |
| Logout deletes the server-side session; a copy of the cookie is refused afterwards | `TestLogout`, `TestCookieReplayedAfterLogout` |

## 3m. Secrets at rest (key derivation, plan 06 §3.1)

The app-keys master is `totp_key` (32 bytes, in `app-keys.age`, decrypted with the age identity).
It is used **directly** as the AES-256-GCM key for TOTP secrets (AAD = user ID) **and** as the
HKDF-SHA256 input keying material for these purposes (`internal/secrets/derive.go`, labels pinned
by `TestPurposeLabelsArePinned`; the `oob-console/` prefix predates the rename and is kept, because
changing a label invalidates sealed data and open forms):

| Label | Keys | AAD / binding |
|---|---|---|
| `oob-console/csrf/v1` | form-token HMAC | form ‖ session (or pre-session) ‖ ts |
| `oob-console/ui-resume/v1` (HKDF of the CSRF key) | sealing of a form stashed across the step-up page | session-bound, 4 per session |
| `oob-console/bmc-cred/v1` | AES-GCM of browser-saved BMC credentials | server ‖ slot ‖ kind ‖ address ‖ port ‖ version |
| `oob-console/tofu/v1` | HMAC proofs of fetched fingerprints | session ‖ purpose ‖ value, 5 min |
| `oob-console/notify/v1` | AES-GCM of notification target secrets | id ‖ kind ‖ url |

Plans 08 (update checker) and 09 (store-ready install) added no purpose. Hash domains that are not
keys: `oob-console/audit/v1` (audit chain), `oob-console/console-ticket/v1` (console session hash).

- **Master used two ways.** Acceptable (HKDF output is independent of the IKM's other use), but no
  new *direct* use of the master may be added. **`oob-manager/totp/v2` is reserved** for moving
  TOTP sealing to a derived key in a future re-enrolment path.
- **Known gap: no `rekey` CLI.** The `key_id = 'v1'` columns would allow one (decrypt with the old
  identity and keys, re-seal with new ones), but it is not built. Consequence for the runbook:
  rotating the app keys or losing the identity means re-entering every sealed secret: BMC
  credentials saved in the browser, notification target secrets, and every user's authenticator
  (`reset-totp`).
- **Backups and the audit chain offline (plan 06 §3.6).** `oob-manager backup <dir>` writes the
  database alone (`VACUUM INTO` on its own connection; never the age identity, the app keys or
  `config.yaml`), sets it 0600 explicitly and verifies its chain; `verify-audit` checks any copy on a
  query-only connection. Both are shell-only (no web route). **Break glass:** `admin-recover -username`
  re-enables an account, makes it an admin, clears its lockout and ends its sessions in one
  transaction with an `admin.recover` row by `cli`; it skips the last-admin and self-change guards on
  purpose (the shell is trusted, like `bootstrap-admin`), and never touches the authenticator; it
  shows the account's state and needs `-yes` or the name typed back, and validates the name before
  any row is written. **CLI rows are shipped:** mutating CLI commands (bootstrap-admin, confirm-totp,
  admin-recover, reset-totp, token create/revoke, settings import, catalog import) start the same GELF
  shipper as serve and flush it on exit (a 3 s flush, then the shipper's own close: up to about 6 s;
  best effort, a failure warns on stderr and never fails the command), so the break-glass row leaves
  the box. The shipper's destination policy still denies every BMC address, read from `config.yaml`
  and the server rows, since the CLI does not load the registry. `os_user` is the shell account (`uid
  65532` inside `docker exec`), not a person.
- **What the offline check cannot prove.** `verify-audit` detects edits and gaps, but not a full
  rewrite by someone with write access to the database (rows and every later hash recomputed), nor a
  copy truncated at the end. The control for both is the log server's copy: compare the head with its
  last `row_hash`. Copies are opened read-only with `trusted_schema` off; paths with `?`, `#` or `%`
  are refused (they would be parsed as URI syntax).
- **File modes.** The binary sets `umask 077` at the top of `main` (Linux and macOS), before any
  subcommand creates anything, so whatever it creates is owner-only: the database and its
  `-wal`/`-shm` files (from `serve` or a CLI command such as `bootstrap-admin`, `token`,
  `settings`), the store-install marker and generated keys and TLS files (directories 0700).
  Backups the app itself writes (the `backup` command) are 0600 whatever the umask; a copy made with
  `cp` or `sqlite3 .backup` from a shell follows *that* shell's umask, so set `umask 077` there
  too. The database holds sealed secrets, token hashes and the audit log; treat every copy like the
  keys file. Databases created before 0.12 keep their mode: `chmod 600` them once.

## 4. BMC account plan (least privilege)

Create per BMC (the BMC's administrator does this in the iDRAC UI; the app never manages BMC users):

| Account | iDRAC role / privileges | IPMI LAN privilege | Used for |
|---|---|---|---|
| `oob_ro` | Read Only (Login) | No Access | Polling sensors, SEL, inventory; the security checks (§3g) read AccountService, the licences and the attribute registry with it when the BMC allows, and report "can't read" otherwise |
| `oob_op` | Custom: Login (`0x1`), Execute Server Control Commands (`0x10`, power), Access Virtual Console (`0x20`, only for the KVM launch); + Configure (`0x2`) **only on iDRAC9** if `redfish-floor` fan mode is used, and on either generation if BMC restart is used and the maintainer's hardware test shows it is required (Dell documents `racreset` under *Configure iDRAC*; unverified, §3h) | No Access (or Operator only if IPMI SOL/legacy is used) | Power, KVM launch, fan floor (iDRAC9), BMC SSH `console com2` (the privilege iDRAC requires for `console com2` is unverified on 2.86/7.00; IPMI SOL minimum privilege may be Administrator on the target servers, see tech_doc §22 Open) |
| `root` (or the renamed default admin) | Administrator | — | People only, unique password, never in this app |

- Separate passwords, 24+ random chars, stored only in the app (age file or sealed in the DB) and the
  administrator's password manager.
- VNC password (if VNC proxy is enabled): random, max length the iDRAC allows (8 chars, a
  limit of the VNC protocol), VNC SSL encryption enabled on the iDRAC, VNC timeout short.
- Recommended: restrict the iDRAC **IP-range filter** (IP Blocking) to the Docker host. The app runs on a
  bridge network, so it egresses as the Docker host's address (for example `192.0.2.20`); iDRAC8 has a single
  range and may reject a /32 mask, in which case the smallest range it accepts also admits a neighbouring
  address, which should then stay unassigned. People reach the iDRAC UIs through the Docker host (for example an
  SSH SOCKS proxy). The in-band KCS path a host fan script uses is unaffected by the IP filter.
- Give every other consumer (a dashboard, a monitoring system) its own read-only account, separate from
  `oob_ro` (one account per consumer, so revocation is surgical).

## 5. IPMI-over-LAN risks and policy

- **RAKP hash disclosure (CVE-2013-4786):** IPMI 2.0's RAKP step 2 returns an HMAC of the
  user's password to *anyone* who sends a valid username, before authentication. It is a
  protocol flaw; no firmware fixes it. Any reachable UDP/623 = offline-crackable hashes for
  every known username.
- **Cipher 0** = authentication bypass. Disable it on the BMC (the security checks flag it). The driver
  refuses to negotiate it regardless.
- Cipher suites 1/2 lack confidentiality or integrity; **the driver prefers 17**
  (HMAC-SHA256 + AES-CBC-128) then 3, and refuses everything else.
- **Recommended policy:** Dell servers do **not** need IPMI-over-LAN for this app
  (Redfish + BMC SSH cover everything). Keep IPMI-over-LAN **disabled** on
  every iDRAC. The `ipmi` driver exists for legacy/non-Dell BMCs; if one is added, put its
  UDP/623 behind a firewall rule that allows only the app's address, use long random passwords
  (RAKP makes password strength the only defense), and never reuse them.
- On iDRAC, `IPMILan.1.AlertEnable` also gates remote syslog: leave it alone when
  disabling IPMI-over-LAN.

## 6. Supply chain and container

- Base `gcr.io/distroless/static-debian12:nonroot`, pinned by digest (the Dockerfile; moving to
  `static-debian13` is an open decision, tech_doc §8 item 1); static binary
  (`CGO_ENABLED=0`, `-trimpath`, `-buildvcs`), so the image has no shell, no package manager.
- Go modules pinned via `go.sum`; `govulncheck` (reachability) in CI.
- **Renovate** (`renovate.json`, tech_doc §33) proposes every bump (Go modules, the Go toolchain,
  SHA-pinned actions, digest-pinned base images, npm test dependencies, and the CI tool pins in the
  Makefile and ci.yml) only once the release is **≥ 14 days old**, security fixes included (lesson
  of the March 2026 Trivy compromise); a release without a timestamp waits; nothing automerges;
  monthly schedule. A digest-only action update (same tag, new commit: what a rewritten tag looks
  like) gets its own branch, created only after approval on the Dependency Dashboard. `internal/repopolicy` tests
  fail if any of that is dropped, if a tool pin has no Renovate annotation, or if the Makefile and
  workflow pins drift. Renovate runs as a GitHub app that only opens PRs: no token or secret is
  added to CI.
- Workflows and composite actions: `TestWorkflowsHardened` reads every YAML document of every
  workflow and `.github/actions/**/action.y*ml` and requires every third-party `uses:` (block style
  only) to be pinned to a full commit SHA with a `# v…` tag comment, local `./` actions to be checked
  files themselves, a read-only top-level `permissions:` block (no `write-all`, no `write` scope; no
  job-level `write-all`), no `pull_request_target` or `workflow_run` trigger, and
  `persist-credentials: false` on every checkout. `.github/CODEOWNERS` puts `.github/`,
  `renovate.json`, the Makefile, `internal/repopolicy` and `internal/covergate` under the maintainer's
  review; enforcing it needs branch protection on `main` with required code-owner review (the
  the maintainer's repository setting).
- Every direct go.mod dependency has a tech_doc §2 row (purpose, licence, why not stdlib) and every
  vendored front-end package has a §2 row and a NOTICE entry: `TestDependenciesDocumented`,
  `TestVendoredAssetsDocumented`.
- Vendored front-end assets checked in with recorded versions and SHA-256s
  (`internal/web/ui/vendor.sha256`); a unit test re-verifies every hash and that nothing else sits
  in the vendor tree. noVNC and xterm.js + addon-fit are **unmodified** upstream files. The Inter
  and JetBrains Mono woff2 fonts (SIL OFL 1.1) are **subsets** of the upstream release TTFs, i.e.
  Modified Versions under the OFL: tech_doc §35 records each upstream release asset and its
  SHA-256, and `tools/fonts/build-fonts.sh` (a maintainer tool, not run in CI) rebuilds them
  byte-identically from those assets with fontTools and brotli installed by hash
  (`tools/fonts/requirements.txt`), checking every hash on the way. New font bytes need a new
  versioned directory (`TestFontBuildsAreAppendOnly`), because the font URLs are cached as
  immutable for a year. Fonts are same-origin only (`font-src 'self'`),
  never from a CDN.
- The visual-baseline runner image (test only) is pinned by digest like the base images and
  tracked by Renovate together with `@playwright/test` (`TestPlaywrightImageMatchesTestRunner`).
  `make visual` runs it with the repository mounted read-only (only `tests/e2e` writable), as the
  invoking non-root user, with no capabilities and `no-new-privileges`.
- CI: `golangci-lint` (incl. `gosec`), `actionlint` with shellcheck (the job fails if shellcheck
  is missing), `go test -race -cover` with 80 % gates on the module total **and** on every package
  on its own (in-repo test doubles excluded; the security-relevant packages `auth`, `authz`, `fan`,
  `power`, `audit`, `console`, `console/rfb`, `netpolicy`, `secrets/credstore`, `tofu`, `registry`
  must be present), a nightly `-race -count=3 -shuffle=on` soak, `govulncheck`,
  Trivy image scan failing on HIGH/CRITICAL (fixable), Syft SBOM (SPDX) as release asset,
  optional cosign keyless signing.
- The app exposes `/api/v1/version` (version, commit, Go version, module list hash), so an
  external vulnerability scanner or inventory can track what is deployed.

## 6a. Safe defaults (re-checked for the public release, plan 07 §4.3)

Each default below was checked in the code and is held by the tests named. Re-run the check
before a release by running those tests (they are part of `make test`) and reading this table
against the code.

| Default | How it holds | Tests |
|---|---|---|
| **No default credentials.** No account or API token exists until an admin is created. | The first account is made only by `bootstrap-admin` (CLI) or `/setup`, both through `CreateFirst` (`INSERT … WHERE NOT EXISTS`); no migration seeds users or tokens; tokens are created only by an admin (UI or `token create`) and are always read-only; an account cannot sign in before its TOTP is confirmed. | `TestBootstrapAdmin`, `TestCreateFirstUserIsAtomic`, `TestBootstrapAdminEndToEnd`, `TestDisabledAndUnconfirmedUsersCannotLogin`, `TestTokensAreReadOnlyRegardlessOfRole`, `TestE2EStoreInstall` |
| **`/setup` only while no account exists.** | On any install with an empty users table (a store install, or a configured one whose admin was never bootstrapped) the start log prints a one-time code and `/setup` accepts it (S11). Every request re-counts users; once one exists the code is burned and `/setup` is 404 for GET and POST. | `TestSetupCreatesTheFirstAdminThenCloses`, `TestSetupClosedWhenAnAccountExists`, `TestConcurrentClaimsMakeOneAdmin`, `TestSetupRateLimited`, `TestSetupCode` |
| **TLS required.** | One listener, `ServeTLS` only: no plain-HTTP port and no redirect listener; plain HTTP on the port gets 400 without a `Location`. `serve` refuses a config.yaml that names no certificate pair; only a store install without config.yaml generates a self-signed one. TLS 1.2 minimum, ECDHE + AEAD suites, HSTS. | `TestServeEndToEnd`, `TestServeRefusesToStartWithoutTLSFiles`, `TestConfigFileWithoutTLSRefuses`, `TestServeRefusesConfigFileWithoutTLS`, `TestTLSConfig`, `TestHSTSOnlyOverTLS` |
| **Dangerous actions off until configured.** | `fan.mode`, `console.serial` and `console.graphical` default to `none`; power and BMC restart need an operator credential on the server; metrics, GELF, the online firmware catalog check and notification targets are off until set. Each dangerous action then needs its role, a fresh TOTP step-up, a rate limit and a "started" audit row written first (fail-closed: no audit row, nothing sent). Exception: ending a fan lease early needs the operator role but no step-up, since it only restores the normal curve (`TestRequiresStepUp`, "end lease no step-up"). | `TestOperatorRequirementPerFeature`, `TestBuildPower`, `TestBMCResetTargets`, `TestRequiresStepUp`, `TestDenyByDefault`, `TestAuditFailsClosed` (power, bmcreset), `TestConsoleAuditFailureFailsClosed`, `TestSerialAuditFailureFailsClosed`, `TestStartAuditFailsClosed` (fan), `TestMetricsDefaultsOff`, `TestGELFFileKeysAndDefaults`, `TestScheduleOffSendsNothingThenChecksWhenTurnedOn` |
| **LAN-only.** | Docs publish the port on one LAN address, never `0.0.0.0` (deploy/README "Networking: keep it on the LAN"). `serve` warns when `listen` or `public_url` is a public IP literal. Browser-added BMCs must sit in `settings.bmc_networks` (default: the RFC 1918 blocks and `fc00::/7`; `0.0.0.0/0` refused). GELF is private-only by default; notification and catalog egress is public-over-TLS or an allow-listed LAN address, never loopback, link-local or the app itself. Forwarding headers are ignored: the client address is the TCP peer. | `TestExposureNotes`, `TestBMCNetworksDefaultAndValidation`, `TestGELFAddrAllowed`, `TestPolicyRefusesNonPublicAndRebinding`, `TestPrivateReceiverBlockedWithoutAllowlist`, `TestForwardingHeadersAreIgnored` |
| **Cookies and CSRF.** | Session cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`; cross-origin protection on every unsafe method plus per-form tokens. | `TestSessionCookieFlags`, `TestCrossOriginPostRejected` |

Known softer defaults, by design: the container listens on all of its own interfaces (`:8443`, the
publish address decides the exposure); `/healthz` and `/readyz` answer without a token (status word
only); `/metrics` needs a read-only token but no source allow-list unless `metrics.allow_networks` is
set; GELF uses plain TCP unless `transport: tls` is chosen (audit rows then cross the LAN in clear);
ending a fan lease is not blocked by a failed audit write, since it only restores the normal curve.

## 7. Residual risks (accepted, documented)

1. Compromise of an admin's identity-provider account (Cloudflare Access mode) or password + TOTP device ⇒ full
   control (the same as for the iDRAC UI itself).
2. iDRAC9 KVM launch exposes single-use temp creds to the browser.
2a. The BMC→browser half of the console stream is relayed without parsing: noVNC parses
    BMC-controlled framebuffer data in the browser (same as any VNC client). A compromised BMC
    that found a bug in a noVNC decoder would run in our origin; the strict CSP (no eval, no
    inline script, `connect-src 'self'`) and HttpOnly cookies limit what it could reach.
c. iDRAC8 VNC TLS uses RSA key exchange (no forward secrecy); recorded sessions are exposed
    if the BMC's private key ever leaks.
d. iDRAC8 SSH needs `ssh-rsa` (SHA-1) and `diffie-hellman-group14-sha1` for the serial console
    (`idrac8_legacy_ssh`). xterm.js parses BMC/host-controlled terminal output in the browser; the same
    CSP limits as 2a apply. Truecolor text renders in the default color because CSP blocks its inline style.
3. `ipmi-oem` mode can leave a legacy BMC in manual (≥ floor) if the app dies mid-lease; not
   used for current hardware.
4. The lease directory is writable by host root; anything with host root already owns the fans.
4a. The host reader checks for a symlink and then reads the path (bash has no O_NOFOLLOW): a
    writer of the lease directory could race a symlink in between. The content is still parsed
    strictly and never echoed (the ack carries only `reason=invalid`), so this can at most make
    the host ignore a lease. Only uid 65532 (the app) and root can write there.
4b. `redfish-floor` revert is app-enforced: if the app is gone for good, the raised minimum fan
    speed stays until someone resets it in the iDRAC (fans faster, never slower). Leases are
    in SQLite and reconciled at every start (expired → restore the recorded value).
5. BMC firmware itself (iDRAC8 is end-of-life hardware): the app reduces exposure but cannot
   patch it. Keep the iDRAC management network restricted.
6. **Audit truncation or rewrite without a log server** (R7): on an install with GELF shipping off,
   nothing can show that the newest audit rows were removed or the chain recomputed.
7. **No `rekey` command** (§3m): rotating the app keys or losing the identity means re-entering every
   sealed secret and re-enrolling every authenticator.
8. **Store installs keep their keys in the data volume** (plan 09): whoever copies `/data` whole has the
   keys and the database together; the backup notice and the README say to keep `/data/keys` separate.
9. **`/readyz` has no request limit** (D1): its cost is a cache read; a flood costs CPU and bandwidth only.
