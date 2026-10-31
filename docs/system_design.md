# System design — oob-manager

## 1. Driver model

```go
// internal/bmc/driver.go (sketch, not code to copy blindly)
type Driver interface {
    Probe(ctx context.Context) (Capabilities, error)
    Snapshot(ctx context.Context) (Snapshot, error)          // sensors, power, PSUs, health
    EventLog(ctx context.Context, since time.Time) ([]Event, error)
    Inventory(ctx context.Context) (Inventory, error)          // firmware, model, serial
    Power(ctx context.Context, a PowerAction) (PowerResult, error)
}

// Optional capabilities discovered by type assertion, never by vendor string checks
type FanController interface { ApplyFan(ctx, FanCommand) error; RestoreAuto(ctx) error }
type SerialConsole interface { OpenSerial(ctx) (io.ReadWriteCloser, error) }
type VNCConsole    interface { DialVNC(ctx) (net.Conn, error) }          // returns post-auth RFB stream
type KVMLauncher   interface { LaunchURL(ctx) (url string, expires time.Time, err error) }
```

- All result types are **values** (structs, copied slices). Pollers build a new `Snapshot`
  each cycle and swap a pointer under `atomic.Pointer`; nothing mutates a published snapshot.
- `PowerAction` and `FanCommand` are closed enums validated at construction
  (`NewPowerAction("GracefulRestart")` returns an error for anything else).
- Driver selection per server, in order: `dellredfish` → `redfish` → `dellipmi` → `ipmi`.
  A server can mix: Redfish for sensors/power, BMC SSH for serial, host-lease for fans.

### Implementations

| Driver | Library | Notes |
|---|---|---|
| `redfish` | gofish | Service root, `Systems/*`, `Chassis/*/Thermal` + `ThermalSubsystem` (newer schema), `Power`/`PowerSubsystem`, `Managers/*/LogServices`. Session auth (`X-Auth-Token`), session deleted on shutdown. |
| `dellredfish` | gofish + raw OEM calls | `Oem/Dell/DellLicenses` (license tier), `DelliDRACCardService.GetKVMSession` (iDRAC9), `Attributes` for `ThermalSettings.1.*` (iDRAC9), Lifecycle log. |
| `ipmi` | go-ipmi (native) | RMCP+ only, `WithCipherSuiteID(17)` then 3; refuses 0/1/2/6/7/11/15 (auth-only or no integrity). SDR + sensor reading, SEL, chassis status/control, DCMI power, SOL. |
| `dellipmi` | go-ipmi raw | Dell OEM `0x30 0x30 0x01` (manual/auto) and `0x30 0x30 0x02` (speed). Only for iDRAC7/8 and iDRAC9 ≤ 3.30.30.30. Later iDRAC9 firmware rejects these commands ("Insufficient privilege"). |
| `bmcssh` | x/crypto/ssh | Pinned host key. Runs exactly one command: `console com2`. No shell, no other commands. |

### iDRAC generation facts used by the design

| | iDRAC8 (R730XD) | iDRAC9 (R240) |
|---|---|---|
| Redfish | Yes (2.40+; tested on 2.86) — `Thermal`/`Power` schema | Yes, richer; `ThermalSubsystem` on newer firmware |
| HTML5 vConsole | Firmware feature, **Enterprise license** | Feature; tier depends on model/license (R240 often ships Basic: verify) |
| `GetKVMSession` | No | Yes (firmware 4.x+; the Dell sample script feature-detects it) |
| VNC server | Yes (port 5901 default, Enterprise) | Yes (Enterprise/Datacenter) |
| Raw fan `0x30 0x30` | Works | Blocked from ~3.34.34.34 |
| SSH `console com2` | Yes | Yes |

## 2. Polling and resilience

- One goroutine per server. Interval 60 s ± 10 % jitter. Each call has a context timeout
  (Redfish 10 s, IPMI 5 s per command, total cycle 30 s).
- Circuit breaker per server: 3 consecutive failures → open for 2 min → half-open probe.
  UI shows "BMC unreachable since …" with the last error class (timeout/TLS/auth/HTTP 5xx).
- Redfish session reuse; if the BMC returns 401, re-login once, then fail.
  iDRAC session slots are limited (iDRAC8: few concurrent Redfish sessions), so one
  session per server, always deleted on shutdown.
- Response body cap 4 MiB; JSON decoding into typed structs only.

## 3. Fan arbitration (the important part)

### 3.1 Principles

1. **Single writer per BMC.** In `host-lease` mode the host script is the only thing that sends
   fan commands. The app writes an intent; it never touches the fans out-of-band.
2. **Leases, not modes.** Every override has an expiry enforced by the component that
   applies it, so an app crash cannot strand the fans.
3. **Floor and guards win.** A lease can never take fans below the safe floor, and any
   thermal guard cancels it.
4. **No new sticky state.** The only BMC manual mode in play is the one the host script
   already manages and re-asserts on every run, with its own watchdog that forces BMC AUTO on a
   stale heartbeat.

### 3.2 Mode `host-lease` (a host fan script, e.g. on a Dell R730XD)

Lease file: `<lease dir>/<server-id>.lease` (`/leases` in the container, a host directory the
script reads), plain `key=value` (the reader is bash + awk, so it runs on minimal hosts without
python; awk parses it strictly). Written atomically
(write temp → fsync → rename) by the app.

```
version=1
lease_id=01JB7Z5Q2W8Y3K4M6N7P9R0S1T          # ULID
mode=boost                                   # boost | pin
pct=55                                       # integer 0-100
issued_at=1792512000                         # epoch seconds
expires_at=1792513800                        # epoch seconds
requested_by=alice
```

Host-script changes (small; the example reader is `deploy/host/fan-lease-reader.sh`, and the
host script keeps its own backup and `bash -n` discipline):

```
LEASE=read_lease()             # strict regex per line; unknown keys ignored; any error -> no lease
valid if: version==1, pct and times are integers, issued_at <= now < expires_at,
          expires_at - issued_at <= 7200, file owned by uid 65532, mode 0640
if valid and not guard_tripped:
    floor = max(SAFE_MIN_PCT, pct)  where SAFE_MIN_PCT=30 (host-side constant, not from file)
    boost: TARGET = max(curve_target, floor)
    pin:   TARGET = floor, unless curve_target is higher than pin and CPU/drive is in the top
           two curve steps (then curve wins)
    write ack file <server-id>.ack: lease_id, applied_pct, applied_at, owner=lease
else:
    normal curve; write ack with owner=curve (and reason if a lease was rejected)
guard_tripped: CPU >= 75 or hottest drive >= 54 (the existing AUTO thresholds) -> AUTO as today
```

- Expiry is enforced **by the host script** reading `expires_at`, so killing the container
  changes nothing: the lease simply stops matching and the curve resumes on the next run.
- The app also deletes the lease file on "End now" and on expiry (belt and braces).
- **Latency:** the cron is `*/3`, so a lease takes effect in ≤ 3 min. Open decision: move the
  cron to `* * * * *` (cost: one `ipmi-sensors` call per minute) or accept 3 min. The UI shows
  "pending → applied" by reading the `.ack` file.
- The host's watchdog is unchanged: the host script keeps writing its heartbeat whether or not
  a lease is active, so the stale-heartbeat → AUTO watchdog still covers everything.
- `pin` below the curve (quieter than the curve wants) is allowed only down to the floor and
  only while temps are outside the top two curve steps. This answers "make it quiet for an
  hour" without letting it cook the drives.

### 3.3 Mode `redfish-floor` (iDRAC9)

Current iDRAC9 firmware blocks raw fan commands, and the host may have no fan script at all (a
firewall appliance, a hypervisor). Instead of manual mode, the app raises the BMC's own
minimum:

- PATCH `/redfish/v1/Managers/System.Embedded.1/Attributes`
  `{"Attributes": {"ThermalSettings.1.MinimumFanSpeed": <pct>}}` (or `FanSpeedOffset` where
  the min-speed attribute is absent; exact attribute names verified in the spike, task P3.1).
- The BMC **stays in AUTO**; the floor just raises its lower bound. There is no sticky manual
  mode to strand.
- Revert: the app restores the recorded original value on expiry. Because this revert is
  app-enforced, the app persists the lease in SQLite and reconciles on startup ("any lease
  past expiry → restore"). Worst case if the app is gone for good: fans run *faster* than
  needed, never slower. That failure direction is acceptable.

### 3.4 Mode `ipmi-oem` (legacy Dell without a host controller)

Only for a future legacy Dell with no host-side script. App-owned manual mode with:
- re-assert every 60 s while the lease is active; `RestoreAuto` on expiry, on graceful
  shutdown, and on startup reconciliation;
- hard cap 60 min per lease; floor 30 %; guard on BMC-reported CPU/inlet temperatures.
- Documented residual risk: if the container dies mid-lease, the BMC stays manual at ≥ floor
  until the app comes back. Mitigation: deploy only together with a host-side or external (uptime monitor) watchdog.
  Default for unknown Dell BMCs is `none`.

### 3.5 Mode `none`

Generic IPMI/Redfish BMCs: fan readout only. No vendor-neutral fan control exists in IPMI 2.0.

## 4. Power control flow

```
POST /servers/{id}/power  {action, confirm_name, csrf}
 → authn (session) → authz(role, action) → step-up fresh (≤5 min)?
 → confirm_name == server.name? → cooldown(server) ok? → rate limit ok?
 → audit.Begin(correlation_id)
 → driver.Power(action)   (Redfish ResetType; IPMI chassis control fallback)
 → poll PowerState up to 60 s for the expected transition
 → audit.End(result) → GELF
 → 303 to server page with flash message + audit id
```

Redfish `ResetType` allowlist: `On`, `GracefulShutdown`, `GracefulRestart`, `ForceOff`, `ForceRestart`, `PowerCycle`. The app intersects this with the
BMC's advertised `ResetType@Redfish.AllowableValues`.

## 5. Remote console

### 5.1 Serial (all servers, operator)

```
Browser xterm.js ──WSS /console/{id}/serial──► console broker ──SSH (pinned)──► iDRAC: "console com2"
                                                         └──or IPMI SOL (go-ipmi sol_stream)──► generic BMC
```

- Dell path uses **BMC SSH, not IPMI SOL**, so it works even if IPMI-over-LAN is disabled.
- WebSocket: same-origin check, session cookie + a one-time WS ticket (30 s, bound to
  session and server), message size cap, server-side idle timeout.
- One serial session per server (the BMC allows one anyway); a second request is offered
  "take over" (admin) or refused.
- The host must actually send its console to the serial port: BIOS "Serial Communication →
  On with Console Redirection via COM2", a Linux kernel command line with `console=ttyS1,115200n8`
  (plus `console=tty0`), or a FreeBSD-based appliance's "Serial console" with dual console. These are host
  changes outside this project (open decision).

### 5.2 Graphical — iDRAC9 HTML5 launch (admin, LAN only)

- `POST DelliDRACCardService.GetKVMSession` (with `SessionTypeName`) returns a
  `TempUsername`/`TempPassword` pair that is single-use and short-lived. The app builds
  `https://<idrac>/console?username=<svc>&tempUsername=..&tempPassword=..` and redirects the
  browser in a new tab. Pattern from Dell's GPL-2.0 sample `LaunchIdracRemoteKvmHtmlSessionREDFISH.py`
  (we reimplement the HTTP calls; no code copied).
- Trade-off: the browser talks to the iDRAC directly, so it only works from the LAN, and the
  single-use temp credential does pass through the browser. It is not the permanent account
  password, it expires, and it works once. Documented as accepted risk; admin-only.

### 5.3 Graphical — VNC proxy (admin, iDRAC8/9 Enterprise or any VNC-capable BMC)

```
noVNC (vendored) ──WSS──► broker: RFB auth terminator ──TLS (pinned)──► BMC VNC :5901
```

- The broker speaks RFB to the BMC, completes VNC authentication (DES challenge with the
  password from the secret store) and then offers the browser security type `None` on an
  already-authenticated WebSocket. The browser never sees the VNC password.
- The broker inspects only the handshake; after `ServerInit` it relays bytes.
- Risk: a 2024 noVNC report of a black screen against iDRAC8's VNC server. Spike first
  (task P5.1). If it fails, iDRAC8 graphical console stays "open the iDRAC UI" (link only).

### 5.4 Not supported

Java/JNLP viewers, virtual media, and proxying the whole iDRAC web UI (its CSRF tokens and
session handling make a transparent reverse proxy brittle and would put an admin UI behind
our auth with unclear semantics).

## 6. Sequences worth testing end to end

1. Lease → host applies → container killed → lease expires → host back to curve.
2. Lease active → CPU hits 75 °C (simulated input) → host goes AUTO, ack shows `guard`.
3. Power ForceOff without fresh step-up → 403 + audit "denied: step-up".
4. BMC TLS cert changes → driver refuses, UI shows pin mismatch, audit warns.
5. Log server (GELF) down → actions still succeed, audit rows queued, `/readyz` degraded.
6. Two concurrent power requests for the same server → second gets 429 (cooldown).
