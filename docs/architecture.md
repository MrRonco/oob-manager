# Architecture — oob-manager

## 1. Context diagram

Example addresses are from 192.0.2.0/24 (RFC 5737). Everything left of the BMCs is optional
except the browser.

```
                     Internet (optional; LAN-only is the recommended default)
                         │
                Identity-aware proxy, e.g. Cloudflare Access (optional, auth.mode cfaccess)
                         │  Cf-Access-Jwt-Assertion
                         │
 ┌───────────────────────┼──────────────────────────── management LAN (192.0.2.0/24) ─────────┐
 │                       ▼                                                                   │
 │  Browser (admin) ──HTTPS──►   ┌──────────────────────────────────────────┐                │
 │  Dashboard  ──token, GET──►   │  oob-manager container                    │                │
 │  Automation ──token, GET──►   │  (bridge, published on 192.0.2.20:8443)   │                │
 │  Uptime monitor ─GET /readyz► │  uid 65532, read-only rootfs, no caps     │                │
 │  Prometheus ─GET /metrics──►  │                                          │                │
 │                               │  ┌────────┐ ┌────────┐ ┌──────────────┐  │                │
 │                               │  │ web/UI │ │ JSON   │ │ console WS   │  │                │
 │                               │  │ (html) │ │ API    │ │ (serial/VNC) │  │                │
 │                               │  └───┬────┘ └───┬────┘ └──────┬───────┘  │                │
 │                               │      └──── authz + audit ─────┘          │                │
 │                               │                 │                        │                │
 │                               │       ┌─────────▼──────────┐             │                │
 │                               │       │ server manager     │ per-server  │                │
 │                               │       │ (poller, breaker)  │ goroutines  │                │
 │                               │       └─────────┬──────────┘             │                │
 │                               │   ┌─────────────┼──────────────┐         │                │
 │                               │   ▼             ▼              ▼         │                │
 │                               │ Redfish      IPMI 2.0       BMC SSH      │                │
 │                               │ (gofish)     (go-ipmi)      (x/crypto)   │                │
 │                               │ + Dell OEM   cipher 17      console com2 │                │
 │                               └───┬─────────────┬──────────────┬─────────┘                │
 │      SQLite + leases volume ◄─────┤ HTTPS/443   │ UDP/623      │ TCP/22, VNC TCP/5901     │
 │      (/data, /leases on the       │ (pinned)    │ (optional)   │ (pinned host key / TLS)  │
 │       Docker host)                ▼             ▼              ▼                          │
 │             │               iDRAC8 192.0.2.10            iDRAC9 192.0.2.11                │
 │             │                                                                            │
 │             ▼  fan lease file (key=value, read by host; host-lease mode only)            │
 │   Host fan script (optional): single writer of that server's fans, in-band KCS,          │
 │                               with its own watchdog that falls back to BMC AUTO          │
 │                                                                                          │
 │   Log server (optional): GELF TCP/TLS input  ◄── audit rows + app logs                    │
 └──────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Components

| Component | Responsibility | Package (planned) |
|---|---|---|
| HTTP server | TLS, routing, security headers, CSP nonce, request limits | `internal/web` |
| Auth | Local login (argon2id + TOTP), CF Access JWT, sessions, API tokens, step-up | `internal/auth` |
| AuthZ | Role → permission matrix, one function `Allowed(principal, action, server)` | `internal/authz` |
| Audit | Hash-chained SQLite log + GELF shipper with bounded queue | `internal/audit` |
| Server manager | Owns one `ServerHandle` per configured BMC: poller, circuit breaker, capability record, immutable snapshots | `internal/fleet` |
| Drivers | `bmc.Driver` interface; implementations `redfish`, `dellredfish` (OEM extension), `ipmi`, `dellipmi` | `internal/bmc/...` |
| Fan arbiter | Lease lifecycle, guard evaluation, mode-specific applier (`hostlease`, `redfishfloor`, `ipmioem`) | `internal/fan` |
| Power service | Validated action → driver call → verify → audit | `internal/power` |
| Console broker | Session limits, WS ↔ SSH/SOL/RFB pumps, RFB auth termination, iDRAC9 KVM launch | `internal/console` |
| Store | SQLite (modernc), migrations, repositories | `internal/store` |
| Secrets | Load age-encrypted credential file, hand out per-server credential values | `internal/secrets` |
| Config | YAML config, schema validation at startup, fail fast | `internal/config` |
| Integrations | `/api/v1/*` read-only JSON, `/healthz`, `/readyz`, optional `/metrics` | `internal/api` |

## 3. Trust boundaries

1. **Browser ↔ app**: untrusted. Everything is authenticated, CSRF-checked, rate-limited.
2. **Identity-aware proxy ↔ app** (optional, Cloudflare Access): JWT is verified, never trusted as a bare header.
3. **App ↔ BMC**: the BMC is semi-trusted. Its responses are untrusted input (size-capped,
   schema-decoded, never rendered as HTML). TLS is pinned per BMC; SSH host keys are pinned.
4. **App ↔ host fan script**: the lease file is the only channel. The host script treats it
   as untrusted (strict parse, clamp, expiry cap). The worst a forged lease can do is raise
   fans or hold them at ≥ the safe floor for ≤ 2 h, and a thermal guard still overrides it.
5. **App ↔ log server (GELF)**: write-only, best effort, no secrets in payloads.

## 4. Deployment

- Docker Compose is the documented default (`deploy/compose.yaml`, `deploy/README.md`); compose is
  preferred over a single `docker run` or a GUI template because compose supports file-based
  `secrets:` that never appear in the `docker inspect` environment. Unraid's compose plugin and its
  Community Applications template are examples of the same layout.
- Network: **bridge** (Docker NAT), HTTPS published on the Docker host's management address (for
  example `192.0.2.20:8443`), not on `0.0.0.0`. A bridge container's outbound traffic leaves as the
  Docker host's address, so a BMC IP allow-list (iDRAC "IP Blocking"/IP filter) only has to admit the
  Docker host. A macvlan/ipvlan container has its own address and must be added to that list too;
  iDRAC8 supports a single filter range, so keeping the Docker host the only BMC client is simpler.
- Volumes (host paths are your choice; `deploy/README.md` uses `$D`):
  - `$D/data` → `/data` (rw: SQLite DB).
  - `$D/leases` → `/leases` (rw: fan lease files; only with `host-lease` fan mode, where the host
    script reads the same directory).
  - secrets via compose `secrets:` → `/run/secrets/{bmc-credentials.age,age-identity,app-keys}` (ro).
  - config `$D/config.yaml` → `/etc/oob-manager/config.yaml` (ro).
- Container flags: `read_only: true`, `user: 65532:65532`, `cap_drop: [ALL]`,
  `security_opt: [no-new-privileges:true]`, `tmpfs: /tmp:size=16m,noexec`, `pids_limit: 64`,
  `mem_limit: 256m` (+ `GOMEMLIMIT=200MiB`), `restart: unless-stopped`, healthcheck via the binary itself
  (`oob-manager healthcheck`, no curl in a distroless image).
- **Keep it out of auto-updaters** (pin the image by digest and bump by hand): a new image can run
  one-way database migrations, which should never happen unattended.
- TLS for the UI: a certificate from your internal CA, a certificate for a public name if the UI is
  published behind an identity-aware proxy, or the self-signed certificate `gen-tls` creates
  (LAN-only), trusted or pinned in the browser.

## 5. Why this shape

- **One process, no sidecars.** No Redis, no separate worker, no reverse proxy inside the
  container. Fewer moving parts to patch.
- **Pull model for sensors.** Background pollers write immutable snapshots; HTTP handlers
  only read snapshots. A slow BMC can never stall the UI.
- **Fan control is cooperative, not competitive.** In `host-lease` mode the app never sends fan
  commands at all. It writes a lease; the host script (already the single writer) applies it.
- **Console traffic never crosses the browser with BMC credentials.** The app terminates
  SSH, SOL and RFB authentication itself and relays only the byte stream.
