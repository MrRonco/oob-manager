# Deploying oob-manager

The app is one distroless container (uid 65532, read-only rootfs). Releases are published to
`ghcr.io/mrronco/oob-manager`, signed and attested ([docs/verify.md](../docs/verify.md)); you can
also build the image from a checkout (`docker build -t oob-manager:<version> .`). **Docker Compose
is the documented way to run it**: the [Quick start](#quick-start-a-data-volume-and-a-port) below
needs one data directory and one port, and [`compose.yaml`](compose.yaml) is the reference project
for the hardened layout with mounted keys. Unraid is covered as [one example](#unraid).

The examples use documentation addresses (RFC 5737): `192.0.2.20` is the Docker host,
`192.0.2.10`/`192.0.2.11` are the BMCs and `192.0.2.100` is an admin workstation. Replace them
with yours. `$D` is the install directory on the host. It must match the bind `source:` paths in
`compose.yaml`, so edit those if you use another path.

```bash
D=/srv/oob-manager                          # example; any root-owned directory works
IMG=ghcr.io/mrronco/oob-manager:<version>   # pin the digest you verified (docs/verify.md)
```

Every command that runs inside the image goes through `docker run --rm $IMG <command>`
(one-off) or `docker exec -it oob-manager /usr/local/bin/oob-manager <command>` (running
container). The image has no shell, so no other way works.

## Quick start: a data volume and a port

Since v0.11.0 the container needs nothing but a writable data directory and a published port
(docs/plans/09-store-ready-install.md). With no `config.yaml`, no mounted secrets and no
certificate, the first start:

1. checks that `/data` is writable (and stops with the `chown` to run if it is not);
2. generates a self-signed UI certificate in `/data/tls/` and logs its SHA-256 fingerprint;
3. generates the age identity and the app keys in `/data/keys/` (0400 files in a 0700
   directory), only because the database is new;
4. logs a one-time **setup code** (8 groups of 4 characters, valid 24 hours, single use).

A minimal `compose.yaml` for this (the same hardening as the reference file, without the key
mounts):

```yaml
name: oob-manager
services:
  oob-manager:
    image: ghcr.io/mrronco/oob-manager:<version>   # pin a tag or, better, the verified digest
    container_name: oob-manager
    restart: unless-stopped
    user: "65532:65532"
    read_only: true
    tmpfs: ["/tmp:size=16m,noexec,nosuid,nodev,mode=1777"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    pids_limit: 64
    mem_limit: 256m
    memswap_limit: 256m
    environment: { GOMEMLIMIT: "200MiB" }
    ports: ["192.0.2.20:8443:8443"]                # the host's LAN address, never 0.0.0.0
    volumes:
      - type: bind
        source: /srv/oob-manager/data
        target: /data
        bind: { create_host_path: false }
```

```bash
install -d -m 0700 -o 65532 -g 65532 /srv/oob-manager/data
docker compose up -d
docker logs oob-manager 2>&1 | grep -E 'fingerprint|setup code'
```

The same with plain `docker run`:

```bash
docker run -d --name oob-manager --restart unless-stopped --user 65532:65532 \
  --read-only --tmpfs /tmp:size=16m,noexec,nosuid,nodev --cap-drop ALL \
  --security-opt no-new-privileges --memory 256m --memory-swap 256m --pids-limit 64 \
  -e GOMEMLIMIT=200MiB -p 192.0.2.20:8443:8443 \
  -v /srv/oob-manager/data:/data ghcr.io/mrronco/oob-manager:<version>
```

Open `https://192.0.2.20:8443/`, compare the certificate fingerprint with the log, follow
"Set up the first administrator", enter the setup code, choose a username and password, add
the authenticator secret shown once, confirm a code, and sign in. Then add servers in
Settings → Servers. Every other setting is in the browser too.

If the authenticator page is lost before a code was confirmed, the account exists but cannot
sign in yet: run `docker exec -it oob-manager /usr/local/bin/oob-manager reset-totp --user <name>`
(it prints a new secret once), add it to the authenticator and confirm a code on `/enroll`.
The generated certificate is valid for 825 days; to replace it, stop the container, remove
`/data/tls/` and start it again (new fingerprint). From 30 days before it ends the start log warns.

**No config.yaml is a store-install property.** The first start of a fresh data volume writes
`/data/store-install`; later starts without config.yaml are allowed only for a volume carrying it.
An install that has run with a config.yaml and loses it (for example an empty mount) refuses to
start instead of coming up on built-in defaults with a new certificate. To run such an install
without config.yaml on purpose, start it with `serve -config=none` (logged at ERROR level every
start). Starting a store install with a config.yaml later removes the marker.

**Adding a config.yaml to a store install.** `serve` needs the config.yaml to name the UI
certificate: one that sets neither `tls.cert_file` nor `tls.key_file` refuses to start, so a `tls:`
block removed by mistake never swaps the certificate for a new one. (The CLI commands, such as
`admin-recover`, `token` or `backup`, never use the certificate and still run on such a file.) To
keep the generated certificate, name it:

```yaml
tls: { cert_file: /data/tls/tls.crt, key_file: /data/tls/tls.key }
```

The keys in `/data/keys/` keep working without any `secrets:` entry.

Once named, the pair is used as written, like any configured file: the start log no longer warns
before it ends, and removing `/data/tls/` no longer makes a new one (startup fails instead). The
generated certificate is valid for 825 days, so note its end date now (on the host, where the data
directory is mounted):

```bash
openssl x509 -in /srv/oob-manager/data/tls/tls.crt -noout -enddate -fingerprint -sha256
```

Before that date, make a new pair with `gen-tls` (it never overwrites files, so write it to an empty
directory, run as the same user as the container), then swap it in while the container is stopped:

```bash
install -d -m 0700 -o 65532 -g 65532 /srv/oob-manager/tls-new
docker run --rm --user 65532:65532 -v /srv/oob-manager/tls-new:/out oob-manager:<version> \
  gen-tls --host 192.0.2.20 --out /out        # every name or IP people use; prints the fingerprint
docker stop oob-manager
mv /srv/oob-manager/data/tls /srv/oob-manager/tls-old
mv /srv/oob-manager/tls-new /srv/oob-manager/data/tls
docker start oob-manager                      # keep tls-old until it reports healthy
```

Browsers ask again (new fingerprint). Or point the `tls:` block at your own certificate
([Using your own certificate](#using-your-own-certificate)).

**Keep config.yaml when `storage.db_path` is not the default.** A start without config.yaml looks
for the database at the default `/data/oob-manager.db` only. An install whose database lives
elsewhere, started without its config.yaml, finds no database there and treats the volume as fresh:
new keys and certificate next to a new, empty database (the real database is not touched, but the
app comes up without its accounts and servers). Such an install must always start with its
config.yaml; do not remove it or its mount.

**Back up `/data/keys/age-identity` off the server.** Without it, the stored BMC passwords,
authenticator secrets and notification secrets cannot be read after a restore. Admins see a
banner until they acknowledge it ("I have a backup"). An identity kept in the data volume
travels with every backup of that volume; if that is not acceptable, keep the identity
outside it and mount it instead (the [First-install checklist](#first-install-checklist)).

**What is never generated.** A file named in `config.yaml` is used as written, and a missing
one stops startup. Keys are generated only when neither the mounted defaults
(`/run/secrets/age-identity`, `/run/secrets/app-keys.age`) nor `/data/keys/` exist **and** the
database holds no accounts, BMC credentials, notification targets or API tokens. A database
with sealed data and no reachable keys refuses to start rather than pairing it with new keys.
Half a key set or half a certificate pair also refuses to start.

### Running as another user

The image is distroless and non-root (uid 65532) with a read-only root filesystem: there is
no root entrypoint that could change ownership, so `PUID`/`PGID` variables are not supported.
Run the container as the owner of the data directory instead, with Docker's own option:
`--user 99:100` (`docker run`), `user: "99:100"` (compose) or the same in Unraid's
*Extra Parameters*. Nothing in the image depends on uid 65532. If the directory is not
writable, the log says which uid/gid the container runs as and the `chown` to run.

### Advanced (optional)

- **Fan leases (`host-lease`)** are an opt-in integration for a server whose fans a host
  script already drives: the example reader in [`deploy/host/`](host/README.md) plus a
  `/leases` mount. See [Enabling fan leases](#enabling-fan-leases). Nothing needs it otherwise.
- **BMC IP allow-lists:** see [Networking](#networking-keep-it-on-the-lan).
- **Prometheus:** off by default; see [Prometheus metrics](#prometheus-metrics) (`config.yaml`).
- **`public_url`** (optional): when set, enrolment links and integration hints use it and it
  is added as a trusted origin. Without it they use the address the browser used.
- **Your own certificate:** set both `tls.cert_file` and `tls.key_file` in `config.yaml`.

## Networking: keep it on the LAN

oob-manager can power servers off and open their consoles, so treat its port like the BMCs'
own web interfaces:

- **Publish it on the host's management-LAN address only** (`192.0.2.20:8443:8443`), never on
  `0.0.0.0` and never through a port forward, a public tunnel or a public reverse proxy. Reach it
  from elsewhere over a VPN into that LAN.
- **Use Docker's default bridge network**, not macvlan or ipvlan. A bridge container's outbound
  traffic is NATed to the Docker host, so the BMCs see the host's address. A BMC IP filter (iDRAC:
  *IP Blocking*/*IP Range*) can then allow the host alone, and needs no change when the container
  is recreated. A macvlan container has an address of its own, which every BMC allow-list would
  have to admit as well; widening a range for it also admits whatever else lives there.
- **No proxy in front** without revisiting the per-IP login limit
  ([Client IPs](#client-ips-and-the-per-ip-login-limit)): behind a proxy every client shares its address.
- **Narrow `settings.bmc_networks`** to the addresses your BMCs actually use, leaving out the Docker
  host and other LAN services (see [Settings in the browser](#settings-in-the-browser)). For
  example, BMCs kept in `192.0.2.48`–`192.0.2.63`:
  ```yaml
  settings:
    bmc_networks: [192.0.2.48/28]   # BMCs only; not the Docker host or other services
  ```

## Docker Compose with mounted keys (hardened layout)

`compose.yaml` is the reference for an install that keeps its keys out of the data volume: the BMC
credentials, app keys and TLS pair are mounted read-only from `$D`, and the age identity comes from a
root-only place outside `$D` (next section). It runs the container non-root with a read-only root
filesystem, no capabilities, `no-new-privileges`, a 16 MiB `/tmp` tmpfs, 64 PIDs and 256 MiB of memory,
publishes 8443 on the host's management-LAN address only, and uses `create_host_path: false` on every
bind so a missing file stops the start instead of becoming an empty directory.

1. Replace `/srv/oob-manager` and `192.0.2.20` in `compose.yaml` with your directory and the host's
   address, and pin `image:` to the release you verified (or the tag you built).
2. Create the files as in the [First-install checklist](#first-install-checklist) (`$D/data` and
   `$D/leases` owned `65532:65532`, `config.yaml` naming every secret path).
3. `docker compose up -d`, then `bootstrap-admin` (or the first-run page if you left the key paths out).

Keep the image out of any auto-updater (Watchtower, Unraid's CA Auto Update and the like): a new
image can migrate the database, and migrations are one-way, so upgrades follow [Upgrade](#upgrade)
by hand.

### Keeping the identity off the data volume

The age identity decrypts every sealed secret. With the identity in the data volume, anyone who gets a
copy of that volume (a backup set, a disk image) has the keys and the data together. The hardened layout
keeps the persistent copy somewhere root-only that is **not** part of the data backups, and a boot hook
copies it into RAM for the container user:

```bash
# run at boot as root, before the container starts (a systemd unit, an init script, Unraid's go file)
install -d -m 0700 -o 65532 -g 65532 /run/oob-manager
install -m 0400 -o 65532 -g 65532 /root/oob-manager/identity /run/oob-manager/identity
```

`compose.yaml` mounts `/run/oob-manager/identity` as `/run/secrets/age-identity`. Keep an offline copy
(a password manager) as well: without the identity the app refuses to start and the sealed secrets are
gone (runbook drill 2).

### Unraid

<!-- repopolicy:allow host-paths -- this Unraid example names Unraid's standard appdata share and flash drive paths -->

Unraid is one example host; everything above applies. Two ways to run it there:

- **Template (simplest):** a draft Community Applications template is in
  [`unraid/oob-manager.xml`](unraid/oob-manager.xml). It is the
  [Quick start](#quick-start-a-data-volume-and-a-port) layout: one data folder (for example
  `/mnt/user/appdata/oob-manager`), port 8443, the container running as `99:100` (Unraid's
  `nobody:users`, see [Running as another user](#running-as-another-user)) and first-run setup in the
  browser. The generated identity then lives in the appdata folder: back up `keys/age-identity`
  off the server and decide whether appdata backups may carry it.
- **Compose project (hardened layout):** with the Compose Manager plugin, create a project named
  `oob-manager` and paste the edited `compose.yaml` as its `docker-compose.yml`; turn on autostart for
  it. The `net.unraid.*` labels give it a WebUI link on the Docker page. Use an appdata folder (for
  example `/mnt/user/appdata/oob-manager`) as `$D`.
- **The identity (compose project):** the flash drive (`/boot`, FAT) is root-only and ignores `chown`,
  so uid 65532 cannot read a file there in place. Keep it at `/boot/config/oob-manager/identity`, add
  the two `install` lines above (with that source path) to `/boot/config/go` as a marker-delimited
  block (`# >>> oob-manager-identity >>>` … `# <<< oob-manager-identity <<<`), run
  `bash -n /boot/config/go`, run the two lines once by hand, and exclude `/boot/config/oob-manager/`
  from flash and appdata backups that leave the box. Check the assumption first:
  `stat -c '%a %U' /boot/config/go` should print `600 root`.
- **Network:** keep the default bridge network (see [Networking](#networking-keep-it-on-the-lan)); a
  br0/macvlan address would need its own entry in every BMC allow-list.
- **Updates:** exclude the container from CA Auto Update and from Compose Manager's update check.

### Audit log server (GELF)

Ship the audit log off the box (Settings → Integrations; TLS with a pinned certificate is recommended).
The log server's copy is what proves the local chain was not cut short or rewritten (security.md R7,
runbook drill 7). In Graylog: a GELF TCP (or TLS) input, a stream with a rule on the sending address
(`gl2_remote_ip`), not on the self-reported host name, and retention at least as long as you keep
database backups. CLI commands ship their rows too: on exit they wait up to about 6 s for delivery
(a 3 s flush, then the shipper's close), and only warn if it fails.

## First-install checklist

- [ ] **1. Get the image.** Pull the release and verify its signature and provenance
      ([docs/verify.md](../docs/verify.md)), then use the verified digest as `$IMG`. Or build it
      from a checkout or a `git archive` tarball:
      `docker build --build-arg VERSION=<version> -t oob-manager:<version> .`.
- [ ] **2. Directories and ownership.** Only `data/` and `leases/` are writable by the app.
  ```bash
  install -d -m 0755 $D
  install -d -m 0700 -o 65532 -g 65532 $D/data $D/tls
  install -d -m 0755 -o 65532 -g 65532 $D/leases   # a host-side fan script may read it as root
  ```
- [ ] **3. age identity** (decrypts the two secret files at startup). Create it on an admin
      machine and keep an offline copy. Install it (`65532`, `0400`) at the path the compose
      `age-identity` bind uses as its source. The reference file stages it in RAM from a
      root-only place (see [Keeping the identity off the data volume](#keeping-the-identity-off-the-data-volume)).
      If that does not matter to you, `$D/age-identity` with that bind's `source:` pointed at it is fine:
  ```bash
  age-keygen -o identity            # prints "Public key: age1..." = the recipient
  age-keygen -y identity            # prints the recipient again later
  ```
  Never put the identity in the same backup set as the `.age` files.
- [ ] **4. App keys** (TOTP sealing key; the CSRF key is derived from it). The plaintext
      never touches disk:
  ```bash
  docker run --rm $IMG gen-app-keys | age -r age1... -o $D/app-keys.age
  chown 65532 $D/app-keys.age && chmod 0400 $D/app-keys.age
  ```
  Losing this file invalidates every TOTP enrolment (run `reset-totp` for each user).
- [ ] **5. Encrypted BMC credentials.** Plaintext format: YAML (or JSON), one entry per
      `credentials:` reference in `config.yaml`, nothing else (unknown fields fail startup):
  ```yaml
  storage1-ro: { username: oob_ro, password: "<read-only account password>" }
  edge1-ro:    { username: oob_ro, password: "<read-only account password>" }
  ```
  Use a **read-only** BMC account. Type the YAML into age directly so it is never
  written in clear (finish with Ctrl-D):
  ```bash
  age -r age1... -o $D/bmc-credentials.age
  chown 65532 $D/bmc-credentials.age && chmod 0400 $D/bmc-credentials.age
  ```
- [ ] **6. TLS certificate** (see [TLS](#tls)): `gen-tls` into `$D/tls/`.
- [ ] **7. SPKI pins** for every BMC (see [BMC certificate pins](#bmc-certificate-pins)).
- [ ] **8. `config.yaml`** at `$D/config.yaml` (`root`, `0644`; see [the example](#configyaml-example)).
      It is mounted read-only and only read at startup.
- [ ] **9. Start:** `docker compose up -d`, then
  ```bash
  docker inspect oob-manager --format '{{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} {{.State.Health.Status}}'
  ```
  should print `65532:65532 ro=true healthy` within about 30 s. If not, `docker logs oob-manager`
  shows the reason. Startup fails fast on a bad config, a missing secret, or a missing or
  unreadable TLS pair.
- [ ] **10. First admin.** Run
      `docker exec -it oob-manager /usr/local/bin/oob-manager bootstrap-admin -username admin`.
      It asks for the password twice with echo off, prints the TOTP secret and `otpauth://` URI
      **once**, then asks for a code. If that is interrupted, finish with `confirm-totp -username admin`.
- [ ] **11. Dashboard token** (read-only, the only token scope):
  ```bash
  docker exec oob-manager /usr/local/bin/oob-manager token create --name dashboard --expires 365d
  ```
  The token is printed **once** on stdout, alone on its line, so it can be piped straight into
  the dashboard's secret store. The ID and expiry go to stderr. The app stores only its hash.
  `token list` shows ID, name, created, last used, expiry and status, but never the token.
  `token revoke <id>` disables a token immediately. Every create and revoke is audited. The
  dashboard sends `Authorization: Bearer <token>` to `/api/v1/servers` or `/api/v1/servers/{id}`.
- [ ] **12. Health checks.** The container HEALTHCHECK runs `oob-manager healthcheck`, a GET of
      `https://127.0.0.1:8443/healthz` from inside the container. From outside:
  ```bash
  curl --cacert $D/tls/tls.crt https://192.0.2.20:8443/healthz   # {"status":"ok"}
  curl --cacert $D/tls/tls.crt https://192.0.2.20:8443/readyz    # "ok" once a BMC was polled
  ```
  Point an uptime monitor at `/readyz` with the keyword `"ok"` (`degraded` = audit shipping down).
- [ ] **13. Sign in** at `public_url` with password and TOTP. Check that every server shows
      fresh data and that `/servers/<id>/logs` renders.

### Lost authenticator

`docker exec -it oob-manager /usr/local/bin/oob-manager reset-totp --user <name>`. It is
available on the CLI only: there is no web route. It replaces the user's TOTP secret, ends
all of that user's sessions, and prints the new secret and `otpauth://` URI **once**. It
refuses to run unless stdout is a terminal, so use `-it`. The account cannot sign in until
the new secret is confirmed, either on the enrolment page (`/enroll`: username, password,
code) or with `confirm-totp -username <name>`. The reset is audited (`admin.totp_reset`).

### Client IPs and the per-IP login limit

Login and enrolment are limited per client IP (5/min) and per account (10/h). The app uses
the TCP peer address and ignores `X-Forwarded-For`. A port published from a Docker
**bridge** network keeps the real client IP: Docker DNATs it with iptables. So the per-IP limit
works with `compose.yaml` as written. Check it once on your host: a sign-in's audit row shows the
source address, and it must be the browser's machine, not the Docker gateway (rootless Docker and
some userland-proxy setups hide it). Do
not put a reverse proxy in front without revisiting this, because every client would then
share the proxy's IP.

## TLS

With a config.yaml, `serve` refuses to start without `tls.cert_file` and `tls.key_file` (only
an install without config.yaml uses the certificate generated in `/data/tls/`, see
[Quick start](#quick-start-a-data-volume-and-a-port)). It checks them before it opens the
database or contacts any BMC, and the error names `gen-tls`. It listens
on exactly one port, the TLS `listen` address. There is **no** plain-HTTP listener and no
HTTP→HTTPS redirect port; a plain `http://` request to the TLS port gets a 400. All cookies
are `__Host-` and need HTTPS.

### Self-signed certificate (`gen-tls`)

```bash
docker run --rm --user 65532:65532 -v $D/tls:/out $IMG \
  gen-tls --host 192.0.2.20 --host oob.example.test --out /out
```

- Pass every name or IP that people use to reach the UI. The `public_url` host must be among them.
- ECDSA P-256, self-signed, server-auth only, valid for 825 days by default (`--days` lowers
  it). 825 days is the most that Apple platforms accept.
- It writes `tls.key` (0600) and `tls.crt` (0644) and never overwrites existing files.
- It prints the certificate's SHA-256 fingerprint. Compare that with what the browser shows.
- The key is never printed.

In `config.yaml`: `tls: { cert_file: /run/secrets/tls.crt, key_file: /run/secrets/tls.key }`
(the compose mounts).

### Trusting it on a Mac

Copy only `tls.crt` (never the key) to the Mac, check the fingerprint, then trust it:

```bash
openssl x509 -in tls.crt -noout -fingerprint -sha256 -ext subjectAltName   # must match gen-tls
sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain tls.crt
```

You can also do it in Keychain Access: import `tls.crt` into *System*, open it, then
*Trust → When using this certificate: Always Trust*. Safari and Chrome use the macOS trust
store. Firefox uses its own: import the certificate under *Settings → Privacy & Security →
Certificates → View Certificates → Authorities*, or set `security.enterprise_roots.enabled`.
To remove the trust later, run
`sudo security delete-certificate -c <CN> /Library/Keychains/System.keychain`.
After any regeneration, trust the new certificate and delete the old one.

### Using your own certificate

Replace the two files with a PEM certificate (leaf first, then any intermediates) and its
PEM private key (PKCS#8, EC or RSA). The SANs must cover the `public_url` host. Keep the
same names, ownership and modes (`tls.crt` 0644, `tls.key` 0600, owner 65532), then run
`docker compose restart oob-manager`. The pair is read only at startup. If the new pair does
not load, the container exits at once with a `tls:` error, so keep the old files until it
reports healthy.

## BMC certificate pins

Each BMC entry needs `tls_pin_sha256`: the hex SHA-256 of the BMC certificate's public key
(SPKI). The pin replaces CA validation, and nothing is sent to the BMC before it matches.
Compute it from an admin machine on the BMC network:

```bash
openssl s_client -connect 192.0.2.10:443 -servername 192.0.2.10 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 | awk '{print $NF}'
```

This is trust-on-first-use. Confirm the certificate is the BMC's own: compare
`openssl s_client … | openssl x509 -noout -fingerprint -sha256` with the fingerprint in
the BMC's web UI (iDRAC: *iDRAC Settings → Services → Web Server → SSL certificate*) or at
its local console. Colons and case in the pin are ignored. The pin changes whenever the BMC
certificate is regenerated, for example after a factory reset, a certificate upload or some
firmware updates. Polling of that server then pauses ("Certificate changed") until you update
the pin and restart, or, for a server managed in the browser, fetch and confirm the new
fingerprint on its Settings → Servers page (no restart; its stored credentials are kept).

## `config.yaml` example

```yaml
# /etc/oob-manager/config.yaml (mounted read-only; changes apply on restart).
listen: ":8443"                      # inside the container; compose publishes it
public_url: https://192.0.2.20:8443/ # the URL people type; must match a gen-tls --host
tls:
  cert_file: /run/secrets/tls.crt
  key_file: /run/secrets/tls.key
auth:
  mode: local
  # General settings (Settings → General in the browser). Leave them out to edit them there;
  # a key written in this file wins and the browser shows it locked ("Managed by config.yaml").
  # session_idle: 30m                # 5 min to 2 h
  # session_max: 12h                 # 1 h to 24 h
  # stepup_window: 5m                # up to 5 min
audit:
  gelf: { address: "" }              # empty: set it in Settings → Integrations (or here, see that section)
  # gelf: { address: "192.0.2.30:12201", transport: tls, pin_sha256: "<64 hex>",
  #         allowed_networks: [192.0.2.0/24] }   # default allowed: the private ranges
poll: { min_interval: 30s }          # also interval (60s) and stale_multiplier (3): General settings
# ui: { instance_name: "", time_zone: UTC, theme: graphite,     # General settings (app defaults; set
#                                                                # them in the browser, a key here locks it);
#       clock_format: 24h, date_format: iso,                     # every user can override each one
#       temperature_unit: c, density: compact }                  # in Display preferences
# ratelimit: { login_ip_per_min: 5, login_acct_per_hour: 10 }  # General settings
# settings:
#   locked: []                       # any of general, servers, integrations: read-only in the browser
#   bmc_networks: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7]  # where browser-added BMCs may be
# notifications: { allowed_networks: [], debounce: 90s, targets: [] }  # see "Settings → Notifications"
# metrics: { enabled: false, allow_networks: [], include_inventory: false }  # see "Prometheus metrics"
# security: { enabled: true, every: 6h, min_firmware: { idrac8: "", idrac9: "", redfish: "" } }  # see "BMC security checks"
# history: { raw_days: 7, hourly_days: 90, daily_days: 730,   # General settings; see "Sensor history"
#            sample_psus: true, sample_voltages: true }
storage:
  db_path: /data/oob-manager.db
  lease_dir: /leases
secrets:
  credentials_file: /run/secrets/bmc-credentials.age
  identity_file: /run/secrets/age-identity
  app_keys_file: /run/secrets/app-keys.age
servers:                             # may be empty: servers can be added in Settings → Servers
  - id: storage1                     # [a-z0-9-], used in URLs
    name: Storage server
    tags: [critical]
    bmc: { address: 192.0.2.10, kind: idrac8 }   # Redfish on iDRAC8; literal IP only, no DNS; port: 443 (default)
    # Optional per server: auth (session | basic, default session) and timeouts.
    # Defaults: idrac8 request 30s / cycle 150s; idrac9 and redfish 15s / 60s.
    # bmc: { address: 192.0.2.10, kind: idrac8, auth: session, timeouts: { request: 30s, cycle: 150s } }
    tls_pin_sha256: "<64 hex: SPKI SHA-256 of this iDRAC's certificate>"
    credentials: { readonly: storage1-ro }
    fan: { mode: none }
    console: { serial: none, graphical: none }
  - id: edge1
    name: Edge server
    bmc: { address: 192.0.2.11, kind: idrac9 }   # Redfish on iDRAC9
    tls_pin_sha256: "<64 hex: SPKI SHA-256 of this iDRAC's certificate>"
    credentials: { readonly: edge1-ro }
    fan: { mode: none }
    console: { serial: none, graphical: none }
```

With real pins in place, this example passes the app's config validation. `bmc.timeouts.request`
must be 5 s to 2 min, and `cycle` must be at least `request` and at most 10 min. A server whose cycle
timeout is longer than `poll.interval` is polled every cycle timeout instead (the log says so at
startup). Use `auth: basic` only for a BMC without a Redfish SessionService. For `fan`,
`console.graphical` and `console.serial` see "Enabling fan leases", "Enabling the graphical
console" and "Enabling the serial console" below. Unknown keys fail startup, and so do
duplicate IDs and a missing pin.

Some servers report no power telemetry. An iDRAC on a server with a cabled, non-PMBus PSU
reports no PSUs and no power draw, only voltages. The UI shows "Not monitored by this
server" for PSUs and power draw on such a server, and lists the voltage sensors on its
server page. That is expected and is not an error.

## Settings in the browser

Admins manage the app under **Settings**, one tab per section: **Users**, **API tokens**,
**General**, **Servers**, **Notifications**, **Integrations** and **Audit log** (version, build and schema are on
**About**). Every change needs a fresh step-up (the authenticator code from the last few minutes,
or a fresh sign-in), is rate-limited and is written to the audit log in the same transaction.

**Precedence: config.yaml > database > built-in default**, per key, server and target. Anything
written in config.yaml shows a **Managed by config.yaml** lock badge and cannot be changed in the
browser; a browser copy with the same key or id is ignored and flagged. To freeze a whole section,
list it in `settings.locked`:

| `settings.locked` entry | Makes read-only in the browser |
|---|---|
| `general` | Settings → General (poll interval, session and step-up limits, login rate limits, app display defaults, sensor history) |
| `servers` | Settings → Servers (add, edit, credentials, fingerprints, enable, disable, remove) |
| `integrations` | Settings → Notifications (targets) and Settings → Integrations (the GELF target); maintenance mode stays available |

**`settings.bmc_networks`** is where a browser-added BMC may live (default: the private ranges).
Narrow it to the subnet or range your BMCs actually live in, excluding the app's own host and other
LAN services: an admin can then not point a "BMC" (and its read-only login, sent on Test connection)
at a NAS, a router or the Docker host. Notification receivers have their own allowlist,
`notifications.allowed_networks`; the two lists are independent.

Secrets saved in the browser (BMC credentials, notification tokens and passwords) are sealed in the
database with AES-256-GCM under keys derived from the app keys, one key per purpose, and bound to
what they belong to (a BMC's address and port, a target's URL): moving either makes them unreadable
and asks for them again. They are never shown again, logged or audited (the audit shows
`[redacted] vN`). Losing the app keys (`app-keys.age`) loses every secret stored in the browser, as
it loses the TOTP enrollments: keep the offline copy of the age identity.

### Settings → General

Each field shows its unit, allowed range and where its value comes from. Changes apply live,
including the poll interval (the pollers are rebuilt). **Reset to default** removes a value saved in
the browser. The **Sensor history** group sets how long readings and their summaries are kept and
whether power supplies and voltage rails are recorded, and shows how big the database file is (see
"Sensor history"). Every user can override the time zone, theme, date, clock, temperature unit and table
density for themselves in **Display preferences** (click the clock in the top bar).

### Settings → Servers

Admins can add, edit, disable and remove servers here without a restart. A disabled server is
not polled and raises no reachability or health notifications (its maintenance window is kept); removing a
server also ends its window. Servers written in config.yaml stay read-only there (lock badge); a server
id defined in both places uses the config.yaml one and the browser copy is shown as ignored.
`settings.locked: [servers]` makes the whole section read-only (see above).

Adding a server walks five steps. Every change needs a fresh step-up and is audited.

1. **Connection.** Id, name, kind and the BMC's IP address (no host names; it must be inside
   `settings.bmc_networks`, and loopback, link-local and multicast addresses are refused).
2. **Fingerprint.** The console completes one TLS handshake with that address (no HTTP request,
   no login) and shows the certificate's SPKI SHA-256 grouped by four, its subject, issuer,
   validity and names. Compare it with the BMC's certificate page or local console and confirm
   it (or paste the pin computed as above). The same flow pins the SSH host key for the serial
   console and the VNC port's certificate when it differs.
3. **Credentials** per slot: read-only (polling), operator (power, fan floor, serial console,
   native console launch), VNC password. They are sealed in the database (AES-256-GCM under a
   key derived from the app keys), bound to the server's kind, address and port, and never shown
   again: the page shows "set · v3 · date by user" and a Replace form. Moving a server to another
   address deletes them.
4. **Features**: fan lease mode and floor, consoles, the power "what goes down" list, an optional
   poll interval.
5. **Review and enable.** A new server starts disabled with nothing on. Enabling checks that the
   pins and the credentials its features need are in place; it is polled within one interval.

**Test connection** reads the Redfish service root, system and manager, the license, the reset
actions, the iDRAC9 fan limits, the VNC banner and the SSH host key, and reports the kind the
answers suggest. It writes nothing to the BMC.

Moving servers between the file and the database, from the shell:

```bash
# Copy config.yaml servers (and their credentials, re-sealed from the age file) into the DB:
docker exec -it oob-manager /usr/local/bin/oob-manager settings import -servers storage1,edge1
# then remove them from config.yaml and restart. Until then config.yaml wins.

# Print the effective settings and servers as config.yaml keys, without any secret:
docker exec oob-manager /usr/local/bin/oob-manager settings export > settings-export.yaml
```

### Settings → Notifications

oob-manager can push alerts to **ntfy**, **Pushover**, **Gotify**, a **generic webhook** and
**email (SMTP)**. Nothing is sent until a target exists. Targets are added here (admin, fresh step-up) or, read-only in the
browser, in `config.yaml`.

**Events** (each target subscribes to classes and a minimum severity; defaults: all classes,
warning and above):

| Class | Sent when | Severity |
|---|---|---|
| `health` | the server's health verdict changes (OK → Warning/Critical) and back | warning / critical |
| `reachability` | no good poll for longer than the stale threshold, and recovered | critical |
| `sel` | new warning/critical SEL or Lifecycle entries (count + worst severity) | warning / critical |
| `psu` | power supply redundancy lost and restored | critical |
| `fan` | fan lease started, ended (or expired), failed | info / warning |
| `power` | power action requested, done, failed | warning / info / warning |
| `bmc` | BMC restart requested, back (the recovery of the request, with the downtime), failed, or not back by its deadline (see "Enabling BMC restart") | warning; critical when the BMC did not come back |
| `console` | graphical, serial or native console session started or taken over | warning |
| `auth` | sign-in lockout; 5 failed sign-in steps within 10 minutes | warning |
| `audit` | the audit hash chain does not verify (startup or Settings → Audit log); the audit stream's GELF target changed in Settings → Integrations (who, and each field before → after) | critical; warning for a minor GELF change or for turning shipping on with its first address, pin and server name |
| `trust` | the BMC's TLS certificate no longer matches its pin (polling pauses), the VNC certificate or SSH host key does not match on a console connect or Test connection, and resolved; the GELF log server's certificate does not match its pin or has expired (shipping pauses), and resolved or closed | critical |
| `security` | a server's security checks found new warnings or failures (one message per run: warning), a BMC certificate expires in 14 (info), 7 or 1 days (warning), an admin accepted a finding as a risk (warning: who, which check, the comment), or an acceptance ended (info) (see "BMC security checks") | info / warning |
| `notify` | another target keeps failing (3 failed messages in a row), and recovered | warning |

**What leaves with an Integrations change.** The `audit` notification about a GELF target change names
the admin and lists each changed field before → after: the log server's address, transport, server
name and certificate fingerprint. Those values go to every target subscribed to `audit` (ntfy, Pushover,
Gotify, a webhook, an email relay), which may be a third-party push service. They are not secrets (GELF
has no credential), but they describe your logging setup; unsubscribe a target from `audit` if that
matters.

Health and PSU changes must hold for `notifications.debounce` (default 90 s) before they are sent;
every problem gets one message and one recovery, sent to every target that received the problem.
Messages name the server, what changed and the severity; BMC log text is added only for targets
with **Include BMC log text** (`include_detail`). Addresses and serial numbers are never sent.

**Maintenance mode** (replaces the per-server mute; active mutes became maintenance windows on
upgrade): on a server page an operator or admin starts a window with a reason, for 30 min, 1 h, 4 h,
24 h, until a chosen time (at most 7 days) or until it is ended, now or scheduled up to 30 days
ahead. While it is active the server shows "In maintenance until … — reason — by user" on the
Overview, the sidebar and its pages; its warnings are listed in an "In maintenance" group and not
counted in the fleet verdict or Needs attention, and its `health`, `reachability`, `sel` and `psu`
notifications are suppressed. Power, BMC restart, console, fan, sign-in, audit and trust events are always sent.
One "maintenance started" and one "maintenance ended" message (class `maintenance`, normal
priority) go to every target that subscribes to any of the four suppressed classes. A window
expires on its own (audited as `system`); problems still present afterwards are reported again
after the usual debounce. A window "until I end it" never expires: once it has lasted 24 h the
Overview shows an **Open-ended maintenance** warning naming it, and the same targets get one "still
in maintenance" reminder per 24 h until someone ends it (a restart neither repeats nor skips one;
after downtime one reminder is sent, not one per missed day).

**Notes and acknowledgements:** operators write plain-text notes on a server page (4 KB, links
clickable, one can be pinned to the top; authors edit and delete their own, admins delete any;
viewers read). On Events and a server's Logs an operator acknowledges a warning or critical entry
(or every one shown for a server) with an optional comment: it stays listed with "Acked by …", but
leaves Needs attention, the event counts and log notifications. A new entry of the same kind is
not acknowledged. Everything is audited; note text never reaches the audit log.

**Network policy.** Targets must be `https://`. A receiver on a private address (a LAN ntfy,
Gotify or mail relay) must be listed in `notifications.allowed_networks`; `http://` and SMTP
without TLS additionally need **Allow plaintext on the LAN** on the target. Redirects are never
followed. Host names are resolved once per message and the checked address is the one dialled.

#### What to have ready

| Kind | You need | Secret fields |
|---|---|---|
| ntfy | a topic URL, e.g. `https://ntfy.sh/<long-random-topic>` (a public topic name is the only protection: make it long and random) or your own server | access token (optional, sent as `Authorization: Bearer`) |
| Pushover | an application created at pushover.net, and your user key | application token, user key |
| Gotify | the server URL and an application created in Gotify | application token |
| Webhook | an HTTPS endpoint that accepts the JSON body below | signing secret (optional) |
| Email | an SMTP server with STARTTLS (587) or TLS (465), a sender and up to 10 recipients | SMTP user name and password (optional, sent only over TLS) |

Priorities: ntfy 3 / 4 / 5 for info / warning / critical (recoveries 3); Pushover −1 / 0 / 1 (an
opt-in maps critical to emergency priority 2, repeated every 5 min for an hour); Gotify 2 / 5 / 8.

#### File-managed targets

```yaml
notifications:
  allowed_networks: [192.0.2.0/24]   # private receivers and the only place plaintext may go
  debounce: 90s
  targets:
    - id: phone
      name: Phone
      kind: ntfy
      url: https://ntfy.example.org/oob-alerts
      secret_ref: notify-ntfy          # entry in the age credential file
      classes: [health, reachability, psu, power, console, auth, audit, trust]
      min_severity: warning
    - id: pager
      name: Pager
      kind: pushover
      url: https://api.pushover.net/1/messages.json
      secret_ref: notify-pushover      # username = user key, password = application token
      min_severity: critical
    - id: lan-gotify
      name: Gotify
      kind: gotify
      url: http://192.0.2.30:8080
      allow_plaintext: true            # LAN only: the address is in allowed_networks
      secret_ref: notify-gotify
    - id: siem
      name: Automation hook
      kind: webhook
      url: https://hooks.example.org/oob
      secret_ref: notify-webhook       # password = HMAC signing secret
      min_severity: info
    - id: ops-mail
      name: Ops mail
      kind: email
      url: smtp://mail.example.org:587
      secret_ref: notify-smtp          # username/password = SMTP AUTH
      email: { from: oob@example.org, to: [ops@example.org], security: starttls }
```

Credential file entries (re-encrypt the file afterwards):

```yaml
notify-ntfy:     { password: "tk_..." }
notify-pushover: { username: "<user key>", password: "<application token>" }
notify-gotify:   { password: "<app token>" }
notify-webhook:  { password: "<random 32+ characters>" }
notify-smtp:     { username: "oob@example.org", password: "..." }
```

A file target shows a **Managed by config.yaml** badge; it can be tested but not edited in the
browser. A browser target with the same id is ignored and flagged. `settings.locked: [integrations]`
makes every target read-only in the browser.

#### Webhook body (version 1)

`POST` with `Content-Type: application/json` and headers `X-OOB-Event: <class>`,
`X-OOB-Delivery: <event id>` (the same on retries: deduplicate on it), `X-OOB-Timestamp: <unix s>`
and, with a secret, `X-OOB-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`.

```json
{
  "version": "1",
  "id": "0123456789abcdef0123456789abcdef",
  "time": "2026-10-21T14:03:00Z",
  "instance": "Lab OOB",
  "class": "health",
  "severity": "critical",
  "recovery": false,
  "server": { "id": "srv-a", "name": "Storage node" },
  "title": "Storage node: health Critical",
  "message": "Storage node reports Critical health (was OK).",
  "count": 0,
  "detail": ["Critical: ..."]
}
```

`server` is absent for app-wide events, `count` for single events, `detail` unless the target
opted in. Fields are only ever added within version 1. Verify the signature in constant time and
reject timestamps older than a few minutes. For services oob-manager does not speak, point the
webhook at an Apprise API container.

#### Checking it

**Send test** on each target delivers a test message at once and shows the result (failure
class only: blocked, dns, timeout, tls, redirect, http_4xx, http_5xx, smtp…). The list shows the
last delivery and failure per target; a target that keeps failing raises a banner on Overview and
an alert to the other targets. Delivery state is kept in memory and resets on restart.

### Settings → Integrations

The **audit shipping (GELF)** panel sends a copy of every audit row (who did what, on which server,
with what result; never a password or token) to a log server's GELF TCP or TLS input, for example
Graylog. The database copy and its hash chain are always kept. The panel shows the live state
(Connected, Disconnected, Disabled, Paused: certificate changed), what is queued, sent and dropped,
and the last error class.

| Key (config.yaml) | Browser field | Notes |
|---|---|---|
| `audit.gelf.address` | Ship audit rows + Address | `host:port`; a non-empty value in the file turns shipping on and locks both |
| `audit.gelf.transport` | Transport | `tls` (pinned) or `tcp` (unencrypted: a trusted segment only). No UDP |
| `audit.gelf.server_name` | Server name (TLS) | Optional SNI; empty sends the host when it is a name. It does not decide trust |
| `audit.gelf.pin_sha256` | Certificate fingerprint | SHA-256 of the public key of the server's certificate or of the CA that issued it; required for `tls` |
| `audit.gelf.allowed_networks` | (file only) | Where any GELF address may point. Default: `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7` |

**Destination policy.** The address (and every DNS answer for a name, checked again on every
connection) must be inside `audit.gelf.allowed_networks`, and is never loopback, link-local,
multicast, broadcast, unspecified, this console's own listen address and port, or the address of a BMC
this console manages. A log server on the same host on another port is fine. List the log server itself
rather than a range: `allowed_networks: [192.0.2.30/32]` (a single address is enough, no port list is
needed), so a misused admin session cannot aim the audit stream at any other LAN host. A hosted log service needs its range listed. A config.yaml with a
literal address outside the list fails startup.

**Turning on TLS with a pin.** On the log server, enable TLS on the GELF TCP input (Graylog:
`tls_enable`, with its certificate and key). In Settings → Integrations, set Ship audit rows to On,
type the address and press **Fetch and confirm the certificate**: the console completes one TLS
handshake (it sends nothing else) and shows the certificate it got and, when the server sent its
chain, the CA that issued it. A host name is fetched at **every** address it resolves to (at most
four), because the shipper may connect to any of them; if they present different certificates the fetch
is refused: use the IP address of one log server, or give every answer the same certificate. Compare the fingerprint with the log server's own:

```bash
openssl x509 -in gelf-input.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256
```

Pin the **issuer** when the server sends its chain and the CA is your own: the server can then renew its
certificate from the same CA without a new pin. The console checks that the certificate chains to the
pinned CA **and is issued for the log server's name**: the Server name when set, else the address
(fetching by IP needs that IP in the certificate; otherwise set Server name to a name it carries).
A publicly trusted CA signs certificates for anyone, so the page preselects the leaf then.
Pin the **leaf** for a self-signed input; when that certificate changes, shipping pauses until you
confirm the new fingerprint. Confirming switches the transport to TLS and applies it at once. A
fingerprint can also be pasted (audited as manual).

**When the certificate stops matching**, nothing is sent to the impostor: shipping pauses for 5 minutes
at a time (rows queue, up to 1 024, then are dropped and counted), Overview shows a banner, a critical
`trust` notification goes to the targets that subscribe to it, and `/readyz` answers `degraded`.

**Changes apply without a restart, and a redirect leaves traces.** In order: the change is committed to
this console's audit log (`admin.integrations.update`, the hash-chained copy that always exists); the
console then waits up to 2 seconds for the **current** destination to receive everything queued for it,
that row included; then the shipper is swapped and `admin.integrations.applied` goes to the new
destination with `previous_confirmed: true|false` (whether the old one received the row) and
`queued_on_previous`. "Received" means the bytes were written to its connection; GELF has no
acknowledgement. When the current destination is down, the page warns before Save and the old log
server may never see the change. Every change of the target also notifies (class `audit`): critical
when shipping is turned off, TLS is dropped for plain TCP, or the address, the pin or the server name
changes; a warning otherwise.
Rows still queued for the old destination are sent within 3 seconds or dropped and counted.

**Watching it.** `/readyz` says `degraded` while a configured shipper is disconnected or paused; turning
shipping **off** in the browser makes it `ok` again by design. To catch that too, alert on the metric
(it is written whenever `/metrics` is on, `0` when shipping is off) with a rule that also fires when
the series is missing:

```yaml
- alert: OobAuditShippingNotWorking
  expr: (oob_audit_shipper_enabled == 0) or absent(oob_audit_shipper_enabled)
        or (oob_audit_shipper_connected == 0) or (oob_audit_shipper_pin_mismatch == 1)
  for: 10m
```

Without Prometheus, the critical `audit` notification on the change itself covers a switch-off.

**Send test** writes one test message (`oob-manager GELF test by <user>`) to the connection and an audit
row. GELF has no reply: success means the log server accepted the bytes, so check it for the message.

The **Dashboards and monitoring** panel shows copy-ready snippets for Homepage (`customapi`), Uptime Kuma
(`/readyz` keyword `ok`, and a `/metrics` keyword monitor when metrics are on) and Prometheus, with
this console's URL and a `<token>` placeholder: mint one read-only token per tool in **API tokens**.
Alerts to people stay in **Notifications** (the generic webhook is an event channel with filtering and
retries; GELF carries every audit row for a log system; the API, `/metrics` and `/readyz` are pulled).
## Prometheus metrics

`GET /metrics` serves the text exposition format 0.0.4 for Prometheus, VictoriaMetrics, Grafana
Agent/Alloy and similar scrapers. It is **off by default**. When it is off the path answers 404.

```yaml
metrics:
  enabled: true
  allow_networks: [192.0.2.30/32]   # the scraper; empty = any address (a token is still required)
  include_inventory: false          # true adds model, serial, service tag, BIOS/BMC firmware, licence tier
```

The section is file-only (no browser setting) and applies on restart.

**Authentication.** Every scrape needs a read-only API token as a bearer token. Mint a dedicated
one so it can be revoked on its own:

```bash
docker exec oob-manager /usr/local/bin/oob-manager token create --name prometheus --expires 365d
```

Browser sessions are never accepted, whatever the role. Requests are checked in this order:
method (GET/HEAD) → `allow_networks` (the TCP peer address; forwarding headers are ignored) →
token → rate limit (the token's API bucket, 60 requests/min). A scrape interval of 15 s or more fits
comfortably.

**Cost.** A scrape never contacts a BMC. It reads the poller's cached snapshots, the fan lease table
and in-memory counters, and a render is reused for 1 s. Values change only when the poller runs (every
60 s, 150 s for an iDRAC8), so scraping faster than the poll interval adds nothing.

### Scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: oob-manager
    scheme: https
    scrape_interval: 30s
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/oob-manager.token   # the oobk_… token, mode 0600
    tls_config:
      ca_file: /etc/prometheus/oob-manager.crt             # the gen-tls certificate (self-signed)
    static_configs:
      - targets: ["192.0.2.20:8443"]
```

### Metric list

Every per-server series has a `server` label (the server ID from the registry). Sensor series add
`sensor`/`fan`/`psu` (the BMC member ID) and `name` (its display name); temperatures add `kind` (the
physical context, e.g. `CPU`, `Intake`). Label values are cut to 64 bytes with control characters
removed.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `oob_build_info` | gauge | version, commit, goversion | Always 1 |
| `oob_process_start_time_seconds` | gauge | | Unix seconds |
| `oob_process_goroutines`, `oob_process_heap_alloc_bytes`, `oob_process_memory_sys_bytes` | gauge | | Go runtime |
| `oob_process_gc_cycles_total` | counter | | Completed GC cycles |
| `oob_audit_chain_ok` | gauge | | 1 when the audit hash chain verified at startup |
| `oob_audit_shipper_enabled` | gauge | | 1 when GELF shipping is on, 0 when off (always written) |
| `oob_audit_shipper_connected`, `oob_audit_shipper_queued` | gauge | | GELF shipper (only when configured) |
| `oob_audit_shipper_dropped_total` | counter | | |
| `oob_login_failures_total` | counter | stage (password, totp, other) | Since start |
| `oob_console_sessions_active` | gauge | type (vnc, serial) | Open consoles |
| `oob_notify_target_failing`, `oob_notify_target_consecutive_failures` | gauge | target | Enabled targets only |
| `oob_notify_sent_total`, `oob_notify_dropped_total` | counter | target | Since start |
| `oob_servers` | gauge | | Servers in the registry |
| `oob_history_rows` | gauge | tier (raw, hourly, daily) | Rows in the sensor history, as of the janitor's last hourly pass |
| `oob_history_db_bytes`, `oob_history_db_freelist_pages` | gauge | | Database file size and the free pages prunes left (reused by later inserts) |
| `oob_history_rollup_last_timestamp_seconds` | gauge | tier (hourly, daily) | Rollup watermark: every bucket before it is summarized |
| `oob_history_prune_duration_seconds` | gauge | | How long the last pass's prunes took |
| `oob_server_info` | gauge | server, name (+ model, serial, service_tag, bios_version, bmc_firmware, license_tier with `include_inventory`) | Always 1 |
| `oob_server_up` | gauge | server | 1 when the last poll succeeded |
| `oob_server_stale` | gauge | server | 1 when the data is older than the stale threshold |
| `oob_server_paused` | gauge | server | 1 when polling is paused by a certificate pin mismatch |
| `oob_server_consecutive_failures` | gauge | server | |
| `oob_server_last_success_timestamp_seconds` | gauge | server | Unix seconds |
| `oob_server_poll_duration_seconds` | gauge | server | Last sensor poll |
| `oob_server_data_age_seconds` | gauge | server | Age of the cached data |
| `oob_server_health` | gauge | server, state (ok, warning, critical, off, unknown) | 1 for the current verdict; `off` while the host is powered off and nothing is critical |
| `oob_server_power_state` | gauge | server, state (on, off, powering_on, powering_off, unknown) | 1 for the current state |
| `oob_server_power_watts` | gauge | server | Only when the BMC reports power |
| `oob_server_maintenance` | gauge | server | 1 while the server is in a maintenance window (its health alerts are paused) |
| `oob_server_maintenance_until_timestamp_seconds` | gauge | server | End of the active window, Unix seconds; 0 when not in maintenance or "until I end it" |
| `oob_server_bmc_restarting` | gauge | server | 1 while the app waits for the BMC to come back after a restart it requested |
| `oob_server_bmc_last_reset_timestamp_seconds` | gauge | server | Last BMC restart, Unix seconds: the BMC's own `LastResetTime` (iDRAC9), else the app's last verified restart, else 0 |
| `oob_bmc_resets_total` | counter | server, result (sent, refused, verified, timeout) | BMC restarts since start |
| `oob_fan_lease_active` | gauge | server | Servers with leasable fans |
| `oob_fan_lease_percent`, `oob_fan_lease_remaining_seconds` | gauge | server | While a lease is active |
| `oob_fan_applied_percent` | gauge | server | What the enforcing side reports |
| `oob_log_entries` | gauge | server, log (sel, lifecycle), severity | Entries in the cached log |
| `oob_events_unacknowledged` | gauge | server, severity (warning, critical) | Warning and critical entries of both cached logs nobody acknowledged (servers with a cached log) |
| `oob_security_checks` | gauge | server, result (pass, info, warn, fail, unknown, cant-read, accepted) | Results of the last security check run; an accepted risk counts as `accepted` only |
| `oob_tls_cert_expiry_timestamp_seconds` | gauge | server, port | Expiry of the BMC certificate on the HTTPS port (and the VNC port when the graphical console uses VNC over TLS), Unix seconds |
| `oob_firmware_components` | gauge | server | Firmware components in the firmware view (last scan) |
| `oob_firmware_flagged` | gauge | server, flag (below_minimum, not_applied, cannot_compare, stale_release) | Components with that flag; versions are never exported |
| `oob_firmware_last_scan_timestamp_seconds` | gauge | server | Last firmware scan, Unix seconds (0: never) |
| `oob_firmware_changes_total` | counter | server | Firmware version changes seen since start |
| `oob_temperature_celsius` | gauge | server, sensor, name, kind | |
| `oob_temperature_upper_warning_celsius`, `oob_temperature_upper_critical_celsius` | gauge | server, sensor, name, kind | Thresholds, when reported |
| `oob_fan_speed_rpm`, `oob_fan_speed_percent` | gauge | server, fan, name | By the fan's units |
| `oob_psu_healthy` | gauge | server, psu, name | 1 when the PSU reports OK |
| `oob_psu_input_watts` | gauge | server, psu, name | When measured |
| `oob_psu_redundant` | gauge | server | 1 when ≥ 2 PSUs report OK |
| `oob_voltage_volts` | gauge | server, sensor, name | Sensors with a numeric reading |
| `oob_scrape_series_dropped` | gauge | | Series left out by the caps (should be 0) |

Sensor, fan, PSU, voltage, power and health values are left out while a server is stale, so a dead
BMC does not keep reporting its last temperatures. Alert on `oob_server_up == 0` or
`oob_server_stale == 1` instead. Health and power state read `unknown` then.

**Maintenance.** A server in maintenance keeps reporting its real health, sensors and log counts
(the data is still true, and a dashboard may want to show it). Overview leaves such a server out of
the verdict and Needs attention; to do the same in an alert or dashboard, combine with
`oob_server_maintenance`, as in the queries below.

Useful queries:

```promql
max by (server) (oob_temperature_celsius{kind="Intake"})           # inlet temperature
oob_server_health{state=~"warning|critical"} == 1                  # unhealthy servers (any)
(oob_server_health{state=~"warning|critical"} == 1)
  unless on (server) (oob_server_maintenance == 1)                 # unhealthy, not in maintenance
sum by (server) (oob_events_unacknowledged{severity="critical"}) > 0
  unless on (server) (oob_server_maintenance == 1)                 # critical log entries to look at
oob_server_maintenance == 1 and on (server)
  (oob_server_maintenance_until_timestamp_seconds == 0)            # open-ended maintenance
time() - oob_server_last_success_timestamp_seconds > 600           # no good poll for 10 min
increase(oob_login_failures_total[1h]) > 10                        # sign-in guessing
```

**Caps.** Each per-server list (temperatures, fans, PSUs, voltages) is capped at 64 items,
notification targets at 64 and any family at 4096 series. Anything left out is counted in
`oob_scrape_series_dropped`.

### Homepage and Uptime Kuma

Settings → Integrations shows these snippets filled in for this install (with a `<token>` placeholder).

- **Homepage:** the simplest tile is still a `customapi` widget on `/api/v1/servers/{id}` with a read-only
  token. If you run Prometheus, Homepage's `prometheusmetric` widget can show any query above (for example
  inlet temperature) from Prometheus, so Homepage needs no oob-manager token at all.
- **Uptime Kuma:** keep the HTTP keyword monitor on `/readyz` for liveness. To alert on a BMC, use a
  Prometheus alert on `oob_server_up`, or Kuma's HTTP keyword monitor on `/metrics` with an
  `Authorization: Bearer …` header and the keyword `oob_server_up{server="<id>"} 1`.

## BMC security checks

Every Redfish server gets a **Security** tab: 31 read-only checks of the BMC itself, run every 6 hours
on the poller's own session, plus a Security column on the Overview and Servers tables ("1 fail · 2
warn"). The checks look at the web certificate (expiry, factory default, key and signature), the TLS
versions and cipher suites the BMC accepts, the SSH algorithms it offers, which services are on (IPMI
over LAN, SNMP v1/v2c, Telnet, plain HTTP without a redirect, SSH, VNC, virtual media, SSDP,
WS-Management), NTP and clock drift, remote syslog, the enabled accounts (factory names such as `root`,
IPMI and serial-over-LAN access, password and lockout policy, Administrator count), BMC firmware
against a minimum you set, BIOS version, licences, the IP filter, DHCP and IPv6.

**What a run does.** Redfish GETs with the read-only account, then handshake-only connections to the
BMC's own ports: TLS handshakes on the HTTPS port (and the VNC port when the graphical console uses VNC
over TLS), the SSH banner on the SSH port, a `HEAD` on the plain-HTTP port and a `HEAD /wsman`. No
credentials are sent on those, no login is attempted, and nothing is ever changed on the BMC: every
finding comes with what to do in the BMC's own interface. A BMC may log the probes as failed handshakes.

**The read-only account.** Some checks need resources a Read Only account may not be allowed to read
(the account list, the attribute registry, the licences). When the BMC refuses, the check says **Can't
read with the read-only account** rather than asking for more privileges. If you want those checks,
grant the read-only account the *Login* privilege only and verify in the tab; never give it more.

```yaml
security:
  enabled: true           # false turns the checks, the tab and the column off
  every: 6h               # 1h to 168h; "Re-run checks" on the tab runs them now (admin, 5-minute cooldown)
  min_firmware:           # the oldest BMC firmware you consider acceptable, per kind (dotted numbers)
    idrac8: "2.86.86.86"  # leave empty to just report the version
    idrac9: "7.10.30.00"
    redfish: ""
```

The section is file-only and applies on restart. The firmware comparison is local: nothing is looked up
online.

**Roles.** Everyone who can view a server sees the summary (verdict and counts). The findings
themselves need the **operator** role, because they describe weaknesses. Admins can **Re-run checks**
and, with a fresh step-up (authenticator code within 5 minutes, like every Settings change),
**accept a finding as a risk** with a comment: it stops counting and is not notified while it stays
the same, and ends by itself when the finding is fixed or changes, or when the server is moved to another
BMC address. The form accepts exactly the finding it showed: if the finding changed while the page was
open, the tab comes back with a notice and nothing is accepted. All of it is audited.

**Notifications and metrics.** Class `security` sends one message per server when a run finds new
warnings or failures, reminds you 14, 7 and 1 days before a BMC certificate expires, and reports every
accepted risk (a warning naming who accepted which check, and the comment) and every acceptance that
ends (info). All at normal priority, not paused by maintenance mode. `/metrics` exports `oob_security_checks` and
`oob_tls_cert_expiry_timestamp_seconds` (see the metric list).

## Firmware view

The **Firmware** page (sidebar, between Servers and Settings) lists what firmware runs on every
component of every server: BIOS, BMC, network, storage controllers, drives, backplanes, power supplies,
CPLD and the vendor's service tools, with the running version, the rollback copy the BMC keeps
(Previous), an image waiting for a reboot (Staged) and, where the BMC reports it, the release date and
its age. Problems come first. Each server's **Inventory** tab has the same list for that server,
grouped by kind, with its recent version changes. **It is read-only**: oob-manager never updates
firmware (that is done on the BMC itself) and never contacts a vendor site.

**When it reads.** Each server's firmware is read at start, every 24 hours, right after a BMC restart
and when the 6-hourly inventory lists different versions. Operators can press **Re-scan firmware** on
the Firmware page or the Inventory tab (6 a minute per user, once per 30 seconds per server, audited). A scan is one request for the
list plus, once per component, the component's own document for its name and release date: names are
kept, so later scans read only new or changed components (on a slow iDRAC8 the first scan may take a
couple of minutes; a scan that runs out of time keeps what it read and continues next time). Every
version change is recorded (the Inventory tab shows the last 20; one scan records at most 16 one by
one plus a summary), written to the audit log as `server.firmware.changed`, and each scan with changes
sends one **BMC security check findings** (`security` class) warning, "firmware changed on N
components": an unexpected firmware change is worth a look.

**Flags.** *Below minimum*: older than the minimum known good version you configured. *Not applied*
(Dell): the BMC holds a newer firmware image for the component than the one installed (shown as
"2.25 stored on the BMC, not installed" next to the running version), typically an update that was
uploaded or bundled but never applied; install it from the BMC's update page when convenient (most
components need a host reboot). An older stored image is shown without a flag. *Cannot compare*: the versions have different shapes
(letters against numbers), so no order is guessed. *Stale release* (off by default): released longer
ago than `stale_after`. The sidebar counts *Below minimum* rows; Overview does not list
firmware (it is posture, not health).

```yaml
firmware:
  stale_after: 0            # e.g. 3y or 400d; 0 (default) never flags by age
  names:                    # display names for components no BMC document names (by component ID)
    "101068": "Backplane expander"
  minimum:                  # "minimum known good"; every key that is set must match
    - { bmc_kind: idrac9, kind: bios, model: "PowerEdge R440", version: "2.20.0" }
    - { component_id: "105897", version: "23.31.1", note: "BCM5720 fix" }
    - { fqdd: "NIC.Slot.*", version: "23.0.8" }   # a trailing * matches a prefix
```

Match keys: `bmc_kind` (idrac8, idrac9, redfish), `kind` (bios, cpld, nic, storage, drive, enclosure,
psu, lc, other), `model` (the system model, exact), `component_id`, `fqdd`; at least one is required,
at most 200 rules. **The BMC's own firmware is not listed here:** its minimum is
`security.min_firmware.<kind>` (see "BMC security checks"), so one value serves both the Security tab
and the Firmware page; a rule with `kind: bmc`, `component_id: "25227"` or an `iDRAC.` FQDD fails startup. The section is file-only (the page shows
it with a lock) and applies on restart.

**CSV.** **Download CSV** on the page (and `GET /api/v1/firmware.csv` with a read-only token, both
with the page's filters `server`, `kind`, `flagged=1`, `updates=1`, `q`) exports the table, at most 6 exports a minute
per user or token. Columns: `server_id, server_name, bmc_kind, kind, component, component_id, fqdd,
running, previous, staged, stored, release_date, updateable, flag, minimum_version, identity,
last_seen_utc, latest_version, latest_released, latest_criticality, update, catalog_version` (the last five
come from the firmware update check and are empty while no vendor catalog is in use). BMC-supplied text that a spreadsheet would read as a formula (starting with `=`, `+`,
`-`, `@`, also after spaces) gets a leading apostrophe. An export larger than 10 000 rows or 4 MiB is
refused (narrow the filter). JSON: `GET /api/v1/firmware` (`{data, meta}`),
`GET /api/v1/servers/{id}/firmware` (the rows, last and next scan, recent changes, catalog coverage) and
`GET /api/v1/firmware/catalog` (the update check's status and its last 20 checks).

### Firmware update check (Dell catalog)

The Firmware page can compare what runs with the newest release Dell publishes for each server model
(column **Latest**, flags **Urgent update** and **Update available**, the sidebar counts urgent ones).
It reads Dell's signed enterprise catalog; it **never downloads a firmware package, never installs
anything and never sends a request to a BMC** for this. Dell only; generic Redfish servers show "No
vendor catalog for this BMC type".

**Getting a catalog.** Either:
- **Online (off by default).** An admin turns on *Settings → General → Firmware update check* (a fresh
  authenticator code; audited). The app downloads `https://downloads.dell.com/catalog/Catalog.xml.gz`
  and its `.sign` 2–10 minutes after start, within 2 minutes of turning it on, then every
  `firmware.catalog.check_every` days (default 7), retrying after 1 h and 6 h on failure. **Check now** on
  the Firmware page (operator) asks again, once per 5 minutes. Only the whole public catalog is fetched:
  nothing about the servers is sent. The container needs outbound HTTPS to downloads.dell.com.
- **Upload** (*Settings → General → Vendor firmware catalog*, admin, fresh code): the `.gz` (16 MiB at
  most) and its `.sign`. For installs without internet access, private mirrors, older catalogs.
- **CLI:** `docker exec <container> oob-manager catalog import /path/Catalog.xml.gz /path/Catalog.xml.gz.sign`.

Every path checks the detached signature against Dell's key (built in, fingerprint
`4172 E2CE 955A 1776 A5E6 1BB7 CA77 951D 23B6 6A9D`) **before** reading the file, then parses it within
fixed bounds. A failed check keeps the previous catalog. A new catalog that lists far fewer components
than the one in use is **held** until an admin confirms it in Settings. The verified file is kept in
`<data>/catalog/dell/` (backed up with the database), so adding a server re-reads it without the network.

**Config** (`firmware.catalog`; the first three are also in Settings → General, a key here wins and locks it):

```yaml
firmware:
  catalog:
    # enabled: false        # the online check (Settings → General)
    # check_every: 7        # days, 1–30
    # notify: urgent        # urgent | all | off
    # url: https://mirror.example.net/catalog/Catalog.xml.gz   # https only; default Dell's
    # extra_keys_file: /etc/oob-manager/catalog-keys.asc       # more trusted signing keys
    # allowed_networks: [192.0.2.0/24]   # private addresses the fetch may reach (a LAN mirror)
    # allow_unsigned: false  # accept unsigned uploads/CLI imports (Repository Manager catalogs)
    # systems: { r1: "088F" } # server ID → Dell system ID, when the BMC reports none
```

The URL, keys, networks, `allow_unsigned` and `systems` are file-only: a browser session can switch the
configured, signature-checked source on or off, never point it elsewhere.

**Matching.** iDRAC9 reports its Dell system ID; iDRAC8 does not, so its model name must name exactly
one model in the catalog (otherwise set `systems`). Each server shows a line: "N of M components
matched · K updates (U urgent)", or that the catalog no longer lists the model (end of support).
An admin can **skip** one version of one component (with a comment, fresh code, audited); a newer
release flags again.

**Notifications.** Class `firmware`: one message per catalog that brings new updates (a warning when
any is urgent, else info; so a target at the default "warning and above" hears about urgent ones only),
and one when the online check fails three times in a row. `notify` caps what is sent.

### Capturing the firmware documents of a BMC (read-only)

The firmware tests use hand-written member documents. To check the names and states against a real
BMC (or to report hardware we have not tested), capture them with the read-only account; this sends
GET requests only:

```bash
B=https://192.0.2.10 U=readonly-user   # your BMC and its read-only account (curl prompts for the password)
curl -sk -u "$U" "$B/redfish/v1/UpdateService/FirmwareInventory" -o FirmwareInventory.json
for m in $(grep -o '"/redfish/v1/UpdateService/FirmwareInventory/[^"]*"' FirmwareInventory.json | tr -d '"'); do
  curl -sk -u "$U" "$B$m" -o "UpdateService_FirmwareInventory_$(basename "$m").json"
done
```

Before sharing the files, replace MAC addresses with documentation ones (`00:00:5E:00:53:xx`), and
remove serial numbers, service tags, host names and IP addresses. On Dell BMCs an `Installed-` member is
the running firmware and a `Current-` member the image the BMC holds in its store (usually the same
version); a capture that shows otherwise is worth a report.

## Sensor history

Every poll's readings are kept, so you can see what a sensor did last night or since a change, inside
the app. Each server has a **History** tab (after Logs): one chart per kind (temperatures, fans, power
draw, power supplies, voltage rails) for the last **24 hours, 7 days, 30 days or year**. A chart draws
up to 16 sensors; pick one in its list to show it in the accent color with its minimum to maximum
range, its numbers for the period and, for a temperature, today's warning and critical levels as
bands. Warning and critical log entries, power actions, fan leases and BMC restarts of the period are
marked on the charts and listed under them; maintenance windows are shaded. Each chart has a data
table (the same points as text) and a **Download CSV** link. The server page's Status panel shows
24-hour sparklines next to the hottest temperature, the inlet and the power draw; each opens the
History tab on that sensor. Temperatures follow each viewer's °C/°F; storage and CSV stay in °C.
Nothing here contacts a BMC: the history is written from the readings the poller already has.

**What is kept** (Settings → General, *Sensor history*, or a `history:` block in config.yaml, which wins):

| Key | Range | Default | What |
|---|---|---|---|
| `history.raw_days` | 1–30 | 7 | every reading of every poll |
| `history.hourly_days` | 7–730, at least `raw_days` | 90 | minimum, average, maximum and count per hour |
| `history.daily_days` | 30–1825, at least `hourly_days` | 730 | the same per day |
| `history.sample_psus` | on/off | on | power supply input and output watts (two series per PSU) |
| `history.sample_voltages` | on/off | on | analog voltage rails (power-good signals are never recorded) |

Summaries are built every hour at two minutes past and, for days, from the hours after midnight UTC; the
same pass deletes what is older than each period (raw readings by whole hours, hourly summaries by
whole days). Lowering a period deletes data at the next pass. The 24-hour chart uses the readings
(10-minute points), the 7- and 30-day charts the hourly summaries (1-hour and 3-hour points, with the
readings for the hour not summarized yet) and the year the daily ones; a range longer than a period
falls back to the next summary and says so ("Hourly averages before …").

**How big it gets.** About 30 bytes a reading and 55 bytes a summary. Per server, at its plateau:

| Poll interval | Sensors | Readings (7 days) | Hourly (90 days) | Daily (2 years) | Total |
|---|---|---|---|---|---|
| 60 s | 16 | 161 000 rows, 4.8 MB | 1.9 MB | 0.6 MB | about 7 MB |
| 60 s | 32 | 323 000 rows, 9.7 MB | 3.8 MB | 1.3 MB | about 15 MB |
| 150 s (iDRAC8) | 32 | 129 000 rows, 3.9 MB | 3.8 MB | 1.3 MB | about 9 MB |

Ten servers at 60 s with 32 sensors each settle near 150 MB. Settings → General shows the real size
(the database file, the row counts and the last summary pass). Freed space is reused by later inserts,
so the file reaches its plateau and stays there; the app never runs `VACUUM` (it would need a copy of
the file in a temporary directory the container does not have).

**On a slow disk** (an SD card, a USB stick), the hourly pass reads the last hour of readings once and
deletes an hour of old ones per sensor in batches of at most 5 000 rows; a chart reads only the rows
of its range from a separate read-only connection. See tech_doc §39 for measured timings.

**CSV.** `Download CSV` gives one sensor's points as drawn: `bucket_start_utc, bucket_end_utc,
server, sensor, name, kind, unit, min, avg, max, samples`; *Every sample (CSV)* (24 hours and 7 days)
gives the readings: `timestamp_utc, server, sensor, name, kind, unit, value`. UTF-8, CRLF, RFC 3339
UTC times, `.` decimals, one header row; a name a spreadsheet would run as a formula gets a leading
`'`. Operators also get **Export every sensor (CSV)** for the range. An export holds at most 100 000
rows (a raw one at most 31 days) and is refused, not cut, beyond that; 6 exports a minute per user.
Downloads are not audited (like every other read); refusals are.

**API** (read-only token):

```
GET /api/v1/servers/{id}/history/sensors
GET /api/v1/servers/{id}/history?sensor=<key>&range=24h|7d|30d|1y
GET /api/v1/servers/{id}/history?sensor=<key>&from=<RFC 3339>&to=<RFC 3339>&step=<seconds>
GET /api/v1/servers/{id}/history.csv?sensor=<key>&range=…[&raw=1]
```

A series is `{data: [{t, min, avg, max, n}], meta: {sensor, kind, unit, tier, tiers, step_s, from, to,
points, clock_jump}}`. A custom window covers at most 2 years and 2 000 points: the step is raised to
fit, rounded to whole minutes (raw), hours or days. Tokens export one sensor per request (every sensor
at once is an operator action in the browser); token exports share the firmware CSV's 6 a minute.

**Prometheus or the built-in history?** The history answers "what happened recently on this box" with
no extra service: days of readings, two years of daily extremes, inside the app, exportable.
Prometheus with Grafana is for real dashboards, alert rules, correlation across systems and long raw
retention; `/metrics` is the integration point and the history never feeds it. With Prometheus
scraping every 60 s, set `history.raw_days: 1` and keep the summaries (a few MB), so the sparklines
and the History tab still work.

**Clock.** Samples carry the app's clock. If it moves back (NTP after a cold boot without a clock
battery), new readings may overlap older ones for a while; they are kept, and the History tab says
when it happened. If it moves forward, or the app was stopped for a while, deleting old readings
catches up gradually: the summary pass keeps its own clock, which advances at most two hours an hour
(on Linux it uses the kernel's uptime, so restarting the app over and over does not speed it up), so a
wrong clock cannot erase the history in one pass. The History tab shows the lag while it lasts.

**Limits.** A server keeps at most 512 sensors in the history (a BMC that invents sensor names cannot
grow the database: new names are not recorded, the log says so once and
`oob_history_keys_refused_total` counts them), and one poll records at most 128 temperatures, 32 fans,
16 power supplies and 64 voltage rails. A sensor whose unit changes (a fan reported in RPM, then in %)
starts a new history; the old one stays, under its archived key, in the CSV of every sensor, and a
change back continues it. Up to four earlier units or kinds are kept per sensor; deleting an older one
is logged and counted in `oob_history_keys_refused_total`.

**Removed servers.** A server that disappears from config.yaml or from Settings → Servers keeps its
history for 30 days after its last reading, so a typo or a commented-out entry loses nothing; after that
the hourly pass deletes it. Deleting a server in the browser works the same way. To keep history longer
(or forever), back up `/data` as in "Upgrade" step 3. A consequence: a server added again under the
same ID within those 30 days continues its old series (the History tab shows the old readings next to
the new ones until they age out). To start it clean, give it a new ID, or wait 30 days after its last
reading before adding it back.

## BMC account privileges per feature

oob-manager never creates or changes BMC accounts. Create them yourself with only the privileges
the features you enable need, and never use Administrator or `root`. One **operator** account
(`credentials.operator`) serves every feature that needs it on a server: give it the union
(bitwise OR) of the rows below for the features you turn on.

| Feature | Enabled by | Account it uses | iDRAC privileges (bitmask) | Other Redfish BMCs |
|---|---|---|---|---|
| Sensors, logs, inventory | always | `credentials.readonly` | Login (`0x1`); the Read Only role | Login (`ReadOnly` role) |
| Security checks | `security.enabled` (default on) | `credentials.readonly` | Login (`0x1`); checks the account cannot read say so | Login (`ReadOnly` role) |
| Power control | an operator login (optional) | `credentials.operator` | Login (`0x1`) + Execute Server Control Commands (`0x10`) = `0x11` | Login + ConfigureComponents |
| BMC restart | an operator login (optional) | `credentials.operator` | **Unverified:** Dell documents a BMC restart under *Configure iDRAC* (`0x2`); try the account you have first (see "Enabling BMC restart") | Login + ConfigureManager (assumed) |
| Fan lease, `redfish-floor` | `fan.mode: redfish-floor` | `credentials.operator` | Login (`0x1`) + Configure (`0x2`) = `0x3` | — (iDRAC9 only) |
| Fan lease, `host-lease` | `fan.mode: host-lease` | none: the app writes a lease file, the host script changes the fans | — | — |
| Serial console | `console.serial: bmcssh` | `credentials.operator` (BMC SSH) | Login (`0x1`) + **Access Virtual Console (`0x20`)** = `0x21`. Verified on hardware; see the note below. | — (iDRAC only) |
| Graphical console, VNC | `console.graphical: vnc` | `credentials.vnc` only (the iDRAC VNC server password, not an account) | — | — |
| iDRAC9 native console launch | an operator login on an iDRAC9 (`console.graphical: kvm-launch`, or alongside `vnc`) | `credentials.operator` | Login (`0x1`) + Access Virtual Console (`0x20`) = `0x21` | — (iDRAC9 only) |

Examples: power only `0x11`; power and the serial console `0x31`;
power, the iDRAC9 fan floor and the native console launch `0x33`. IPMI LAN privilege: No
Access, unless a feature needs IPMI. Give each consumer its own accounts and name them after their role, for
example `oob_ro` (read-only) and `oob_op` (operator), so one can be revoked without touching the
others.

**Serial console privilege (verified on hardware).** `console com2` checks **Access
Virtual Console (`0x20`)**. On an iDRAC8 (firmware 2.86) an account with Login + Execute Server
Control Commands (`0x11`) was refused with "Insufficient user privileges for console
redirection"; `0x31` (adding Access Virtual Console) worked. On an iDRAC9 (firmware 7.00) an
account with `0x33` worked. Administrator is not needed: never hand the app an Administrator
account.

## Enabling the graphical console

The graphical console shows a server's screen, keyboard and mouse in the browser (noVNC).
oob-manager connects to the BMC's built-in VNC server, logs in with the VNC password itself
and hands the browser an already authenticated stream, so the VNC password never reaches the
browser. Opening it needs the **admin** role and a fresh authenticator code (the step-up
window). Treat it like physical access to the server.

**Supported:** iDRAC7, iDRAC8 and iDRAC9 with an **Enterprise** (or Datacenter) licence, and any
BMC with a standard RFB server. iDRAC6 and other BMCs that only offer a Java viewer are not
supported; the server page says so and points to the serial console.

### 1. Turn on the BMC's VNC server

oob-manager never changes BMC settings. Set these in the iDRAC web UI
(iDRAC8: *iDRAC Settings → Network → Services → VNC Server*; iDRAC9: *iDRAC Settings →
Services → VNC Server*) or with racadm:

| Setting | Value | racadm |
|---|---|---|
| Enabled | Enabled | `racadm set iDRAC.VNCServer.Enable Enabled` |
| Port | 5901 (default) | `racadm set iDRAC.VNCServer.Port 5901` |
| Timeout | at least the app's `console.idle_timeout` (900 s for the 15 min default) | `racadm set iDRAC.VNCServer.Timeout 900` |
| SSL encryption | `128-Bit or higher` (TLS required). `Auto Negotiate` also works for oob-manager, but it still answers plain-text VNC clients, which the security checks warn about (`svc.vnc`) | `racadm set iDRAC.VNCServer.SSLEncryptionBitLength "128-Bit or higher"` |
| Password | exactly 8 characters | `racadm set iDRAC.VNCServer.Password '<password>'` |

- **The password:** VNC authentication uses only the first 8 characters, so use exactly 8
  random ones. iDRAC9 also requires an upper-case letter, a lower-case letter, a digit and a
  special character. Use a password that is unique to this BMC.
- **Keep SSL encryption on.** Without it the screen, every keystroke and the VNC challenge
  cross the management network in clear text, and the 8-character DES challenge can be
  cracked offline. oob-manager then logs a warning at startup and the console page says
  the connection is not encrypted.
- **While a VNC session is open, the iDRAC's own virtual console is disabled**, and the iDRAC
  accepts one VNC session at a time.

### 2. Pin the VNC port's certificate

With SSL on, the VNC port speaks TLS. oob-manager checks its certificate against a pin, like the
web port. Compute the VNC port's pin the same way as in "BMC certificate pins", but on 5901:

```bash
openssl s_client -connect 192.0.2.10:5901 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 | awk '{print $NF}'
```

If it equals the server's `tls_pin_sha256`, nothing more is needed. If it differs, set
`console.vnc.tls_pin_sha256` to it.

### 3. Store the password

Add a password-only entry to the credentials file (VNC has no user name) and re-encrypt it:

```yaml
storage1-vnc: { password: "<8 characters>" }
```

### 4. Configure the server

```yaml
  - id: storage1
    # ...
    credentials: { readonly: storage1-ro, vnc: storage1-vnc }   # operator: optional, see below
    console:
      serial: none
      graphical: vnc
      vnc:
        port: 5901          # default
        tls: true           # default; must match the iDRAC's SSL encryption setting
        # tls_pin_sha256: "<64 hex>"   # only if the VNC certificate differs from the web one
        # quirks: []        # iDRAC8 default: [idrac8_safe_encodings, idrac8_low_colour, idrac8_rsa_kex_tls]
```

A server with `graphical: vnc` needs only `credentials.vnc`. `credentials.operator` is optional
for the VNC console: it is needed for the iDRAC9 native console launch (below), fan control
and the serial console. Without it the native launch is simply not offered, and the card says
why. Optional app-wide limits (top level of `config.yaml`):

```yaml
console:
  idle_timeout: 15m             # no keyboard or mouse input for this long ends the console
  max_session: 4h               # absolute limit
  close_on_stepup_expiry: false # true: end the console when the 5-minute step-up window lapses
```

Restart oob-manager. On the server page the **Graphical console** card shows *Ready* (open it),
*In use* (who and since when; an admin can take it over), *Needs setup* (with the reason:
password missing or rejected, VNC server not answering, certificate pin or TLS mismatch),
*Needs a higher BMC licence*, or *Not supported*. The app checks the VNC port with a
harmless banner read (connect, read the 12-byte RFB version, close; never a login) at
startup and every 6 hours.

**iDRAC8 black screen.** iDRAC8's VNC server shows a black screen with noVNC's default
encodings. The iDRAC8 default quirks restrict the encodings to Raw/CopyRect/DesktopSize and
make noVNC use 8-bit colour. Set `quirks: []` only if a firmware update fixes it.

**iDRAC8 TLS: RSA key exchange.** With SSL on, iDRAC8 2.8x firmware offers only TLS 1.2 with
RSA key-exchange suites on the VNC port (no ECDHE), which Go's default TLS settings refuse
("remote error: tls: handshake failure", shown as a TLS mismatch on the card). The
`idrac8_rsa_kex_tls` quirk (iDRAC8 default) adds `TLS_RSA_WITH_AES_256_GCM_SHA384` and
`TLS_RSA_WITH_AES_128_GCM_SHA256` after the ECDHE suites for the VNC port only, never for the
web/Redfish port. The connection stays encrypted and pinned but has **no forward secrecy**,
and oob-manager logs that once per server at startup. If you set `quirks` explicitly on an
iDRAC8, include `idrac8_rsa_kex_tls`. oob-manager never falls back to plain RFB when
`tls: true`, even though iDRAC8 answers a client that sends no TLS handshake with a
plain RFB banner.

### iDRAC9: native console launch

On iDRAC9 the server card can also offer **Open native iDRAC console**: the app asks the iDRAC
for a single-use temporary login (Dell `GetKVMSession`) and shows a link that opens the
iDRAC's own HTML5 console in a new tab. It needs:

- `credentials.operator` (optional for the VNC console; without it this button is not
  offered): the operator account with the native console launch row of "BMC account
  privileges per feature" (*Login* and *Access Virtual Console*, `0x21`; not Administrator);
- a browser that can reach the iDRAC directly (the console runs between the browser and the
  iDRAC, not through oob-manager).

The button appears only when the iDRAC offers the action. The temporary login passes through
the browser; it works once and expires quickly. The permanent operator password never does.

## Enabling power control

The **Operations** tab of a server can power it on, shut it down or restart it gracefully
(*safe* actions: operator or admin role) and force it off, power-cycle it or force a restart
(*forced* actions: admin role). Every action needs a fresh authenticator code, goes through a
confirm page, is limited to one per server per minute, and is audited (requested, refused,
succeeded or failed, also shipped to GELF). Forced actions, and safe actions that take down a
server tagged `critical` or marked `power.self_host`, also need the server name typed exactly.

oob-manager sends exactly one kind of write for this: `POST` to the system's own
`/redfish/v1/Systems/<id>/Actions/ComputerSystem.Reset` with the body `{"ResetType": "<value>"}`,
where the value is one of `On`, `GracefulShutdown`, `GracefulRestart`, `ForceOff`,
`PowerCycle`, `ForceRestart` **and** is listed in the BMC's `ResetType@Redfish.AllowableValues`.
It never sends `Nmi`, `PushPowerButton` or vendor values, and never emulates a missing action
(no "ForceOff then On" for a missing `PowerCycle`). An action the BMC does not list is shown
disabled with "Not offered by this BMC" (for example iDRAC8 2.x lists neither
`GracefulRestart` nor `PowerCycle`; iDRAC9 lists all six). After the BMC accepts a request,
the app reads `PowerState` until the expected state appears (graceful actions up to 5 minutes,
the others up to 2 minutes) and shows the result on the Operations tab. A restart that never
leaves `On` while being watched is reported as *unconfirmed*, not as a failure.

### 1. Create an operator BMC account

Power control uses the server's `credentials.operator` login, never the read-only one. Without
it every action is disabled with "Needs an operator BMC account". Give the account the power
row of "BMC account privileges per feature" above (iDRAC `0x11`, plus the bits of any other
feature it also serves).

With racadm on an iDRAC (pick a free user slot `<N>`; iDRAC8 passwords are at most 20
characters):

```bash
racadm set iDRAC.Users.<N>.UserName oob_op
racadm set iDRAC.Users.<N>.Password '<random password>'
racadm set iDRAC.Users.<N>.Privilege 0x11            # power only; OR in other features' bits
racadm set iDRAC.Users.<N>.IpmiLanPrivilege 15      # No Access
racadm set iDRAC.Users.<N>.Enable Enabled
```

Generic Redfish (BMCs with a free-form account collection):

```bash
curl --cacert bmc.pem -u admin -X POST https://192.0.2.10/redfish/v1/AccountService/Accounts \
  -H 'Content-Type: application/json' \
  -d '{"UserName":"oob_op","Password":"<random password>","RoleId":"Operator","Enabled":true}'
```

iDRAC accounts are fixed slots: `PATCH /redfish/v1/AccountService/Accounts/<N>` instead
(on iDRAC8 one property per request). An iDRAC `RoleId` of `Operator` grants more than power
control; prefer the racadm bitmask above. These commands follow vendor documentation and are
not exercised by the test suite.

### 2. Reference it in the config

Add the login to the credentials file (`edge1-op: { username: oob_op, password: "…" }`),
re-encrypt it, and set `credentials.operator: edge1-op` on the server. Restart the app.

### 3. Optional: say what goes down

```yaml
  - id: gateway1
    tags: [critical]            # every action that takes it down needs the typed name
    power:
      self_host: false          # true on the machine oob-manager itself runs on
      impact:                   # shown as "What goes down" on the confirm page (≤ 8 lines)
        - "Network gateway: all internet access drops"
        - "VPN and remote access end"
```

`self_host: true` adds "This server runs oob-manager; the console will go offline until it
boots" to every action that takes the server down, and requires the typed name for them. After
a shutdown or force off of that server, powering it on again needs another way in (the BMC's
own web interface or physical access).

**Not supported yet:** BMCs configured with `kind: ipmi` (IPMI chassis control, task 2.2)
get no power actions.

## Enabling BMC restart

When a BMC hangs (the console will not launch, its web UI crawls, SSH stopped answering) an admin can
restart it from the server's **Operations** tab: the **BMC** panel shows the BMC model, firmware and
last restart, and **Restart BMC…** opens a confirm page that needs the server name typed exactly and a
fresh authenticator code. Only the management controller restarts: **the host and its operating
system keep running.** What it costs, and what oob-manager does about it:

- Every console on the server ends at once (graphical, serial, and a native console opened from the
  BMC), each with its own audit row; the confirm page names whose console is open.
- Sensors, logs and power control are unavailable for about 2–5 minutes. oob-manager shows the server
  as **BMC restarting** (not stale, not unreachable), sends no "unreachable" alert for the restart and
  refuses power actions until the BMC is back. It waits 60 s, then checks every 30 s; it gives up after
  5 minutes (3 on an iDRAC9) and then reports **did not come back** (a critical `bmc` notification,
  followed by the usual reachability alert).
- Dell servers commonly run their fans at full speed while the iDRAC reboots; that is expected. A host
  fan script that reads the BMC in-band (IPMI over KCS) cannot read sensors meanwhile and must fail
  safe. A `redfish-floor` fan lease is applied again once the BMC is back.
- After a restart the same server waits **10 minutes** before the next one (429 with `Retry-After`).
  The BMC restart is refused while a power action is still being verified.

oob-manager sends exactly one kind of write for this: `POST` to the BMC's own
`/redfish/v1/Managers/<id>/Actions/Manager.Reset` with the body `{"ResetType":"GracefulRestart"}`, and
only when that manager advertises the action with `GracefulRestart`. It never sends `ForceRestart`,
`ResetToDefaults` or any vendor action. A BMC without the action shows "Not offered by this BMC".
`kind: ipmi` servers get no BMC restart.

### 1. The operator account

The restart uses the server's `credentials.operator` login (as power control does). Which privilege a
Dell iDRAC requires for it is **not verified**: Dell documents the BMC restart (`racreset`) under
*Configure iDRAC* (`0x2`). Try the account you already have. If the BMC refuses (HTTP 403), nothing
restarts and the BMC panel says that the operator account lacks the privilege for this action (on a
Dell iDRAC: *Configure iDRAC*). The refused POST still starts the 10-minute cooldown (no retry loop
against the BMC), and the Restart button stays disabled with that reason until you clear it: after
changing the account's privilege on the BMC, save any setting (Settings → Servers or General) or
restart the app. Granting *Configure iDRAC*
lets the app's account change iDRAC settings too; it is the same privilege the `redfish-floor` fan
mode already needs on an iDRAC9. Decide per server.

### 2. Verify once on your hardware

The behaviour above was built and tested against a mock BMC only. Do one restart per BMC, at a quiet
moment, and write down what you see:

1. Warn whoever watches the alerts (the `bmc` notifications fire: requested, then back), and close
   your own consoles first (the restart ends them).
2. On the Operations tab note the **Last BMC restart** value (it counts only confirmed restarts: a
   return without a confirmation is reported as "not confirmed" and leaves it unchanged) and, on an iDRAC9 with a `redfish-floor`
   lease active, the minimum fan speed the lease set.
3. Restart the BMC. Expect a redirect to the Operations tab and **BMC restarting · requested … ·
   expected back by …**; the fleet pill counts it as restarting, not stale.
4. Watch, with a stopwatch: how long until the panel says **BMC back after …** (the downtime), and
   compare it with the deadline oob-manager allows (3 minutes on an iDRAC9, 5 on an iDRAC8 and other
   BMCs; a longer restart is reported as "did not come back"); what the fans do (full speed, and for
   how long); whether the host stays up (it must).
5. Afterwards check: the account's result (accepted, or the privilege message: then decide on
   *Configure iDRAC*); on an iDRAC9 that **Last BMC restart** moved to now (else the panel says the BMC
   did not report a restart); whether `MinimumFanSpeed` survived (the app applies an active floor
   again either way and audits `fan.lease.reapply` with `reason=bmc_reset`); that you can sign in to the
   BMC's own web interface again; that a console opens again; that no `reachability` ("BMC
   unreachable") alert fired for the restart; and, where a host fan script drives the fans in-band
   (manual fan mode over IPMI/KCS), that it resumes its manual mode after the BMC returns (a BMC
   restart may hand the fans back to the BMC's automatic control).
6. Settings → Audit log shows `bmc.reset` started and ok, `bmc.reset.verified` ok with `downtime_s`,
   and the console stop rows with `reason=bmc_reset`.

## Enabling fan leases

A fan lease is a time-boxed **minimum** fan speed ("at least 60 % for 30 minutes"), started
by an operator on the server's Operations tab (review page, then the authenticator code when
the 5-minute step-up window has lapsed) and ended early with **End now** (no code). Leases
only ever raise the fans: the floor is clamped up to `safe_min_pct`, and whatever enforces the
lease never goes below its own automatic control. Every start, end, confirmation and expiry is
in the audit log (and GELF when configured). Fan leases are off (`none`) unless you configure them.
Pick one mode per server: `redfish-floor` needs nothing but an iDRAC9 operator account;
`host-lease` is an **opt-in integration** for a server whose fans a script on that server already
drives (common on iDRAC8 machines with a custom fan curve), and needs the example reader from
[`deploy/host/`](host/README.md) added to that script.

| `fan.mode` | BMC kinds | Who changes the fans | Revert |
|---|---|---|---|
| `host-lease` | idrac8 | a fan script on the server itself, which reads a lease file | the host ignores the file after `expires_at`, even if the app is down |
| `redfish-floor` | idrac9 | the BMC: the app raises `ThermalSettings.1.MinimumFanSpeed` | the app restores the recorded value at expiry, on End now and at its next start |
| `ipmi-oem` | — | not implemented yet (the server is left without fan control, with a warning in the log) | — |
| `none` | any | nobody (default) | — |

Common limits: `safe_min_pct` (at least 20; `host-lease` at least 30, `redfish-floor` at least
41) and `max_lease` (at most 2h). The UI offers 15 min, 30 min, 1 h and 2 h up to `max_lease`.

### `host-lease`: a host fan script reads the lease file

oob-manager never sends a fan command in this mode. It writes `<lease_dir>/<id>.lease`
(atomically, owner 65532, mode 0640) and reads `<id>.ack`, which your fan script writes after
every run, to show *Pending* → *Applied* (or a warning when the script is stale, rejected the
file, or a thermal guard handed the fans to the BMC).

1. Mount a host directory on `/leases` (`storage.lease_dir`), owned by 65532, mode 0755 (see
   checklist step 2), and point your script at the host side of it.
2. Add the lease reader from [`deploy/host/`](host/README.md) to your fan script (bash + awk,
   drop-in, with tests), and run the script **every minute**: the app treats an ack older than
   3 minutes as stale. The reader enforces expiry, a maximum duration, its own safe minimum,
   and a strict file format, and it never lowers the speed your curve chose.
3. Configure the server:
   ```yaml
   fan: { mode: host-lease, safe_min_pct: 30, max_lease: 2h }
   ```
4. Restart oob-manager, start a 15-minute lease and check the card turns *Applied* within a
   minute and the reported speed matches what the script set.

### `redfish-floor`: iDRAC9 minimum fan speed

The iDRAC stays in automatic control; the lease only raises its lower bound, so there is no
manual fan mode to strand. The app sends exactly one kind of write: a PATCH of
`ThermalSettings.1.MinimumFanSpeed` on `/redfish/v1/Managers/System.Embedded.1/Attributes`
(the transport refuses any other PATCH). It reads the current value first (255 means not set),
clamps the floor to the range the iDRAC reports (`MFSMinimumLimit`..`MFSMaximumLimit`), and
restores the recorded value when the lease ends. If the app is gone for good, the fans run
faster than needed, never slower.

1. `credentials.operator`: the operator account with the `redfish-floor` row of "BMC account
   privileges per feature" (*Login* and *Configure*, `0x3`; the floor is an iDRAC attribute).
   Without it the config is rejected; a login missing from the credentials file leaves the
   server without fan control (logged).
2. Configure the server:
   ```yaml
   credentials: { readonly: edge1-ro, operator: edge1-op }
   fan: { mode: redfish-floor, safe_min_pct: 35, max_lease: 2h }
   ```
3. Restart oob-manager, start a short lease, and check the iDRAC's cooling settings show the new
   minimum fan speed, then End now and check it is back to its previous value.

## Enabling the serial console

The serial console shows a server's text console (BIOS setup, boot loader, kernel messages,
operating system login) in the browser, with a terminal that screen readers can follow and a
plain-text transcript beside it. oob-manager logs in to the BMC's SSH service with the operator
account, checks the BMC's host key against the one in `config.yaml`, and runs exactly one
command, `console com2`. The password never reaches the browser, and the browser cannot send
the BMC anything but keystrokes, a terminal size, a serial break and "end the console".
Opening it needs the **admin** role and a fresh authenticator code. Treat it like physical
access to the server.

**Supported:** Dell iDRAC8 and iDRAC9 (`console.serial: bmcssh`). IPMI Serial-over-LAN
(`console.serial: sol`) is accepted in the config but not implemented yet; the server page says
so.

Two sides must be set up: the **BMC** (SSH, serial over LAN, an account, the host key) and the
**host** (BIOS serial redirection to COM2, and a serial console in the operating system).
Without the host side the console connects and stays blank; the page then shows a hint.

### 1. BMC settings

oob-manager never changes BMC settings. Set these in the iDRAC web UI or with racadm (attribute
names from Dell's documentation; check them against your firmware):

| Setting | Value | racadm |
|---|---|---|
| SSH | Enabled, port 22 | `racadm set iDRAC.SSH.Enable 1` |
| Serial Over LAN | Enabled, 115200 baud | `racadm set iDRAC.IPMISOL.Enable 1`, `racadm set iDRAC.IPMISOL.BaudRate 115200` |
| Serial redirection | Enabled, quit key `^\` (the default) | `racadm set iDRAC.SerialRedirection.Enable 1`, `racadm set iDRAC.SerialRedirection.QuitKey '^\'` |
| SSH idle timeout | at least `console.idle_timeout` (900 s for the 15 min default) | `racadm set iDRAC.SSH.Timeout 1800` |

- **The account** is `credentials.operator`, the same one power control, the iDRAC9 fan floor
  and the native console launch use (see "BMC account privileges per feature": `console com2`
  needs Access Virtual Console, `0x20`). If the card says "The BMC refused the serial
  console", the account's privilege is too low. Never use `root`.
- Keep the quit key at `^\` (Ctrl-\). oob-manager never forwards a typed Ctrl-\ (it would end
  `console com2`); its **Send Ctrl-\ (end console)** button sends it and closes the session.

### 2. Pin the BMC's SSH host key

oob-manager accepts exactly one host key per BMC and never trusts a key on first use. Read the
key from the management network and check it before you paste it:

```bash
ssh-keyscan -t ed25519 192.0.2.11 2>/dev/null | cut -d' ' -f2-   # iDRAC9: ed25519 (or ecdsa-sha2-nistp256)
ssh-keyscan -t rsa 192.0.2.10 2>/dev/null | cut -d' ' -f2-       # iDRAC8 offers RSA
ssh-keyscan -t ed25519 192.0.2.11 2>/dev/null | ssh-keygen -lf -  # fingerprint, to compare
```

Compare the fingerprint from a second machine (or with what `ssh` shows the first time an admin
logs in from a trusted host). A mismatch later — after a BMC reset or a firmware update that
regenerates keys — shows as "host key does not match" on the card. Nothing, not even the
password, is sent to a BMC whose key does not match.

### 3. Store the operator login and configure the server

```yaml
# credentials file (re-encrypt it afterwards)
edge1-op: { username: "<operator account>", password: "<password>" }
```

```yaml
  - id: edge1
    # ...
    ssh_host_key: "ssh-ed25519 AAAA..."      # the line from step 2 (algorithm and base64)
    credentials: { readonly: edge1-ro, operator: edge1-op }
    console:
      serial: bmcssh
      graphical: none
      ssh: { port: 22 }                      # default
      # ssh: { quirks: [] }                  # iDRAC8 default: [idrac8_legacy_ssh]
```

A missing `ssh_host_key` or a missing operator entry is not a startup error: the app starts,
logs a warning and the card says what to set up. The idle and maximum session limits are the
shared `console.idle_timeout` and `console.max_session` (15 minutes and 4 hours by default).

**iDRAC8: legacy SSH algorithms.** iDRAC8 2.8x firmware offers only old SSH algorithms. The
`idrac8_legacy_ssh` quirk (default for `kind: idrac8`) adds exactly two: the `ssh-rsa` host key
signature (SHA-1; only when the pinned key is RSA) and the `diffie-hellman-group14-sha1` key
exchange. Everything else stays on the modern list (no CBC ciphers, no `hmac-sha1-96`).
oob-manager logs a warning for every server that uses it, and the card shows it. iDRAC9 needs
no quirk. If an iDRAC8 still fails with "no SSH algorithm in common", note the message and
report it; do not widen the list by hand.

### 4. The host: send its console to COM2

The iDRAC's serial console (`console com2`) is the server's second serial port. The host must
write its console there. All of this needs a reboot of the host; plan it.

**BIOS** (System Setup → System BIOS → Serial Communication, Dell 13th/14th generation):

| Setting | Value | racadm (BIOS job, applied at the next reboot) |
|---|---|---|
| Serial Communication | On with Console Redirection via COM2 (Auto also works when COM2 is the BMC) | `racadm set BIOS.SerialCommSettings.SerialComm OnConRedirCom2` |
| Serial Port Address | Serial Device1 = COM1, Serial Device2 = COM2 (COM2 is the BMC) | `racadm set BIOS.SerialCommSettings.SerialPortAddress Serial1Com1Serial2Com2` |
| External Serial Connector | Serial Device 1 (the rear port stays COM1) | `racadm set BIOS.SerialCommSettings.ExtSerialConnector Serial1` |
| Failsafe Baud Rate | 115200 | `racadm set BIOS.SerialCommSettings.FailSafeBaud 115200` |
| Remote Terminal Type | VT100/VT220 | `racadm set BIOS.SerialCommSettings.ConTermType Vt100Vt220` |
| Redirection After Boot | Enabled (keeps the boot loader on COM2) | `racadm set BIOS.SerialCommSettings.RedirAfterBoot Enabled` |

Then `racadm jobqueue create BIOS.Setup.1-1` and reboot. With only the BIOS part done, the console
shows POST and BIOS setup, then goes blank when the operating system starts.

**Linux** (COM2 is `ttyS1`):

- Kernel command line: `console=tty0 console=ttyS1,115200n8`. The last `console=` receives the
  boot messages and `/dev/console`; put `ttyS1` last to see them on the serial console.
- GRUB (`/etc/default/grub`, then regenerate the config): `GRUB_TERMINAL="console serial"` and
  `GRUB_SERIAL_COMMAND="serial --unit=1 --speed=115200 --word=8 --parity=no --stop=1"`.
- Syslinux/extlinux boot loaders: `SERIAL 1 115200` at the top of the config, and the same
  `console=` arguments on the `APPEND` line.
- Login prompt: systemd starts `serial-getty@ttyS1` by itself when `ttyS1` is on the kernel
  command line; otherwise `systemctl enable --now serial-getty@ttyS1.service`. Distributions
  without systemd: a getty line for `ttyS1` at 115200 in `/etc/inittab`.

**FreeBSD-based appliances (pfSense- or OPNsense-style firewalls)** — dual console, so the
local screen keeps working:

- In the web UI's console settings choose a serial console as primary or secondary console and
  115200 baud; that writes the loader settings below. Otherwise add them to the loader's local
  override file, which upgrades leave alone (`/boot/loader.conf` with the suffix `.local`):

  ```
  boot_multicons="YES"
  boot_serial="YES"
  console="comconsole,efi"      # "comconsole,vidconsole" on legacy BIOS boot
  comconsole_speed="115200"
  comconsole_port="0x2F8"       # COM2; 0x3F8 would be COM1
  hint.uart.1.flags="0x10"      # COM2 is the system console
  ```

- Enable a login on the serial port (`ttyu1` for COM2) in `/etc/ttys` with `onifconsole` or
  `on`, if the appliance does not do it.

**Windows:** Emergency Management Services (SAC) on COM2:
`bcdedit /ems on` and `bcdedit /emssettings EMSPORT:2 EMSBAUDRATE:115200`.

### Using it

The **Serial console** card on the server page (and on the Operations tab) shows *Ready*,
*In use* (who and since when; an admin can take it over), *Needs setup* (operator login
missing or rejected, host key missing or not matching, no common SSH algorithm, console
refused by the BMC; with the steps), *Not supported* or *Not checked yet*. The console page has
Send break, Send Ctrl-\ (end console), Copy, text size and Disconnect. Press Enter once after
connecting: a login prompt only redraws when the host writes something. Ctrl+Alt+Shift moves the
keyboard focus from the terminal back to the toolbar. Each start, takeover and stop is in the
audit log (`console.serial.*`, with duration and byte counts). A rejected login blocks new
attempts for a minute, so the app cannot lock the BMC account.

## Memory limit

`compose.yaml` sets `mem_limit`/`memswap_limit: 256m` and `GOMEMLIMIT=200MiB`. Do not go
back to 128m. Every `docker exec` (for example `bootstrap-admin`, `reset-totp`, `tokens`)
starts a second process inside the container's cgroup and counts against the same limit.
argon2id also needs 19 MiB per password hash. The app runs at most two hashes at once, so
a burst of logins uses no more than about 100 MiB even for the costliest stored hash it
accepts (`auth.HashMemoryBudgetKiB`). With 128m the kernel OOM-killed the container while an
operator ran `bootstrap-admin` and several logins happened close together (anon-rss was about
68 MB at the kill). `GOMEMLIMIT` makes the Go GC return hash buffers before the cgroup limit
is reached.

## Verifying a release

Releases are built by `.github/workflows/release.yml` from a tag whose CI run passed. Each one has:
- a multi-arch image (`linux/amd64`, `linux/arm64`) at `ghcr.io/mrronco/oob-manager`, tagged `vX.Y.Z` and `vX.Y`;
- a keyless cosign signature, an SPDX SBOM attestation and SLSA build provenance;
- static binaries (`oob-manager_<version>_linux_<arch>.tar.gz`), `checksums.txt` and `oob-manager.spdx.json` on the
  GitHub release.

Verify before you run it. **[docs/verify.md](../docs/verify.md) has the full steps** (signature identity,
provenance, the SBOM, the binaries); in short:

```sh
IMAGE=ghcr.io/mrronco/oob-manager
DIGEST=$(docker buildx imagetools inspect "$IMAGE:<version>" --format '{{json .Manifest}}' | jq -r .digest)
# Signed by this repository's release workflow and nothing else.
cosign verify --certificate-identity-regexp '^https://github.com/MrRonco/oob-manager/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE@$DIGEST"
# Built by GitHub Actions from this repository (SLSA provenance).
gh attestation verify "oci://$IMAGE@$DIGEST" --repo MrRonco/oob-manager
```

Then pin the digest you verified, not the tag, in your compose file, for example
`image: ghcr.io/mrronco/oob-manager:<version>@sha256:<digest>`. For maintainers: the workflow only
publishes while `RELEASE_LIVE` in release.yml is `"true"`; otherwise a manual run is a dry run that
uploads workflow artifacts and pushes or signs nothing.

## Upgrade

1. Warn whoever watches the alerts: the `/readyz` monitor will flap.
2. Pull and verify the new release (or build the new tag) **without** removing the old image.
3. Copy the data before switching, because schema migrations are one-way:
   `docker stop oob-manager && cp -a $D/data $D/data.backup.$(date +%Y%m%d)`.
4. Back up the compose file, set `image:` to the new tag, then run `docker compose up -d`.
5. Verify with the `docker inspect` line from step 9, `curl --cacert $D/tls/tls.crt https://192.0.2.20:8443/readyz`,
   and `docker exec oob-manager /usr/local/bin/oob-manager version`.

**Database paths with `%` are refused (plan 06).** `storage.db_path` (and any path given to `backup` or
`verify-audit`) may not contain `?`, `#` or `%`: they are URI syntax in SQLite's `file:` names, and a `%`
used to be decoded silently (`%41` opened a file named `A`). If yours has one, rename the file and the
key before upgrading; the app refuses to start otherwise.

**A config.yaml must name its TLS pair (plan 09 L5).** From this version `serve` refuses a `config.yaml`
that sets neither `tls.cert_file` nor `tls.key_file`; before, it quietly served a certificate generated
into the data volume. An install started without any `config.yaml` (a store install, or `-config=none`)
is not affected. A store install that later added a `config.yaml` without a `tls:` block **will not start
after the upgrade** until you add the pair it has been using:
`tls: { cert_file: /data/tls/tls.crt, key_file: /data/tls/tls.key }` (paths inside the container). The
data and the certificate are untouched, and the CLI commands keep working meanwhile. See "Adding a
config.yaml to a store install" for the expiry note that comes with naming the pair.

**Upgrading to owner-only files (plan 06, `umask 077`).** From this version the binary creates every file
owner-only, whichever command creates it: the database and its `-wal`/`-shm` files, backups and
generated keys are 0600. Files that
already exist keep their mode, so tighten them once after the upgrade (the data directory itself is
0700 already if you followed the host layout):
`chmod 600 $D/data/*.db $D/data/*.db-wal $D/data/*.db-shm 2>/dev/null; ls -l $D/data`.
The database holds sealed secrets, token hashes and the audit log, so treat its backups like the keys
file (security.md §3m). The `leases/` files the host fan script reads stay readable by root.

**`/readyz` is cached for one second.** However often it is polled, the database is checked at most about
once a second; it never answers 429, so monitors that share a source address are not locked out.

**Upgrading to the BMC security checks (migration 0011).** A notification target with no class list
(`classes:` empty or absent in `config.yaml`; in the browser, every box ticked, which is the default)
subscribes to *every* class, and the new `security` class is one of them: after the upgrade such a target
also receives the new-findings message per server (info; warning when a check fails), the certificate
reminders 14, 7 and 1 days ahead, and the accepted-risk events (warning on accept, info when an
acceptance ends), filtered by its `min_severity` as before. The first run after the upgrade reports every
open warning and failure of every BMC at once, so expect one message per server then. To keep a target
out of it, list the classes it should get without `security` in `config.yaml`, or untick **BMC security
check findings** in its browser form; nothing else about subscriptions changed. Accepting a finding as a
risk needs a fresh step-up (authenticator code within 5 minutes) from this version on.

**Upgrading to Settings → Integrations (migration 0012).** `audit.gelf` in `config.yaml` is now checked
against a destination policy at startup, so some files that loaded before **fail startup** now:
a literal address that is public (e.g. `203.0.113.9:12201`), in carrier-grade NAT or Tailscale space
(`100.64.0.0/10`), or on loopback (`127.0.0.1:12201`). The error names the entry to add to
`audit.gelf.allowed_networks` (for example `203.0.113.9/32`); loopback, link-local and multicast stay
refused whatever is listed, so a log forwarder on the same host must be reached on its LAN or bridge
address. Host names may contain `_` (container names); a name is checked on every connection instead.
`transport: udp` was never supported and still fails. An empty `address: ""` now leaves the whole GELF
section to the browser (other `audit.gelf` keys next to it no longer lock anything).

**Upgrading to BMC restart (migration 0013).** The new table `bmc_resets` records BMC restarts; nothing
existing changes. The new notification class `bmc` behaves like `security` did: a target with no class
list (`classes:` empty or absent in `config.yaml`) subscribes to every class, so after the upgrade it
also receives BMC restart events (requested and back: warning, a BMC that did not come back:
critical), filtered by its `min_severity`. A target saved in the browser lists its classes and is
**not** subscribed until you tick **BMC restarts** (the form marks it as new). No restart happens unless
an admin requests one.

**Upgrading to the firmware view (migration 0014).** Three new tables hold the firmware view;
nothing existing changes. Each server is scanned after its first poll (the iDRAC8's first scan reads
one document per component and may take a couple of minutes). Firmware version changes go to the
`security` class as warnings, so a target subscribed to it (or with no class list) gets one message per
scan with changes from then on (the first scan of a server is not a change). Set
`firmware.minimum` if you want rows flagged below a minimum; `security.min_firmware` keeps setting the
BMC's own minimum and now also flags the BMC row of the Firmware page.

**Upgrading to the sensor history (migration 0015).** The old `sensor_samples` table (seven days of
temperatures, fans and power draw) is copied into the new history tables and dropped; the copy takes
a few seconds per million rows, before the app serves. Sensor names appear after the first poll. The
first hourly pass after the upgrade summarizes those seven days (minutes on a slow disk; the app
serves meanwhile). Power supplies and voltage rails are recorded from now on (turn them off in
Settings → General, *Sensor history*). The database grows to its plateau over the raw period (see
"Sensor history"). Old samples whose key is longer than 160 bytes or whose server ID is longer than 64
bytes (none in a normal install: keys are `temp:`, `fan:` or `power:` plus the BMC's member ID) are not
copied, and neither are keys without an ID part. Rolling back to the previous version needs the data copy of step 3: the new
schema is one-way.

**Old names from before the rename (oob-console).** Releases up to v0.7.2 were called oob-console (the
project was renamed before v0.8.0). The app still finds the old
defaults, so such an install starts unchanged: with no `-config`, `/etc/oob-console/config.yaml` is
used when `/etc/oob-manager/config.yaml` does not exist, and with no `storage.db_path`,
`/data/oob-console.db` is opened when `/data/oob-manager.db` does not exist (if both exist, the new
one is used). `serve` logs a `deprecated config path` or `deprecated database path` warning at every
start; move the file (the database with its `-wal` and `-shm` files, container stopped) or set the
path explicitly to silence it. Key-derivation and hash labels keep their old names on purpose, so
nothing is re-sealed or re-enrolled.

## Backups and verifying the audit chain

`oob-manager backup <dir>` writes a consistent copy of the database (`VACUUM INTO`, safe while the app
runs) as `oob-manager-<UTC time>.db`, mode 0600, then verifies the copy's audit chain and prints its
schema version and head hash:

```bash
docker exec oob-manager /usr/local/bin/oob-manager backup /data/backups
# backup: /data/backups/oob-manager-20261030T041500Z.db
# schema: 18
# audit: chain verified, 1234 rows, head 3f2a…
```

The directory must exist and be absolute; in the container use a path under `/data` (the root
filesystem is read-only and `/tmp` is a small tmpfs). Only the database is copied: `config.yaml`, the
`.age` files and the TLS pair are yours to back up, and **the age identity is never included**. The copy
holds sealed secrets, token hashes and the audit log, so treat it like the keys file (security.md §3m).

`oob-manager verify-audit [db]` checks a chain offline (the configured database by default, or any copy)
on a query-only connection (with `trusted_schema` off, so a hostile copy's schema cannot run functions),
so it is safe beside a running app. A broken link exits 1 with the first bad sequence number (`audit:
chain tampered at seq N: …`).

**What it cannot see.** The chain is a hash chain in the same file, not a signature: someone with write
access to the database can rewrite rows *and* recompute every later hash, and a copy cut short at the end
(the newest rows deleted) still verifies. The control for both is outside the file: compare the head hash
with the last `row_hash` the log server received (GELF audit shipping, Settings → Integrations; CLI
commands ship their rows too). Without a log server there is nothing to compare against.

**Store-style installs:** the generated age identity and app keys live in `/data/keys`. A volume-level
backup of `/data` therefore carries the keys next to the database; keep `/data/keys` out of such backup
sets (or encrypt them) and keep its own offline copy instead.

## Recovery runbook

Each scenario was drilled on 2026-10-30 against the test harness (the test named in brackets runs it
on every CI build).

**Restoring a backup** (used by several scenarios). `$D` is the host directory mounted at `/data`, and
`oob-manager.db` stands for the file `storage.db_path` names:

```bash
docker stop oob-manager
ts=$(date +%Y%m%d-%H%M%S)
for f in oob-manager.db oob-manager.db-wal oob-manager.db-shm; do   # keep the damaged one aside
  [ -e "$D/data/$f" ] && mv "$D/data/$f" "$D/data/$f.broken-$ts"
done
cp /path/to/oob-manager-<UTC time>.db "$D/data/oob-manager.db"
chown 65532:65532 "$D/data/oob-manager.db" && chmod 600 "$D/data/oob-manager.db"   # the app's user
docker start oob-manager && docker logs oob-manager 2>&1 | grep -i 'audit'          # the startup chain check
```

Copied as root without the `chown`, the file is root-owned 0600 and the app (uid 65532) cannot open it.
A backup made by a **newer** version than the image you start (a higher schema number than it knows)
is refused at startup; restore it with that version or newer.

**1. Lost database** (disk failure, deleted by mistake) [`TestDrill1LostDatabase`]. Lost: users,
sessions, API tokens, settings saved in the browser, browser-managed servers and their credentials,
notification targets, notes, acknowledgements, maintenance windows, leases, history and the audit chain
(the GELF copy on the log server survives). Survives: `config.yaml`, the `.age` files, TLS.
- Restore the newest backup if you have one (see "Restoring a backup"; then drill 7 applies). Otherwise start: the app creates
  an empty database. Run `bootstrap-admin`, mint new API tokens (dashboards fail until then), re-add
  servers (or `settings import` for those in `config.yaml`) and notification targets.
- Fan leases: `host-lease` expires on the host by itself. `redfish-floor` (iDRAC9) leaves the raised
  minimum fan speed in the BMC (`ThermalSettings.1.MinimumFanSpeed`; iDRAC9 UI: Configuration → System
  Settings → Cooling → Minimum Fan Speed) until someone resets it: set it back, or start and end a new
  lease once the server is re-added.

**2. Lost age identity or app keys** [`TestDrill2LostKeys`]. The app **refuses to start** and names
the missing file; it never generates new keys for an existing database. Recoverable only from your
offline copy of the identity. Without it: make a new identity, re-encrypt the credentials file and new
app keys with it, start, then `reset-totp` for every user (TOTP secrets are sealed with the old keys)
and re-enter every browser-saved BMC credential and notification secret (no `rekey` command exists;
security.md §3m). The audit chain stays intact (it is hashed, not encrypted).

**3. Crash mid-lease** [`TestCrashRestart`, fan package]. On start the reconciler heals from the lease
row: a `pending` lease without an acknowledgement is re-applied, an expired one is released. Look for
`fan.lease.reapply` or `fan.lease.expire` in the audit log.

**4. Crash mid-maintenance** [`TestOpenEndedReminder`, maint package]. Windows and the reminder
watermark are in the database: after the restart the window is still on, no second "started" row is
written, and an open-ended reminder is not repeated early (after a long outage you get one, not one
per missed day).

**5. Crash mid-power action.** The operation is lost: the audit log has the `power.*` row (for example `power.force_off`) with
result `started` and no final row. The BMC decides what happened: read the server's power state on its
page (or the BMC's own UI) and the BMC event log (Events tab) around that time, then act again if needed.
Nothing retries a power action by itself.

**6. Crash mid-BMC restart** [`TestStartRearmsOpenWindowsAndClosesExpiredOnes`, bmcreset package]. An
open `bmc_resets` row re-arms the restart window on start (polls tolerate the BMC being away); a window
that already expired is closed and the server shows its real state.

**7. Restored an older backup** [`TestDrill7OlderBackup`]. The restored chain verifies, but its newest
rows are gone and nothing in the database can show it.
- **With GELF audit shipping on:** compare the head printed by `verify-audit` (or by `backup` when the
  copy was made) with the last `row_hash` the log server received (Graylog: the newest message of the
  GELF stream). If they differ, everything after the restored head is missing: notifications,
  acknowledgements, notes and settings changes made since the backup. CLI commands ship their rows too,
  waiting up to about 6 s on exit; a warning on stderr means some did not leave the box.
- **With shipping off** (no log server): there is nothing to compare against. Assume everything since the
  backup's time is gone, and use its row count and head (printed by `backup`) only to tell copies
  apart. Turning GELF shipping on is what makes this drill answerable.

**8. Locked out** [`TestAdminRecover`]. What fixes what:

| Problem | Fix |
|---|---|
| The last admin is disabled or demoted, or the account is locked by failed passwords | `docker exec -it oob-manager /usr/local/bin/oob-manager admin-recover -username <name>`: shows the account's role and state, asks for the name to be typed back (or `-yes`), then re-enables it, makes it an admin, clears its **per-account** lockout and ends its sessions (audited `admin.recover`). The row's `os_user` is the shell account (`uid 65532` inside `docker exec`), not a person: who ran it is in the host's shell history or Docker's logs. A name that does not exist is refused before anything is written, so it leaves no audit row |
| Authenticator lost | `reset-totp --user <name>` (shows a new secret once, on a terminal) |
| Password lost | an admin who can sign in uses Settings → Users → Reset authenticator: its one-time link sets a new password and a new authenticator. With no admin who can sign in: `admin-recover` an account whose password you still know, then reset the other from the browser |
| Your **address** is rate limited (the per-IP login limit) | wait the minute out, or sign in from another address; `admin-recover` does not clear IP limits |
| A section locked by `settings.locked`, or a value in `config.yaml` that breaks sign-in | edit `config.yaml` and restart; `admin-recover` does not change stored settings |

If the account was disabled because its credentials may be compromised, follow `admin-recover` with
`reset-totp --user <name>` and set a new password before using it again.

## Rollback

1. Run `docker compose down`, then set `image:` back to the previous tag. It is still
   present locally, because upgrades never delete it.
2. If the new version migrated the database (for example v0.5 adds migrations 0006–0008: servers,
   display defaults, notifications),
   restore `data.backup.<date>` over `data/`. An older binary refuses to open a newer schema.
3. Run `docker compose up -d` and verify as above.
4. Remove the old tag only after the new one has run cleanly for a week.

