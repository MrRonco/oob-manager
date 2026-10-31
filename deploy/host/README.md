# Host fan script integration (fan mode `host-lease`)

In `host-lease` mode oob-manager never sends a fan command. Your host's existing fan
script stays the **single writer** of fan speeds. The app only writes a small lease file
("keep the fans at least at N % until T"); your script reads it, applies it as a floor on
top of its own curve, and writes an acknowledgement back so the UI can show
"pending → applied".

This directory is a **drop-in snippet, not something the app installs**. Nothing here is
applied to any host automatically. Review it, test it, and add it to your script yourself.

| File | What it is |
|---|---|
| `fan-lease-reader.sh` | bash + awk functions to source from your fan script |
| `test/fan-lease-reader.bats` | tests (`make host-test`; bats via `npx`, nothing installed) |

## Safety properties

- The lease can only **raise** the speed your curve computed (`max(curve, floor)`), never
  lower it. A non-numeric curve value (for example `AUTO`) passes through untouched.
- The floor is clamped to **your** safe minimum (`FAN_LEASE_SAFE_MIN`), not the app's.
- Expiry is enforced **by the host**: a lease past `expires_at` is ignored even if the app
  is dead. Leases longer than `FAN_LEASE_MAX_SECS` (default 2 h) or issued in the future
  are rejected.
- The file is untrusted: size cap (512 bytes), only `[a-z0-9_=-]` and newlines, exactly
  the six known keys, no duplicates, no symlink, optionally a fixed owner uid. Anything
  else counts as no lease (`reason=invalid` in the ack).
- Your thermal guards still win: when your script hands the fans to the BMC (AUTO), it
  calls `fan_lease_ack_guard` and ignores the lease.
- The ack is written with `mktemp` + `mv`, so a symlink planted in the lease directory is
  replaced, never written through.

## File formats

Lease, written atomically by the app as `<lease_dir>/<server-id>.lease` (mode 0640):

```
version=1
server=node-a
lease_id=0123456789abcdef0123456789abcdef
pct=55
issued_at=1800000000
expires_at=1800001800
```

Ack, written by your script after every run as `<lease_dir>/<server-id>.ack` (mode 0644):

```
version=1
server=node-a
lease_id=0123456789abcdef0123456789abcdef   # or none
owner=lease                                  # lease | curve | guard
applied_pct=55                               # or auto
reported_at=1800000060
reason=ok                                    # ok | none | expired | invalid | guard
```

The app treats an ack older than 3 minutes as stale (warning in the UI), so run your
script **every minute**.

## Integrating it

1. Back up your script and the file that installs its cron entry.
2. Copy `fan-lease-reader.sh` next to your script.
3. Add, near the place where your script sets the fan speed:

```bash
FAN_LEASE_DIR=/path/to/oob-manager/leases   # the host side of the app's /leases mount
FAN_LEASE_SERVER=node-a                     # this server's id in the app's config.yaml
FAN_LEASE_SAFE_MIN=30                       # your floor for any lease
FAN_LEASE_OWNER_UID=65532                   # optional: the app's uid owns the lease file
. /path/to/fan-lease-reader.sh

target=$(your_curve)                        # existing logic: a percentage, or AUTO

if your_guard_tripped; then                 # existing logic: hand the fans to the BMC
    your_set_auto
    fan_lease_read
    fan_lease_ack_guard
    exit 0
fi

fan_lease_apply "$target"                   # FAN_LEASE_TARGET = max(target, lease floor)
your_set_fans "$FAN_LEASE_TARGET"
fan_lease_ack "$FAN_LEASE_TARGET"
```

4. Run your script's syntax check (`bash -n`) and the tests (`make host-test`).
5. Run the script by hand once without a lease file: the ack must say `owner=curve`,
   `reason=none`. Then start a short lease in the app and check the UI turns "applied"
   within a minute.
6. Schedule the script every minute (if it was less frequent).

Keep any existing heartbeat/watchdog of your script unchanged: the lease reader does not
replace it. Nothing in the reader talks to a BMC or runs as anything but your script.
