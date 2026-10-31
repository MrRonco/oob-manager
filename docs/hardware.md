# Hardware compatibility

oob-manager talks to BMCs over Redfish (HTTPS), the BMC's SSH server (serial console) and its VNC
server (graphical console). It has been run on **two servers only**. Everything else is untested:
it may work, and a [hardware report](#sending-a-hardware-report) tells us either way.

"for Dell iDRAC" describes what the app was built and tested against. The project is not
affiliated with or endorsed by Dell.

## Tested hardware

| Server | BMC | BMC firmware | Licence | Server kind in oob-manager |
|---|---|---|---|---|
| Dell PowerEdge R730XD | iDRAC8 | 2.86 | Enterprise | `idrac8` |
| Dell PowerEdge R240 | iDRAC9 | 7.00 | Enterprise | `idrac9` |

### What was verified on each

**Verified** means the feature was used on that server with the BMC account privileges listed in
[deploy/README.md](../deploy/README.md) ("BMC account privileges per feature"). **Mock only** means
it is built and covered by the test suite against the mock BMCs, but nobody has exercised it on that
hardware yet; reports are especially welcome for those.

| Feature | iDRAC8 2.86 (R730XD) | iDRAC9 7.00 (R240) |
|---|---|---|
| Inventory and licence (model, BIOS, BMC firmware, licence tier, components) | Verified | Verified |
| Sensors, history and event logs (SEL and Lifecycle log) | Verified | Verified: the R240 reports no PSUs and no power telemetry, so power draw shows as unavailable and the voltages are shown instead |
| Power control (on, graceful shutdown or restart, force off, power cycle) | Mock only | Graceful restart verified (the OS restarted and the action was audited as verified); the other reset types mock only |
| BMC restart (`Manager.Reset`, `GracefulRestart`) | Mock only | Mock only |
| Fan lease, `host-lease` (a host fan script reads a lease file) | Verified with the example reader in [deploy/host/](../deploy/host/README.md): lease file and acknowledgement every minute, and a lease raised the fans | Not applicable (an iDRAC9 uses `redfish-floor`) |
| Fan lease, `redfish-floor` (iDRAC9 minimum fan speed) | Not applicable | Verified: the thermal attributes and the BMC's limits (`MFSMinimumLimit` 35) read, floor configured |
| Graphical console, VNC over TLS | Verified with the default iDRAC8 quirks (see below) | Verified |
| iDRAC9 native console launch | Not applicable | Verified |
| Serial console over the BMC's SSH (`console com2`) | Verified (needs *Access Virtual Console*, see below) | Verified |
| Firmware view (running and stored versions) | Verified | Verified |
| Firmware update check (Dell's signed catalog, optional) | Verified | Verified |
| BMC security checks (Security tab) | Verified: no probe counted as a failed login | Verified: no probe counted as a failed login |

The graphical console needs an iDRAC licence that includes the virtual console (Enterprise or
Datacenter on these generations). Without it the server page says so and points to the serial
console.

## Known quirks

The app ships defaults for these, chosen per server kind; nothing needs to be set by hand unless
noted. Details are in [docs/tech_doc.md](tech_doc.md) (§17 Redfish sessions, §18 graphical console,
§22 serial console, §31 security checks, §38 firmware view).

### iDRAC8 (firmware 2.86)

- **Slow Redfish.** Every request with Basic authentication took 5.5 to 9.5 seconds. The app
  therefore logs in once with a Redfish session (`X-Auth-Token`) and **reuses that one session** for
  every request, which brings a request down to 1 to 3 seconds; it re-logs in once on a 401 and never
  loops. The iDRAC8 defaults are a 30-second request timeout and a 150-second poll cycle, so a full
  read of an R730XD takes up to two and a half minutes. Logs are read every 5 minutes and the
  inventory every 6 hours. `bmc.auth: basic` exists for BMCs without a session service and is slow on
  an iDRAC8.
- **The VNC server takes one client,** and stays busy for minutes after a connection ends. A second
  client, or a quick reconnect, can time out. The security checks therefore never open an iDRAC8's VNC
  port (its certificate is reported as "Not checked"), and a console session can be taken over in the
  app rather than opened twice.
- **VNC TLS offers only RSA key exchange** (TLS 1.2, no ECDHE). Go refuses those suites by default, so
  the `idrac8_rsa_kex_tls` quirk adds the two RSA AES-GCM suites for the VNC connection only, never for
  the web or Redfish connection. The app logs a warning at start for each such server: that console
  stream has no forward secrecy. Setting the iDRAC's VNC encryption to "128-Bit or higher" is still
  recommended.
- **Black screen with noVNC defaults.** The `idrac8_safe_encodings` and `idrac8_low_colour` quirks limit
  the encodings to Raw, CopyRect and DesktopSize and ask for 8-bit colour. With both on (the default)
  the console works.
- **Plain RFB banner with TLS on.** The iDRAC8 also answers a client that sends no TLS ClientHello with
  a plain-text VNC banner. The app never falls back to plain text when TLS is configured.
- **Legacy SSH algorithms.** The BMC's SSH server needs `ssh-rsa` host keys and
  `diffie-hellman-group14-sha1`; the `idrac8_legacy_ssh` quirk allows only those two on top of the
  modern defaults, for the serial console.
- **Serial console privilege.** `console com2` checks *Access Virtual Console* (`0x20`): an account with
  Login and Server Control (`0x11`) is refused with "Insufficient user privileges for console
  redirection"; `0x31` works.
- **No attribute registry over Redfish** (`/Attributes` answers 404 on 2.86), so the security checks
  cannot read some iDRAC8 settings (for example the VNC encryption setting) and report them as not
  checked.

### iDRAC9 (firmware 7.00)

- **Fan floor range.** `ThermalSettings.1.MinimumFanSpeed` is 255 when not set; the BMC's own lower
  limit (`MFSMinimumLimit`) was 35 on the R240, so `safe_min_pct` for `redfish-floor` must be at least 35.
- **Firmware states.** In the firmware inventory, a Dell `Installed-` member is the version that runs
  and a `Current-` member is an image stored on the BMC (OEM status "AvailableForInstallation"). The
  firmware view shows the stored one as "Not applied" when it is newer.
- **VNC over TLS 1.3** with the same certificate as the web port; the iDRAC9 logs every VNC connection as
  a short session in its own log.
- **Power telemetry** depends on the model: the R240 has no PSU sensors and no `PowerControl` data.

### Both

- Neither BMC logged a failed login for any security-check probe (unauthenticated TLS handshakes, the
  SSH banner, `HEAD` requests), so the checks do not count towards the BMC's IP-blocking threshold.
- If the BMC accepts connections only from listed addresses, list the address the container's
  traffic leaves from (on the default bridge network, the Docker host's address).

## Untested, expected to work

These use the same Dell Redfish schema and the same drivers, so they are likely to work, but nobody
has tried them yet:

- other PowerEdge servers with an **iDRAC9**, for example R440, R640, R740 and T440; firmware close to
  7.00 is the best bet;
- other 13th-generation PowerEdge servers with an **iDRAC8**, for example R630, R730 and T630, on
  firmware 2.8x;
- iDRAC7 (12th generation) for read-only monitoring: its Redfish support is limited, so expect gaps.

Feature differences to expect: a model without PSU sensors shows no power draw, the graphical console
needs a licence with the virtual console, and `redfish-floor` fan leases are iDRAC9 only.

## Other Redfish BMCs: untested

HPE iLO, Lenovo XClarity Controller, Supermicro, OpenBMC and any other Redfish BMC (server kind
`redfish`) are **untested**. The generic driver reads standard Redfish resources and may show
something useful; the Dell-specific parts (Lifecycle
log, licence, iDRAC9 fan floor, native console launch, Dell firmware catalog) do not apply. There is
no vendor-specific code for these yet; it will be written when someone with the hardware can test it.

**IPMI-only BMCs are not supported:** oob-manager has no IPMI driver and talks Redfish only.

## Sending a hardware report

Open a [hardware report](https://github.com/MrRonco/oob-manager/issues/new?template=hardware_report.yml)
on GitHub. It asks for the server vendor and model, the BMC type, firmware and licence tier, and for
each feature whether it worked, plus a short log excerpt. Reports that something does **not** work
are just as useful.

Before you submit, **anonymise** the report and its logs: remove IP addresses, host names, domains,
serial numbers, service tags, MAC addresses, licence IDs, user names and every password, token or
setup code. Model names and firmware versions are what we need.

Reports are summarised in the tables above, with the firmware version they were made on, so this
page stays the one place to check before buying or trying hardware.
