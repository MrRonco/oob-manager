# Research: in-browser graphical console for old and new BMCs

Date: 2026-10-20. Scope: public web and GitHub research only. Nothing was sent to any BMC.
Status: **input for a decision**, not a decision. Two hard rules are affected: CLAUDE.md rule 11
("Java consoles out of scope") and architecture.md §5 ("one process, no sidecars"). Changing
either needs the maintainer's call and an ADR.

Confidence tags: **[V]** verified in a primary source (vendor doc, schema, source code);
**[R]** reported by a third party (forum, README); **[I]** my inference; check it in the spike.

---

## 0. TL;DR

1. **Dell already ships a standard RFB (VNC) server** on iDRAC7, 8 and 9 (Enterprise licence).
   Our planned design (noVNC in the browser → WebSocket → Go RFB auth terminator → BMC :5901)
   is the right first tier, and it covers both tested servers (iDRAC8 R730XD, iDRAC9 R240).
2. **The iDRAC8 "black screen with noVNC" bug has a known workaround** in an open-source Go
   project (`zackpollard/kvm-switcher`). It rewrites the client's `SetEncodings` to
   Raw/CopyRect/DesktopSize and forces noVNC into 8-bit colour. This should be a per-BMC
   quirk flag in our terminator. [V: source code]
3. **The vendor HTML5 consoles are not standard RFB.** iDRAC7/8 HTML5 speaks the Avocent
   protocol over `wss://<idrac>:5900`. iDRAC9 eHTML5 uses a Dell WebSocket at `/vnc/vconsole?vck=…`
   on 443, and kvm-switcher reports it "isn't compatible with noVNC". The only way to relay them
   is to reverse-proxy and **rewrite Dell's JavaScript** into our origin. One project does this
   (talos-control-system). It is brittle, and it runs BMC-supplied JS in our origin.
   **Not recommended.** For iDRAC9, keep the `GetKVMSession` "open native console" launch as a
   secondary button.
4. **Java is only truly needed for iDRAC6** (no VNC server, no HTML5) and for other old BMCs
   (Supermicro X8/X9 ATEN, iLO 2/3, IBM IMM). The proven pattern is DomiStyle/docker-idrac6
   (957 stars, MIT, Zulu 8, jlesage noVNC base): fetch `avctKVM.jar` from the user's own iDRAC,
   run it under Xvfb, and export it over VNC. An **optional sidecar** built this way fits our
   constraints if the app relays its VNC and passes only **one-time KVM tokens** to it.
5. **Native, Java-free reimplementations of the Avocent protocol appeared in 2026**:
   - `SeineEloquenz/idrac-6-rs` (Rust, iDRAC6)
   - `the-curve-consulting/modern-idrac-client` (Go, iDRAC6/7/8, **no licence**)
   - `mhamzahkhan/ipmi-connect` (Go, **Apache-2.0**, Avocent + ATEN, ASPEED decoder)

   This is a credible long-term "tier D": an in-process Go APCP→RFB adapter, with no Java and
   no sidecar. But all three projects are weeks old and tested on 1–2 boards each.
6. **Redfish has no standard way to launch a graphical console.** `Manager.GraphicalConsole` only
   gives `ServiceEnabled`, `MaxConcurrentSessions` and `ConnectTypesSupported` ∈ {`KVMIP`, `Oem`}.
   Use it for feature detection only. [V: DMTF schema]

---

## 1. Console technology per iDRAC generation

| | iDRAC6 (11G) | iDRAC7 (12G) | iDRAC8 (13G) — R730XD fw 2.86 | iDRAC9 (14G–16G) — R240 fw 7.00 |
|---|---|---|---|---|
| Vendor viewer | Java JNLP (`avctKVM.jar`) and ActiveX (IE) | Java, ActiveX, HTML5 (fw 2.x) | Java, ActiveX, HTML5 | HTML5 → **eHTML5 only from fw 6.00.02.00** (Java/ActiveX gone) |
| HTML5 introduced | never | 2.x line (exact version disputed, see below) | same | from launch; eHTML5 later |
| Built-in VNC server | **no** | yes, Enterprise | yes, Enterprise | yes, Enterprise / Datacenter |
| VNC default port | — | 5901 | 5901 | 5901 (`VNCServer.1.Port`) |
| Native console port | 5900 (APCP, TLS) | 5900 (and 5901 legacy) | 5900 | 443 (eHTML5), 5900 (legacy) |
| Licence for vConsole | Enterprise (rack) | Enterprise (rack); Express for Blades has it [R] | Enterprise (rack) | Enterprise / Datacenter |

Sources and details:

- **Plug-in types and ports.** Dell KB 000185549 lists HTML5, Java, ActiveX and eHTML5. It also
  says that "starting with release version 6.00.02.00, access to Virtual Console uses only eHTML5"
  and that "eHTML5 Virtual Console traffic is routed through port 443". 5900 is the
  native/remote-presence port. For iDRAC6 the KB names Java "8 update 121 and older". [V]
  https://www.dell.com/support/kbdoc/en-ca/000185549/idrac-virtual-console-troubleshooting
- **eHTML5 is the single option from iDRAC9 6.00.00.** [V]
  https://infohub.delltechnologies.com/p/advanced-features-of-the-idrac9-ehtml-virtual-console/
- **When HTML5 arrived on iDRAC7/8.** The iDRAC8 2.30.119.30 release notes list "Added support
  for HTML5 virtual console and virtual media" [V]. AGLT2's wiki says "above 2.60" [R]. Either way,
  fw 2.86 has it.
  https://dl.dell.com/manuals/all-products/esuprt_software/esuprt_remote_ent_sys_mgmt/esuprt_rmte_ent_sys_rmte_access_cntrllr/idrac8-lifecycle-controller-v2.30.119.30_Release%20Notes_en-us.pdf
- **iDRAC6 legacy TLS.** The viewer needs TLS 1.0 and RC4. Modern Java 8 disables RC4, and the
  usual "fix" is editing `jdk.tls.disabledAlgorithms`. [R]
  https://blog.workinghardinit.work/2017/07/25/dell-idrac-6-remote-console-connection-failed/
  idrac-6-rs: "legacy (1024-bit cert) … negotiated at OpenSSL security level 0". [R]

### 1.1 iDRAC VNC server (iDRAC7/8/9)

- **Licence and behaviour** (iDRAC7/8 UG 2.50) [V]:
  - "VNC feature is licensed and is available in the iDRAC Enterprise license."
  - Any standard VNC client works (RealVNC is named).
  - **Only one VNC session at a time.**
  - **After the handshake the VNC server disables Virtual Console** (Virtual Media stays). The
    console returns when the VNC session ends.
  - A new VNC session is rejected if a vConsole session is open.
  - If video encryption is off, the client starts RFB directly. If on, there is an SSL handshake
    first ("Setting up VNC viewer with SSL encryption" = an stunnel-style TLS wrapper).
  - A minimised client window for more than 60 s closes the session.

  https://www.dell.com/support/manuals/en-ca/idrac7-8-lifecycle-controller-v2.50.50.50/idrac_2.50.50.50_ug_pub/using-vnc-client-to-manage-remote-server
- **iDRAC9 attributes and defaults** (Redfish `Managers/iDRAC.Embedded.1/Attributes`, from a
  public mockup) [V]:
  `VNCServer.1.Enable=Disabled`, `Port=5901`, `Timeout=300`, `MaxSessions=2`, `ActiveSessions`,
  `SSLEncryptionBitLength=Disabled`, `LowerEncryptionBitLength`, `Password` (write-only, reads `null`).
  `VirtualConsole.1.PluginType=eHTML5`, `VirtualConsole.1.Port=5900`, `EncryptEnable=Enabled`.
  https://github.com/cholcombe973/libredfish/blob/main/tests/mockups/dell/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1/index.json
- **Password.**
  - Classic RFB VNC auth (type 2, DES challenge) uses **only the first 8 bytes** of the password.
    This is a protocol property [V], https://gitlab.gnome.org/GNOME/vinagre/-/issues/17.
  - kvm-switcher notes that **iDRAC9 enforces complexity** on the VNC password (upper, lower,
    digit, special) [R: code comment].
  - Dell's exact maximum length was not found in a readable doc; most reports say 8 [I]. Use
    exactly 8 complex characters.
- **SSL on the VNC port.** `traktuner/dell-infra-manager` (Go) turns `SSLEncryptionBitLength` off
  because "with SSL on … noVNC rejects [it] as unexpected data message". That only shows noVNC
  cannot speak TLS-wrapped RFB. A Go terminator can: `tls.Client` to :5901 with a pinned cert,
  then RFB. **The spike must confirm that the iDRAC is the TLS server on that port**, and which
  TLS versions and suites iDRAC8 2.86 offers there. [I]
  https://github.com/traktuner/dell-infra-manager/blob/main/backend/redfish/vnc.go
- **TLS on 5900 on old firmware.** Dell community (2017, iDRAC8): "There is no way to disable TLS
  1.0 on the console/virtual media port" [R]. Dell KB 000208968 later ties scanner findings on
  5900 to `iDRAC.Webserver.TLSProtocol`, with "TLS 1.2 Only" as the recommended setting [V].
  https://dell.com/support/kbdoc/en-us/000208968/

### 1.2 The black-screen report (iDRAC8 + noVNC)

- **The report.** noVNC Google Group, 2024-03-15: iDRAC8 gives "a black screen with a cursor"
  while iDRAC9 works with the same configuration. Pierre Ossman replied that "embedded VNC
  servers are often buggy". There is no resolution in the thread. [V]
  https://groups.google.com/g/novnc/c/QiQalT3QxIw
- **The workaround** (kvm-switcher `internal/vnc/bridge.go`, Go) [V: code]:
  - It replaces every client `SetEncodings` (msg type 2) with `[Raw(0), CopyRect(1), DesktopSize(-223)]`
    (flag `FilterEncodings`).
  - It rewrites the ServerInit desktop name to `"Intel(r) AMT KVM"` (flag `RewriteName`). noVNC
    special-cases that name and requests **8-bit depth** (`core/rfb.js`: "Intel AMT KVM only
    supports 8/16 bit depths. Using low color mode.") [V: noVNC source].
  - The same project lists "native pixel format for iDRAC9, compressed encodings pass-through",
    so the quirks are iDRAC8-only.

  https://github.com/zackpollard/kvm-switcher/blob/main/internal/vnc/bridge.go
- **Implication for us.** Our RFB terminator already parses the handshake, so it can apply
  per-BMC quirks:
  - `encodings: [raw, copyrect, desktopsize]`
  - `low-colour` (8 bpp; the name-rewrite trick, or our own `SetPixelFormat` handling)

  The P5.1 spike should find which of the two is actually needed. Raw at 8 bpp is roughly
  1 MB per full 1024×768 frame; acceptable on a LAN.

### 1.3 Vendor HTML5 consoles: the protocol, and whether we can proxy them

- **iDRAC7/8 HTML5.** The Avocent viewer `virtualconsolehtml5.html?ipAddr=…&kvmPort=5900&…&ST2=…&TokenKey=…`
  runs a Worker (`websockethandler.js`) that dials **`wss://<idrac>:5900`** directly. This is
  why Dell's KB says to "browse to https://idrac:5900 and accept the certificate". The payload is
  the Avocent APCP/AVSP protocol over WebSocket, not RFB. [V: talos-control-system rewrite code; R: Dell KB]
  https://github.com/aedan/talos-control-system/blob/main/backend/src/integration/ilo_console/idrac_proxy.rs
- **iDRAC9 eHTML5.**
  - The viewer is `/restgui/vconsole/index.html?ip=<host>&kvmport=443&VCSID=<TempUsername>&VCSID2=<TempPassword>`
    (OpenStack Ironic's Dell driver) [V].
  - Its WebSocket is `wss://<host>:<port>/vnc/vconsole?vck=…` [R: browser error in the Vivaldi thread].
  - Devolutions RDM calls it "VNC over WebSockets" [R]. kvm-switcher says "iDRAC9's proprietary
    WSS protocol isn't compatible with noVNC, so we use the standard VNC server instead" [R: code comment].
  - Dell's launch URL for temp credentials is `https://<idrac>/console?username=…&tempUsername=…&tempPassword=…`
    (Dell sample `LaunchIdracRemoteKvmHtmlSessionREDFISH.py`, GPL-2.0) [V].

  https://github.com/openstack/ironic/blob/master/tools/vnc-container/extension/Dell.js
  https://forum.vivaldi.net/topic/90385/
- **Proxyable?**
  - Only by reverse-proxying the viewer's HTML/JS and every WebSocket from our origin. You
    strip frame-busting headers, rewrite absolute URLs, and inject a script that patches
    `fetch`/`XHR`/`WebSocket`/`Worker`. talos-control-system (Apache-2.0, Rust) does exactly
    this for iDRAC7/8/9 and iLO. Its rewrite code is long and version-specific.
  - That approach conflicts with our strict CSP (it needs inline script injection).
  - It also executes **BMC-served JavaScript in our origin**. A compromised or buggy BMC would
    then get same-origin access to our session cookies and CSRF tokens.
  - **Verdict:** do not do this in the main app. If ever wanted, it must live on a **separate
    origin** (its own host/port, no app cookies), the way Proxmox and cloud consoles isolate it.
    It stays in the "out of scope" list.

---

## 2. Open-source projects that bring old consoles into a browser

| Project | How it works | Status | Security posture | Licence / size |
|---|---|---|---|---|
| **DomiStyle/docker-idrac6** | jlesage `baseimage-gui:debian-13-v4` (Xvfb + x11vnc + noVNC web on 5800, VNC on 5900). At start, `wget --no-check-certificate` fetches `avctKVM.jar`, `avctKVMIOLinux64.jar`, `avctVMLinux64.jar` from `https://<idrac>/software/`. Runs `java -cp avctKVM.jar com.avocent.idrac.kvm.Main ip=… kmport=5900 user=… passwd=… apcp=1` directly (no Web Start) | Active, last commit 2026-02-28, 957 stars, 34 open issues | Holds the **permanent iDRAC password** (env or Docker secret). The password is in the **java argv** (visible to `ps` in the container). It **deletes `java.security`** entirely, which disables every algorithm restriction JVM-wide. No cert verification. One iDRAC per container. noVNC exposed without auth unless you set the jlesage password | MIT; 155 MB compressed (Zulu 8). https://github.com/DomiStyle/docker-idrac6 |
| ncerny/docker-idrac | Fork of the above for iDRAC5/6 | Dead (2019) | Same | MIT. https://github.com/ncerny/docker-idrac |
| HappyKuro/docker-idrac7, pkeech/docker-idrac7 | Same pattern for iDRAC7 (`IDRAC_BYPASS_CERT_JNI` shim, `reconnect=2` etc.) | Small, 2024 / 2026 | Same | **No licence** (cannot reuse). https://github.com/HappyKuro/docker-idrac7 |
| **sciapp/nojava-ipmi-kvm** (+ `-server`) | Python CLI/web service that **starts a Docker container per session** (OpenJDK 7u51 … 8u242, or HTML5 mode). It logs into the BMC web form (templated per vendor), downloads the JNLP, runs it under IcedTea-Web, and shows it via noVNC. The server variant adds OAuth/LDAP | CLI pushed 2026-04 (latest images 2022); server dormant since 2022 | **Server needs the Docker socket** (root-equivalent). The BMC password is typed per session. Optional `allow_insecure_ssl` | MIT; 330–364 MB. https://github.com/sciapp/nojava-ipmi-kvm |
| solarkennedy/ipmi-kvm-docker | Xvfb + x11vnc + noVNC + Firefox + Java plugin: a remote browser | Unmaintained (2022) | Generic remote desktop, no auth | Apache-2.0; ~300 MB |
| dillonbrowne/ipmi-bmc-toolkit | linuxserver/webtop (KasmVNC + XFCE + Chromium) + Temurin 8 + IcedTea-Web 1.8.4, with all `disabledAlgorithms` emptied and `AllPermission` | 2026-08, 4 stars | Full desktop with sudo-ish tooling. "Ships no built-in auth". Supermicro IPMIView is downloaded at runtime (EULA forbids bundling) | MIT; large (webtop ≈ 1 GB+). https://github.com/dillonbrowne/ipmi-bmc-toolkit |
| **OpenStack Ironic `vnc-container`** | Per-node container: x11vnc; on connect, Xvfb + **Firefox kiosk + extension** that drives the vendor's **HTML5** console (Dell via `GetKVMSession` → `/restgui/vconsole`, HPE `/irc.html` + form fill, Supermicro click-through). `ironic-novncproxy` (fork of nova's) relays to the browser | Upstream since Ironic 2025.1 (29.0.0), maintained | Docs: "VNC servers exposed by console containers are unencrypted and unauthenticated". The container holds BMC credentials | Apache-2.0. https://github.com/openstack/ironic/tree/master/tools/vnc-container, https://docs.openstack.org/ironic/2025.2/install/graphical-console.html |
| **SeineEloquenz/idrac-6-rs** | **Native Rust APCP client** for iDRAC6. It mints the one-time KVM token via the web UI, decodes RLE/RGB555, and serves standard RFB or an in-process noVNC bridge | New (2026-08), active | Legacy TLS scoped to the one connection (OpenSSL seclevel 0); a "self-serve" mode where credentials are typed in the browser; RFB is unauthenticated, so bind to localhost | **No licence file** (cannot reuse code). https://github.com/SeineEloquenz/idrac-6-rs |
| **the-curve-consulting/modern-idrac-client** | **Native Go** Avocent APCP/DVC client for iDRAC6/7/8 (iDRAC9 untested), with `kvm vnc` bridge. Detailed reverse-engineering notes (`docs/kvm-idrac8-notes.md`: iDRAC8 viewer = APCP 2.41, both sockets on 5900, plaintext user/password inside TLS) | New (2026-10) | n/a | **No licence**: read-only reference, do not copy. https://github.com/the-curve-consulting/modern-idrac-client |
| **mhamzahkhan/ipmi-connect** | **Native Go** browser console for Dell Avocent (C6220, APCP on 7578) and Supermicro ATEN (RFB 3.8 + Hermon). Includes a Go **ASPEED video decoder** (port of Aspeed's MPL-2.0 reference). Loopback + per-run token | Created 2026-10-18 | Accepts any cert, TLS 1.0. ATEN KVM is plaintext | **Apache-2.0** (reusable). https://github.com/mhamzahkhan/ipmi-connect |
| Informatic/idrac-kvmclient | Python reimplementation of the AMI JViewer KVM (5900/5901 framing, AMI iUSB), with VNC proxy | 2023, hackish | — | MIT |
| kelleyk/noVNC (bmc-support) | noVNC fork with the ATEN "AST2100" (0x57) encoding | Dead (2017) | — | MPL-2.0 |
| zackpollard/kvm-switcher | Go + SvelteKit. **iDRAC8/iDRAC9 via the VNC server**, relayed to noVNC (black-screen quirks above). AMI MegaRAC via a JViewer container. Auto-login web proxy | 2026-03 | Passwords in env vars; it **auto-sets the iDRAC9 VNC password** to `<bmc password>+"1!"` (do not copy that) | No licence file. https://github.com/zackpollard/kvm-switcher |
| Guacamole (guacd + VNC) | Could front any BMC VNC server | Mature | Heavy (Tomcat + guacd). Adds nothing over noVNC for RFB | Apache-2.0 |

Not found: a project called "nvlr", or a maintained "idrac-java-kvm". The GitHub search for
`nvlr` returned only spam repos.

**Common weaknesses of the container approach:**

1. It holds the permanent BMC password.
2. It globally weakens the JVM's crypto policy.
3. It exposes an unauthenticated VNC/noVNC port.
4. It is one container per BMC, or on-demand containers that need the Docker socket.

Our design must avoid all four.

---

## 3. How other managers do it

- **OpenBMC** [V]:
  - `obmc-ikvm` is a real RFB server on `127.0.0.1:5900`.
  - bmcweb exposes it as **`wss://<bmc>/kvm/0`** (privileges ConfigureComponents/ConfigureManager,
    session cookie), and webui-vue renders it with noVNC.
  - This is directly relayable by our terminator (WebSocket client upstream instead of TCP).

  https://github.com/openbmc/bmcweb/blob/master/features/kvm/kvm_websocket.hpp
- **Redfish** [V]:
  - `Manager.GraphicalConsole{ServiceEnabled, MaxConcurrentSessions, ConnectTypesSupported}`,
    where the enum is only `KVMIP` | `Oem` (Manager v1_25_0).
  - There is no launch URL or action. `ComputerSystem.GraphicalConsole` is the host-OS
    equivalent.
  - Vendor OEM actions are the only launch hooks: Dell `DelliDRACCardService.GetKVMSession`
    (→ `TempUsername`/`TempPassword`).

  https://redfish.dmtf.org/schemas/v1/Manager.v1_25_0.json
- **OpenStack Ironic**: `redfish-graphical` console interface + per-node VNC container + `ironic-novncproxy`
  (see table). This is the closest prior art to our "sidecar + relay", but it automates vendor
  HTML5 in a real browser instead of Java.
- **MeshCentral**: Intel AMT KVM is RFB-like. The browser speaks it over a server-relayed
  WebSocket, and auth is terminated by the server. Same shape as our terminator.
- **Proxmox VE** (VM consoles, same pattern): `POST …/vncproxy` returns a one-time `ticket` +
  port, then the browser opens `…/vncwebsocket?port&vncticket`. A good model for our
  one-time WS ticket.
- **MAAS, Tinkerbell/bmclib, Metal3**: power/boot/virtual-media only. **No graphical console.**
  bmclib has no KVM provider. [V: no KVM in provider list; our tech_doc already reviews bmclib]
- **Other vendors, for the feature-detection table** [R, verify per model]:
  - HPE iLO: HTML5 console from iLO 4 2.70 and iLO 5 v2 onward; Java/.NET IRC before that;
    iLO 2/3 Java/.NET only. Ironic automates `/irc.html`.
    https://www.hpe.com/psnow/resources/ebooks/a00115977en_us_v4/s_server-task-remoteconsole.html
  - Supermicro: X8/X9 ATEN Java iKVM (RFB 3.8 with proprietary encodings); HTML5 iKVM on
    X10 (later firmware) and X11+.
  - Lenovo: IMM/IMM2 Java/ActiveX; XCC HTML5. None of these expose a documented standard VNC
    server, so they are tier C (sidecar) or "open BMC UI".

---

## 4. Recommended architecture

### 4.1 Tiers

| Tier | Mechanism | Where | Credentials reach browser? | Main image change |
|---|---|---|---|---|
| **A** (default) | noVNC ⇄ WSS ⇄ **RFB auth terminator** ⇄ TLS-or-TCP ⇄ BMC VNC server (or OpenBMC `/kvm/0` WS) | iDRAC7/8/9 Enterprise with VNC enabled; OpenBMC; any BMC with a real RFB server | No | none (already planned) |
| **B** | iDRAC9 `GetKVMSession` → new tab to `https://<idrac>/console?…temp…` | iDRAC9 with the action present | Single-use temp pair only (accepted risk, documented) | none (already planned) |
| **C** (optional) | **Legacy-viewer sidecar**: vendor Java viewer under Xvfb → RFB on a Unix socket → same terminator → noVNC | iDRAC6, iDRAC7/8 without VNC, Supermicro ATEN Java, iLO 2/3, IMM | No | none; a separate image under a compose profile |
| D (future) | In-process Go **APCP→RFB adapter** (Avocent), modelled on ipmi-connect (Apache-2.0) | iDRAC6/7/8 without Java | No | new `internal/bmc/avocent` package |
| — | Vendor HTML5 reverse proxy | — | — | **Rejected** (§1.3) |

### 4.2 Tier A details (refines system_design §5.3)

- **Upstream dial:**
  - If `VNCServer.1.SSLEncryptionBitLength != Disabled`, use `tls.Client` with a pinned SPKI hash.
    The pin can differ from the 443 cert; capture it on first use with admin approval, as for
    the web cert.
  - Otherwise use plain TCP. The UI then shows "VNC traffic unencrypted on the management
    network" as a warning, not a blocker.
- **Handshake:**
  - Offer RFB 3.8 and pick type 2 (VNC auth).
  - The DES response uses the first 8 bytes of the secret from the age store.
  - Send ClientInit `shared=0` (the iDRAC allows one session anyway) and keep the ServerInit.
  - To the browser: RFB 3.8, security type None, then the (possibly rewritten) ServerInit.
- **Quirks, per server in config** (closed enum, not user input):
  - `rfb_encodings: [raw, copyrect, desktopsize]`
  - `rfb_low_colour: true`

  Prefer intercepting the client's `SetPixelFormat`/`SetEncodings` over the name trick. If the
  name trick is the only thing that makes noVNC choose 8 bpp, use it and document why.
- **Concurrency:** one session per BMC, enforced by the broker. A second admin gets "in use by X
  since T" (from audit), with an optional **view-only share** that drops client input messages
  4/5 (kvm-switcher's input gating).
- **The vConsole is disabled while VNC is open.** Warn in the UI, and close the session after
  the idle timeout (≤ `VNCServer.1.Timeout`).
- **WS auth:** a one-time ticket, Proxmox-style. `POST /servers/{id}/console/graphical`
  (admin + fresh TOTP step-up + CSRF) returns a 30-second single-use ticket bound to the
  session and origin. The WS upgrade checks Origin, the ticket and the cookie.
- **Message filter (defence in depth):** after ServerInit, parse client→server messages and
  allow only types 0, 2, 3, 4, 5 and 6, each with a length check. Drop anything else, so a
  browser cannot send arbitrary bytes to the BMC.
- **noVNC v1.7.0** (2026-04-28, passes the 14-day rule): vendored unmodified, served from `'self'`.

### 4.3 Tier C: legacy-viewer sidecar (optional)

Goal: the main image stays distroless with no `os/exec`, no Docker socket, and no proprietary
code; the sidecar never sees the permanent BMC password.

```
browser ─WSS─► oob-manager ── RFB over unix socket (shared tmpfs volume) ──► legacy-console sidecar
                   │  (holds BMC password)                                    │ Xvfb + x11vnc(-unixsock)
                   │  1. web login to BMC, GET JNLP (one-time token)          │ + supervisor (small Go)
                   │  2. POST launch{args allowlisted, jar sha256, cert pin}  │ + Java 8 (Temurin/Zulu)
                   └── control: HTTP over a 2nd unix socket ─────────────────►│ ─TLS1.0/legacy─► BMC :443/:5900
```

- **Lifecycle without the Docker socket:**
  - The sidecar is a long-running service under compose `profiles: [legacy-console]`, off by default.
  - It idles with only the supervisor running (≈10–20 MB).
  - On `launch` it starts Xvfb + x11vnc + `java -cp avctKVM.jar com.avocent.idrac.kvm.Main …`.
  - On WS close or idle timeout it kills the viewer and logs out.
  - One sidecar can serve N BMCs sequentially, or run 1 instance per concurrent session
    (`replicas`/named services).
- **Credentials:**
  - The app performs the BMC web login itself and fetches the JNLP. The iDRAC6/7/8 JNLP
    carries a **one-time KVM token / temp user-pass pair**: idrac-6-rs mints one per connection,
    and modern-idrac-client's notes describe the launch args [R].
  - The app parses `<argument>` values, **allowlists names** (`ip`, `kmport`, `vport`, `user`,
    `passwd`, `apcp`, `version`, `title`, `reconnect`, …), validates values (IP = the configured
    BMC, ports numeric) and sends them on the control socket.
  - The permanent password never leaves the app.
  - **Never pass secrets on argv.** The supervisor writes args to a 0600 file in tmpfs, or
    passes them via stdin to a tiny Java launcher class we ship (our own code, Apache-2.0)
    that calls `Main.main(args)` in-process.
  - For BMCs that demand the real password in the viewer (DomiStyle passes it), mark the
    template `requires_password: true`. The UI then warns that the sidecar receives it for the
    duration of the session; it lives in tmpfs only and is never in env.
- **Proprietary jars:**
  - Downloaded **at runtime from the user's own BMC** (`/software/avctKVM.jar` etc.), over the
    pinned cert the app passes in.
  - On first fetch the sha256 is recorded per BMC and firmware; a later mismatch needs admin
    re-approval.
  - Cached in a sidecar volume, never in our image or repo.
- **Legacy TLS, scoped:**
  - Never delete or empty the global `java.security`.
  - Ship `legacy.security` and start the viewer JVM with `-Djava.security.properties=/etc/legacy.security`,
    which removes only `TLSv1`, `TLSv1.1`, `RC4`, `3DES_EDE_CBC`, `MD5withRSA` and
    `RSA keySize < 1024` from the disabled lists.
  - Only that JVM, only in that container.
  - Set `jdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2` per launch template.
  - **Add a trust store holding the pinned BMC cert** instead of an all-trusting TrustManager.
    If the Avocent jar bypasses JSSE trust, document that the sidecar→BMC hop is unauthenticated.
- **Network isolation:**
  - App↔sidecar uses Unix sockets on a shared `tmpfs` volume (no TCP listener at all).
  - The sidecar's only network is the one that reaches the BMC subnet. Docker cannot filter
    egress per IP, so document an optional host or firewall rule that limits it to BMC :443/:5900
    (/:5901/:623 for vmedia, which is out of scope).
  - No published ports.
- **Hardening:**
  - Non-root, `read_only`, tmpfs `/tmp` and `/home`, `cap_drop: ALL`, `no-new-privileges`,
    `pids_limit: 128`, `mem_limit: 768m`.
  - No browser in the image (Java viewer only, unlike Ironic and webtop).
  - Base `debian:13-slim` + Temurin 8 JRE (Adoptium supports 8 to at least 2030) [I].
- **Resource cost** (estimate):
  - Idle ≈ 20 MB.
  - Active: JVM 150–300 MB RSS + Xvfb 30–60 MB, CPU 2–10 % of one core at 1024×768.
  - Image ≈ 150–250 MB compressed (DomiStyle's is 155 MB).
- **What it does not solve:** keyboard layout (the Avocent viewer sends scancodes, so it's
  fine), virtual media (still out of scope) and audio.

### 4.4 Feature detection (cached capability record per server; re-probed daily and on demand)

1. **Redfish `/redfish/v1`** (unauth): vendor (`Oem` key / `Vendor`) and Redfish version.
   No Redfish means a legacy BMC (iDRAC6, iLO 2/3, X8/X9).
2. **Manager:** `Model`, `FirmwareVersion`, `GraphicalConsole{ServiceEnabled, ConnectTypesSupported}`.
   If `ServiceEnabled=false`, the result is "disabled on BMC".
3. **Dell licence:** `DellLicenses` / attributes (Express → no vConsole on rack servers).
4. **Dell VNC:** `Attributes` `VNCServer.1.{Enable,Port,SSLEncryptionBitLength,Timeout}`.
   - Verify that iDRAC8 2.86 exposes `Managers/iDRAC.Embedded.1/Attributes`; if not, fall back
     to the read-only `racadm get iDRAC.VNCServer` over the existing BMC SSH channel.
   - Then do a **banner probe**: TCP/TLS connect, read 12 bytes, expect `RFB 003.00x\n`, close
     before auth. This adds a pinned-cert step if TLS.
5. **Dell iDRAC9 Tier B:** `DelliDRACCardService` `Actions` contains `#DelliDRACCardService.GetKVMSession`.
6. **OpenBMC:** `Oem.OpenBmc` present → tier A over `wss://bmc/kvm/0`.
7. **Legacy (tier C eligible):** only if the sidecar is configured and the server has a
   `legacy_viewer` template. The probe is `HEAD https://<bmc>/software/avctKVM.jar` (iDRAC6/7/8)
   or the vendor JNLP endpoint, reached through the sidecar's network path.

**UX:** the server page shows one "Graphical console" card with the state and the reason:

| State | Card shows |
|---|---|
| Ready (A) | **Open console**; secondary **Open native iDRAC console** (B, iDRAC9). Shows "VNC over TLS" or "unencrypted", and "disables iDRAC virtual console while open" |
| In use | "Session by *user* since *t*", plus **View only** |
| Needs setup | "VNC server disabled on BMC / no password stored." Gives exact steps (iDRAC → iDRAC Settings → Services → VNC Server: enable, port 5901, SSL on, 8-char complex password; add it to the secrets file). The app does **not** write BMC settings itself (rule: BMC writes need approval) |
| Licence | "iDRAC Express: graphical console requires Enterprise." Offers the serial console |
| Legacy, sidecar off | "This BMC only offers a Java console. Enable the optional legacy-console sidecar (docs link) or use the BMC UI." |
| Unsupported | "Open BMC UI" link + **Serial console** button |

### 4.5 TLS strategy summary

| Hop | Approach |
|---|---|
| Browser ↔ app | TLS 1.3, unchanged |
| App ↔ iDRAC8/9 VNC (tier A) | Go `crypto/tls` client, pinned. Allow down to TLS 1.2 by default. A per-server `legacy_tls: tls10` flag lowers `MinVersion` and adds the needed suites **on that one `tls.Config` only**. Go still implements TLS 1.0 and RSA-kex/3DES/RC4 suites listed under `InsecureCipherSuites()` [V: pkg docs list the RC4 constant; verify actual RC4 negotiation in a test] |
| Sidecar ↔ iDRAC6 | Java with a per-JVM `java.security.properties` override. Network path treated as trusted; documented |
| Never | Global crypto downgrade, `InsecureSkipVerify` without a pin, deleting `java.security` |

---

## 5. Risks, licences, effort

### 5.1 Risks

| Risk | Sev | Mitigation |
|---|---|---|
| iDRAC8 VNC quirks beyond encodings/depth (black screen, resize) | H | P5.1 spike against the R730XD; websockify-style recording of the session for a regression fixture; quirk flags |
| VNC session disables the vConsole, and only one VNC session is allowed | M | Broker lock, idle timeout, UI warning |
| VNC auth is 8-byte DES, and plaintext RFB if SSL is off | M | Recommend SSL on; terminator does TLS; iDRAC IP filter; 8-char complex password unique per BMC |
| Executing BMC JS in our origin (if anyone adds an HTML5 proxy) | H | Rejected; keep in "out of scope"; separate origin if it is ever revisited |
| Sidecar compromise via the old JVM / proprietary viewer | M | No secrets at rest, one-time tokens, no TCP listeners, no browser, read-only, egress-limited, opt-in |
| Legacy TLS weakens the BMC hop | M | Scoped per connection; document a trusted management VLAN |
| Account lockout from repeated failed logins | M | Never auto-retry a rejected credential (modern-idrac-client does the same); breaker |
| Avocent "one console session"; unclean exit locks you out until timeout | M | Always log out the web session and close KVM cleanly; janitor on startup |
| Tier D reverse-engineering correctness and legality | M | Only reuse Apache/MIT/MPL code (ipmi-connect, Aspeed reference); no code from unlicensed repos; interoperability-only use |

### 5.2 Licences

- **noVNC**: MPL-2.0 (core) + bundled third-party files (pako MIT/zlib, etc.). GitHub reports
  "NOASSERTION" because the repo holds multiple licences. MPL is file-level copyleft, so ship the
  files unmodified with the LICENSE.txt; any modified file stays MPL. Compatible with our
  Apache-2.0 release. Already in the task_list 8.5 NOTICE.
- **Dell/Avocent viewer jars** (`avctKVM.jar`, `avctKVMIO*.jar`): proprietary, with no
  redistribution grant found. **Do not bundle, mirror or cache them in the image or repo.**
  The sidecar downloads them from the user's own BMC at runtime, as DomiStyle does.
  Supermicro IPMIView's EULA explicitly forbids redistribution [V: ipmi-bmc-toolkit README];
  the same applies to Oracle JRE 7/8 (BCL). Use Temurin/Zulu 8 (GPLv2+CPE, redistributable).
- **Dell `iDRAC-Redfish-Scripting`**: GPL-2.0. Reimplement the HTTP calls; do not copy code.
  This matches the current plan.
- **Reusable code**: ipmi-connect (Apache-2.0: Avocent/ATEN clients, ASPEED decoder), Ironic
  (Apache-2.0: ideas and URL formats), talos-control-system (Apache-2.0: reference only), noVNC
  (MPL-2.0). Reference-only, because they have no licence: modern-idrac-client, idrac-6-rs,
  kvm-switcher, HappyKuro/docker-idrac7. **Facts and protocol knowledge are fine to use;
  copying code is not.**

### 5.3 Effort (developer-days, TDD included)

| Item | Est |
|---|---|
| P5.1 spike: iDRAC8 2.86 VNC with/without SSL, encodings/depth quirks, iDRAC9 VNC complexity rules | 0.5–1 |
| P5.2 terminator + quirk flags + client message filter + TLS pin + one-time WS ticket | 2 |
| P5.3 noVNC page + Playwright vs a fake RFB server | 0.75 |
| P5.4 iDRAC9 GetKVMSession (tier B) | 0.5 |
| **New** 5.6: capability probe + detection matrix + card UX states | 1 |
| **Tier A+B total** | **≈ 5–5.5 d** (was 3–5) |
| Tier C sidecar: image, Go supervisor, control protocol, JNLP fetch/allowlist (iDRAC6/7/8), jar pinning, scoped java.security, hardening, docs | 5–7 |
| Tier C extra vendor templates (Supermicro ATEN, iLO 2/3) | 1–2 each; needs hardware to test |
| Tier D native Go Avocent adapter (iDRAC6 RLE first, then iDRAC7/8 ASPEED) | 10–20+, high risk; only with test hardware |

**Recommendation:** do tiers A and B now, within P5. For tier C, write an ADR (it changes
rule 11 and the "no sidecars" principle) and schedule it after P8 as an opt-in feature.
Neither tested server needs it, and public iDRAC6 users are the main audience. Watch
ipmi-connect and idrac-6-rs for 3–6 months before considering tier D.
