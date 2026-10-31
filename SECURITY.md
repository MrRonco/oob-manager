# Security policy

oob-manager holds BMC credentials and can power servers off, so security reports come first.
It is a hobby project maintained in spare time: the commitments below are what one maintainer
can keep, written down so you know what to expect.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting**: open the repository's
[Security tab](https://github.com/MrRonco/oob-manager/security) and choose **Report a
vulnerability** (or go straight to the
[new advisory form](https://github.com/MrRonco/oob-manager/security/advisories/new)). The report
stays private between you and the maintainers until an advisory is published.

Please do **not** open a public issue, pull request or discussion for a vulnerability, and do not
send it by email: there is no security mailbox, and a private advisory keeps the report, the fix
and the CVE request in one place.

A useful report says:

- the oob-manager version (the page footer or `/about`, `/api/v1/version`, or `docker run --rm <image> version`);
- how it is deployed (Docker Compose, Unraid, other) and which features are turned on;
- what an attacker needs first (network position, an account and its role, a BMC under their control);
- the steps to reproduce, ideally against the mock BMCs (`make dev`, see
  [CONTRIBUTING.md](CONTRIBUTING.md)), and what happens compared with what should happen.

### What not to put in a report

- **No credentials:** no BMC passwords, VNC passwords, TOTP secrets, API tokens, session cookies,
  setup codes or the age identity, even ones you believe are expired. Replace them with `<redacted>`.
- **No real addresses or names:** no BMC or host IP addresses, host names, domains, serial numbers,
  service tags, MAC addresses or licence IDs. Use `192.0.2.10` for a BMC, `192.0.2.20` for the host
  and `example.com` names.
- **No full database or data-volume copies.** If a log excerpt matters, trim it to the lines that
  show the problem and redact as above.

If the only way to show the problem involves sensitive data, say so in the report and we will
agree on a way to share it.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement of your report | within **7 days** |
| First assessment (accepted or not, severity) | within 14 days |
| Fix, or a written plan with a date, for **high or critical** severity | within **30 days** |
| Medium and low severity | in a following release, usually within 90 days |

Severity uses CVSS v4 as a guide, weighed against the documented deployment (LAN only, behind
TOTP sign-in). When a fix is released, the advisory is published with credit to you unless you
prefer to stay anonymous, and a CVE is requested through GitHub where it applies. Please give us
until the fix is released, or 90 days from your report, whichever comes first, before you
disclose publicly; if we miss the targets above, tell us and we will agree on a date together.

These are targets, not guarantees: there is no paid support and no SLA.

## Supported versions

During the public beta only the **latest minor release** gets security fixes. Upgrade to the
newest `v0.x` release before reporting, if you can; a report against an older minor is still
welcome when the problem is also in the latest one.

| Version | Security fixes |
|---|---|
| Latest `v0.x` minor | Yes |
| Older minors | No |

After `v1.0.0` this table will say how long a minor stays supported.

## Scope

In scope:

- the oob-manager application: the web UI, the JSON API, sign-in, TOTP and step-up, sessions,
  role checks, the audit chain, sealed secrets, the console relays (VNC and serial), fan leases,
  power actions, notifications and metrics;
- how it talks to BMCs: certificate and host-key pinning, the request allowlists, the address
  policy (`settings.bmc_networks`), and anything that lets user input reach a BMC;
- the container image and the release artifacts: base image, signatures, provenance, SBOM;
- the example host fan reader in `deploy/host/` and the documented deployment defaults in
  `deploy/`.

Out of scope:

- **BMC firmware itself** (iDRAC or any other BMC). Report those to the BMC vendor. If
  oob-manager makes a BMC weakness easier to reach, or fails to protect against one it claims to,
  that part is in scope.
- Problems that need an attacker who already has root on the Docker host, the age identity, or a
  signed-in administrator account and a fresh TOTP code: the threat model treats those as trusted
  (see [docs/security.md](docs/security.md), "Residual risks").
- Exposing the UI to the internet against the documentation, missing hardening on deployments
  that changed the documented defaults, and denial of service by flooding the network.
- Findings from automated scanners without a demonstrated impact, and missing headers that the
  threat model already discusses.
- Vulnerabilities in third-party dependencies with no reachable path in oob-manager (govulncheck
  says which are reachable); report those upstream. If one is reachable, it is in scope.

## Safe harbour

We will not pursue or support legal action against you for security research that follows this
policy in good faith: you test only against your own installation, your own BMCs or the mock
BMCs in this repository; you do not access, change or destroy data that is not yours; you do not
degrade other people's systems; and you report what you find privately and give us a reasonable
time to fix it before disclosing. If a third party takes action against you for research that
followed this policy, we will make it known that your work was authorised by this policy.

Never test against a BMC or server you do not own or have written permission to test.

## Hardening guidance

The threat model, the controls and the BMC account plan are in [docs/security.md](docs/security.md).
How to verify a release before running it is in [docs/verify.md](docs/verify.md), and the
deployment defaults (LAN-only binding, TLS, least-privilege BMC accounts) are in
[deploy/README.md](deploy/README.md).
