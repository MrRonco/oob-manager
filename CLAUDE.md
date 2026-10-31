# oob-manager — project rules

Out-of-band server management web app (sensors, event logs, firmware view, power, fan leases,
remote console) for Dell iDRAC 8/9 and, untested, other Redfish BMCs, aimed at homelabs and small
racks. Read `README.md` and the `docs/` set before changing anything; they are the source of truth
for design decisions.

## Status

Public beta. Build follows `docs/task_list.md` phase by phase; the design decisions are recorded
there ("Decisions") and in `docs/tech_doc.md`.

## Hard rules

1. **TDD.** Tests first, watch them fail, then implement. 80 % coverage gate in CI; the
   `auth`, `authz`, `fan`, `power`, `audit` packages each stay ≥ 80 % on their own.
2. **No shell-outs. Ever.** No `os/exec` in this codebase (enforce with a lint rule).
   IPMI is native go-ipmi, Redfish is gofish, BMC SSH runs exactly `console com2`.
3. **Nothing user-supplied reaches a BMC.** Server IDs are looked up from the effective server
   registry (config.yaml + admin-managed DB rows, `internal/registry`); actions are closed enums;
   fan percentages are validated integers clamped to the floor. The only BMC values an admin
   types are an IP literal and port (checked by `internal/netpolicy` against
   `settings.bmc_networks`), pinned by TOFU before any credential is sent, and credentials that
   are sealed and bound to that address.
4. **Immutability.** Value types for snapshots/results; pollers publish new snapshots via
   `atomic.Pointer`; no package-level mutable state otherwise.
5. **Small files.** 200–400 lines typical, 800 max; functions < 50 lines; nesting ≤ 4.
6. **Secrets** never in env, argv, logs, templates, test fixtures or git. Fixtures captured
   from real iDRACs are sanitized (serials, MACs, hostnames, IPs) before commit.
7. **IPMI policy:** RMCP+ only, cipher 17 then 3, refuse 0/1/2 and anything without
   integrity + confidentiality. IPMI is the legacy path; Dell hardware uses Redfish + BMC SSH.
8. **Fan control is cooperative.** In `host-lease` mode a host fan script is the single
   writer of that server's fan commands; this app only writes a lease file. Never add code that
   sends fan commands out-of-band to a server in `host-lease` mode. Never create sticky BMC
   manual mode without an enforced revert path.
9. **Dangerous actions** (power, fan lease, graphical console) need role + step-up TOTP +
   audit + rate limit. Don't add a bypass "for testing"; use the mock BMCs.
10. **No new dependency** without a row in `docs/tech_doc.md` §2 (purpose, license, why not
    stdlib). Pin versions; dependency bumps wait ≥ 14 days after upstream release.
11. **Out of scope by design:** virtual media, firmware updates, BIOS settings, BMC user
    management, Java consoles, proxying the full iDRAC web UI.
12. **Public project.** No homelab specifics anywhere in the tree: no real IPs, MAC addresses,
    host names, domains, people's names, serials, service tags, licence IDs or host paths, in
    code, tests, fixtures or docs. Examples use 192.0.2.0/24 (RFC 5737), 2001:db8::/32 (RFC 3849),
    MAC addresses 00:00:5E:00:53:xx (RFC 7042) and `.example` names (RFC 2606). Hardware models
    are fine. Anything site-specific goes behind config, not into code. Enforced by
    `internal/repopolicy` (`TestPublicTreeHasNoNetworkDetails`, generic patterns with a
    per-file `repopolicy:allow <rule> -- <reason>` opt-out) and, before a release cut, by the
    maintainer's private identifier grep in `scripts/public-cut.sh`.

## Working against real hardware

Development and CI use the mock BMCs (`internal/bmc/redfishmock`, `bmcssh/sshtest`,
`console/rfbtest`) only. Fixture capture from a real BMC is read-only: Redfish GETs with a
read-only account (for example `oob_ro`), then sanitize serials, service tags, MACs, host names,
IPs and licence IDs before commit (rule 6). Any write to a BMC, any host-script change, any
container deploy and any firewall change happens only with the hardware owner's explicit
approval, and with a backup of whatever is changed.

## Commands

```bash
make test        # go test -race -count=1 ./...
make cover       # tests + the per-package 80 % coverage gate
make lint        # golangci-lint run (incl. gosec)
make vuln        # govulncheck ./...
make actionlint  # lint .github/workflows
make image       # build distroless image
make scan        # trivy image --severity HIGH,CRITICAL --exit-code 1
```

## Commits

Conventional Commits (`feat(fan): add lease arbiter`), signed off for the DCO
(`git commit -s`, see `CONTRIBUTING.md`). Agent sessions end the message with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` (or the attribution the current
session specifies).
