# Repository presentation (apply when the repository goes public)

Settings that live on GitHub rather than in the tree. Apply them at go-public, then check the
rendered README against the review list in the showcase plan (light and dark images, badges,
anchors, alt text).

## About (the repository sidebar)

**Description** (283 characters):

> Self-hosted out-of-band management for Dell iDRAC over Redfish: one web console for health, sensor
> history, event logs, firmware and BMC security checks, plus power, fan boosts and serial/VNC
> consoles behind TOTP step-up and an audit log. Read-only by default, LAN-only. Public beta.

**Website:** `https://github.com/MrRonco/oob-manager/blob/main/deploy/README.md` (the install
guide), until a docs site exists. Switch it to the Unraid support thread only if that becomes the
main help channel.

**Topics** (14): `homelab`, `self-hosted`, `idrac`, `idrac8`, `idrac9`, `redfish`, `bmc`,
`out-of-band-management`, `server-management`, `server-monitoring`, `poweredge`,
`serial-console`, `unraid`, `golang`. Leave out `ipmi`: it would attract people whose BMCs
oob-manager cannot manage (it is Redfish only).

**Sidebar:** untick Wikis and Projects; tick Releases and Packages.

## Social preview

Settings › General › Social preview: upload `docs/screenshots/social-preview.png` (1280 × 640,
made by `make showcase` / the showcase workflow from `tests/e2e/showcase/social.html`). Check a
link unfurl afterwards (Slack, Discord or a Reddit preview): the text must sit inside the safe area.

## Sponsorships

`.github/FUNDING.yml` names the Buy Me a Coffee page (`buy_me_a_coffee: mrronco`,
https://www.buymeacoffee.com/mrronco). GitHub shows the repository's **Sponsor** button only once
sponsorships are turned on: Settings › General › Features › **Sponsorships**.
