# Plan 07 — Public release on GitHub (P8)

Status: plan 2026-10-29; release decisions recorded in §6. Items 4.1, 4.2, 4.3,
4.5 and the 4.6 script are built on branch `public-cut`. Turns task_list P8 (8.1–8.6, 8.5a) and the
"ready for public release" checklist of plan 06 §4 into an ordered plan. Plans 04 (redesign) and 06
(P7 hardening) have landed.

## 1. Goal and non-goals

**Goal.** Publish `oob-manager` as a generic, safe-by-default, Apache-2.0 project that anyone with a
Dell iDRAC 8/9 (and, marked untested, other Redfish BMCs) can run from a signed container image, with
no detail of any real install anywhere in the public tree or its history, and that Unraid users can
install from Community Applications (§4.8).

**Non-goals.** New features, multi-vendor drivers (backlog M0–M7), a hosted demo, paid support.

## 2. Where things stand (2026-10-29)

| Area | State |
|---|---|
| Product | P0–P6, S1–S4, plans 01–03 and 05 merged. Redesign: slices A and B merged, C on its branch, D not started. |
| Gates | CI: lint + actionlint, per-package 80 % coverage, govulncheck, image (Trivy, Syft SBOM as artifact), Go e2e, Playwright e2e + axe, blocking visual diff, nightly soak, repo-policy tests (since 4.1: a whole-tree test for network details, CLAUDE.md rule 12). |
| Supply chain | Actions pinned by SHA, tools ≥ 14 days old, Renovate installed (dashboard not yet seen). No release workflow, no signing, no provenance. |
| Hardening (plan 06) | P7-early done. Open: reviews pass (3.1), ZAP (3.2), release workflow + cosign (3.3), CSP decision (3.4), fuzzing (3.5), restore drills + `backup`/`verify-audit` CLI (3.6), threat-model refresh (3.7), trivyignore policy (3.8), generic deploy docs (3.10). ≈ 6 d. |
| Install-specific material in the repo (before 4.1) | One deploy section and the decisions record written for a single install, hardware notes tied to its servers, tech_doc session notes, and plans and reviews written against that install. Moved out of the repository by 4.1. |
| History | The private repository's history contains install details and a 36 MB build blob (tech_doc "Repository hygiene"). It must never be published. |

## 3. Sequence

```
slice C merge → [slice D] → P7 rest (plan 06, ≈ 6 d) → soak ≥ 7 days on real hardware
→ P8 prep on a `public-cut` branch (≈ 2 d) → dry-run cut + review → go public → public beta
→ Community Applications submission (§4.8) once the published image has run a week without a fix
```

The store-ready install items of §4.8 (no host script, user/group, first-run setup) do not need the
repo to be public and help existing installs too, so they can land in any minor before P8.

The soak is the release candidate running unchanged on real hardware for a week with nightly CI green.
Any fix during the soak restarts the week only if it touches auth, sessions, power, fans or the
console relay.

## 4. Work items

### 4.1 Split generic from personal (task 8.1) — 0.5 d

- Install-specific material (one install's deploy notes and decisions, notes tied to its servers,
  live-install session notes) moves out of the repository into private notes outside it, not into a
  `deploy/homelab/` folder: nothing personal stays in the product repo, so the cut needs no exclusion
  list to stay correct.
- tech_doc keeps design and implementation notes but drops "deployed on …" lines; plans 01–09 and
  `docs/reviews/` are reviewed one by one: keep what explains a design choice, drop the rest.
- Fixtures and tests use neutral names: BMC accounts `oob_ro` / `oob_op` / `oob_kvm`, servers
  "Storage node R730XD" and "Edge node R240", documentation addresses and `.example` names.
- Test: `internal/repopolicy` `TestPublicTreeHasNoNetworkDetails` walks the whole tree and fails on
  RFC 1918 literals (the three blocks themselves are allowed), host paths (Unraid mount and flash
  paths, application-data shares), real-looking MAC addresses outside 00:00:5E:00:53:xx and host names
  under home-network TLDs. RFC 5737 / RFC 3849 examples are allowed. A file that needs a pattern on
  purpose opts in with a `repopolicy:allow <rule> -- <reason>` line. The rules are generic on purpose:
  a denylist naming real identifiers would itself be the leak, so those are checked only by
  the cut script (§4.6) against a private list kept outside the repository.

### 4.2 Generic deployment (8.2, plan 06 §3.10) — 0.25 d

Docker Compose as the documented default; Unraid as one example; `host-lease` fan mode documented as
an opt-in integration with the example host script; every example IP from 192.0.2.0/24.

### 4.3 Safe defaults re-check (8.3) — 0.25 d

First-admin bootstrap only, no default credentials, TLS required, dangerous actions off until
configured, LAN-binding guidance. Re-run the security reviewer and ZAP on the generic build.

### 4.4 Release engineering (8.4, plan 06 §3.3) — 0.5 d on top of plan 06

- `release.yml` on tag `v*`: multi-arch (amd64, arm64) image to GHCR, cosign keyless signature,
  SLSA provenance and SBOM attestations, GitHub release with CHANGELOG excerpt and checksums.
- `docs/verify.md`: how to verify the signature and provenance before running the image.
- CHANGELOG.md from the merged tech_doc sections, written for users.

### 4.5 Community files (8.5, 8.5a) — 0.5 d

LICENSE (Apache-2.0), NOTICE (already maintained), SECURITY.md (GitHub private vulnerability
reporting, supported versions, response expectations for a hobby project), CONTRIBUTING.md (tests
first, the gates, the 14-day dependency rule, DCO or not: §6 decision 6), CODE_OF_CONDUCT.md
(Contributor Covenant 2.1), issue templates (bug, feature, **hardware report**), PR template,
`docs/hardware.md` (verified: iDRAC8 2.86 on R730XD, iDRAC9 7.00 on R240; everything else untested),
README rewrite (what it is, screenshots from the mock fixtures, quick start, security model in one
paragraph, tested hardware, support statement).

### 4.6 The clean cut (8.6) — 0.25 d + review

1. `scripts/public-cut.sh <tag> <outdir> --identifiers <file>` exports the tree at a tag with
   `git archive` into an empty directory (no `.git`), so no private history or blob can travel. It
   never runs `git init` or pushes; those steps stay manual.
2. Scans on that exact directory: gitleaks and trufflehog (filesystem mode), the repopolicy
   whole-tree test, a grep for real identifiers from the private list named by
   `--identifiers` (kept outside the repo, never copied into it), and `exiftool` over every image
   (screenshots and visual baselines must carry no GPS, author or camera metadata). A missing scanner
   fails the cut and prints how to install it; image metadata is stripped only when a flag asks.
3. `git init` → one commit "Initial public release" → push to the new public repository while it
   is still **private**.
4. Owner review on GitHub (§7 checklist), then switch visibility to public.

### 4.7 Public repository setup — 0.25 d

Branch protection on `main` (now free: public repo) with required checks and code-owner review;
private vulnerability reporting on; secret scanning and push protection on; Dependabot alerts on
(Renovate keeps doing updates); Discussions off at first; topics and description; GHCR package
linked and public.

### 4.8 Unraid Community Applications listing — 1.25 d (store-ready install 1 d, listing 0.25 d)

Community Applications (CA) accepts only **public, active** GitHub repositories with an
**OSI-approved licence**, and every Docker app needs a valid template XML with a `Repository` tag
pointing at a public image. Submission is the CA web flow (add the repo, Validate, Scan, fix, submit
for moderator review). Sources: https://ca.unraid.net/submit and
https://ca.unraid.net/submit/help/repository-xml (checked 2026-10-29; re-read both before submitting,
the requirements change).

**Store-ready install (no host changes, can ship before P8): built in v0.11.0, see
[plan 09](09-store-ready-install.md).** Deviations: `PUID`/`PGID` are not supported (no root
entrypoint in a distroless image); the container runs with Docker's `--user` instead. The draft
template is [`deploy/unraid/oob-manager.xml`](../../deploy/unraid/oob-manager.xml). A CA user installs from a form and
never edits the host's boot script, so the container must start correctly from its data volume alone:

1. **Keys without a host script.** Before v0.11.0 the age identity had to be staged by a host boot script
   into a tmpfs path the container mounts. Add a first-start path: when no identity is mounted,
   generate one in the data volume (0400, owned by the app user) and seal `app-keys.age` with it, and
   print a one-time "back up this file" notice in the UI and the log. The mounted-identity path stays
   for installs that keep the key off the data volume. Document the trade-off: an identity in the
   data volume travels with backups of that volume.
2. **User and group.** The image runs as 65532; Unraid's application-data share is normally
   `nobody:users` (99:100).
   Support `PUID`/`PGID` (or a documented `--user 99:100`) and refuse to start with a clear message
   when the data directory is not writable, instead of failing mid-migration.
3. **First admin in the browser.** `bootstrap-admin` needs `docker exec -it`. Add a first-run setup
   page that exists only while there are no users. It is protected by a one-time setup token printed
   to the container log (so a LAN neighbour cannot claim the instance first), and it creates the admin
   with TOTP enrolment exactly like the CLI.
4. **TLS out of the box.** Generate the self-signed certificate on first start when none is mounted
   (`gentls` exists as a CLI today), with the fingerprint shown in the log for the first visit.
5. **Optional integrations stay optional.** `host-lease` fan mode and its host script, the iDRAC IP
   filter advice and Prometheus scraping go in an "Advanced" docs section and are not in the template.

**Listing (after go-public).**

- Separate public repo `MrRonco/unraid-templates` (decision 11), built from CA's starter repository:
  `README.md`, `LICENSE`, icon (SVG + PNG), `ca_profile.xml` with a non-empty `Profile`, and
  `templates/oob-manager.xml`.
- Template: `Repository` = the signed GHCR image (pinned minor tag), `Registry`, `Project`, `Support`
  (decision 12), `Overview` (what it is, tested hardware, "read-only by default"), `Category`
  (Tools / Network:Management), `WebUI` = `https://[IP]:[PORT:8443]/`, `Icon`, `TemplateURL`, and
  Config entries: port 8443, `/data` (the application-data share), optional `/config` (config.yaml), optional
  `/leases`, `PUID`/`PGID`, `TZ`, memory limit 256m in `ExtraParams`. No secrets in the template.
- Network: default **bridge**, with a note that the container's egress address is the Unraid host,
  so a BMC IP allow-list must include the host.
- Run CA Validate and Scan until clean, install from the template on a clean data path (a
  second container name on an existing host) and walk first-run setup end to end before submitting.
- Repo-policy test: the template repo gets the same denylist grep as the product (§4.1).

## 5. Effort

| Item | Days |
|---|---|
| Plan 06 P7 rest | ≈ 6 |
| 4.1 split | 0.5 |
| 4.2–4.3 | 0.5 |
| 4.4 on top of plan 06 §3.3 | 0.5 |
| 4.5 | 0.5 |
| 4.6–4.7 | 0.5 |
| 4.8 store-ready install (may ship earlier) | 1 |
| 4.8 listing | 0.25 |
| **P8 total** | **≈ 3.75 d** after P7, plus the 7-day soak and a week on the published image before the CA submission (calendar time, no work) |

## 6. Release decisions

| # | Topic | Decision |
|---|---|---|
| 1 | Repository | The public `MrRonco/oob-manager` is a fresh repository made by the clean cut (§4.6); the earlier working repository is archived. |
| 2 | Where development continues | In the public repository. No recurring cut. |
| 3 | First version | The minor current at the cut, labelled **public beta**, with a call for hardware reports; `v1.0.0` after the first hardware reports and a month without a security fix. |
| 4 | Support statement | "As-is homelab project, issues and contributions welcome, security reports answered first." |
| 5 | Registry | GHCR only (`ghcr.io/mrronco/oob-manager`); Docker Hub later if people ask. |
| 6 | Contributor sign-off | DCO sign-off (`git commit -s`), no CLA. |
| 7 | Redesign slice D | Motion and view transitions shipped in v0.10.0; the command palette in v0.13.0. |
| 8 | Plan 06 questions | ZAP smoke per PR and a full scan nightly; keyless cosign; the `backup` CLI before release; `umask 077`. |
| 9 | Screen-reader pass | Before the cut, on Overview, a server page, Settings and the sign-in flow. |
| 10 | Test BMCs | Fix or accept what the product's own Security tab flags on the BMCs used for testing, so hardware notes never describe a weakened setup. |
| 11 | CA template repository | A separate public `MrRonco/unraid-templates` (CA's starter layout). |
| 12 | CA support link | A support thread in the Unraid forum's Docker Containers section, linking to GitHub issues for bugs. |
| 13 | Keys on store installs | Generate the age identity in the data volume on first start with a "back this up" notice; keep the mounted-key path for installs that keep the key elsewhere (plan 09). |

## 7. Release steps

Done on the new repository while it is still private, before its visibility changes:

1. Plan 06 §4 checklist complete.
2. The release workflow produced a signed, attested image, and the `docs/verify.md` steps succeed
   from a clean machine.
3. The §4.6 scans are clean on the exact tree, and README, docs/, deploy/ and any images were read
   through once more for install-specific details.
4. The repository settings of §4.7 are applied.
5. The SECURITY.md contact works (a test advisory draft opened and deleted).
6. After a week on the published image: CA Validate and Scan clean, a fresh install from the
   template walked end to end, then the template is submitted (§4.8).

## 8. Risks

- **An install identifier slips through** in prose, a screenshot or a test fixture: mitigated by the
  repopolicy whole-tree test, the private-identifier grep, exiftool, and a final read-through before visibility flips.
- **Support load** from hardware the project never saw: the hardware-report template and the
  untested labels set expectations.
- **Security reports on a hobby schedule:** SECURITY.md states response times honestly; dependency
  bumps stay automated.
- **Dell trademarks:** use "for Dell iDRAC" descriptively; no Dell logos.

## 9. After release

Monthly dependency and base-image bumps (Renovate), triage of hardware reports into
`docs/hardware.md`, the multi-vendor backlog only when real hardware or a tester exists, and keeping
the Community Applications template in step with each release (pinned tag, changed Config entries).
