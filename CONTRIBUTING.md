# Contributing to oob-manager

Thanks for helping. oob-manager is an as-is homelab project: issues and contributions are
welcome, and security reports are answered first. It is maintained in spare time, so a review
can take a few days; a small, focused pull request with tests gets merged fastest.

- **Security problem?** Do not open an issue or pull request. Follow [SECURITY.md](SECURITY.md).
- **Tried it on your hardware?** A [hardware report](https://github.com/MrRonco/oob-manager/issues/new?template=hardware_report.yml)
  is one of the most useful contributions right now, working or not ([docs/hardware.md](docs/hardware.md)).
- **Bug or idea?** Open an issue first for anything bigger than a small fix, so we can agree on
  the approach before you spend time on it.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## The project rules

[CLAUDE.md](CLAUDE.md) holds the hard rules every change has to keep (it is written for both
people and coding agents). The ones that most often matter in a review:

1. **Tests first.** Write the failing test, watch it fail, then implement (below).
2. **No shell-outs.** No `os/exec` anywhere; `make noexec` and the linters enforce it.
3. **Nothing user-supplied reaches a BMC.** Actions are closed enums, server IDs come from the
   registry, and the only BMC values an admin types are an address (checked against
   `settings.bmc_networks`) and the credentials sealed to it.
4. **Immutable values,** small files (200–400 lines typical, 800 max), functions under 50 lines,
   nesting at most 4 deep.
5. **No secrets** in env, argv, logs, templates, fixtures or git.
6. **Dangerous actions** (power, BMC restart, fan lease, consoles) need the role, a fresh TOTP
   step-up, a rate limit and an audit row. No bypass "for testing": use the mock BMCs.
7. **Out of scope by design:** virtual media, firmware updates, BIOS settings, BMC user
   management, Java consoles and proxying the full BMC web UI. Pull requests adding these will be
   declined.
8. **Public tree:** no detail of a real network anywhere (see [Fixtures and test data](#fixtures-and-test-data)).

The design documents in [docs/](docs/) are the source of truth: read the relevant section of
[docs/tech_doc.md](docs/tech_doc.md), [docs/system_design.md](docs/system_design.md) and
[docs/security.md](docs/security.md) before changing a subsystem, and update them in the same
pull request when behaviour changes.

## Development setup

You need:

- **Go** at the version in [`go.mod`](go.mod) (the `toolchain` line; `go` downloads it if your
  installed Go is older);
- **Node.js 22** with `npm`, for the Playwright tests;
- **Docker**, for the image, the visual comparison and the ZAP scan (the ZAP target needs Linux).

Nothing in development talks to real hardware. `make dev` runs the app against two mock BMCs (an
iDRAC8 R730XD fixture and an iDRAC9 R240 fixture) and prints the URL, a sign-in file and a fresh
TOTP code every 30 seconds:

```bash
make dev                       # https://127.0.0.1:8443/ by default; Ctrl-C to stop
make dev DEV_ADDR=127.0.0.1:9443
```

## Tests first

Every change starts with a test that fails without it:

1. Write the test (unit test next to the code, an e2e or Playwright spec for a page or flow).
2. Run it and watch it fail for the right reason.
3. Write the smallest change that makes it pass.
4. Refactor, then run `make check`.

Bug fixes include a test that reproduces the bug. A fuzz crasher is committed under the
package's `testdata/fuzz/<Target>/` together with its fix, and every new `func Fuzz…` is listed in
exactly one of the `FUZZ_A` / `FUZZ_B` sets in the [Makefile](Makefile).

## Running the checks locally

`make check` is the local equivalent of the CI gates that need no Docker:

| Command | What it runs |
|---|---|
| `make check` | `vet`, `noexec`, `lint`, `actionlint`, `test` and `cover`, in that order |
| `make test` | `go test -race -count=1 ./...` (includes the repository-policy tests in `internal/repopolicy`) |
| `make cover` | tests with coverage, then the 80 % gate on the module total and on every package |
| `make lint` | golangci-lint (incl. gosec); skipped with a warning when it is not installed, CI always runs it |
| `make actionlint` | actionlint over `.github/workflows` (with shellcheck when it is on your PATH) |
| `make vuln` | govulncheck, reachability-aware |
| `make e2e-go` | the Go end-to-end test against the mock BMCs |
| `make e2e-ui` | the Playwright specs with axe accessibility checks (`PW_ARGS="servers.spec.ts"` for one file) |
| `make visual` | the visual comparison inside the pinned Playwright image (Docker) |
| `make zap-quick` | the ZAP passive baseline of the unauthenticated pages (Linux + Docker) |
| `make image` then `make scan` | the distroless image, then Trivy (fails on fixable HIGH/CRITICAL) |
| `make host-test` | the bats tests of the example host fan reader in `deploy/host/` |
| `make fuzz` / `make soak` | the nightly fuzz targets (`FUZZTIME=2m`) and the three-times shuffled race run |

Linters and scanners are pinned in the Makefile and run with `go run`, so nothing is installed
globally. `make lint` uses an installed golangci-lint when there is one; install the pinned
version with the command it prints.

**Visual changes.** If your change moves pixels on a page, the visual comparison fails until the
baseline is updated. Run `make visual-update` (it rewrites the PNGs in `tests/e2e/visual-baseline/`
and compares once more), check the new images, and commit them in the same pull request with
`[visual]` in its title. Only the Linux PNGs from the pinned image are valid; see
[tests/e2e/README.md](tests/e2e/README.md).

## What CI checks

Every pull request runs [ci.yml](.github/workflows/ci.yml) on GitHub-hosted runners; all jobs
must pass:

| Job | Gate |
|---|---|
| `lint` | `make noexec`, `go vet` (also with the `e2e` tag), gofmt, golangci-lint (incl. gosec, forbidigo, depguard), then actionlint with shellcheck over every workflow (the job fails if shellcheck is missing) |
| `test` | `go test -race` with coverage: **80 % on the module total and on each package on its own**, with the security packages required to be present; then the static build. The repository-policy tests run here |
| `vulncheck` | govulncheck (reachability-aware) |
| `e2e` | the Go end-to-end test against the mock BMCs: sign-in, TOTP, the pages, the API, CSRF, sign-out and the feature flows |
| `e2e-ui` | Playwright on Chromium in two parts (the every-page sweep with both themes, and every other spec), with axe WCAG 2.2 AA checks |
| `zap` | the ZAP passive baseline of the unauthenticated pages; any warning not justified in `tests/zap/rules.tsv` fails |
| `visual` | the screenshot comparison against `tests/e2e/visual-baseline/`, blocking |
| `image` | builds the image (after all of the above), checks it runs as non-root with no shell, Trivy fails on fixable HIGH/CRITICAL, and Syft writes the SPDX SBOM |

[nightly.yml](.github/workflows/nightly.yml) adds the slower checks on `main`: the soak (every test
three times in random order with the race detector), the fuzz targets, the authenticated ZAP
baseline plus the API scan of [docs/api/openapi.yaml](docs/api/openapi.yaml), and an advisory
(non-blocking) download-and-verify of Dell's signed firmware catalog. A nightly failure is fixed
before the next release.

The **repository-policy tests** in [`internal/repopolicy`](internal/repopolicy) hold the rules
above in code. Among other things they fail when:

- a workflow uses an action that is not pinned to a full commit SHA, or loses its read-only
  `permissions:` block or `persist-credentials: false`;
- a tool pin has no `# renovate:` line, or the Makefile and `ci.yml` pins disagree;
- a direct Go dependency or a vendored front-end package has no row in
  [docs/tech_doc.md](docs/tech_doc.md) §2 (and, for vendored files, no [NOTICE](NOTICE) entry);
- a route is missing from the OpenAPI document, a fuzz target is not listed, or a ZAP allowlist
  entry has no reason;
- any file carries a private address, a host path, a real-looking MAC address or a home-network
  host name.

## Dependencies and the supply chain

- **Ask first.** A new dependency needs a row in [docs/tech_doc.md](docs/tech_doc.md) §2: its
  purpose, its licence (Apache-2.0 compatible) and why the standard library is not enough. Prefer
  the standard library.
- **The 14-day rule.** A dependency, tool, base image or action version may be adopted only
  when its release is at least **14 days old**, security fixes included. Renovate
  ([renovate.json](renovate.json)) proposes bumps monthly under the same rule and never
  automerges; please do not open pull requests that bump to a newer release.
- **Actions pinned by full SHA.** Every third-party action in `.github/` is referenced by its
  full 40-character commit SHA with the tag in a comment (`uses: owner/action@<sha> # v1.2.3`).
  Workflows keep a read-only top-level `permissions:` block, `persist-credentials: false` on every
  checkout, and no `pull_request_target` or `workflow_run` trigger.
- **Images by digest.** Base and test images are pinned by digest next to their tag.
- **Front-end assets** are vendored unmodified with their SHA-256 in
  `internal/web/ui/vendor.sha256`; no CDN, ever.
- Files under `.github/`, the Makefile, `renovate.json`, `internal/repopolicy` and
  `internal/covergate` have the maintainer as code owner ([CODEOWNERS](.github/CODEOWNERS)).

## Fixtures and test data

- **Mock BMCs only.** Tests and the dev server use `internal/bmc/redfishmock`,
  `internal/bmc/bmcssh/sshtest` and `internal/console/rfbtest`. Never point a test, a fixture
  script or CI at a real BMC, and never add a test that needs one.
- **No real BMC data or addresses in fixtures.** Do not commit responses captured from your own
  BMC as they are. If a fixture from real hardware is needed to reproduce a bug, capture it
  read-only (Redfish GETs with a read-only account) and replace every serial number, service tag,
  MAC address, host name, IP address, licence ID, user name and certificate before committing.
  Synthetic data written by hand is better still.
- **Documentation values:** IPv4 addresses from 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24
  (RFC 5737), IPv6 from 2001:db8::/32 (RFC 3849), MAC addresses 00:00:5E:00:53:xx (RFC 7042) and
  `.example`, `.test` or `.invalid` names (RFC 2606). Hardware model names are fine.
- **No secrets,** not even test ones that look real: tests generate keys and passwords at run time.
- A file that has to contain one of the policed patterns on purpose (a test of the address policy,
  for example) opts out of that one rule with a line naming the rule and a reason:
  `repopolicy:allow <rule> -- <reason of a few words>`. Reviewers will ask why.

## Commits and the DCO

Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), with the
package or area as the scope:

```text
feat(fan): add a lease arbiter
fix(console): close the relay when the BMC drops the socket
docs(deploy): explain the operator account bitmask
```

Every commit must be **signed off** under the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO). There is no CLA. By signing off you certify that you wrote the change, or otherwise have
the right to submit it under the project's licence. The sign-off is one line at the end of the
commit message, with your real name (or the name you are known by) and an email address you can
be reached at:

```text
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it for you from `user.name` and `user.email`. To fix commits that are
missing it:

```bash
git commit --amend --no-edit -s           # the last commit
git rebase --signoff main                 # every commit on your branch
git push --force-with-lease
```

A pull request with a commit that is not signed off will not be merged.

## Pull requests

- One topic per pull request, based on the latest `main`.
- Tests for the change, and `make check` passing locally.
- Documentation updated where behaviour changes: [deploy/README.md](deploy/README.md) for
  anything an operator sees, [docs/tech_doc.md](docs/tech_doc.md) for implementation notes,
  [docs/security.md](docs/security.md) for anything that touches a control.
- A user-facing entry in [CHANGELOG.md](CHANGELOG.md) under **Unreleased** (skip it for
  changes users cannot notice: tests, CI, refactoring).
- The [pull request template](.github/pull_request_template.md) has the checklist.

Pull requests from forks always run on GitHub-hosted runners, and workflow runs for first-time
contributors wait for a maintainer's approval.

## Licence

oob-manager is licensed under the [Apache License 2.0](LICENSE). Contributions are accepted under
the same licence (section 5 of the licence), certified by your DCO sign-off.
