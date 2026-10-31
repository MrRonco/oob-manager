# End-to-end tests (Playwright)

The specs run against the Go dev harness (`bin/e2e.test`: two mock BMCs, a temp install and
the real `serve` command). Nothing here contacts a real BMC.

```bash
make e2e-ui                    # every spec except the visual one, on port 18443
make e2e-ui E2E_PORT=18444     # when 18443 is taken (another run in progress)
make visual                    # the visual comparison, in the pinned container (needs Docker)
make visual-update             # rewrite the baseline, then compare once more
```

## Visual baseline (`visual.spec.ts`)

Plan 04 §3. Each stable page is captured at 1440 × 900 and 390 × 844, in the dark and the
light scheme, and compared with `toHaveScreenshot` against `visual-baseline/<page>-<width>-<scheme>[-2]-linux.png`
(`-2` is a second clip one viewport further down, taken only on pages taller than 1.5
viewports; no full-page images).

**Where it runs.** Only inside the pinned Playwright image
(`mcr.microsoft.com/playwright:v1.63.0-noble`, amd64, by digest: `PW_IMAGE` in the
Makefile). Font rasterising and the system fallback fonts differ between macOS, Windows and
Linux distributions, so a baseline is valid only in the image that made it. The UI and mono
faces are vendored (Inter, JetBrains Mono), so the remaining system-font dependence is the
few glyphs still outside their subsets (the ✓ in steppers; slice B replaced the status
glyphs with the icon sprite), and those come from the image too. Outside
the container the spec skips (`OOB_VISUAL` unset), and `.gitignore` refuses `-darwin` and
`-win32` PNGs. `make visual` cross-compiles the harness for linux/amd64 and runs the spec in
the image with Docker; CI's `visual` job runs the same targets, so local and CI results are
the same pixels. The container sees the repository read-only (only `tests/e2e` is writable),
runs as your user with no capabilities and `no-new-privileges`, and installs the two test
dependencies with `npm ci --ignore-scripts`. `tests/e2e` itself stays writable, so code from
those packages that runs at test time can write there; CI runners are ephemeral, but locally
the changes persist in your checkout. If in doubt, run `make visual` on a fresh checkout.

**Determinism.** Chromium only, `reducedMotion: 'reduce'`, `animations: 'disabled'`,
`caret: 'hide'`, CSS-pixel scale, fixed viewports, fonts awaited. The run first waits until
the mock servers' first security check has finished. Run-dependent regions are masked:
times, the clock, the data-age chips (class `age-chip`; the Events count and filter chips are
compared) and the data-age line, poll durations, the footer (version, page time),
step-up lines, certificate fingerprints of the mock BMCs, the inventory "Probed" time and the
notification delivery table. `visual.css` (injected only while screenshotting) gives those
inline boxes a fixed width and the times tabular digits, so a "1 s" versus "12 s" cannot
move what follows. The contexts set `bypassCSP` for that injection alone; the CSP itself is
covered by `security_test` and the other specs.

**Determinism is unproven inside the container** until the baseline exists: so far only a dry
run on macOS Chromium (outside the image) has shown repeated runs passing. The first manual
`visual_update` run is the first real check (it writes every PNG, then compares once in the same
job); the first ordinary CI run after the baseline is committed is the second, in a fresh
container. The job stays advisory until both have passed.

**Motion.** Every spec runs with `reducedMotion: 'reduce'` (`playwright.config.ts`), so nothing is half-way
through an entrance or a view transition when a spec acts; `motion.spec.ts` turns motion back on to check the
250 ms budget and the view-transition names (tech_doc §43).

**Excluded pages.** Pages whose content the run itself creates (users, user detail and its
confirm pages, API tokens and the revoke confirm, the audit log, enrollment links) and the two
consoles (connection state drawn by script), and `notify-new-pushover`, `notify-new-email` and
`stepup` (form variants of covered pages; step-up also shows a run-dependent freshness window).
They join when their content is deterministic.

**Tolerance.** `maxDiffPixelRatio` 0.2 % by default; the text-heavy pages (Help, About,
Events, logs, Security) allow 0.5 %. The per-pixel pixelmatch `threshold` is 0.02, low enough to
see a tonal change inside one theme (at 0.2 pixelmatch cannot tell Graphite's background from
its border colour); anti-aliased pixels are ignored by pixelmatch itself. A failure leaves
`<name>-expected.png`, `-actual.png` and `-diff.png` in `test-results/`; CI uploads them as
the `visual-diffs` artifact.

**Changing the baseline.** Only in a PR whose title carries `[visual]`, with the before and
after images attached (the `visual-diffs` artifact). A reviewer approves the look; the gate
approves everything else. To regenerate: `make visual-update` with Docker, or without Docker
run the CI workflow by hand (Actions → ci → Run workflow, `visual_update` = true), download the
`visual-baseline` artifact into `tests/e2e/visual-baseline/` and commit it in a `[visual]`
commit; the next ordinary CI run compares against it. A compare run passes
`--update-snapshots=none`, so it never writes a baseline (a missing PNG fails, and its
`-actual.png` is in `visual-diffs`). A feature PR that adds a page adds its baselines the same way.

**Blocking.** Advisory during redesign slice A (`continue-on-error` in CI, the font change
moved every glyph); blocking since slice B (the job fails the workflow).

## README screenshots (`showcase.spec.ts`)

The images in `docs/screenshots/` (the README tour, light and dark, and `social-preview.png`)
come from `showcase.spec.ts`, which runs only with `OOB_SHOWCASE=1`; every other run skips it.
It starts the dev harness with `OOB_DEV_SHOWCASE=1`, which changes fixture text and the fake
consoles only (a real-looking firmware note, a host login prompt on the serial console, the
boot menu in `testdata/showcase/` on the graphical console, neutral "What goes down" lines, and
log entries moved so the newest is a few minutes old), so the e2e specs and the visual baseline
never see it. `make showcase` builds its own harness binary with the latest tag stamped in
(`SHOWCASE_VERSION=vX.Y.Z` to choose another), so the footer shows a release version. Shots are taken in a fixed order, because
the power, fan and maintenance actions it takes change the pages after them; the power
confirmation waits for the 5-minute step-up window to lapse, so a run takes about 6 minutes.
Desktop shots are 1440 × 900 at device scale 1, phone shots 390 × 844 at scale 2. The six
shots shown two to a row (firmware, security, events, activity, palette, settings-servers) are
the main column only, about 1100 × 700 CSS px at scale 2, so they stay readable at half width.

Before each capture the spec checks the text in the viewport for dev artefacts ("e2e", "mock",
loopback addresses, the 3 s test refresh, error pages and so on) and fails if it finds one. The
viewport text of every shot is written to `test-results/showcase-text/` for a final grep.

```bash
brew install pngquant oxipng            # or apt install pngquant + the oxipng release binary
make showcase                           # screenshots, then pngquant (quality 80-95) and oxipng
make showcase SHOWCASE_RAW=1            # without the optimisers: a local look only, never commit
```

To update the committed images, run the **showcase** workflow (Actions › showcase › Run
workflow). It installs the tools, runs `make showcase`, checks with exiftool that no PNG carries
metadata, and uploads the `screenshots` artifact: review every image, then commit it to
`docs/screenshots/`. After changing `testdata/showcase/boot-menu.html`, re-render its PNG with
`node showcase/render-frame.mjs` from this directory. The social preview's source is
`showcase/social.html`; upload `social-preview.png` in the repository settings (see
`docs/maintainers/repo-settings.md`).
