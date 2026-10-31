# Plan 04 — Implementing the round-2 design (approach)

Status 2026-10-23: **direction decided** (A, Quiet signal, with C's recorder and B's incident
mode; §11, §15); **slice A implemented** (tech_doc §35); **slice B implemented** (tech_doc §40: components
1–7, colour anchors, icon sprite, favicons); **slice C implemented** on `redesign-slice-c` (tech_doc §41:
components 8–10, Overview hero with incident mode and the flight recorder, Security posture map, and the IA
step of §11 items 8–9 as one commit, 2026-10-28); **slice D implemented** (tech_doc §43, 2026-10-29: motion,
view transitions, console frames). The **command palette** (item 7), deferred out of slice D, is **implemented** on `command-palette` (tech_doc §52, 2026-10-30): `palette.js`, the `/go` page and the
shortcuts.

Original status: plan, 2026-10-21. No code. The round-2 UX audit is **not finished**; this plan fixes
the *method* so that, once a direction is chosen, the implementation can run in short,
deployable slices with an objective gate at every step. Inputs: `docs/design/direction-b.md`
(what exists), `docs/reviews/2026-10-21-ux-audit.md` (brief and acceptance criteria),
tech_doc §13/§19/§24 (templates, CSP, themes, preferences), `tests/e2e/pages.spec.ts`
(the axe matrix), CLAUDE.md rules 5, 10 and 12.

## 1. Goal and non-goals

**Goal.** Move the UI from direction B to the round-2 design without breaking the three
properties the app is built on: strict CSP (no inline script or style), everything works
without JavaScript, WCAG 2.2 AA with zero axe violations in both schemes at 1440 and 390 px.
Every slice is deployable on its own and reversible by `git revert`.

**Non-goals.** A SPA, a CSS framework or build step (Tailwind, PostCSS, Sass), web fonts
from a CDN (NFR-6), client-side routing, skeleton screens, redesigning the console pages'
third-party widgets (noVNC canvas, xterm.js) beyond their frame, i18n.

## 2. What exists (the migration starts from here)

- Tokens: `app.css` `:root` hex values (`--bg`, `--surface`, `--surface-2`, `--border`,
  `--field-border`, `--text`, `--muted`, `--accent`/`--on-accent`, `--focus`, `--ok/--warn/
  --crit/--info/--stale-fg` + `-bg`, `--danger`/`--on-danger`, `--bar-h`), dark default,
  light via `prefers-color-scheme` and `[data-theme]`; six palettes in `themes.css`, each
  written three times (media query, `data-theme`, preview selectors); contrast pairs are
  checked numerically by `TestThemeContrast` (hex only) and `TestGraphiteMatchesBaseTokens`.
- Components (direction-b.md §3): badge, chip, headroom meter (width classes `.w0–.w90`,
  ticks `.t0–.t90`, because CSP forbids `style=`), strip, panel, data table with the stacked
  phone variant (`data-label`), dense list / feed, action bar, confirm page, step-up line,
  form field, secret reveal, stepper, pager/filters, in-template icon set (~17 SVG paths
  emitted inline per use), lock badge, swatches, maintenance badge.
- Shell: sticky top bar (brand, instance, fleet pill, clock, user menu), 15 rem sidebar,
  phone Menu sheet (`<details>`), footer. 38 templates, `app.css` 529 lines, `themes.css`
  174, `app.js` 65 (optional: Escape/outside click, Copy, role button).
- Gates: `pages.spec.ts` (≈ 40 pages × 2 widths × 2 schemes: axe, one h1, no horizontal
  scroll; the 5-second test at 390×844), `themes.spec.ts` (every palette, JS disabled),
  feature specs, `copy_test` (US English), `security_test` (no `<script`/`style=`/handlers
  in pages), `theme_contrast_test`, `vendor_test` (SHA-256 of vendored files). Screenshots
  are produced on demand (`OOB_SCREENSHOTS=1`) but **not compared**.

## 3. Step 0 — freeze a visual baseline before touching anything

A redesign without a visual diff is reviewed by eye on 160 screenshots. Add Playwright
`toHaveScreenshot` to a new spec `visual.spec.ts` (separate CI job `visual`, same dev
server), **before** the first token change, and commit the baselines.

- **Determinism**: Chromium only (pinned by `@playwright/test` 1.63.0), Linux only
  (baselines generated in CI's Ubuntu image via `--update-snapshots`, never on macOS: font
  rasterising differs; the Makefile target `visual-update` refuses to run outside Linux and
  prints how to update through a CI workflow dispatch). Fonts: system stacks differ per OS,
  so baselines are only meaningful once the vendored fonts (§6) ship — hence slice A ships
  fonts **first** and the baseline is frozen right after it. `animations: 'disabled'`,
  `caret: 'hide'`, `reducedMotion: 'reduce'`, fixed viewport sizes, `colorScheme` per run.
- **Masking**: dynamic regions (`.clock`, `.dataage`, `time`, the footer version, the
  "generated" line, countdowns, charts if plan 02 lands first) are masked with `mask:`
  selectors declared once in the spec; the harness clock is wall time, so masking beats
  faking.
- **Tolerance policy** (documented in `tests/e2e/README.md`): `maxDiffPixelRatio: 0.002`
  (0.2 %) and `threshold: 0.2` per page by default; pages with large text areas (Help,
  About, Events) get 0.005. A failure prints the diff image as a CI artifact. Baselines
  change only in a PR whose title carries `[visual]`, with the before/after grid attached
  (the job uploads `*-diff.png` and `*-actual.png`); a reviewer approves the look, the gate
  approves everything else.
- **Scope**: the same page list as `pages.spec.ts` at 1440 and 390, dark and light
  (≈ 160 images, ~10 MB of PNG in git; acceptable once; use `-fullPage: false` for the
  long pages and a second clip at the fold).
- **Blocking**: advisory for slice A (the font change moves every glyph), blocking from
  slice B on.

Effort: 0.5 d. This step is useful even if the redesign is postponed: it also protects
plans 01–03 and 05 against accidental layout breakage.

**As implemented (2026-10-22, tech_doc §35):** instead of "Linux only, CI's Ubuntu runner",
the spec runs only inside the **pinned Playwright image** (by digest), locally through
`make visual` with Docker and in CI's `visual` job, so local and CI produce the same pixels
and a runner image update cannot rot the baseline. Masked regions also get a fixed width
(`tests/e2e/visual.css`), because a masked "1 s" versus "12 s" still moves what follows.
Pages whose content the run creates (users, tokens, audit log, setup links) and the two
consoles are left out for now. A compare run never writes a baseline (`--update-snapshots=none`).
Determinism inside the container is proven only by the first `visual_update` run (write, then
compare in the same job) and the next ordinary run against the committed PNGs. Policy:
`tests/e2e/README.md`.

## 4. Step 1 — tokens-first migration (OKLCH primitives, derived semantics)

- New `static/tokens.css`, loaded before `app.css`: **primitive** tokens in OKLCH
  (`--p-gray-05: oklch(12% 0.01 240)` … `--p-cyan-70`, `--p-green-60`, `--p-amber-70`,
  `--p-red-60`, `--p-blue-60`), then **semantic** tokens with the names that already exist
  (`--bg: var(--p-gray-05)`, `--text: var(--p-gray-95)`, `--ok: var(--p-green-60)` …), plus
  the new ones the audit brief asks for: spacing scale `--sp-1…--sp-8` (4 px base), radii
  `--r-1/--r-2`, elevation `--elev-1/--elev-2` (border + shadow pairs; no blur-heavy
  shadows), `--font-ui`, `--font-mono`, `--fs-0…--fs-5` (fluid `clamp()`), `--lh-tight/
  --lh-body`, `--dur-1: 120ms`, `--dur-2: 200ms`, `--ease: cubic-bezier(.2,.7,.2,1)`.
- The six palettes become **primitive overrides only** (each palette redefines the
  `--p-*` ramp it changes; the semantic layer is written once). The light mode is a
  primitive flip too. This removes the triple duplication in `themes.css` and makes the
  per-palette file a dozen lines. Mode (dark/light) and palette stay separate
  (`data-theme`, `data-palette`), with the same server-rendered attributes and cookie.
- Browser support: OKLCH is in every evergreen browser since 2023 (Chromium 111, Safari
  15.4, Firefox 113). The app targets evergreen browsers on a LAN; no fallback hex layer
  (it would double the file and defeat the point). `forced-colors` rules are unaffected.
  **As implemented (slice A):** the palettes use `light-dark()`, which raises the floor to
  **Chromium 123, Safari 17.5, Firefox 120**. Below it, one `@supports not (color:
  light-dark(#000, #fff))` block gives every semantic name its plain Graphite dark value, so
  older browsers lose the palette and mode choice but keep a readable page (tech_doc §35).
- **`TestThemeContrast` must learn OKLCH**: implement OKLCH → OKLab → linear sRGB → sRGB in
  the test (≈ 60 lines, Björn Ottosson's matrices), clamp detection (an out-of-gamut
  colour fails the test rather than being silently clipped by the browser), and resolve
  `var()` chains through the primitive layer. `TestGraphiteMatchesBaseTokens` becomes
  "Graphite resolves to the documented hex values within ΔE 1" during the transition and
  is then deleted (the documented values move to OKLCH in direction-b.md's successor).
- Keep every existing semantic **name** in this step so templates and `app.css` rules do
  not change; only values move. Visual diff expected: near zero (ΔE-tuned conversion of
  the current hex), which is what the baseline from step 0 verifies.
- Rule: no `color-mix()`/relative colour syntax in the semantic layer (harder to verify in
  the Go test); allowed inside primitives if the test evaluates them — prefer explicit
  values.

## 5. Step 2 — component inventory and rewrite order

The rewrite goes component by component, one PR each, lowest risk first; each PR passes
axe, the visual diff (baseline updated in that PR only for the pages the component
touches), `TestThemeContrast`, `security_test`, `copy_test`. A component PR may not change
templates' *content* or routes, only markup structure and CSS.

| Order | Component (direction B class / partial) | Why here | Risk |
|---|---|---|---|
| 1 | Base typography, links, focus ring, `.sr-only`, `.skip` | everything inherits | low (visual diff large but mechanical) |
| 2 | Badge / chip / tag / maintenance badge (`health`, `chip`) | used on every page, pure CSS | low |
| 3 | Buttons (`.btn*`), action bar (`actionbar`), `why-off` | hit areas, states (disabled-with-reason) | low |
| 4 | Form field, radio cards, filters, `.field.inline`, secret reveal, codeblock | contrast rules (UX-20) and errors | medium (axe sensitive) |
| 5 | Panel, grids (`.g2/.g3/.ov`), strip/strip-line, alerts | layout at 3 breakpoints | medium |
| 6 | Data table + stacked phone rows (`table.stack`, `.tw`), headroom meter cells | the hardest CSS; most pages | high |
| 7 | Lists: dense, feed, kv, notes, acks | content-heavy pages | medium |
| 8 | Shell: top bar, sidebar, phone sheet, footer, breadcrumbs, tabs | navigation and the 5-second test | high |
| 9 | Pager, stepper, stepup line, lock badge, swatches | settings pages | low |
| 10 | Confirm page, step-up page, sign-in/enrollment panels | dangerous-action patterns (C-11/C-12) | medium (security review re-read) |
| 11 | Console and serial frames (`console.css`, `serial.css`) only | vendor constraints; last | medium |

The order also matches the audit's component inventory (C-01 … C-20); the brief's new
components (C-04 stat tile, C-05 server card if it returns, C-20 empty-state block) are
added where the chosen direction needs them.

## 6. Typography vendoring

- **As implemented (slice A):** Inter + JetBrains Mono, **Latin and Latin-1 only** (no
  latin-ext): the UI is US English, and a character outside the subset in user-typed text is
  drawn by the metric-matched fallback. Provenance and the byte-identical rebuild script are in
  tech_doc §35; new bytes need a new versioned directory.
- Decision inputs from the audit: one UI family and one mono family (candidates with an
  OFL-1.1 licence and a variable build; the audit picks). Variable fonts only (one file
  per family, `wght` axis; italics as a second file only if the design uses them).
- Files: WOFF2, subset to `latin` + `latin-ext` (+ the glyphs the UI uses: `✓ ▲ ✕ ◆ ? ◷ ‖ ×
  °`; otherwise those come from the system fallback and look different per OS). Budget:
  **≤ 120 KB per family, ≤ 250 KB total**, enforced by a test on the vendored sizes.
- Location: `internal/web/ui/static/vendor/fonts/<family>-<version>/` with the licence
  file, SHA-256 in `vendor.sha256` (existing re-verifying test), entry in `NOTICE` (OFL
  text and reserved font name rule), a row in tech_doc §2 ("vendored, not a Go module").
- CSS: `@font-face` in `tokens.css` with `font-display: swap`, `size-adjust`/
  `ascent-override`/`descent-override` metrics on the local fallback (system-ui) to limit
  reflow; `<link rel="preload" as="font" type="font/woff2" crossorigin>` for the two
  files in `layout.html`; served with the existing 1 h cache and `?v=` versioning (fonts
  can move to `Cache-Control: public, max-age=31536000, immutable` under the versioned
  URL). CSP `font-src 'self'` already allows it. The sign-in page loads fonts too (no
  version fingerprint in the font URL on signed-out pages: use a content hash instead of
  the build version there, as `?v=` is hidden before sign-in today).
- The console pages keep their own mono stack for xterm.js unless the chosen mono family
  has the box-drawing and powerline coverage xterm needs (test: render the glyph set).

## 7. Motion, view transitions, icons, optional JS

- **CSS-only motion**, opt-in: replace today's "disable everything under
  `prefers-reduced-motion: reduce`" with motion declared only inside
  `@media (prefers-reduced-motion: no-preference)`; durations from `--dur-*`; allowed:
  hover/focus colour fades, `<details>` panel reveal, sheet slide-in; forbidden: anything
  on status changes (no pulsing alerts, 2.3.1/2.3.3), autoplay loops, parallax. The
  Playwright runs set `reducedMotion: 'reduce'` so screenshots stay deterministic; one
  extra test asserts that with `no-preference` no element has an animation longer than
  400 ms.
- **Cross-document view transitions**: `@view-transition { navigation: auto; }` in
  `tokens.css` with `view-transition-name` on the top bar, sidebar and main column, inside
  the no-preference media query. Pure CSS, same-origin navigations only, ignored by
  browsers without support (Chromium 126+, Safari 18.2+), no JavaScript, no CSP impact.
  Form POST → 303 → GET flows transition too. Known caveat: a long server render shows the
  old page until the new one arrives (there is no skeleton, by design).
- **Icon sprite**: today each `icon` use inlines the full SVG path. Switch to one
  in-document sprite: `layout.html` emits `<svg class="sprite" aria-hidden="true">` with
  `<symbol id="i-power" viewBox="0 0 24 24">…</symbol>` once, and the `icon` partial emits
  `<svg class="ic"><use href="#i-power"/></svg>`. Same-document `<use>` needs no fetch and
  raises no CSP question (an external sprite file would be fetched under rules that vary
  by browser, so it is not used). A template test asserts every `use href` resolves to a
  symbol and that every page includes the sprite. Icons stay 24-grid, 1.8 stroke,
  `currentColor`.
- **Optional progressive JS behind the no-JS rule**: one additional `'self'` script,
  `palette.js`, loaded with `defer`: a command palette (Ctrl+K or `/` outside inputs) that
  filters the links already present in the sidebar (nav, servers, settings tabs) and
  recent pages (`sessionStorage`, try/catch), `role="dialog"` + `aria-modal`, focus trap,
  Escape closes, arrow keys, Enter navigates. It never submits a form and never exposes
  an action that is not a plain GET link. Without the script nothing is missing (the
  sidebar is the palette). CSP unchanged. axe scans the open palette; the keyboard-only
  test covers it. Removable by deleting one `<script>` line.

## 8. IA changes as a separate, reversible step

Nav model changes the audit may propose (Operations folded into an actions sheet or split
button on the server head; Settings tab order; where History/Firmware/Integrations
appear; the phone sheet contents) are **one slice, one commit**, touching templates and
routes only:

- Old GET paths keep working with 301s to the new ones (`/servers/{id}/operations` →
  `/servers/{id}#actions`, for example); POST routes do not move (forms, CSRF bindings
  and tests stay valid).
- `pages.spec.ts` page list, the sidenav partial, `servertabs`, `settingstabs` and the
  Help page change together; `TestMatrixCoversEveryAction` is untouched (authz is
  route-independent).
- Reversal is `git revert` of that commit; nothing in the DB or config refers to paths.

## 9. Page-by-page migration gates

For each page group (Overview; Server Hardware; Logs/Events; Inventory/Firmware/History;
Operations/Confirm/Step-up; Settings; Sign-in/Enrollment; Help/About/Errors; Console/Serial):

1. Component PRs (step 2) already restyled its parts; this PR changes the page's
   structure to the mockup.
2. Gate: `make e2e` (Go + all Playwright specs incl. axe at 1440/390 × dark/light and
   `themes.spec.ts` for every palette), `visual.spec.ts` with updated baselines for that
   page only, the 5-second-test assertions (verdict, worst item, data age above the fold
   at 390×844 on Overview and Server), `expectNoHorizontalScroll` at 320 px added for
   Overview, Server and Logs (audit §7), `copy_test`, `security_test`,
   `TestThemeContrast`, Go view-model tests (no behaviour change allowed).
3. A manual check on the two remaining things automation misses: a screen-reader pass
   (VoiceOver + Safari, NVDA + Firefox) on the changed page, and forced-colors mode.

## 10. Rollout slices (each deployable)

| Slice | Content | Days | Visual gate |
|---|---|---|---|
| **A** | Fonts vendored, `tokens.css` with OKLCH primitives mapped to today's values, palettes rewritten as primitive overrides, `TestThemeContrast` OKLCH support, step-0 baseline frozen **after** this slice | 1.5 | advisory |
| **B** | Components 1–7 (typography → lists), icon sprite | 2.0 | blocking |
| **C** | Components 8–10 (shell, settings bits, confirm/step-up/sign-in) and the page-by-page structure changes of the chosen mockups | 2.0 | blocking |
| **D** | Motion + view transitions, console frames (IA step done in C; **command palette deferred to a later minor**) | 1.0–1.5 | blocking |
| **Total** | | **6.5–7** (+0.5 for step 0) | |

Slice A can ship before the audit concludes (it changes nothing visible except the font).
B–D wait for the direction decision. Plans 01–03 and 05 add templates; land them before
B/C or rebase them onto the new components — the README's sequencing recommends features
first, then the redesign.

## 11. Decision checklist

**Direction:** direction A, *Quiet signal*, is the product (round-2
mockup package `PACKAGE.md`, `a-quiet-signal/`). Two pieces are borrowed: C's shared-axis
24-hour **flight recorder** becomes the desktop fleet view on Overview (and the shape of the
History tab, plan 02), and B's **incident mode** for the hero (the display numeral and one
restrained glow, only while something is critical). Slice A is foundations only; the
borrowed pieces arrive in slices C and D.

| # | Decision | Default if undecided | Chosen | Slice |
|---|---|---|---|---|
| 1 | UI font family, mono family, licence confirmed OFL | keep system stacks | **Inter + JetBrains Mono**, SIL OFL 1.1, vendored woff2 from the mockup package (`mockups/fonts`), OFL texts, NOTICE, tech_doc §2 row. **Atkinson Hyperlegible** stays a candidate for an optional per-user typeface preference **later** (not in slice A) | A (fonts); preference later |
| 2 | OKLCH ramps: anchor hues, neutral tint | convert today's hex, no hue change | Slice A converts today's hex exactly (the only visible change is the font). **Target anchors for slice B:** accent cyan-teal **H 198** (A's); status hues **OK 158, warning 78, critical 24, info 245, stale 98**; a slate **off** tone (powered off); the accent stays **≥ 40°** from every status hue | A (as-is), B (anchors) |
| 3 | Keep six palettes, or reduce | keep six | **Keep all six** (Graphite, High contrast, Solarized, Nord, Dracula, Color-blind safe), both modes; **Graphite is the default** | A |
| 4 | Density defaults unchanged? | unchanged | **Unchanged** | — |
| 5 | Motion | fades only | Budget **≤ 250 ms, ease-out**, nothing on alarms or status changes, **all off under reduced motion**; keep **menu entrances** and the **value-change tint** | D |
| 6 | Cross-document view transitions | on (no-preference only) | **On, no-preference only**, with the **server header morph** and the **tab ink** slide | D |
| 7 | Command palette | off | **On**, with the **`/go` page fallback**; shortcuts **`g o`** (Overview), **`g s`** (Servers), **`/`** (filters), **`?`** (help) | later minor: **done** 2026-10-30 (tech_doc §52) |
| 8 | IA changes | none | **Retire Operations**; persistent server header **Console ▾ · Power ▾ · More ▾**; stable tab set **Overview · Sensors · History · Events · Activity · Inventory · Security**; **Firmware** as a sidebar item; **Restart BMC** under Power ▾; **Settings → Integrations** between Notifications and Audit log; a global **Activity** page visible to viewers for **actions only** (never IPs, sign-ins or settings changes); power-off rules as already implemented | C / D |
| 9 | Phone navigation | sheet stays | **Menu sheet stays**; a **sticky bottom action bar** (Console · Power · More) on server pages; the fleet pill shows the **short worst word** | C |
| 10 | Icon style and sprite | 1.8 / 24, sprite | **Lucide** (ISC) as one inline sprite of about **40 icons**, stroke **1.8 on 24**, every icon **beside a visible label**; the side-channel mark and **five status favicons** | B |
| 11 | Brand mark and logo colour | current | The **side-channel mark** (with item 10) | B |
| 12 | Visual tolerance | 0.2 % / 0.5 % | **0.2 %** of pixels by default, **0.5 %** on text-heavy pages; per-pixel pixelmatch `threshold` **0.02** (code review: 0.2 cannot see a tonal change inside a theme) | A |
| 13 | Redesigned vs restyled page groups | consoles restyled only | **Consoles restyled only** | D |
| 14 | Accessibility statement and screen-reader pass | before P8 | **Screen-reader pass before P8, by the maintainer** | before P8 |

**Item 7 deferred:** the command palette, its `/go` fallback and the `g o` / `g s` / `/` / `?`
shortcuts are **not** in slice D; they move to a later minor. The §7 design for `palette.js` stands for when it
is built. Slice D ships items 5, 6 and 13 (tech_doc §43).

**Item 7 done (2026-10-30, tech_doc §52):** `palette.js` as designed in §7 (one deferred `'self'` script, CSP
unchanged, `role="dialog"` + `aria-modal`, focus trap, Escape restores focus, arrows, Enter navigates, never a form),
reading the destination list the server renders for the user, the server page's tabs and a capped `sessionStorage`
recent list; the `/go` page with a GET filter and the shortcut table. Decisions: **`/`** focuses the page's filter
field where there is one and opens the palette elsewhere; **`?`** goes to `/go#shortcuts` (a page, not an overlay);
no shortcut fires in a field or anywhere on a page with a **connected console**; the single-key shortcuts can be
switched off per browser (WCAG 2.1.4).

Security tab details (from the mockup checklist, item 8 there): **viewers see the summary
only**; passes and infos fold into **"N more checks" per group**; the **posture map** is
shown (it doubles as the group jump list). Slice C.

## 12. Tests (summary of new or changed gates)

`visual.spec.ts` + baselines; `TestThemeContrast` OKLCH + gamut; font size budget test;
`vendor.sha256` entries; sprite resolution test; `security_test` extended to `tokens.css`
and the sprite (no `style=`); 320 px overflow assertions on three pages; animation-duration
test; palette keyboard test (`palette.spec.ts`, done: tech_doc §52); `copy_test` unchanged; every existing feature spec.

## 13. Docs to update

`docs/design/round-2.md` (successor of direction-b.md: tokens with contrast ratios in
OKLCH and the hex they resolve to, components, patterns, deviations), tech_doc §2 (fonts
row), NOTICE (font licences), `tests/e2e/README.md` (baseline policy), Help › Accessibility
statement, security.md §6 (vendored fonts under the hash check), CLAUDE.md "Commands"
(`make visual`, `make visual-update` CI-only).

## 14. Risks

- Baselines rot when features land (plans 01–03, 05 add pages): each feature PR adds its
  own baselines; the policy makes that a normal step, not a fight.
- OKLCH conversion drifts contrast slightly; the Go test catches any pair below the
  thresholds before merge.
- Vendored fonts add ≈ 250 KB to the image (NFR-4 budget 30 MB: fine) and to each cold
  page load on a slow remote link (cached after the first).
- View transitions may surprise users who prefer instant pages; they follow the OS motion
  preference and can be removed by one CSS block.
- A command palette is the one JS surface with input handling; it only navigates to links
  already on the page.

## 15. Resolved questions

1. ~~Ship slice A (fonts + token refactor) now, before the audit finishes?~~ **Yes.** The
   direction was chosen the same day (§11); slice A is on branch `redesign-slice-a`
   (tech_doc §35).
2. ~~Fill the decision checklist (§11) when the round-2 direction is picked.~~ **Done**: §11.
   Item 7 (command palette **on**) and item 8 (the IA list) add to the slice D estimate as
   foreseen; the History tab and Firmware placement depend on plans 02 and 03 landing.
3. ~~Who does the screen-reader pass?~~ **The maintainer**, before P8.

~~Still open for slice B~~ **Answered in slice B (tech_doc §40):** the ramps are generated by
`tools/themegen` (a Go port of `palettes.mjs`) from the §11 anchors and pass `TestThemeContrast` in all six
palettes and both modes; `docs/design/round-2.md` replaces `direction-b.md` for tokens and components now,
and for the shell when slice C lands.
