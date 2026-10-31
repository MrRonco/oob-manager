# UI design direction B ("Ops / NOC")

> **Superseded entirely** by `round-2.md`: tokens and components in redesign slice B (2026-10-23), the
> shell and page layouts in slice C (2026-10-28). Kept only as the historical record of v0.7, because
> plan 04, the round-2 UX audit and tech_doc cite it. Nothing below describes the live UI.

Status: implemented on branch `redesign-b` (2026-10-21). Chosen by the maintainer over the
recommended direction A because it is the most useful and best looking. Source mockups:
`design/mockups/b-ops/` and `design/mockups/PACKAGE.md` in the design worktree; audit:
`docs/reviews/2026-10-21-ux-audit.md` (with the implementation status of every finding).
Screenshots are not committed. To generate the
full set (25 pages x 2 widths x 2 schemes, 100 files): `make e2e-bin`, then
`cd tests/e2e && OOB_SCREENSHOTS=1 OOB_E2E_PORT=18443 npx playwright test pages.spec.ts`.

**Concept.** A tool people stare at. A permanent sidebar lists the servers with a status
glyph and one number, a sticky top bar holds the fleet verdict pill and a clock with the
data age, and the Overview leads with a severity-first fleet table beside Needs attention
and a 24 h event feed. Tables are 36 px rows on desktop and labelled stacked rows on
phones. Numbers are monospace.

## 1. Tokens (`internal/web/ui/static/app.css`, `:root`)

Taken unchanged from the mockup; every pair is in PACKAGE.md §2 with its ratio.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` / `--surface` / `--surface-2` | `#0a0d10` / `#11161b` / `#181e25` | `#eaeef2` / `#ffffff` / `#f0f3f6` | page, panels, insets and field fill |
| `--border` | `#263039` | `#cfd7df` | panel and row rules (decorative) |
| `--field-border` | `#7f8c99` (5.30:1 on card) | `#5f6b78` (5.44:1) | inputs, chips, meters: ≥ 3:1 on card, fill and page (UX-20) |
| `--text` / `--muted` | `#dfe5ea` / `#9ba7b3` | `#12181e` / `#44505c` | body 14.3:1 / 7.4:1 on card |
| `--accent` / `--on-accent` | `#4fd0e0` / `#04161a` | `#00677a` / `#ffffff` | links, primary button (10.1:1 / 6.5:1) |
| `--focus` | `#ffffff` | `#000000` | 3 px focus ring + 6 px halo; never the warning colour |
| `--ok`, `--warn`, `--crit`, `--info`, `--stale-fg` (+ `-bg`) | see CSS | see CSS | badges, row gutters, meter fills (all ≥ 4.5:1 text, ≥ 3:1 fill) |
| `--danger` / `--on-danger` | `#ff6b6b` / `#1a0505` | `#a8160e` / `#ffffff` | destructive button (7.1:1 / 7.5:1) |

**Color themes (palettes, S2).** Mode (dark/light) and palette are separate. `static/themes.css`
defines Graphite (these tokens), High contrast, Solarized, Nord, Dracula and Color-blind safe, each in
both modes, selected by the server-rendered `<html data-palette>` (user preference, else `ui.theme`).
Every pair is checked numerically by `TestThemeContrast` (tech_doc §24). Table density is
`<html data-density="compact|comfortable">`.

**Themes.** Dark is the default. Without a preference the page follows the OS
(`prefers-color-scheme`); `<html data-theme="dark|light">` overrides it. The preference
is a per-browser cookie (`__Host-oob_theme`), set by a server-rendered POST form in the
user menu and the phone Menu sheet ("Theme: Auto → Dark → Light"), so it works without
JavaScript and applies on the sign-in page too.

## 2. Shell

- **Top bar** (`.bar`, sticky, 48 px): brand, instance name (`ui.instance_name`), fleet
  pill (`.gpill`: "1 warning · 1 stale", "All 3 OK"; links to Overview), clock
  (generation time + age of the oldest current data), user menu (`<details>`: theme,
  Help, Sign out). On phones (≤ 51.25 rem) the clock, instance and user menu hide and a
  Menu sheet holds the navigation, the server list, the user, the theme and Sign out.
- **Sidebar** (`.side`, 15 rem, sticky): Overview, Events (count of warning/critical
  events in 24 h), Servers, Settings (admin), Help, About; then every server with a status
  glyph (`.sdot`) and its hottest temperature, or its data age when stale.
- **Main column**: breadcrumb, page head (`.ph`: h1 + tools), content, footer (version
  and commit, Help, About and licenses, Accessibility statement, Report a problem,
  generation time).
- **Signed-out pages** use the same bar with a Help link and no sidebar (`.app.plain`).

## 3. Components

| Component | Class / partial | Notes |
|---|---|---|
| Status badge (C-01) | `.badge.b-ok|warn|crit|info|unknown|stale`, partial `health` | glyph (✓ ▲ ✕ ◆ ? ◷) + word; stale is dashed |
| Age chip (C-02) | `.chip`, `.chip-aging`, `.chip-stale`, partial `chip` | Live (< half the stale threshold), Aging, Stale, No data; absolute time in `title` |
| Headroom meter (C-03) | `.hm`, `.hm-fill.f-*.wNN`, `.hm-tick.tNN`, partials `meterbar`, `mcell` | critical at ~91 % of the bar; text equivalent; widths are classes (CSP) |
| Summary strip / line | `.strip`, `.strip-line` | the line replaces the strip on a healthy fleet |
| Panel | `.panel`, `.p-warn|crit|stale|ok|danger`, `.flush` | 4 px radius, 5 px severity edge |
| Data table (C-06) | `table.stack` inside `.tw[role=region][tabindex=0]` | 36 px rows, sticky header; `data-label` on every cell for the stacked phone layout; row gutters `.r-warn|crit|stale`, `.ev-*` |
| Needs attention / feed (C-09) | `.dense`, `.feed` | badge + server + sentence + jump link |
| Action bar (C-10) | partial `actionbar` | disabled actions: `aria-disabled` + visible reason (`.why-off`) |
| Confirm (C-11) | `confirm.html` | two columns: consequences (danger panel), form (typed name, step-up, Cancel default focus, named button) |
| Step-up (C-12) | `.stepup-line`, `.stepup` | one line when fresh; otherwise the code block names the action |
| Form field (C-15) | `.field`, `.radio` | label above, hint below, `aria-describedby`, error ties `aria-invalid` |
| Secret reveal (C-16) | `.secret`, `[data-copy]`, `.codeblock` | Copy appears only with JavaScript |
| Stepper (C-18) | `.stepper`, `.steps` | enrollment 1-2-3, first-run checklist |
| Pager / filters (C-19) | `.pager`, `.filters` | GET forms |
| Icons | partial `icon` | one inline SVG set, 24 px grid, 1.8 stroke, `aria-hidden` |

## 4. Patterns

- **Anomaly first.** Lists sort problems first (fleet rows: critical, warning, stale,
  unknown, OK; sensors: at critical, at warning, close to warning, rest). The server
  page opens with a verdict sentence and its exceptions.
- **Destructive actions** are a GET confirm page on the action's path and a POST that
  enforces confirm, typed name and step-up (tech_doc §19).
- **Stacked rows on phones**: every table, including logs and events (UX-09).
- **No JavaScript needed**: menus and sheets are `<details>`, filters are GET forms, theme
  and refresh are POST forms. `static/app.js` only adds Escape/outside-click closing,
  Copy buttons and the "disabled until changed" role button.
- **Strict CSP unchanged**: no inline script or style, no nonces used by templates.

## 5. Pages the mockups did not draw

| Page | How B was extended |
|---|---|
| Logs (server) | server head + tabs + SEL/Lifecycle tabs; stacked table with severity gutter, Info badge, folded repeats |
| Inventory | System and Capabilities panels side by side, License, firmware table (grouped, legend) |
| Operations | placeholder tab: Power with Safe and Forced groups, Fan lease (state None, owner host curve), Serial console; all disabled with reasons |
| Servers | the fleet table on its own page |
| Help | two columns of prose panels (setup, glossary, keyboard, accessibility statement, report a problem, hardware) |
| About | build panel with a copyable build-info block, license and support links, modules table |
| Settings: tokens, audit, user detail, reveal | B's settings tabs, step-up line, `g2` split (list left, form right); audit rows as sentences |
| Sign-in flow | login is B's two-column page; code, enrollment and step-up are a centred 28 rem panel |
| Error pages | centred panel, status as an eyebrow, onward buttons, configured servers with health |
| Console | B's slim toolbar + session side panel around the real noVNC canvas (black) |

## 6. Deviations from the mockup, and why

| Mockup | Implementation | Why |
|---|---|---|
| "Power…" opens a forced power confirm | "Power…" links to the Operations tab, where each action opens its own confirm page (P2); Fans stay disabled with "not in this version" | one confirm page per action keeps the typed-name and step-up rules per action; fan leases (P3) do not exist yet |
| CRIT tag and "what goes down" list | tag from config `tags: [critical]`; "What goes down" from the optional per-server `power.impact` list (P2) | the list is plain config text, not derived from other systems |
| Serial console link, release chord | serial console marked "planned"; the chord (Ctrl+Alt+Shift) is implemented in `console.js` | no serial console in this version |
| Events filters show Log/Severity/Range/Search | all implemented, plus Server; counts are links | the per-server filter replaces the old "F-07" deferral |
| Fleet table everywhere | no cards view any more (`?view=` is ignored) | B is table-first; it scales to 30 servers |
| Settings nav as tabs with General/Servers "(coming)" | General is a live tab (S2); Servers stays plain text | Servers is S3 |
| Version on the sign-in page | not shown | the build must not be fingerprinted before sign-in (earlier decision) |
| Time zone "EDT" labels | the viewer's zone with its abbreviation (app default `ui.time_zone`, per-user override) | S2 (tech_doc §24) |
| Healthy overview hides Needs attention | same; the strip line states the 24 h event scope | as drawn |
| Attention list after the table in DOM (reordered on phones) | attention comes first in DOM; the grid places it right of the table on desktop | PACKAGE.md flagged the reorder as a 2.4.3 risk |
| Badge text never wraps | badges wrap in h1 and stacked tables | long statuses ("Enrollment pending (link valid until …)") would scroll the page at 390 px |

## 7. Verification

- Go: view-model tests (meters, sorting, power-good split, chips, times, audit sentences,
  event folding and filters), handler tests for every page, confirm and step-up rules.
- Playwright (`make e2e`): `pages.spec.ts` runs axe (WCAG 2.2 AA + best-practice) on 25
  pages and states at 1440x900 and 390x844 in both schemes (100 scans, 0 violations), checks
  one h1 and no horizontal scroll; asserts the server verdict, data age and fleet pill are in
  the first 390x844 viewport; the theme switch works without JavaScript.
  `OOB_SCREENSHOTS=1 npx playwright test pages.spec.ts` (with the e2e binary built)
  writes every screenshot to `tests/e2e/test-results/screenshots/` (not committed).
- Not covered by the dev harness: a stale or never-polled server page and an empty fleet
  (first-run) are covered by Go tests only; a real screen-reader pass is still needed.
