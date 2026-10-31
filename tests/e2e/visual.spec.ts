// Visual baseline (plan 04 §3, tests/e2e/README.md): every stable page at 1440x900 and
// 390x844, dark and light, compared with toHaveScreenshot against the PNGs in
// tests/e2e/visual-baseline/.
//
// Runs ONLY inside the pinned Playwright container (`make visual`, `make visual-update`,
// CI job "visual"): font rasterising and the system fallback fonts differ per OS and per
// image, so a baseline is only valid where it was made. Everywhere else this spec skips.
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { loadState, signIn } from './auth';
import * as path from 'node:path';

test.skip(process.env.OOB_VISUAL !== '1', 'runs in the pinned Playwright container only: make visual');

const viewports = [
  { tag: '1440', width: 1440, height: 900 },
  { tag: '390', width: 390, height: 844 },
] as const;
const schemes = ['dark', 'light'] as const;

// Regions that change between runs (wall clock, data age, poll timing, build version).
// The harness clock is real time, so masking beats faking it.
// Fingerprints are of the mock BMCs' certificates, generated per run.
const dynamic = [
  'time', 'time + .meta', '.clock', '.dataage', '.strip-age', '.age-chip', 'footer', '.polltook', '.rec-axis',
  '[title^="How long the last poll"]', '.stepup-line', '#fingerprints .codeblock', 'dt:text-is("Probed") + dd',
  'section[aria-labelledby="nt-h"] table', // delivery state of the run's own notifications
  '#credentials .badge.b-ok', // "Set · v1 · <date> by admin" of the run's own browser-managed server
].join(', ');

// Default tolerance 0.2 % of pixels; pages that are mostly running text get 0.5 %.
const defaultRatio = 0.002;
const textHeavyRatio = 0.005;
const textHeavy = new Set(['help', 'help-signed-out', 'about', 'events', 'events-all', 'logs-sel', 'logs-lifecycle',
  'security-r730xd', 'security-r240']);

type Spec = { name: string; path: string; signedOut?: boolean };

// The pages.spec.ts list minus the pages whose content is created by the run itself
// (users, tokens, the audit log, setup links) and the two consoles, whose live
// connection state is drawn by script; they join when their content is deterministic.
const pages: Spec[] = [
  { name: 'overview', path: '/' },
  { name: 'servers', path: '/servers' },
  { name: 'server-r730xd', path: '/servers/r730xd' },
  { name: 'server-r240', path: '/servers/r240' },
  { name: 'logs-sel', path: '/servers/r730xd/events' },
  { name: 'logs-lifecycle', path: '/servers/r240/events?log=lifecycle' },
  { name: 'inventory', path: '/servers/r730xd/inventory' },
  { name: 'sensors', path: '/servers/r730xd/sensors' },
  { name: 'server-activity', path: '/servers/r730xd/activity' },
  { name: 'fan', path: '/servers/r730xd/fan' },
  { name: 'activity', path: '/activity' },
  { name: 'security-r730xd', path: '/servers/r730xd/security' },
  { name: 'security-r240', path: '/servers/r240/security' },
  { name: 'confirm-power-safe', path: '/servers/r240/power/graceful-shutdown' },
  { name: 'confirm-power-forced', path: '/servers/r240/power/force-off' },
  { name: 'confirm-power-selfhost', path: '/servers/r730xd/power/force-restart' },
  { name: 'events', path: '/events' },
  { name: 'events-all', path: '/events?severity=all&range=all' },
  { name: 'help', path: '/help' },
  { name: 'go', path: '/go' },
  { name: 'about', path: '/about' },
  { name: 'settings-general', path: '/settings/general' },
  { name: 'settings-servers', path: '/settings/servers' },
  { name: 'settings-server-new', path: '/settings/servers/new' },
  { name: 'settings-server-file', path: '/settings/servers/r730xd' },
  { name: 'settings-server-db', path: '/settings/servers/pw-visual' },
  { name: 'settings-notifications', path: '/settings/notifications' },
  { name: 'notify-new-ntfy', path: '/settings/notifications/new?kind=ntfy' },
  { name: 'display', path: '/preferences' },
  { name: 'error-404', path: '/servers/nope' },
  { name: 'login', path: '/login', signedOut: true },
  { name: 'help-signed-out', path: '/help', signedOut: true },
];

type Storage = Awaited<ReturnType<BrowserContext['storageState']>>;
let storage: Storage;

// settled waits until the first BMC security check of both mock servers has finished,
// so the fleet table shows results instead of "Checking now".
async function settled(page: Page) {
  await expect(async () => {
    await page.goto('/servers');
    await expect(page.getByRole('region', { name: 'Fleet table' }).getByText('Checking now')).toHaveCount(0);
  }).toPass({ timeout: 90_000, intervals: [2_000] });
}

// addBrowserServer adds a browser-managed server (left disabled, so the fleet pages and
// the sidebar stay as they are) with its read-only credential stored: the editable server
// page is the one an install whose servers live in the database uses (slice D).
async function addBrowserServer(page: Page, st: Awaited<ReturnType<typeof loadState>>) {
  await page.goto('/settings/servers/new');
  await page.getByLabel('Id').fill('pw-visual');
  await page.getByLabel('Name').fill('Database node');
  await page.getByLabel('BMC kind').selectOption('idrac9');
  await page.getByLabel('BMC address').fill(st.extra_address);
  await page.getByRole('button', { name: 'Fetch fingerprint' }).click();
  await page.getByRole('button', { name: 'Confirm fingerprint and add the server' }).click();
  await expect(page.getByText('Server added, disabled.')).toBeVisible();
  const ro = page.locator('form[action="/settings/servers/pw-visual/credentials/readonly"]');
  await ro.getByLabel('Username').fill(st.extra_user);
  await ro.getByLabel('Password').fill(st.extra_password);
  await ro.getByRole('button', { name: /Store/ }).click();
  await expect(page.getByText('Credential stored. It is never shown again.')).toBeVisible();
}

// One sign-in for all four runs (auth.ts allows one per TOTP step).
test.beforeAll(async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  await signIn(page, await loadState());
  await settled(page);
  await addBrowserServer(page, await loadState());
  storage = await ctx.storageState();
  await ctx.close();
});

// shoot compares the first viewport and, on a page taller than 1.5 viewports, a second
// clip one viewport further down (no full-page images: they are huge and fragile).
async function shoot(page: Page, spec: Spec, label: string, height: number) {
  await page.goto(spec.path);
  await page.evaluate(() => document.fonts.ready);
  const opts = {
    mask: [page.locator(dynamic)],
    maxDiffPixelRatio: textHeavy.has(spec.name) ? textHeavyRatio : defaultRatio,
    fullPage: false,
    stylePath: path.join(__dirname, 'visual.css'),
  };
  await expect.soft(page).toHaveScreenshot(`${label}.png`, opts);
  const tall = await page.evaluate(() => document.documentElement.scrollHeight > window.innerHeight * 1.5);
  if (tall) {
    await page.evaluate((h) => window.scrollTo(0, h), height);
    await expect.soft(page).toHaveScreenshot(`${label}-2.png`, opts);
  }
}

for (const vp of viewports) {
  for (const scheme of schemes) {
    test(`visual ${vp.tag} ${scheme}`, async ({ browser }) => {
      test.setTimeout(240_000);
      for (const signedOut of [false, true]) {
        const ctx = await browser.newContext({
          // bypassCSP only lets Playwright inject visual.css (a <style> the strict CSP would
          // block); the CSP itself is asserted by security_test and the other specs.
          ignoreHTTPSErrors: true, bypassCSP: true, colorScheme: scheme, reducedMotion: 'reduce',
          viewport: { width: vp.width, height: vp.height }, storageState: signedOut ? undefined : storage,
        });
        const page = await ctx.newPage();
        for (const spec of pages.filter((p) => !!p.signedOut === signedOut)) {
          await test.step(spec.name, () => shoot(page, spec, `${spec.name}-${vp.tag}-${scheme}`, vp.height));
        }
        await ctx.close();
      }
    });
  }
}
