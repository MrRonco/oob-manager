// Every page of the direction B UI at 1440x900 and 390x844, in the dark and the light
// scheme: axe WCAG 2.2 AA (plus best-practice), no horizontal page scroll, and the
// "5-second test" (the verdict in the first phone viewport) on Overview and Server. It also
// fails on any Content-Security-Policy violation outside the allowlist in csp.ts (plan 06 §3.4).
// With OOB_SCREENSHOTS=1 it also writes test-results/screenshots/<page>-<w>-<scheme>.png (not committed).
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { expectNoHorizontalScroll } from './overflow';
import { loadState, signIn, type DevState } from './auth';
import { allowedCSP, cspViolations, describeCSP, recordCSP } from './csp';
import { mkdirSync } from 'node:fs';
import * as path from 'node:path';

const shotsDir = path.resolve(__dirname, 'test-results/screenshots');
const screenshots = process.env.OOB_SCREENSHOTS === '1';
const viewports = [
  { tag: '1440', width: 1440, height: 900 },
  { tag: '390', width: 390, height: 844 },
] as const;
const schemes = ['dark', 'light'] as const;

// One admin sign-in for the whole spec: the harness allows 20 sign-ins of an account an hour
// (config maximum) and every spec of the run signs the admin in, so the four tests here share
// one session (a worker restarted after a failure signs in again).
let signedState: Awaited<ReturnType<BrowserContext['storageState']>> | undefined;

async function signInContext(browser: Browser, st: DevState): Promise<BrowserContext> {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, storageState: signedState });
  if (!signedState) {
    await signIn(await ctx.newPage(), st);
    signedState = await ctx.storageState();
  }
  return ctx;
}

async function axe(page: Page, label: string) {
  const r = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
    .analyze();
  const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s): ${v.help}`);
  expect(summary, `accessibility violations on ${label}`).toEqual([]);
}

async function noHorizontalScroll(page: Page, label: string, width: number) {
  await expectNoHorizontalScroll(page, label, width);
}

// Pages that need setup state (a user, a token) are resolved by setup().
type PageSpec = { name: string; path: string; signedOut?: boolean };

async function setup(page: Page): Promise<PageSpec[]> {
  await page.goto('/settings/users');
  const name = `matrix${Date.now() % 100000}`;
  await page.getByLabel('Username').fill(name);
  await page.getByRole('button', { name: 'Create user and copy setup link' }).click();
  const link = await page.locator('#secret').inputValue();
  await page.goto('/settings/tokens');
  await page.getByLabel('Name').fill(`tok${Date.now() % 100000}`);
  await page.getByRole('button', { name: 'Create token' }).click();
  await page.goto('/settings/users');
  const userHref = await page.getByRole('link', { name, exact: true }).getAttribute('href');
  await page.goto('/settings/tokens');
  const revoke = await page.locator('a[href$="/revoke"]').first().getAttribute('href');
  return [
    { name: 'overview', path: '/' },
    { name: 'servers', path: '/servers' },
    { name: 'server-r730xd', path: '/servers/r730xd' },
    { name: 'server-r240', path: '/servers/r240' },
    { name: 'logs-sel', path: '/servers/r730xd/events' },
    { name: 'logs-lifecycle', path: '/servers/r240/events?log=lifecycle' },
    { name: 'history', path: '/servers/r730xd/history' },
    { name: 'history-7d-focus', path: '/servers/r730xd/history?range=7d&focus=power%3Aconsumed' },
    { name: 'history-r240-1y', path: '/servers/r240/history?range=1y' },
    { name: 'inventory', path: '/servers/r730xd/inventory' },
    { name: 'inventory-r240', path: '/servers/r240/inventory?details=1' },
    { name: 'firmware', path: '/firmware' },
    { name: 'firmware-details', path: '/firmware?details=1&flagged=1' },
    { name: 'sensors', path: '/servers/r730xd/sensors' },
    { name: 'server-activity', path: '/servers/r730xd/activity' },
    { name: 'fan', path: '/servers/r730xd/fan' },
    { name: 'activity', path: '/activity' },
    { name: 'security-r730xd', path: '/servers/r730xd/security' },
    { name: 'security-r240', path: '/servers/r240/security' },
    { name: 'confirm-power-safe', path: '/servers/r240/power/graceful-shutdown' },
    { name: 'confirm-power-forced', path: '/servers/r240/power/force-off' },
    { name: 'confirm-power-selfhost', path: '/servers/r730xd/power/force-restart' },
    { name: 'confirm-bmc-reset', path: '/servers/r730xd/bmc/reset' },
    { name: 'console', path: '/servers/r730xd/console' },
    { name: 'serial', path: '/servers/r730xd/serial' },
    { name: 'events', path: '/events' },
    { name: 'events-all', path: '/events?severity=all&range=all' },
    { name: 'help', path: '/help' },
    { name: 'go', path: '/go' },
    { name: 'go-filtered', path: '/go?q=zzz' },
    { name: 'about', path: '/about' },
    { name: 'settings-users', path: '/settings/users' },
    { name: 'settings-user', path: userHref ?? '/settings/users' },
    { name: 'confirm-disable', path: `${userHref}/disable` },
    { name: 'confirm-reset', path: `${userHref}/reset-totp` },
    { name: 'settings-tokens', path: '/settings/tokens' },
    { name: 'confirm-revoke-token', path: revoke ?? '/settings/tokens' },
    { name: 'settings-audit', path: '/settings/audit' },
    { name: 'settings-general', path: '/settings/general' },
    { name: 'settings-servers', path: '/settings/servers' },
    { name: 'settings-server-new', path: '/settings/servers/new' },
    { name: 'settings-server-file', path: '/settings/servers/r730xd' },
    { name: 'settings-notifications', path: '/settings/notifications' },
    { name: 'notify-new-ntfy', path: '/settings/notifications/new?kind=ntfy' },
    { name: 'notify-new-pushover', path: '/settings/notifications/new?kind=pushover' },
    { name: 'notify-new-email', path: '/settings/notifications/new?kind=email' },
    { name: 'settings-integrations', path: '/settings/integrations' },
    { name: 'display', path: '/preferences' },
    { name: 'stepup', path: '/stepup?next=/settings/users' },
    { name: 'error-404', path: '/servers/nope' },
    { name: 'login', path: '/login', signedOut: true },
    { name: 'enroll-link', path: new URL(link).pathname, signedOut: true },
    { name: 'help-signed-out', path: '/help', signedOut: true },
  ];
}

test('every page: axe in both schemes at 1440 and 390, no horizontal scroll, verdict above the fold', async ({ browser }) => {
  // About 40 pages x 2 widths x 2 schemes with axe each: 3-5 min on a hosted runner, so 10 min of headroom.
  test.setTimeout(600_000);
  const st = await loadState();
  const signed = await signInContext(browser, st);
  const pages = await setup(await signed.newPage());
  const storage = await signed.storageState();
  if (screenshots) mkdirSync(shotsDir, { recursive: true });
  const csp: string[] = [];

  for (const vp of viewports) {
    for (const scheme of schemes) {
      for (const signedOut of [false, true]) {
        const ctx = await browser.newContext({
          ignoreHTTPSErrors: true, colorScheme: scheme, viewport: { width: vp.width, height: vp.height },
          storageState: signedOut ? undefined : storage,
        });
        await recordCSP(ctx);
        const page = await ctx.newPage();
        for (const spec of pages.filter((p) => !!p.signedOut === signedOut)) {
          const label = `${spec.name} ${vp.tag} ${scheme}`;
          await test.step(label, async () => {
            await page.goto(spec.path);
            await expect(page.locator('h1')).toHaveCount(1);
            csp.push(...(await cspViolations(page)).filter((v) => !allowedCSP(v)).map(describeCSP));
            await axe(page, label);
            await noHorizontalScroll(page, label, vp.width);
            if (screenshots) {
              await page.screenshot({ path: path.join(shotsDir, `${spec.name}-${vp.tag}-${scheme}.png`), fullPage: true });
            }
          });
        }
        await ctx.close();
      }
    }
  }
  await signed.close();
  expect([...new Set(csp)], 'CSP violations outside the allowlist (csp.ts)').toEqual([]);
});

test('5-second test at 390x844: verdict, worst item and data age in the first viewport', async ({ browser }) => {
  const st = await loadState();
  const signed = await signInContext(browser, st);
  const storage = await signed.storageState();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 390, height: 844 }, storageState: storage });
  const page = await ctx.newPage();

  for (const id of ['r730xd', 'r240']) {
    await page.goto(`/servers/${id}`);
    const verdict = page.locator('#problems .verdict');
    await expect(verdict).toBeInViewport();
    const box = await verdict.boundingBox();
    expect(box && box.y + box.height, `verdict of ${id} below the fold`).toBeLessThanOrEqual(844);
    await expect(page.locator('#problems .chip').first()).toBeInViewport(); // data age
    // Plan 04 §11 item 9: the server's three verbs in the sticky bottom bar on phones.
    const bar = page.getByRole('navigation', { name: 'Server actions, phone' });
    await expect(bar.locator('summary', { hasText: 'Power' })).toBeInViewport();
    await noHorizontalScroll(page, `server ${id}`, 390);
  }

  await page.goto('/');
  for (const sel of ['#verdict .verdict', '#verdict .worst', '#verdict .dataage']) { // verdict, worst item, data age
    await expect(page.locator(sel)).toBeInViewport();
    const b = await page.locator(sel).boundingBox();
    expect(b && b.y + b.height, `${sel} on the Overview below the fold`).toBeLessThanOrEqual(844);
  }
  await expect(page.locator('.gpill')).toBeInViewport(); // fleet pill

  // The theme switch is a server-rendered form: it works without JavaScript.
  await page.locator('details.sheet summary').click();
  await page.locator('.sheet-actions').getByRole('button', { name: /Theme: Auto/ }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await ctx.close();
  await signed.close();
});

// Plan 04 §9: no horizontal page scroll at 320 px (WCAG 1.4.10 reflow) on the three pages
// an operator opens first, in both schemes.
test('reflow at 320 px: Overview, Server and Logs scroll only vertically', async ({ browser }) => {
  const st = await loadState();
  const signed = await signInContext(browser, st);
  const storage = await signed.storageState();
  for (const scheme of schemes) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, colorScheme: scheme, viewport: { width: 320, height: 640 }, storageState: storage });
    const page = await ctx.newPage();
    for (const p of ['/', '/servers/r730xd', '/servers/r730xd/events']) {
      await page.goto(p);
      await expect(page.locator('h1')).toHaveCount(1);
      await noHorizontalScroll(page, `${p} 320 ${scheme}`, 320);
    }
    await ctx.close();
  }
  await signed.close();
});

// Review M4: the server's Power menu open, in the header at 1440 and in the phone bottom
// bar at 390, and the phone page scrolled to the bottom (the footer must not sit under
// the fixed bar), each in both schemes. Violations name their nodes.
test('server menus open, and the phone page bottom: axe in both schemes', async ({ browser }) => {
  test.setTimeout(120_000);
  const st = await loadState();
  const signed = await signInContext(browser, st);
  const storage = await signed.storageState();
  const scan = async (page: Page, label: string) => {
    const r = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
      .analyze();
    const summary = r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
    expect(summary, `accessibility violations on ${label}`).toEqual([]);
  };
  for (const scheme of schemes) {
    for (const vp of viewports) {
      const ctx = await browser.newContext({ ignoreHTTPSErrors: true, colorScheme: scheme,
        viewport: { width: vp.width, height: vp.height }, storageState: storage });
      const page = await ctx.newPage();
      await page.goto('/servers/r240');
      const where = vp.width < 800 ? '.bottombar' : '.shead';
      const power = page.locator(`${where} details.hmenu`, { hasText: 'Power' });
      await power.locator('summary').click();
      await expect(power.getByText(/Restart BMC/)).toBeVisible(); // a link, or disabled after another spec's restart
      await scan(page, `Power menu open ${vp.tag} ${scheme}`);
      await noHorizontalScroll(page, `Power menu open ${vp.tag} ${scheme}`, vp.width);
      if (vp.width < 800) {
        await power.locator('summary').click();
        await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
        const foot = await page.locator('footer.foot').boundingBox();
        const bar = await page.locator('.bottombar').boundingBox();
        expect(foot && bar && foot.y + foot.height <= bar.y + 1, 'the footer ends above the bottom bar').toBeTruthy();
        await scan(page, `server page bottom ${vp.tag} ${scheme}`);
      }
      await ctx.close();
    }
  }
  await signed.close();
});
