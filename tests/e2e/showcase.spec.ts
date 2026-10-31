// README screenshots (`make showcase`, workflow "showcase"): walks the shot list of the
// README in a fixed order, because the actions it takes change the pages after them, and
// writes docs/screenshots/<name>-{light,dark}.png plus social-preview.png. The dev server
// runs with OOB_DEV_SHOWCASE=1 (fixture text without test wording, a host transcript on
// the serial console, a boot menu on the graphical console). No masks and no injected
// CSS: the data is synthetic, so clocks and dates stay real. Every capture first checks
// the text in the viewport for dev artefacts and fails the run if it finds one.
//
// Skipped unless OOB_SHOWCASE=1, so the e2e-ui runs never touch docs/screenshots.
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { freshTotp, loadState, signIn, type DevState } from './auth';

test.skip(process.env.OOB_SHOWCASE !== '1', 'README screenshots only: make showcase');

const outDir = path.resolve(__dirname, '../../docs/screenshots');
// The viewport text of every capture, for the maintainer's identifier grep (git-ignored).
const textDir = path.join(__dirname, 'test-results', 'showcase-text');

const common = { ignoreHTTPSErrors: true, reducedMotion: 'reduce', locale: 'en-US', timezoneId: 'UTC' } as const;
const desktop = { ...common, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 };
const phone = { ...common, viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true };
// The six 2-up shots: the main column only (no navigation, no top bar), about 1100 x 700
// CSS px at scale 2, so they stay readable at half the README width.
const detail = { ...common, viewport: { width: 1364, height: 756 }, deviceScaleFactor: 2 };
const detailSize = { width: 1100, height: 700 };

// Text that must never reach a README image: test wording, the visual spec's server, the
// 3 s test refresh, loopback addresses of the harness, the fixtures' redacted service tag
// and the e2e "What goes down" line, and error pages.
const artefacts =
  /\be2e\b|mock|pw-visual|deliberately|dev harness|playwright|REDACTED|gateway|127\.0\.0\.1|localhost|\(3 s\)|Something went wrong|ERROR \d{3}/i;

// The step-up window is 5 minutes; a confirm page asks for a code only after it.
const stepUpWindowMS = 5 * 60_000;

type Shot = { caret?: boolean; clip?: boolean };

// visibleText is the text of every rendered node inside the viewport, plus the values of
// visible form fields.
async function visibleText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const inView = (rects: DOMRectList | DOMRect[]) =>
      [...rects].some((b) => b.width > 0 && b.height > 0 && b.bottom > 0 && b.top < vh && b.right > 0 && b.left < vw);
    const out: string[] = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const t = (n.textContent ?? '').trim();
      const el = n.parentElement;
      if (!t || !el || getComputedStyle(el).visibility === 'hidden') continue;
      const r = document.createRange();
      r.selectNodeContents(n);
      if (inView(r.getClientRects())) out.push(t);
    }
    for (const f of document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input, textarea')) {
      if (f.value && f.type !== 'hidden' && inView(f.getClientRects())) out.push(f.value);
    }
    return out.join('\n');
  });
}

// mainClip is the main column below the top bar, at most detailSize.
async function mainClip(page: Page): Promise<{ x: number; y: number; width: number; height: number }> {
  return page.evaluate((max) => {
    const main = document.querySelector('main')!.getBoundingClientRect();
    const bar = document.querySelector('[role="banner"], body > header')?.getBoundingClientRect().bottom ?? 0;
    const top = Math.max(main.top, bar, 0);
    return { x: main.left, y: top, width: Math.min(main.width, max.width, window.innerWidth - main.left),
      height: Math.min(max.height, window.innerHeight - top) };
  }, detailSize);
}

// shoot captures the viewport (or with clip, the main column) in light and dark, back to
// back on the same page state.
async function shoot(page: Page, name: string, opts: Shot = {}): Promise<void> {
  expect(new URL(page.url()).pathname, `${name}: signed out`).not.toMatch(/^\/(login|stepup)/);
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.evaluate(() => document.fonts.ready);
    const text = await visibleText(page);
    writeFileSync(path.join(textDir, `${name}-${scheme}.txt`), text);
    expect(text, `${name} (${scheme}) shows a dev artefact`).not.toMatch(artefacts);
    await page.screenshot({ path: path.join(outDir, `${name}-${scheme}.png`), animations: 'disabled',
      caret: opts.caret ? 'initial' : 'hide', clip: opts.clip ? await mainClip(page) : undefined });
  }
  await page.emulateMedia({ colorScheme: 'light' });
}

class Codes {
  // last is when the session's step-up was last refreshed (a sign-in counts).
  last = Date.now();
  constructor(private readonly st: DevState) {}

  async take(): Promise<string> {
    const code = await freshTotp(this.st.totp_secret);
    this.last = Date.now();
    return code;
  }

  // fill answers a confirm page's code field when the step-up has lapsed.
  async fill(page: Page): Promise<void> {
    const field = page.locator('#code');
    if (await field.isVisible()) await field.fill(await this.take());
  }

  // stepUp answers the /stepup page when an action sent us there.
  async stepUp(page: Page): Promise<void> {
    if (!new URL(page.url()).pathname.startsWith('/stepup')) return;
    await page.getByLabel(/6-digit code/).fill(await this.take());
    await page.getByRole('button', { name: 'Confirm' }).click();
  }

  // stale waits until the step-up window has lapsed, so confirm pages ask for a code.
  async stale(): Promise<void> {
    const wait = this.last + stepUpWindowMS + 15_000 - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }
}

// settled waits until both servers have polled, the first BMC security checks have
// finished and the firmware scans are in, so no page shows "Checking now" or a stale chip.
async function settled(page: Page): Promise<void> {
  await expect(async () => {
    await page.goto('/servers');
    await expect(page.getByRole('region', { name: 'Fleet table' }).getByText('Checking now')).toHaveCount(0);
    await page.goto('/firmware');
    await expect(page.getByText('Not scanned yet.')).toHaveCount(0);
  }).toPass({ timeout: 120_000, intervals: [2_000] });
  const backup = page.getByRole('button', { name: 'I have a backup' });
  if (await backup.isVisible()) await backup.click();
}

async function phoneShot(browser: Browser, ctx: BrowserContext, url: string, name: string): Promise<void> {
  const mobile = await browser.newContext({ ...phone, storageState: await ctx.storageState() });
  const page = await mobile.newPage();
  await page.goto(url);
  await page.evaluate(() => window.scrollTo(0, 0));
  await shoot(page, name);
  await mobile.close();
}

async function historyShot(page: Page): Promise<void> {
  await page.goto('/servers/r730xd/history?range=24h');
  const legend = page.getByRole('list', { name: 'Temperatures: show a sensor' });
  await legend.getByRole('link', { name: 'CPU2 Temp', exact: true }).click();
  await expect(legend.getByRole('link', { name: 'CPU2 Temp', exact: true })).toHaveAttribute('aria-current', 'true');
  await page.evaluate(() => window.scrollTo(0, 0)); // the focus link jumps to the chart
  await shoot(page, 'history');
}

// paletteShot opens Go to on the Overview of a new tab (its Recent list starts empty, as
// in a fresh browser tab), so the results are the Pages and Servers groups.
async function paletteShot(ctx: BrowserContext): Promise<void> {
  const page = await ctx.newPage();
  await page.goto('/');
  await page.keyboard.press('Control+k');
  const palette = page.getByRole('dialog', { name: 'Go to' });
  // "s" matches pages, settings and servers alike.
  await palette.getByRole('combobox', { name: 'Go to a page, server or setting' }).pressSequentially('s');
  await expect(palette.getByRole('option').first()).toHaveAttribute('aria-selected', 'true');
  await expect(palette.getByRole('group', { name: 'Pages' })).toBeVisible();
  await expect(palette.getByRole('group', { name: 'Servers' })).toBeVisible();
  await shoot(page, 'palette', { clip: true });
  await page.close();
}

async function enableCatalog(page: Page, codes: Codes): Promise<void> {
  await page.goto('/settings/general');
  await page.locator('select[name="firmware.catalog.enabled"]').selectOption({ label: 'On' });
  await page.getByRole('button', { name: 'Save settings' }).click();
  await codes.stepUp(page);
  await expect(async () => {
    await page.goto('/firmware');
    await expect(page.getByText(/online update check is off/i)).toHaveCount(0);
  }).toPass({ timeout: 60_000, intervals: [1_000] });
}

async function serialShot(page: Page): Promise<void> {
  await page.goto('/servers/r730xd/serial');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('#serial-status')).toHaveText('Connected');
  await expect(page.getByRole('log')).toContainText('storage-node login:');
  await page.locator('#serial-term').click();
  await shoot(page, 'console-serial', { caret: true });
  await page.getByRole('button', { name: 'Disconnect' }).click();
}

async function graphicalShot(page: Page): Promise<void> {
  await page.goto('/servers/r730xd/console');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('#console-status')).toHaveText('Connected');
  // The boot menu frame (1024x768) has drawn once the highlighted entry is light grey.
  await expect
    .poll(() =>
      page.evaluate(() => {
        const c = document.querySelector<HTMLCanvasElement>('#console-screen canvas');
        if (!c || c.width < 1000) return 'no frame';
        const d = c.getContext('2d')!.getImageData(Math.floor(c.width * 0.1), Math.floor(c.height * 0.16), 1, 1).data;
        return d[0] > 120 && Math.abs(d[0] - d[2]) < 40 ? 'menu' : `rgb(${d[0]},${d[1]},${d[2]})`;
      }), { timeout: 15_000 })
    .toBe('menu');
  await page.evaluate(() => window.scrollTo(0, 0)); // connecting scrolls to the screen
  await shoot(page, 'console-graphical');
  await page.getByRole('button', { name: 'Disconnect' }).click();
}

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

// actions leaves a verified graceful restart, a fan boost started and ended, and a
// maintenance window started and ended in the activity log, spread over about three
// minutes like a person would (the run waits for the step-up window afterwards anyway).
async function actions(page: Page, codes: Codes): Promise<void> {
  await page.goto('/servers/r240/power/graceful-restart');
  await page.getByLabel(/Type .*Edge node R240.* to confirm/).fill('Edge node R240'); // a critical server
  await codes.fill(page);
  await page.getByRole('button', { name: /Edge node R240$/ }).click();
  await expect(page).toHaveURL(/\/servers\/r240#now-h$/);
  await expect
    .poll(async () => {
      await page.reload();
      return page.locator('#pw-last').innerText();
    }, { timeout: 60_000, intervals: [1_000] })
    .toMatch(/done/i);

  await pause(40_000);
  await page.goto('/servers/r240/fan');
  const card = page.locator('section[aria-labelledby="fan-h"]');
  await card.getByLabel('Minimum fan speed (%)').fill('50');
  await card.getByLabel('Duration').selectOption('30');
  await card.getByRole('button', { name: 'Review lease' }).click();
  await codes.fill(page);
  await page.getByRole('button', { name: 'Start lease' }).click();
  await expect(card.getByText('Lease started.')).toBeVisible();
  await pause(45_000);
  await card.getByRole('button', { name: 'End now' }).click();
  await expect(card.getByText(/Lease ended\./)).toBeVisible();

  await pause(35_000);
  await page.goto('/servers/r730xd/maintenance/new');
  await codes.stepUp(page);
  await page.getByLabel(/^Reason/).fill('Disk swap');
  await page.getByLabel('Duration').selectOption('1h');
  await codes.fill(page);
  await page.getByRole('button', { name: 'Start maintenance' }).click();
  await codes.stepUp(page);
  await expect(page.locator('#maint')).toContainText('Disk swap');
  await pause(40_000);
  await page.goto('/servers/r730xd/activity');
  await page.getByRole('button', { name: 'End maintenance now' }).click();
  await codes.stepUp(page);
  await expect(page.getByText('Not in maintenance')).toBeVisible();
}

async function powerConfirmShot(page: Page): Promise<void> {
  await page.goto('/servers/r730xd/power/force-off');
  await expect(page.locator('#code')).toBeVisible(); // the step-up has lapsed
  await page.getByLabel(/Type .*Storage node R730XD.* to confirm/).fill('Storage node R730XD');
  await page.getByRole('link', { name: 'Cancel' }).focus();
  await shoot(page, 'power-confirm');
}

async function addBenchNode(page: Page, st: DevState, codes: Codes): Promise<void> {
  await page.goto('/settings/servers/new');
  await page.getByLabel('Id').fill('bench');
  await page.getByLabel('Name').fill('Bench node');
  await page.getByLabel('BMC kind').selectOption('idrac9');
  await page.getByLabel('BMC address').fill(st.extra_address);
  await page.getByRole('button', { name: 'Fetch fingerprint' }).click();
  await codes.stepUp(page);
  await page.getByRole('button', { name: 'Confirm fingerprint and add the server' }).click();
  await codes.stepUp(page);
  await expect(page.getByText('Server added, disabled.')).toBeVisible();
  const ro = page.locator('form[action="/settings/servers/bench/credentials/readonly"]');
  await ro.getByLabel('Username').fill(st.extra_user);
  await ro.getByLabel('Password').fill(st.extra_password);
  await ro.getByRole('button', { name: /Store/ }).click();
  await expect(page.getByText('Credential stored. It is never shown again.')).toBeVisible();
  await page.getByRole('button', { name: 'Enable server' }).click();
  await expect(page.getByText('Server enabled.')).toBeVisible();
  await page.getByRole('button', { name: 'Test connection' }).click();
  await expect(async () => {
    await page.goto('/settings/servers');
    await expect(page.getByRole('row', { name: /Bench node/ }).getByText('Polling')).toBeVisible();
    await expect(page.getByRole('row', { name: /Bench node/ })).not.toContainText(/Never|Running/);
  }).toPass({ timeout: 60_000, intervals: [2_000] });
}

async function socialPreview(browser: Browser): Promise<void> {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  await page.goto(pathToFileURL(path.join(__dirname, 'showcase', 'social.html')).href);
  await page.evaluate(() => document.fonts.ready);
  await expect(page.locator('.shot img')).toHaveJSProperty('complete', true);
  await page.screenshot({ path: path.join(outDir, 'social-preview.png') });
  await ctx.close();
}

test('README screenshots', async ({ browser }) => {
  test.setTimeout(20 * 60_000);
  mkdirSync(outDir, { recursive: true });
  mkdirSync(textDir, { recursive: true });
  const st = await loadState();
  const ctx = await browser.newContext(desktop);
  const page = await ctx.newPage();
  await signIn(page, st);
  const codes = new Codes(st);
  await settled(page);
  // The same session in the detail viewport, for the six main-column shots.
  const wideCtx = await browser.newContext({ ...detail, storageState: await ctx.storageState() });
  const wide = await wideCtx.newPage();
  // A step-up renews the session cookie, so the detail context takes the current one first.
  const syncSession = async () => wideCtx.addCookies(await ctx.cookies());
  const detailShot = async (url: string, name: string) => {
    await syncSession();
    await wide.goto(url);
    await shoot(wide, name, { clip: true });
  };

  await test.step('1 hero-server', async () => {
    await page.goto('/servers/r730xd');
    await shoot(page, 'hero-server');
  });
  await test.step('2 overview', async () => {
    await page.goto('/');
    await shoot(page, 'overview');
  });
  await test.step('3 history', () => historyShot(page));
  await test.step('7 security', () => detailShot('/servers/r730xd/security', 'security'));
  await test.step('8 events', async () => {
    // The default filter (warning and worse, last 7 days): the harness moved the logs so the
    // newest entry is a few minutes old.
    await syncSession();
    await wide.goto('/events');
    await expect(wide.getByRole('cell', { name: /Warning|Critical/ }).first()).toBeVisible();
    await shoot(wide, 'events', { clip: true });
  });
  await test.step('10 palette', async () => {
    await syncSession();
    await paletteShot(wideCtx);
  });
  await test.step('12 phone-server', () => phoneShot(browser, ctx, '/servers/r730xd', 'phone-server'));
  await test.step('6 firmware (online check on)', async () => {
    await enableCatalog(page, codes);
    await detailShot('/firmware', 'firmware');
  });
  await test.step('4 console-serial', () => serialShot(page));
  await test.step('14 console-graphical', () => graphicalShot(page));
  await test.step('9 activity', async () => {
    await actions(page, codes);
    await detailShot('/activity', 'activity');
  });
  await test.step('5 power-confirm (step-up lapsed)', async () => {
    await codes.stale();
    await powerConfirmShot(page);
  });
  await test.step('13 phone-confirm', () => phoneShot(browser, ctx, '/servers/r730xd/power/graceful-shutdown', 'phone-confirm'));
  await test.step('11 settings-servers', async () => {
    await addBenchNode(page, st, codes);
    await detailShot('/settings/servers', 'settings-servers');
  });
  await test.step('social preview', () => socialPreview(browser));
  await wideCtx.close();
  await ctx.close();
});
