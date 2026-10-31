// The fleet table (Servers page since round-2 slice C) at laptop widths (audit R2-04): the table fits its region without
// an internal scroll, so the health-relevant Draw and Data columns stay in view from
// 1024 to 1536 px (they were clipped off-screen before; the rail now stacks below 1600).
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { loadState, signIn, type DevState } from './auth';

// signedInContext signs the shared admin in through auth.ts (one sign-in per TOTP step,
// single-use codes) and returns the context that holds the session.
async function signedInContext(browser: Browser, st: DevState): Promise<BrowserContext> {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  await signIn(page, st);
  await page.close();
  return ctx;
}

async function fleetFits(page: Page, width: number) {
  await page.goto('/servers');
  const region = page.getByRole('region', { name: 'Fleet table' });
  await expect(region).toBeVisible();
  const { sw, cw } = await region.evaluate((el) => ({ sw: el.scrollWidth, cw: el.clientWidth }));
  expect(sw, `${width}px: the fleet table overflows its region by ${sw - cw}px`).toBeLessThanOrEqual(cw + 1);
  for (const name of ['Draw W', 'Security', 'Data']) {
    await expect(region.getByRole('columnheader', { name, exact: true }), `${width}px: ${name} column`).toBeInViewport();
  }
  await expect(region.getByRole('columnheader', { name: 'Issue', exact: true })).toBeInViewport();
}

test('the fleet table fits laptop widths without hiding Draw, Security or Data', async ({ browser }) => {
  test.setTimeout(120_000);
  const st = await loadState();
  const signed = await signedInContext(browser, st);
  const storage = await signed.storageState();
  for (const width of [1024, 1280, 1366, 1440, 1536]) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 800 }, storageState: storage });
    const page = await ctx.newPage();
    await test.step(`${width} px`, () => fleetFits(page, width));
    await ctx.close();
  }
  await signed.close();
});
