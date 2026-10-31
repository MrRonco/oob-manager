// Confirm pages on phones (audit R2-05): Cancel keeps the default focus, and the page
// opens at the top with the title, the critical-server warning and the confirm button
// all in the first 390×844 viewport (autofocus used to scroll the title away).
import { expect, test, type Browser, type BrowserContext } from '@playwright/test';
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

test('phone confirm pages open at the top with Cancel focused', async ({ browser }) => {
  test.setTimeout(90_000);
  const st = await loadState();
  const signed = await signedInContext(browser, st);
  const storage = await signed.storageState();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 390, height: 844 }, storageState: storage });
  const page = await ctx.newPage();
  for (const [path, button] of [
    ['/servers/r240/power/force-off', 'Force off Edge node R240'],
    ['/servers/r240/power/graceful-shutdown', 'Graceful shutdown Edge node R240'],
  ] as const) {
    await test.step(path, async () => {
      await page.goto(path);
      await expect(page.getByRole('link', { name: 'Cancel' })).toBeFocused();
      expect(await page.evaluate(() => window.scrollY), `${path} opened scrolled`).toBe(0);
      await expect(page.locator('h1')).toBeInViewport();
      await expect(page.getByText('Edge node R240 is tagged critical')).toBeInViewport();
      await expect(page.getByRole('button', { name: button })).toBeInViewport();
    });
  }
  await ctx.close();
  await signed.close();
});
