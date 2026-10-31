// Fan lease lifecycle in a real browser (P3): review → confirm (the login's step-up is
// fresh) → pending → End now on the host-lease R730XD, and start → applied → End now on
// the redfish-floor R240 (mock iDRAC9). axe (WCAG 2.2 AA + best practice) on every state
// in the dark scheme at 1440 and the light scheme at 390; no horizontal scroll.
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { expectNoHorizontalScroll } from './overflow';
import { loadState, signIn, type DevState } from './auth';

// signInContext is a signed-in context for one scheme and viewport (the page it signs in
// on is closed; the test opens its own).
async function signInContext(browser: Browser, st: DevState, scheme: 'dark' | 'light', width: number, height: number): Promise<BrowserContext> {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, colorScheme: scheme, viewport: { width, height } });
  const page = await ctx.newPage();
  await signIn(page, st);
  await page.close();
  return ctx;
}

async function check(page: Page, label: string, width: number) {
  await expect(page.locator('h1')).toHaveCount(1);
  const r = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
    .analyze();
  const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s): ${v.help}`);
  expect(summary, `accessibility violations on ${label}`).toEqual([]);
  await expectNoHorizontalScroll(page, label, width);
}

const runs = [
  { scheme: 'dark' as const, width: 1440, height: 900, id: 'r730xd', pct: '55', pending: true },
  { scheme: 'light' as const, width: 390, height: 844, id: 'r240', pct: '50', pending: false },
];

test('fan lease: review, confirm, owner/countdown, End now (both modes)', async ({ browser }) => {
  test.setTimeout(180_000);
  const st = await loadState();
  for (const run of runs) {
    const label = `${run.id} ${run.width} ${run.scheme}`;
    const ctx = await signInContext(browser, st, run.scheme, run.width, run.height);
    const page = await ctx.newPage();
    await page.goto(`/servers/${run.id}/fan`);
    const card = page.locator('section[aria-labelledby="fan-h"]');
    await expect(card.getByRole('heading', { name: 'Fan lease' })).toBeVisible();
    await check(page, `fan page ${label}`, run.width);

    await card.getByLabel('Minimum fan speed (%)').fill(run.pct);
    await card.getByLabel('Duration').selectOption('30');
    await card.getByRole('button', { name: 'Review lease' }).click();
    await expect(page.getByRole('heading', { level: 1, name: /Start a fan lease on/ })).toBeVisible();
    await expect(page.getByText(`Fans run at least at ${run.pct} %`)).toBeVisible();
    await expect(page.getByRole('link', { name: 'Cancel' })).toBeFocused();
    await check(page, `confirm ${label}`, run.width);

    await page.getByRole('button', { name: 'Start lease' }).click();
    await expect(page).toHaveURL(new RegExp(`/servers/${run.id}/fan\\?fan=started$`));
    await expect(card.getByText('Lease started.')).toBeVisible();
    await expect(card.locator('.badge', { hasText: run.pending ? 'Pending' : 'Applied' })).toBeVisible();
    await expect(card.getByText(/minutes left/)).toBeVisible();
    await check(page, `lease active ${label}`, run.width);

    await card.getByRole('button', { name: 'End now' }).click();
    await expect(card.getByText(/Lease ended\./)).toBeVisible();
    await expect(card.getByRole('button', { name: 'Review lease' })).toBeVisible();
    await ctx.close();
  }
});
