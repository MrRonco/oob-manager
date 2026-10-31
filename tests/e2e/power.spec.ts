// Power control (P2) in a real browser: the Operations tab, the direction B confirm
// interstitial (Cancel focused by default, warnings, "What goes down", typed server
// name), a forced power cycle verified at the mock BMC, and axe WCAG 2.2 AA scans of the
// confirm page in its normal and error states at 1440 and 390 px.
import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { expectNoHorizontalScroll } from './overflow';
import { loadState, signIn } from './auth';

async function axe(page: Page, label: string) {
  const r = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
    .analyze();
  const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s): ${v.help}`);
  expect(summary, `accessibility violations on ${label}`).toEqual([]);
}

test('power cycle through the confirm interstitial, verified, accessible', async ({ page }) => {
  test.setTimeout(120_000);
  const st = await loadState();
  await signIn(page, st);

  await test.step('Power ▾ offers the actions this BMC supports', async () => {
    await page.goto('/servers/r240');
    await axe(page, 'server r240');
    const panel = page.locator('.shead details.hmenu', { hasText: 'Power' });
    await panel.locator('summary').click();
    await expect(panel.getByRole('link', { name: /Power cycle/ })).toBeVisible();
    await expect(panel.getByText('The server is already on.')).toBeVisible(); // Power on is disabled with its reason
  });

  await test.step('the confirm page states the action, its effect and what goes down; Cancel has focus', async () => {
    await page.locator('.shead').getByRole('link', { name: /Power cycle/ }).click();
    await expect(page).toHaveURL(/\/servers\/r240\/power\/power-cycle$/);
    await expect(page.getByRole('heading', { name: 'Power cycle Edge node R240?', level: 1 })).toBeVisible();
    await expect(page.getByText('Edge node R240 is tagged critical')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'What goes down' })).toBeVisible();
    await expect(page.getByText('Network gateway: all internet access drops')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Cancel' })).toBeFocused();
    await axe(page, 'confirm power cycle');
    await page.setViewportSize({ width: 390, height: 844 });
    await axe(page, 'confirm power cycle 390');
    await expectNoHorizontalScroll(page, 'confirm power cycle 390', 390);
    await page.setViewportSize({ width: 1440, height: 900 });
  });

  await test.step('a wrong typed name is refused with an accessible error', async () => {
    await page.getByLabel(/Type .*Edge node R240.* to confirm/).fill('edge node r240');
    await page.getByRole('button', { name: 'Power cycle Edge node R240' }).click();
    await expect(page.getByText('The name you typed does not match.')).toBeVisible();
    await expect(page.locator('#typed')).toHaveAttribute('aria-invalid', 'true');
    await axe(page, 'confirm power cycle, typed name error');
  });

  await test.step('the exact name runs it; the result is verified', async () => {
    await page.getByLabel(/Type .*Edge node R240.* to confirm/).fill('Edge node R240');
    await page.getByRole('button', { name: 'Power cycle Edge node R240' }).click();
    await expect(page).toHaveURL(/\/servers\/r240#now-h$/);
    await expect
      .poll(async () => {
        await page.reload();
        return page.locator('#pw-last').innerText();
      }, { timeout: 30_000, intervals: [1_000] })
      .toContain('Power cycle done');
    await page.screenshot({ path: 'test-results/power-done.png', fullPage: true });
  });

  await test.step('the self-host warning on the server oob-manager runs on', async () => {
    await page.goto('/servers/r730xd/power/force-restart');
    await expect(page.getByText('This server runs oob-manager; the console will go offline until it boots.')).toBeVisible();
    await axe(page, 'confirm self-host');
    await page.getByRole('link', { name: 'Cancel' }).click();
    await expect(page).toHaveURL(/\/servers\/r730xd$/);
  });
});
