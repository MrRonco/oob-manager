// BMC restart (tech_doc §37) in a real browser: Power ▾ → Restart BMC… (keyboard only), the
// confirm page (Cancel focused, typed server name, what the restart costs), a refused
// wrong name, then a restart of the R240 mock BMC: the restarting server page while it
// is down, and the verified result. axe WCAG 2.2 AA on every state, at 1440 and 390 in
// both schemes for the confirm page.
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

test('BMC restart through the confirm page, the restarting state, verified, accessible', async ({ page }) => {
  test.setTimeout(120_000);
  const st = await loadState();
  await signIn(page, st);

  await test.step('Power ▾ offers Restart BMC; the System panel has the BMC facts (keyboard only)', async () => {
    await page.goto('/servers/r240');
    await axe(page, 'server r240');
    const panel = page.getByRole('region', { name: 'System', exact: true });
    await expect(panel.getByText('14G Monolithic')).toBeVisible();
    await expect(panel.getByText('(reported by the BMC)')).toBeVisible();
    const power = page.locator('.shead details.hmenu', { hasText: 'Power' });
    await power.locator('summary').focus();
    await page.keyboard.press('Enter');
    await expect(power).toHaveAttribute('open', '');
    const restart = power.getByRole('link', { name: /Restart BMC/ });
    await expect(restart).toBeVisible();
    await page.keyboard.press('Escape'); // app.js closes the menu and returns focus
    await expect(power).not.toHaveAttribute('open', '');
    await expect(power.locator('summary')).toBeFocused();
    await page.keyboard.press('Enter');
    await restart.focus();
    await page.keyboard.press('Enter');
  });

  await test.step('the confirm page says what the restart costs; Cancel has focus', async () => {
    await expect(page).toHaveURL(/\/servers\/r240\/bmc\/reset$/);
    await expect(page.getByRole('heading', { name: 'Restart the BMC of Edge node R240?', level: 1 })).toBeVisible();
    await expect(page.getByText(/Every console on this server closes now/)).toBeVisible();
    await expect(page.getByText(/The host keeps running/)).toBeVisible();
    await expect(page.getByRole('link', { name: 'Cancel' })).toBeFocused();
    for (const scheme of ['dark', 'light'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
        await axe(page, `confirm BMC restart ${width} ${scheme}`);
        await expectNoHorizontalScroll(page, `confirm BMC restart ${width} ${scheme}`, width);
      }
    }
    await page.setViewportSize({ width: 1440, height: 900 });
  });

  await test.step('a wrong typed name is refused with an accessible error', async () => {
    await page.getByLabel(/Type .*Edge node R240.* to confirm/).fill('edge node r240');
    await page.getByRole('button', { name: 'Restart BMC of Edge node R240' }).click();
    await expect(page.getByText('The name you typed does not match.')).toBeVisible();
    await expect(page.locator('#typed')).toHaveAttribute('aria-invalid', 'true');
    await axe(page, 'confirm BMC restart, typed name error');
  });

  await test.step('the exact name restarts the BMC; the server page says it is restarting', async () => {
    await page.getByLabel(/Type .*Edge node R240.* to confirm/).fill('Edge node R240');
    await page.getByRole('button', { name: 'Restart BMC of Edge node R240' }).click();
    await expect(page).toHaveURL(/\/servers\/r240#now-h$/);
    await page.goto('/servers/r240');
    await expect(page.locator('#problems .verdict')).toContainText('BMC restarting');
    await axe(page, 'server r240 while its BMC restarts');
  });

  await test.step('the restart is verified once the BMC answers', async () => {
    await expect
      .poll(async () => {
        await page.goto('/servers/r240');
        return page.locator('#bmc-last').innerText();
      }, { timeout: 30_000, intervals: [1_000] })
      .toContain('BMC back after');
    await axe(page, 'server r240 after the restart');
  });
});
