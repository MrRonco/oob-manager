// Settings → Integrations in a real browser (slice S4): turn audit shipping on over TLS
// by fetching and confirming the log server's certificate (the issuer is offered first),
// see it connect, send a test, copy a hint with the Copy button (JavaScript), then turn
// shipping off again. axe (WCAG 2.2 AA) on the page and on the certificate confirmation
// at 1440 and 390 px in both schemes, with no horizontal page scroll.
import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { loadState, signIn } from './auth';
import { expectNoHorizontalScroll } from './overflow';

async function check(page: Page, label: string) {
  for (const vp of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(vp);
    for (const scheme of ['dark', 'light'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      const r = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
        .analyze();
      const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s): ${v.help}`);
      expect(summary, `accessibility violations on ${label} ${vp.width} (${scheme})`).toEqual([]);
      await expect(page.locator('h1')).toHaveCount(1);
      await expectNoHorizontalScroll(page, `${label} ${vp.width} ${scheme}`, vp.width);
    }
  }
  await page.setViewportSize({ width: 1440, height: 900 });
}

test('audit shipping over TLS: fetch and confirm, connected, test, copy a hint, off again', async ({ page, context }) => {
  test.setTimeout(180_000);
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const st = await loadState();
  await signIn(page, st);

  await page.goto('/settings/integrations');
  await expect(page.getByRole('heading', { name: 'Integrations', level: 1 })).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: 'Disabled' }).first()).toBeVisible();
  await expect(page.locator('#hint-homepage')).toContainText('Bearer <token>');
  await check(page, 'integrations (disabled)');

  await page.getByLabel('On', { exact: true }).check();
  await page.getByLabel('Address', { exact: true }).fill(st.gelf_tls_address);
  await page.getByRole('button', { name: 'Fetch and confirm the certificate' }).click();
  await expect(page.getByRole('heading', { name: 'Confirm the log server certificate' })).toBeVisible();
  await expect(page.getByLabel(/The CA that issued it/)).toBeChecked();
  await check(page, 'confirm log server certificate');
  await page.getByRole('button', { name: 'Confirm fingerprint and apply' }).click();
  await expect(page.getByText('Fingerprint confirmed and applied.')).toBeVisible();

  await expect(async () => {
    await page.goto('/settings/integrations');
    await expect(page.getByRole('status').filter({ hasText: 'Connected' }).first()).toBeVisible();
  }).toPass({ timeout: 30_000 });
  await expect(page.getByText('TLS, pinned', { exact: false })).toBeVisible();
  await check(page, 'integrations (connected over TLS)');

  await page.getByRole('button', { name: 'Send test' }).click();
  await expect(page.getByText(/Test sent: the log server accepted the bytes/)).toBeVisible();

  await page.getByRole('button', { name: 'Copy scrape config' }).click();
  await expect(page.locator('[data-copy-status="hint-prom"]')).toHaveText('Copied.');
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toContain('job_name: oob-manager');
  expect(copied).toContain('<token>');

  // Enter in a field submits Save (the Reset buttons belong to their own form).
  await page.getByLabel('Off', { exact: true }).check();
  await page.getByLabel('Address', { exact: true }).press('Enter');
  await expect(page.getByText('Saved and applied without a restart.')).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: 'Disabled' }).first()).toBeVisible();
});
