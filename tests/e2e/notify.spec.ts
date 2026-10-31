// Notifications (tech_doc §26) in a real browser: the file-managed webhook and its test
// send, the add-target wizard with a validation error, delete through the confirm page,
// and axe WCAG 2.2 AA scans of each state at 1440 and 390 px.
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

async function axeBoth(page: Page, label: string) {
  await axe(page, label);
  await page.setViewportSize({ width: 390, height: 844 });
  await axe(page, `${label} 390`);
  await expectNoHorizontalScroll(page, label, 390);
  await page.setViewportSize({ width: 1440, height: 900 });
}

test('notification targets: test, add, validation error, delete', async ({ page }) => {
  test.setTimeout(120_000);
  const st = await loadState();
  await signIn(page, st);

  await test.step('the file-managed webhook is listed with a lock and can be tested', async () => {
    await page.goto('/settings/notifications');
    await expect(page.getByRole('heading', { name: 'Notifications', level: 1 })).toBeVisible();
    await expect(page.getByText('Managed by config.yaml')).toBeVisible();
    await page.getByRole('button', { name: 'Send test to E2E hook' }).click();
    await expect(page.getByText('Test sent. The receiver accepted it.')).toBeVisible();
    await axeBoth(page, 'notifications list');
  });

  await test.step('the wizard refuses plaintext without the opt-in, accessibly, and keeps the secret out', async () => {
    await page.getByLabel(/Gotify/).check();
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByRole('heading', { name: 'Add Gotify target', level: 1 })).toBeVisible();
    await page.getByLabel('ID').fill('pw-gotify');
    await page.getByLabel('Name').fill('Playwright Gotify');
    await page.getByLabel('Server URL').fill('http://gotify.example.net');
    await page.getByLabel('Application token').fill('pw-secret-token');
    await page.getByRole('button', { name: 'Add target' }).click();
    await expect(page.getByRole('alert')).toContainText('allow plaintext');
    expect(await page.content()).not.toContain('pw-secret-token');
    await axeBoth(page, 'notification form error');
    await page.getByLabel('Server URL').fill('https://gotify.example.net');
    await page.getByLabel('Application token').fill('pw-secret-token');
    await page.getByRole('button', { name: 'Add target' }).click();
    await expect(page.getByText('Target added.')).toBeVisible();
    await expect(page.getByRole('rowheader', { name: /Playwright Gotify/ })).toBeVisible();
  });

  await test.step('edit shows no secret, then delete through the confirm page', async () => {
    await page.getByRole('link', { name: 'Edit Playwright Gotify' }).click();
    await expect(page.getByText('Secret set · v1')).toBeVisible();
    expect(await page.content()).not.toContain('pw-secret-token');
    await axeBoth(page, 'notification edit');
    await page.goto('/settings/notifications');
    await page.getByRole('link', { name: 'Delete… Playwright Gotify' }).click();
    await expect(page.getByRole('link', { name: 'Cancel' })).toBeFocused();
    await page.getByRole('button', { name: 'Delete Playwright Gotify' }).click();
    await expect(page.getByText('Target deleted.')).toBeVisible();
  });
});
