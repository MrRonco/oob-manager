// Settings → Servers in a real browser (slice S3): add a BMC that is not in config.yaml
// through the trust-on-first-use flow, store its read-only login, enable it and see it
// polled on the Overview without a restart; axe (WCAG 2.2 AA) on every Servers page in
// both schemes, including the fingerprint confirmation and the removal confirmation.
import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { loadState, signIn } from './auth';

async function axe(page: Page, label: string) {
  for (const scheme of ['dark', 'light'] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    const r = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
      .analyze();
    const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s): ${v.help}`);
    expect(summary, `accessibility violations on ${label} (${scheme})`).toEqual([]);
    await expect(page.locator('h1')).toHaveCount(1);
  }
}

test('add a server in the browser: TOFU, credentials, enable, polled without a restart', async ({ page }) => {
  test.setTimeout(180_000);
  const st = await loadState();
  await signIn(page, st);

  await page.goto('/settings/servers');
  await expect(page.getByRole('heading', { name: 'Servers', level: 1 })).toBeVisible();
  await axe(page, 'servers list');
  await page.getByRole('link', { name: 'Add server' }).click();
  await axe(page, 'add server');
  await page.getByLabel('Id').fill('pw-edge');
  await page.getByLabel('Name').fill('Playwright edge');
  await page.getByLabel('BMC kind').selectOption('idrac9');
  await page.getByLabel('BMC address').fill(st.extra_address);
  await page.getByRole('button', { name: 'Fetch fingerprint' }).click();

  await expect(page.getByRole('heading', { name: 'Confirm the HTTPS certificate' })).toBeVisible();
  await expect(page.getByLabel('Fingerprint')).toContainText(/^[0-9a-f]{4}( [0-9a-f]{4}){15}$/);
  await axe(page, 'confirm fingerprint');
  await page.getByRole('button', { name: 'Confirm fingerprint and add the server' }).click();

  await expect(page.getByText('Server added, disabled.')).toBeVisible();
  await axe(page, 'server settings (new, disabled)');
  const ro = page.locator('form[action="/settings/servers/pw-edge/credentials/readonly"]');
  await ro.getByLabel('Username').fill(st.extra_user);
  await ro.getByLabel('Password').fill(st.extra_password);
  await ro.getByRole('button', { name: /Store/ }).click();
  await expect(page.getByText('Credential stored. It is never shown again.')).toBeVisible();
  await expect(page.locator('body')).not.toContainText(st.extra_password);
  await page.getByRole('button', { name: 'Enable server' }).click();
  await expect(page.getByText('Server enabled.')).toBeVisible();

  await expect(async () => {
    await page.goto('/');
    await expect(page.getByRole('link', { name: /Playwright edge/ }).first()).toBeVisible();
  }).toPass({ timeout: 30_000 });

  await page.goto('/settings/servers/pw-edge/delete');
  await axe(page, 'remove server confirmation');
  await page.getByLabel(/Type/).fill('pw-edge');
  await page.getByRole('button', { name: 'Remove Playwright edge' }).click();
  await expect(page.getByText('Server removed.')).toBeVisible();
  await page.goto('/settings/servers/r730xd');
  await expect(page.getByText('Managed by config.yaml').first()).toBeVisible();
  await axe(page, 'server settings (config.yaml)');
});
