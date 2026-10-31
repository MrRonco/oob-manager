// The read-only firmware view (tech_doc §38) in a real browser: the fleet table with
// names from the member documents and its flags, the filter, the sidebar count, a
// server's Inventory section, an operator's re-scan with its status, and axe WCAG 2.2 AA
// scans of each state at 1440 and 390 px.
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

const table = (page: Page) => page.getByRole('region', { name: 'Firmware of every server' });

test('firmware view: fleet table, filter, inventory section and a re-scan', async ({ page }) => {
  const st = await loadState();
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, st);

  await test.step('both servers are scanned at start', async () => {
    await expect
      .poll(
        async () => {
          await page.goto('/firmware');
          return page.getByText('Not scanned yet.').count();
        },
        { timeout: 60_000, intervals: [1_000] },
      )
      .toBe(0);
  });

  await test.step('the table names every component and flags the problems first', async () => {
    await page.goto('/firmware');
    await expect(page.getByRole('heading', { level: 1, name: 'Firmware' })).toBeVisible();
    await expect(table(page).getByRole('rowheader', { name: 'Backplane 0', exact: true })).toBeVisible();
    await expect(table(page).getByText('Broadcom Gigabit Ethernet BCM5720 - 00:00:5E:00:53:00')).toBeVisible();
    const first = table(page).getByRole('row').nth(1);
    await expect(first).toContainText('Below minimum');
    await expect(first).toContainText('BIOS');
    await expect(table(page).getByText('(2.25 stored on the BMC, not installed)')).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: /Firmware/ })).toHaveAttribute(
      'aria-current',
      'page',
    );
    await axeBoth(page, 'firmware');
  });

  await test.step('the vendor catalog: Latest column, urgent update, skip form, settings panel', async () => {
    await expect
      .poll(
        async () => {
          await page.goto('/firmware');
          return page.getByText('Urgent update').count();
        },
        { timeout: 60_000, intervals: [1_000] },
      )
      .toBeGreaterThan(0);
    await expect(table(page).getByRole('columnheader', { name: 'Latest' })).toBeVisible();
    await expect(page.getByText(/Dell catalog 26\.10\.22/)).toBeVisible();
    const skip = page.getByText('Skip this version…').first();
    await skip.click();
    await expect(page.getByRole('textbox', { name: /Why skip/ }).first()).toBeVisible();
    await axe(page, 'firmware skip form');
    await page.goto('/settings/general');
    await expect(page.getByRole('heading', { name: 'Firmware update check' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Vendor firmware catalog' })).toBeVisible();
    await axeBoth(page, 'settings general catalog');
    await page.goto('/firmware');
  });

  await test.step('the filter keeps the flagged rows of one server', async () => {
    await page.getByLabel('Server', { exact: true }).selectOption('r730xd');
    await page.getByLabel('Flagged only', { exact: true }).check();
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(page).toHaveURL(/flagged=1/);
    await expect(table(page).getByRole('row')).toHaveCount(3); // header, below minimum, not applied
    await expect(page.getByRole('link', { name: 'Download CSV' })).toHaveAttribute('href', /firmware\.csv\?flagged=1/);
    await axe(page, 'firmware filtered');
  });

  await test.step('a server Inventory tab groups its components and re-scans', async () => {
    await page.goto('/servers/r240/inventory');
    const section = page.locator('section[aria-labelledby="fw-h"]');
    await expect(section.getByRole('heading', { name: 'Firmware' })).toBeVisible();
    await expect(section.getByRole('columnheader', { name: 'Released' })).toBeVisible();
    await section.getByRole('button', { name: /Re-scan firmware/ }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Re-scan requested.' })).toBeVisible();
    await axeBoth(page, 'inventory after a re-scan');
    await expect
      .poll(
        async () => {
          await page.goto('/servers/r240/inventory');
          return page.getByText('Scanning…').count();
        },
        { timeout: 60_000, intervals: [1_000] },
      )
      .toBe(0);
  });
});
