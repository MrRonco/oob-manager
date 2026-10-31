// The sensor history (tech_doc §39) in a real browser: the History tab with its range
// picker, focus links, charts with a text alternative and a data table, the events of
// the period, a CSV download, the Hardware tab's sparklines, and axe WCAG 2.2 AA scans
// of each state at 1440 and 390 px in both color schemes. The dev harness seeds 48 h of
// samples before the app starts.
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

async function axeEverywhere(page: Page, label: string) {
  for (const scheme of ['dark', 'light'] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const vp of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(vp);
      await axe(page, `${label} ${vp.width} ${scheme}`);
      await expectNoHorizontalScroll(page, `${label} ${scheme}`, vp.width);
    }
  }
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.setViewportSize({ width: 1440, height: 900 });
}

test('sensor history: tab, ranges, focus, data table, events, CSV and sparklines', async ({ page }) => {
  const st = await loadState();
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, st);

  await test.step('the Hardware tab links its sparklines to the History tab', async () => {
    await page.goto('/servers/r730xd');
    const spark = page.locator('a.spark').first();
    await expect(spark).toBeVisible();
    await expect(spark.getByRole('img')).toHaveAccessibleName(/last 24 hours.*Minimum/);
    await spark.click();
    await expect(page).toHaveURL(/\/servers\/r730xd\/history\?focus=temp%3A.*range=24h#h-temp$/);
  });

  await test.step('the History tab: one chart per kind, the range picker and the events', async () => {
    await page.goto('/servers/r730xd/history');
    await expect(page.getByRole('heading', { level: 1 })).toContainText('history');
    await expect(page.getByRole('navigation', { name: 'Server sections' }).getByRole('link', { name: 'History' }))
      .toHaveAttribute('aria-current', 'page');
    await expect(page.getByRole('navigation', { name: 'Range' }).getByRole('link', { name: '24 hours' }))
      .toHaveAttribute('aria-current', 'page');
    for (const name of ['Temperatures', 'Fans', 'Power draw']) {
      await expect(page.getByRole('heading', { level: 2, name: new RegExp(`^${name}`) })).toBeVisible();
    }
    await expect(page.getByRole('img', { name: /^Temperatures: .*, last 24 hours/ })).toBeVisible();
    await expect(page.getByRole('heading', { level: 2, name: 'Events in this period' })).toBeVisible();
    await axeEverywhere(page, 'history 24h');
  });

  await test.step('a focus link and a range link keep each other', async () => {
    const legend = page.getByRole('list', { name: 'Temperatures: show a sensor' });
    const second = legend.getByRole('link').nth(1);
    const name = (await second.textContent())?.trim() ?? '';
    await second.click();
    await expect(legend.getByRole('link', { name, exact: true })).toHaveAttribute('aria-current', 'true');
    await expect(page.getByRole('img', { name: new RegExp(`^Temperatures: ${name}, last 24 hours`) })).toBeVisible();
    await page.getByRole('navigation', { name: 'Range' }).getByRole('link', { name: '7 days' }).click();
    await expect(page.getByRole('img', { name: new RegExp(`^Temperatures: ${name}, last 7 days`) })).toBeVisible();
    await axeEverywhere(page, 'history 7d focus');
  });

  await test.step('the data table lists the points and the CSV downloads', async () => {
    await page.goto('/servers/r730xd/history');
    const panel = page.locator('#h-temp');
    await panel.locator('details.hist-table summary').click();
    const rows = panel.getByRole('region', { name: /data table$/ }).getByRole('row');
    // A header and one row per ten-minute bucket with data. The 24 h window and the bucket
    // grid rarely align, so 143 to 145 buckets are all correct.
    await expect(rows.nth(143)).toBeVisible();
    expect(await rows.count()).toBeLessThanOrEqual(146);
    await axeEverywhere(page, 'history data table');
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      panel.getByRole('link', { name: 'Download CSV' }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^r730xd_temp-.*_24h_\d{8}T\d{4}Z\.csv$/);
    const body = await (await download.createReadStream()).toArray();
    const text = Buffer.concat(body as Buffer[]).toString('utf8');
    expect(text.split('\r\n')[0]).toBe('bucket_start_utc,bucket_end_utc,server,sensor,name,kind,unit,min,avg,max,samples');
  });

  await test.step('a server with history but no power telemetry, over a year', async () => {
    await page.goto('/servers/r240/history?range=1y');
    await expect(page.getByRole('navigation', { name: 'Range' }).getByRole('link', { name: '1 year' }))
      .toHaveAttribute('aria-current', 'page');
    await expect(page.getByRole('heading', { level: 2, name: /^Temperatures/ })).toBeVisible();
    await axeEverywhere(page, 'history r240 1y');
  });
});
