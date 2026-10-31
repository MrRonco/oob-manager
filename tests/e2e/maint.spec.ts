// Maintenance mode, server notes and event acknowledgement (tech_doc §28) in a real
// browser, with axe WCAG 2.2 AA scans of each state at 1440 and 390 px.
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


test('maintenance mode, notes and acknowledgements', async ({ page }) => {
  const st = await loadState();
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, st);

  await test.step('start maintenance (its own page, never auto-refreshed)', async () => {
    await page.goto('/servers/r730xd/activity');
    await axeBoth(page, 'server Activity tab, maintenance card');
    await page.getByRole('link', { name: 'Start maintenance…' }).click();
    await expect(page).toHaveURL(/\/servers\/r730xd\/maintenance\/new$/);
    await axeBoth(page, 'start maintenance page');
    await page.getByLabel(/^Reason/).fill('PSU2 replacement');
    await page.getByLabel('Duration').selectOption('4h');
    await page.getByRole('button', { name: 'Start maintenance' }).click();
    await expect(page.locator('.shead .maint-line')).toContainText('In maintenance until');
    await expect(page.locator('#maint')).toContainText('PSU2 replacement');
    await axeBoth(page, 'server in maintenance');
    await page.goto('/');
    await expect(page.getByRole('heading', { name: /In maintenance/ })).toBeVisible();
    await expect(page.locator('.gpill')).toContainText('in maintenance');
    await axeBoth(page, 'overview with a server in maintenance');
  });

  await test.step('add, pin and edit a note (escaped, links safe)', async () => {
    await page.goto('/servers/r730xd/activity');
    await page.getByRole('link', { name: 'Add a note…' }).click();
    await expect(page).toHaveURL(/\/servers\/r730xd\/notes\/new$/);
    await axeBoth(page, 'add note page');
    await page.getByLabel('Note text').fill('PSU2 cable loose <img src=x onerror=alert(1)>\nRMA https://example.com/rma');
    await page.getByRole('button', { name: 'Add note' }).click();
    await expect(page).toHaveURL(/\/servers\/r730xd\/activity#notes$/);
    const note = page.locator('#notes .notes li').first();
    await expect(note).toContainText('<img src=x onerror=alert(1)>');
    expect(await page.locator('#notes img').count()).toBe(0);
    await expect(note.getByRole('link', { name: 'https://example.com/rma' })).toHaveAttribute('rel', 'noopener noreferrer');
    await note.getByRole('button', { name: /Pin to top/ }).click();
    await page.goto('/servers/r730xd'); // the pinned note heads the server's Overview tab
    await expect(page.getByRole('complementary', { name: 'Pinned note' })).toContainText('PSU2 cable loose');
    await page.goto('/servers/r730xd/activity');
    await note.getByRole('link', { name: /^Edit/ }).click();
    await expect(page).toHaveURL(/\/servers\/r730xd\/notes\/\d+\/edit$/);
    await axeBoth(page, 'edit note page');
    await page.getByLabel('Note text').fill('PSU2 cable reseated');
    await page.getByRole('button', { name: 'Save note' }).click();
    await page.goto('/servers/r730xd');
    await expect(page.getByRole('complementary', { name: 'Pinned note' })).toContainText('PSU2 cable reseated');
    await axeBoth(page, 'server with a pinned note');
  });

  await test.step('acknowledge log entries', async () => {
    await page.goto('/servers/r730xd/events');
    await expect(page.getByRole('button', { name: /Acknowledge all \d+ shown/ })).toBeVisible({ timeout: 30_000 });
    await axeBoth(page, 'logs with acknowledge');
    await page.locator('details.ack summary').first().click();
    await page.locator('details.ack[open] input[name="comment"]').fill('chassis opened for the swap');
    await page.locator('details.ack[open]').getByRole('button', { name: 'Acknowledge' }).click();
    await expect(page.getByText('chassis opened for the swap').first()).toBeVisible();
    await page.getByLabel(/Comment for all/).fill('swap');
    await page.getByRole('button', { name: /Acknowledge all \d+ shown/ }).click();
    await expect(page.getByRole('button', { name: /Un-acknowledge/ }).first()).toBeVisible();
    await page.goto('/events?server=r730xd&range=all');
    await expect(page.getByText(/Acked\s+by/).first()).toBeVisible();
    await axeBoth(page, 'events with acknowledgements');
  });

  await test.step('end maintenance', async () => {
    await page.goto('/servers/r730xd/activity');
    await page.getByRole('button', { name: 'End maintenance now' }).click();
    await expect(page.getByText('Not in maintenance')).toBeVisible();
  });
});
