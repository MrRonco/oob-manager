// Auto-refresh never discards typed input (audit R2-02): the pages that refresh carry
// no typed controls at all (the forms live on their own pages), and with JavaScript the
// reload waits while a field has focus or unsaved input. The dev server runs with
// OOB_DEV_REFRESH=3s (playwright.config.ts), so a reload is observable in seconds.
import { expect, test } from '@playwright/test';
import { loadState, signIn } from './auth';

const typed = 'textarea, input[type="text"], input[type="search"], input[type="datetime-local"], input[type="password"], input[type="number"]';

test('auto-refresh never runs over typed input', async ({ page }) => {
  test.setTimeout(90_000);
  const st = await loadState();
  await signIn(page, st);

  await test.step('turn it on; the refreshed pages carry no typed controls', async () => {
    await page.goto('/servers/r730xd');
    await page.getByRole('button', { name: /Turn on/ }).click();
    await expect(page.getByText('Auto-refresh On')).toBeVisible();
    for (const path of ['/', '/servers', '/servers/r730xd']) {
      await page.goto(path);
      await expect(page.locator('meta[name="oob-refresh"]')).toHaveAttribute('content', '3');
      await expect(page.locator(typed), `${path} carries typed input`).toHaveCount(0);
    }
    // The forms moved to their own pages, which never refresh.
    await page.goto('/servers/r240/maintenance/new');
    await expect(page.locator('meta[name="oob-refresh"]')).toHaveCount(0);
    await expect(page.getByLabel(/^Reason/)).toBeVisible();
  });

  await test.step('a focused or dirty field pauses the reload; leaving it resumes', async () => {
    await page.goto('/servers/r730xd');
    await page.evaluate(() => {
      const probe = document.createElement('input');
      probe.type = 'text';
      probe.id = 'probe';
      document.querySelector('main')?.append(probe);
      (window as unknown as { __alive: number }).__alive = 1;
    });
    await page.locator('#probe').focus();
    await page.keyboard.type('draft');
    await page.waitForTimeout(5_000); // past the 3 s interval
    expect(await page.evaluate(() => (window as unknown as { __alive?: number }).__alive)).toBe(1);
    await expect(page.locator('html')).toHaveAttribute('data-refresh-paused', '1');
    await page.evaluate(() => {
      const probe = document.getElementById('probe') as HTMLInputElement;
      probe.value = '';
      probe.blur();
    });
    await page.waitForFunction(() => (window as unknown as { __alive?: number }).__alive === undefined, null, { timeout: 20_000 });
  });

  await page.goto('/servers/r730xd');
  await page.getByRole('button', { name: 'Turn off' }).click();
  await expect(page.getByText('Auto-refresh Off')).toBeVisible();
});
