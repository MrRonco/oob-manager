// Motion (round-2 slice D, plan 04 §7 and §11 items 5-6): with motion allowed, nothing
// lasts longer than the 250 ms budget, the view-transition names are in place and menus
// get their entrance; with reduced motion nothing moves at all. The CSS rules themselves
// are checked statically by TestMotionOnlyWhenAllowed (Go).
import { expect, test, type Page } from '@playwright/test';
import { loadState, signIn } from './auth';

const pages = ['/', '/servers/r730xd', '/servers/r730xd/sensors', '/settings/general', '/settings/servers/r730xd', '/events'];

// longestMotion returns the longest transition or animation duration (ms) of any element
// on the page, and the element that has it.
async function longestMotion(page: Page): Promise<{ ms: number; where: string }> {
  return page.evaluate(() => {
    const ms = (v: string) => Math.max(0, ...v.split(',').map((x) => (x.trim().endsWith('ms') ? parseFloat(x) : parseFloat(x) * 1000)));
    let best = { ms: 0, where: '' };
    for (const el of Array.from(document.querySelectorAll('*'))) {
      const cs = getComputedStyle(el);
      const d = Math.max(ms(cs.transitionDuration), cs.animationName === 'none' ? 0 : ms(cs.animationDuration));
      if (d > best.ms) best = { ms: d, where: `${el.tagName.toLowerCase()}.${el.className}` };
    }
    return best;
  });
}

const vtName = (page: Page, sel: string) => page.locator(sel).first().evaluate((el) => getComputedStyle(el).viewTransitionName);

test('motion stays within the budget, and is off under reduced motion', async ({ page }) => {
  test.setTimeout(120_000);
  const st = await loadState();
  await signIn(page, st);

  await page.emulateMedia({ reducedMotion: 'no-preference' });
  for (const path of pages) {
    await page.goto(path);
    const m = await longestMotion(page);
    expect(m.ms, `${path}: ${m.where} moves for ${m.ms} ms`).toBeLessThanOrEqual(250);
  }
  await page.goto('/servers/r730xd/sensors');
  expect(await vtName(page, '.bar')).toBe('topbar');
  expect(await vtName(page, '.side')).toBe('sidebar');
  expect(await vtName(page, '.shead')).toBe('server-head');
  expect(await vtName(page, '.tabs [aria-current="page"] .tab-ink')).toBe('tab-ink');
  await expect(page.locator('.tab-ink')).toHaveCount(1);
  const pop = page.locator('.shead .hmenu').first();
  await pop.locator('summary').click();
  const dur = await pop.locator('.menu-pop').evaluate((el) => getComputedStyle(el).transitionDuration);
  expect(dur).not.toBe('0s');
  await pop.locator('summary').click();

  // The head's view-transition name makes it a stacking context: its menus must still open
  // above the tabs and panels that follow (they were covered before .shead got a z-index).
  await page.goto('/servers/r730xd');
  const power = page.locator('.shead .hmenu').filter({ hasText: 'Power' });
  await power.locator('summary').click();
  await page.waitForTimeout(300); // the entrance
  const items = power.locator('.menu-pop .mi');
  for (let i = 0; i < (await items.count()); i++) {
    await items.nth(i).scrollIntoViewIfNeeded();
    const onTop = await items.nth(i).evaluate((el) => {
      const r = el.getBoundingClientRect();
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return hit !== null && el.contains(hit);
    });
    expect(onTop, `Power menu item ${i} is covered by the page`).toBe(true);
  }

  await page.emulateMedia({ reducedMotion: 'reduce' });
  for (const path of pages) {
    await page.goto(path);
    const m = await longestMotion(page);
    expect(m.ms, `${path}: ${m.where} moves for ${m.ms} ms under reduced motion`).toBe(0);
  }
  await page.goto('/servers/r730xd/sensors');
  expect(await vtName(page, '.bar')).toBe('none');
  expect(await vtName(page, '.tab-ink')).toBe('none');
});
