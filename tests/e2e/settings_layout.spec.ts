// Settings › General lines up (v0.9.1, from a layout review): in every row of a field
// grid the labels end, the controls start and the help lines start at the same height,
// whatever the lock badges, units or help lengths; the catalog panel's values sit beside
// their labels; nothing scrolls sideways on a phone.
import { expect, test, type Page } from '@playwright/test';
import { loadState, signIn } from './auth';

type Misfit = { group: string; part: string; spread: number };

// rowMisfits groups each .gen-rows grid's fields by row (same top) and reports any part
// (label bottom, control top, help top) whose position differs within a row.
async function rowMisfits(page: Page): Promise<Misfit[]> {
  return page.evaluate(() => {
    const out: { group: string; part: string; spread: number }[] = [];
    document.querySelectorAll<HTMLElement>('.gen-rows').forEach((grid, gi) => {
      const rows = new Map<number, HTMLElement[]>();
      grid.querySelectorAll<HTMLElement>(':scope > .field').forEach((f) => {
        const top = Math.round(f.getBoundingClientRect().top);
        rows.set(top, [...(rows.get(top) ?? []), f]);
      });
      rows.forEach((fields) => {
        if (fields.length < 2) return;
        const parts: Record<string, number[]> = { 'label bottom': [], 'control top': [], 'help top': [] };
        for (const f of fields) {
          const [label, control, help] = Array.from(f.children) as HTMLElement[];
          parts['label bottom'].push(label.getBoundingClientRect().bottom);
          parts['control top'].push(control.getBoundingClientRect().top);
          parts['help top'].push(help.getBoundingClientRect().top);
        }
        for (const [part, v] of Object.entries(parts)) {
          const spread = Math.max(...v) - Math.min(...v);
          if (spread > 1) out.push({ group: `grid ${gi}`, part, spread });
        }
      });
    });
    return out;
  });
}

test('Settings › General fields line up and the catalog values sit beside their labels', async ({ browser }) => {
  test.setTimeout(120_000);
  const st = await loadState();
  const signed = await browser.newContext({ ignoreHTTPSErrors: true });
  const first = await signed.newPage();
  await signIn(first, st);
  await first.close();
  const storage = await signed.storageState();
  for (const width of [1700, 1280, 390]) {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height: 900 }, storageState: storage });
    const page = await ctx.newPage();
    await test.step(`${width} px`, async () => {
      await page.goto('/settings/general');
      await expect(page.getByRole('heading', { name: 'App-wide settings' })).toBeVisible();
      await expect(page.getByLabel('Instance name')).toBeVisible();
      expect(await rowMisfits(page), `${width}px: fields out of line`).toEqual([]);
      const kv = await page.evaluate(() =>
        Array.from(document.querySelectorAll<HTMLElement>('.kv-cols > div')).map((row) => {
          const dt = row.querySelector('dt')!.getBoundingClientRect();
          const dd = row.querySelector('dd')!.getBoundingClientRect();
          return { label: row.querySelector('dt')!.textContent!.trim(), dtTop: dt.top, dtBottom: dt.bottom, ddTop: dd.top, ddBottom: dd.bottom };
        }));
      for (const r of kv) {
        // Beside (wide) or directly under (phone) its own label, never in the next row.
        expect(r.ddTop, `${width}px: ${r.label} value starts below its row`).toBeLessThanOrEqual(r.dtBottom + 6);
      }
      const { sw, cw } = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
      expect(sw, `${width}px: page scrolls sideways`).toBeLessThanOrEqual(cw + 1);
    });
    await ctx.close();
  }
  await signed.close();
});
