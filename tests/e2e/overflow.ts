// Shared "no horizontal page scroll" assertion. On failure it names the elements whose
// right edge passes the viewport, so a CI-only overflow (different fonts) is diagnosable
// from the log alone.
import { expect, type Page } from '@playwright/test';

type Offender = { sel: string; right: number; width: number };

// Elements clipped by an overflow:hidden/clip ancestor (e.g. .sr-only text) cannot widen
// the page, so they are skipped; only the outermost offender of each subtree is kept.
async function offenders(page: Page, width: number): Promise<Offender[]> {
  return page.evaluate((w) => {
    const sel = (el: Element): string => {
      const parts: string[] = [];
      for (let e: Element | null = el; e && e !== document.body && parts.length < 4; e = e.parentElement) {
        const cls = [...e.classList].slice(0, 2).map((c) => `.${c}`).join('');
        parts.unshift(e.tagName.toLowerCase() + (e.id ? `#${e.id}` : '') + cls);
      }
      return parts.join(' > ');
    };
    const clipped = (el: Element): boolean => {
      for (let e = el.parentElement; e && e !== document.documentElement; e = e.parentElement) {
        const o = getComputedStyle(e).overflowX;
        if (o === 'hidden' || o === 'clip' || o === 'auto' || o === 'scroll') return true;
      }
      return false;
    };
    const out: { sel: string; right: number; width: number; el: Element }[] = [];
    for (const el of document.querySelectorAll('body *')) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.right <= w + 0.5 || clipped(el)) continue;
      if (out.some((o) => o.el.contains(el))) continue;
      out.push({ sel: sel(el), right: Math.round(r.right), width: Math.round(r.width), el });
    }
    return out.slice(0, 8).map(({ sel: s, right, width: wd }) => ({ sel: s, right, width: wd }));
  }, width);
}

export async function expectNoHorizontalScroll(page: Page, label: string, width: number): Promise<void> {
  const sw = await page.evaluate(() => document.documentElement.scrollWidth);
  if (sw <= width) return;
  const list = (await offenders(page, width)).map((o) => `${o.sel} (right ${o.right}px, width ${o.width}px)`);
  expect(sw, `horizontal page scroll on ${label}; widest: ${list.join('; ') || 'none found'}`).toBeLessThanOrEqual(width);
}
