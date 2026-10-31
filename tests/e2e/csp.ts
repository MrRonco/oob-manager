// Plan 06 §3.4: there is no CSP report endpoint (security.md §3), so the page matrix in
// pages.spec.ts is the detector instead: every page it visits records its
// `securitypolicyviolation` events, and any outside this allowlist fails the run. The one
// allowed case: xterm.js injects a <style> element for its renderer on the serial page.
import type { BrowserContext, Page } from '@playwright/test';

export type CSPViolation = { path: string; directive: string; blocked: string; sample: string };

// recordCSP makes every page of ctx collect its violations in window.__csp.
export async function recordCSP(ctx: BrowserContext): Promise<void> {
  await ctx.addInitScript(() => {
    const w = window as unknown as { __csp: Array<Record<string, string>> };
    w.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => {
      w.__csp.push({ directive: e.effectiveDirective || e.violatedDirective, blocked: e.blockedURI,
        sample: e.sample || '' });
    });
  });
}

// cspViolations returns the violations recorded on the current page.
export async function cspViolations(page: Page): Promise<CSPViolation[]> {
  const got = await page.evaluate(() => (window as unknown as { __csp?: Array<Record<string, string>> }).__csp ?? []);
  const path = new URL(page.url()).pathname;
  return got.map((v) => ({ path, directive: v.directive, blocked: v.blocked, sample: v.sample }));
}

// allowedCSP: xterm.js style injection on /servers/<id>/serial, nothing else.
export function allowedCSP(v: CSPViolation): boolean {
  return /^\/servers\/[a-z0-9-]+\/serial$/.test(v.path) && v.directive.startsWith('style-src') &&
    (v.blocked === 'inline' || v.blocked === '');
}

export function describeCSP(v: CSPViolation): string {
  return `${v.path}: ${v.directive} blocked ${v.blocked || '(inline)'} ${v.sample}`.trim();
}
