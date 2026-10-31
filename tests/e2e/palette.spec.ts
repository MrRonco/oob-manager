// Go to palette (plan 04 §7 and §11 item 7, docs/tech_doc.md §52): palette.js opened from the
// keyboard and from the account menu, filtering, arrow keys, Enter navigating, Escape
// restoring focus, the g o / g s / "/" / "?" shortcuts, no shortcut inside a field or a
// connected console, the per-browser switch for the single-key shortcuts (WCAG 2.1.4), the
// recent pages (paths only, cleared at sign-out), axe on the open palette in both schemes,
// the 250 ms motion budget, and the no-script /go page.
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { loadState, signIn } from './auth';

type Storage = Awaited<ReturnType<BrowserContext['storageState']>>;
let storage: Storage;

test.beforeAll(async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  await signIn(await ctx.newPage(), await loadState());
  storage = await ctx.storageState();
  await ctx.close();
});

async function context(browser: Browser, opts: Parameters<Browser['newContext']>[0] = {}): Promise<BrowserContext> {
  return browser.newContext({ ignoreHTTPSErrors: true, storageState: storage, ...opts });
}

const palette = (page: Page) => page.getByRole('dialog', { name: 'Go to' });
const field = (page: Page) => palette(page).getByRole('combobox', { name: 'Go to a page, server or setting' });
const selected = (page: Page) => palette(page).locator('[role="option"][aria-selected="true"]');

async function axe(page: Page, label: string) {
  const r = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
    .analyze();
  const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s): ${v.help}`);
  expect(summary, `accessibility violations on ${label}`).toEqual([]);
}

test('a connected console (serial and graphical) gets every key: no shortcut fires on its page', async ({ browser }) => {
  const st = await loadState();
  const ctx = await context(browser);
  const page = await ctx.newPage();
  await page.goto('/servers/r730xd/serial');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('#serial-status')).toHaveText('Connected');
  await page.locator('#serial-term').click();
  await page.keyboard.type('gs/?go');
  await page.keyboard.press('Control+k');
  await expect(page).toHaveURL(/\/servers\/r730xd\/serial$/);
  await expect(palette(page)).toBeHidden();
  const ssh = async () => (await (await fetch(st.vnc_debug_url + '/ssh')).json()) as { input: string };
  await expect.poll(async () => (await ssh()).input).toContain('gs/?go');
  // Focus outside the terminal (the toolbar) does not bring the shortcuts back either.
  await page.getByRole('button', { name: 'Send break' }).focus();
  await page.keyboard.press('g');
  await page.keyboard.press('o');
  await expect(page).toHaveURL(/\/servers\/r730xd\/serial$/);
  await page.getByRole('button', { name: 'Disconnect' }).click();
  await expect(page.getByRole('button', { name: 'Reconnect' })).toBeVisible();

  // The graphical console: no shortcut on its page either, even with focus on the toolbar. (No
  // key is typed into the canvas: the fake BMC keeps one key record for the whole run, and
  // smoke.spec.ts expects exactly its own Ctrl-Alt-Del there.)
  await page.goto('/servers/r730xd/console');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page.locator('#console-status')).toHaveText('Connected');
  await page.getByRole('button', { name: 'View only' }).focus();
  await page.keyboard.press('g');
  await page.keyboard.press('s');
  await page.keyboard.press('Control+k');
  await expect(page).toHaveURL(/\/servers\/r730xd\/console$/);
  await expect(palette(page)).toBeHidden();
  await page.getByRole('button', { name: 'Disconnect' }).click();
  await expect(page.locator('#console-status')).toHaveText('Disconnected');
  // On a console page the "Go to…" link is a plain link to /go: the palette never opens there.
  await page.locator('details.usermenu summary').click();
  await expect(page.locator('details.usermenu [data-palette-key]')).toBeHidden();
  await page.locator('details.usermenu').getByRole('link', { name: /Go to/ }).click();
  await expect(page).toHaveURL(/\/go$/);
  await expect(page.getByRole('heading', { name: 'Go to', level: 1 })).toBeVisible();
  await ctx.close();
});

// addControls adds a text area, a select and a checkbox to the page's main column, so
// each kind of unsaved input can be tried on any page.
async function addControls(page: Page) {
  await page.evaluate(() => {
    const main = document.querySelector('main')!;
    const form = document.createElement('form');
    form.id = 'pw-unsaved';
    const ta = document.createElement('textarea');
    ta.id = 'pw-ta';
    ta.setAttribute('aria-label', 'Test text');
    const sel = document.createElement('select');
    sel.id = 'pw-sel';
    sel.setAttribute('aria-label', 'Test select');
    for (const v of ['a', 'b']) sel.appendChild(new Option(v, v, v === 'a', v === 'a'));
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.id = 'pw-cb';
    cb.setAttribute('aria-label', 'Test box');
    form.append(ta, sel, cb);
    main.prepend(form);
  });
}

test('unsaved input in a text area, a select or a checkbox holds every way off the page', async ({ browser }) => {
  const ctx = await context(browser);
  const page = await ctx.newPage();
  await page.goto('/activity');
  const h1 = page.getByRole('heading', { level: 1 }).first();
  const edits: Array<[string, (p: Page) => Promise<void>, (p: Page) => Promise<void>]> = [
    ['text area', (p) => p.locator('#pw-ta').fill('half-typed'), (p) => p.locator('#pw-ta').fill('')],
    ['select', (p) => p.locator('#pw-sel').selectOption('b'), (p) => p.locator('#pw-sel').selectOption('a')],
    ['checkbox', (p) => p.locator('#pw-cb').check(), (p) => p.locator('#pw-cb').uncheck()],
  ];
  await addControls(page);
  for (const [kind, edit, undo] of edits) {
    await edit(page);
    await h1.click();
    await page.keyboard.press('g');
    await page.keyboard.press('s');
    await page.keyboard.press('?');
    await expect(page, `${kind}: g s / ? left the page`).toHaveURL(/\/activity$/);
    // The palette refuses too, and says why.
    await page.keyboard.press('Control+k');
    await page.keyboard.type('overview');
    await page.keyboard.press('Enter');
    await expect(palette(page).getByText(/unsaved input/)).toBeVisible();
    if (kind === 'text area') await axe(page, 'palette with the unsaved-input note');
    await expect(page, `${kind}: the palette left the page`).toHaveURL(/\/activity$/);
    await page.keyboard.press('Escape');
    await undo(page);
  }
  // Back to the defaults: the shortcuts work again.
  await h1.click();
  await page.keyboard.press('g');
  await page.keyboard.press('s');
  await expect(page).toHaveURL(/\/servers$/);
  await ctx.close();
});

test('recent pages: lists of other users, stale paths and lost Settings are never offered; names stay text', async ({ browser }) => {
  const ctx = await context(browser);
  const page = await ctx.newPage();
  await page.goto('/servers');
  const user = (await page.locator('.usermenu .who-n').textContent())?.trim() ?? '';
  const store = (u: string, items: Array<{ p: string; l: string }>) =>
    page.evaluate(([who, list]) => sessionStorage.setItem('oob.palette.recent', JSON.stringify({ u: who, items: list })),
      [u, items] as const);
  const recent = palette(page).getByRole('group', { name: 'Recent' });

  // Bound to the username: a list stored for someone else shows nothing.
  await store(`${user}-other`, [{ p: '/activity', l: 'Their activity' }]);
  await page.goto('/servers');
  await page.keyboard.press('Control+k');
  await expect(recent).toHaveCount(0);
  await page.keyboard.press('Escape');

  // Only paths this user can still reach: a destination, or a page below one (a server's tab).
  await store(user, [{ p: '/servers/r240/sensors', l: 'Edge sensors' }, { p: '/servers/gone', l: 'Gone server' },
    { p: '/nope', l: 'Nowhere' }, { p: '/settings/users', l: 'Settings users' }, { p: '/events', l: 'All events' },
    { p: '/servers/r240/../../settings/users', l: 'Dot escape' }]);
  await page.goto('/servers');
  await page.keyboard.press('Control+k');
  await expect(recent.getByRole('option')).toHaveText(['Edge sensors', 'Settings users', 'All events']);
  await page.keyboard.press('Escape');
  // A role without Settings or Events (simulated: the server list without them) hides those.
  await page.evaluate(() => {
    const tpl = document.getElementById('oob-go') as HTMLTemplateElement;
    tpl.content.querySelector('[data-group="Settings"]')?.remove();
    tpl.content.querySelectorAll('a[href="/settings"], a[href="/events"]').forEach((a) => a.closest('li')?.remove());
  });
  await page.keyboard.press('Control+k');
  await expect(recent.getByRole('option')).toHaveText(['Edge sensors']);
  await page.keyboard.press('Escape');

  // A name with markup is shown as text, never parsed.
  await page.evaluate(() => {
    const tpl = document.getElementById('oob-go') as HTMLTemplateElement;
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = '/servers/r240';
    a.textContent = '<img src=x id=pw-xss>';
    li.appendChild(a);
    tpl.content.querySelector('[data-group="Servers"] ul')?.appendChild(li);
  });
  await page.keyboard.press('Control+k');
  await page.keyboard.type('img');
  await expect(palette(page).getByRole('option', { name: '<img src=x id=pw-xss>' })).toBeVisible();
  await expect(page.locator('#pw-xss')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await ctx.close();
});

test('Ctrl+K and Cmd+K open it; typing filters, arrows move, Enter navigates, Escape restores focus', async ({ browser }) => {
  const ctx = await context(browser);
  const page = await ctx.newPage();
  await page.goto('/servers');
  const brand = page.locator('a.brand');
  await brand.focus();
  await page.keyboard.press('Control+k');
  await expect(palette(page)).toBeVisible();
  await expect(field(page)).toBeFocused();
  await expect(palette(page).getByRole('group', { name: 'Pages' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(palette(page)).toBeHidden();
  await expect(brand).toBeFocused();

  await page.keyboard.press('Meta+k');
  await expect(palette(page)).toBeVisible();
  // Tab stays inside the dialog.
  for (let i = 0; i < 4; i++) await page.keyboard.press('Tab');
  expect(await page.evaluate(() => !!document.activeElement?.closest('dialog.pal'))).toBe(true);
  await field(page).focus();

  await page.keyboard.type('edge');
  await expect(palette(page).getByRole('option')).toHaveCount(1);
  await expect(selected(page)).toContainText('Edge node R240');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Backspace');
  await page.keyboard.type('node');
  const first = await selected(page).textContent();
  await page.keyboard.press('ArrowDown');
  await expect(selected(page)).not.toHaveText(first ?? '');
  await page.keyboard.press('ArrowUp');
  await expect(selected(page)).toHaveText(first ?? '');
  await page.keyboard.press('ArrowUp'); // wraps to the last match
  await expect(selected(page)).toContainText('Edge node R240');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/servers\/r240$/);
  await page.waitForLoadState();

  // Nothing matches: the listbox is hidden and a note points to the Go to page.
  await page.keyboard.press('Control+k');
  await page.keyboard.type('zzzz');
  await expect(palette(page).getByText('Nothing matches.')).toBeVisible();
  await expect(field(page)).toHaveAttribute('aria-expanded', 'false');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/servers\/r240$/);
  await page.keyboard.press('Escape');
  await ctx.close();
});

test('g o, g s, "/" and "?" work outside fields, and never inside one', async ({ browser }) => {
  const ctx = await context(browser);
  const page = await ctx.newPage();
  await page.goto('/activity');
  await page.keyboard.press('g');
  await page.keyboard.press('s');
  await expect(page).toHaveURL(/\/servers$/);
  await page.waitForLoadState();
  await page.keyboard.press('g');
  await page.keyboard.press('o');
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
  await expect(page).toHaveURL(/\/$/);

  // "/" focuses the page's filter field where there is one, else opens the palette.
  await page.goto('/events');
  await page.keyboard.press('/');
  await expect(page.getByLabel('Search message')).toBeFocused();
  // Typing in the field: no shortcut fires, every key reaches the field.
  await page.keyboard.type('gs/?go');
  await page.keyboard.press('Control+k');
  await expect(page).toHaveURL(/\/events$/);
  await expect(palette(page)).toBeHidden();
  await expect(page.getByLabel('Search message')).toHaveValue('gs/?go');
  // Out of the field, but with that input not yet submitted: the leaving shortcuts wait.
  await page.getByRole('heading', { name: 'Events', level: 1 }).click();
  await page.keyboard.press('g');
  await page.keyboard.press('s');
  await page.keyboard.press('?');
  await expect(page).toHaveURL(/\/events$/);
  await page.goto('/servers');
  await page.keyboard.press('/');
  await expect(palette(page)).toBeVisible();
  await page.keyboard.press('Escape');

  await page.keyboard.press('?');
  await expect(page).toHaveURL(/\/go#shortcuts$/);
  await expect(page.getByRole('heading', { name: 'Keyboard shortcuts' })).toBeVisible();
  await ctx.close();
});

test('the single-key shortcuts can be switched off per browser; Ctrl+K stays', async ({ browser }) => {
  const ctx = await context(browser);
  const page = await ctx.newPage();
  await page.goto('/go#shortcuts');
  const box = page.getByLabel(/Use the single-key shortcuts/);
  await expect(box).toBeChecked();
  await box.uncheck();
  await page.goto('/activity');
  await page.keyboard.press('g');
  await page.keyboard.press('s');
  await page.keyboard.press('?');
  await expect(page).toHaveURL(/\/activity$/);
  await page.keyboard.press('Control+k');
  await expect(palette(page)).toBeVisible();
  await page.keyboard.press('Escape');
  await page.goto('/go');
  await expect(box).not.toBeChecked();
  await box.check();
  await page.goto('/activity');
  await page.keyboard.press('g');
  await page.keyboard.press('s');
  await expect(page).toHaveURL(/\/servers$/);
  await ctx.close();
});

test('the account menu opens the palette and focus returns to the menu', async ({ browser }) => {
  const ctx = await context(browser);
  const page = await ctx.newPage();
  await page.goto('/');
  const summary = page.locator('details.usermenu summary');
  await summary.click();
  await expect(page.locator('details.usermenu [data-palette-key]')).toHaveText(/K$/);
  await page.locator('details.usermenu').getByRole('link', { name: /Go to/ }).click();
  await expect(palette(page)).toBeVisible();
  await expect(page.locator('details.usermenu')).not.toHaveAttribute('open', '');
  await page.keyboard.press('Escape');
  await expect(summary).toBeFocused();
  // A click on the backdrop closes it too.
  await page.keyboard.press('Control+k');
  await page.mouse.click(5, 5);
  await expect(palette(page)).toBeHidden();
  await ctx.close();
});

test('axe passes on the open palette in both schemes, at 1440 and 390', async ({ browser }) => {
  for (const colorScheme of ['dark', 'light'] as const) {
    for (const width of [1440, 390]) {
      const ctx = await context(browser, { colorScheme, viewport: { width, height: 844 } });
      const page = await ctx.newPage();
      await page.goto('/servers/r730xd');
      await page.keyboard.press('Control+k');
      await expect(palette(page)).toBeVisible();
      await axe(page, `palette ${colorScheme} ${width}`);
      await page.keyboard.type('zzzz');
      await axe(page, `palette (no match) ${colorScheme} ${width}`);
      const box = await palette(page).boundingBox();
      expect(box && box.x >= 0 && box.x + box.width <= width, 'palette fits the viewport').toBe(true);
      await ctx.close();
    }
  }
});

test('the palette enters within the motion budget, and not at all under reduced motion', async ({ browser }) => {
  for (const reducedMotion of ['no-preference', 'reduce'] as const) {
    const ctx = await context(browser, { reducedMotion });
    const page = await ctx.newPage();
    await page.goto('/');
    await page.keyboard.press('Control+k');
    const dur = await palette(page).evaluate((el) => getComputedStyle(el).transitionDuration);
    const ms = Math.max(...dur.split(',').map((x) => (x.trim().endsWith('ms') ? parseFloat(x) : parseFloat(x) * 1000)));
    if (reducedMotion === 'reduce') expect(ms).toBe(0);
    else expect(ms).toBeGreaterThan(0);
    expect(ms).toBeLessThanOrEqual(250);
    await ctx.close();
  }
});

test('without scripts, Go to is a page with a working filter and the menu link goes there', async ({ browser }) => {
  const ctx = await context(browser, { javaScriptEnabled: false });
  const page = await ctx.newPage();
  await page.goto('/');
  await page.locator('details.usermenu summary').click();
  await page.locator('details.usermenu').getByRole('link', { name: /Go to/ }).click();
  await expect(page).toHaveURL(/\/go$/);
  await expect(page.getByRole('heading', { name: 'Go to', level: 1 })).toBeVisible();
  await expect(page.locator('#sc-toggle')).toBeHidden();
  await page.getByLabel('Filter', { exact: true }).fill('edge');
  await page.getByRole('button', { name: 'Filter', exact: true }).click();
  await expect(page).toHaveURL(/\/go\?q=edge$/);
  await expect(page.locator('.golist a')).toHaveText(['Edge node R240']);
  await page.locator('.golist a').click();
  await expect(page).toHaveURL(/\/servers\/r240$/);
  await ctx.close();
});

// Last: it signs the shared session out.
test('the palette lists the server tabs and recent pages, never a query string, and forgets them at sign-out', async ({ browser }) => {
  const ctx = await context(browser);
  const page = await ctx.newPage();
  await page.goto('/servers/r730xd/sensors');
  await page.goto('/events?severity=all&range=all');
  await page.goto('/servers/r730xd');
  await page.keyboard.press('Control+k');
  const tabs = palette(page).getByRole('group', { name: 'This server' });
  await expect(tabs.getByRole('option', { name: /Sensors/ })).toBeVisible();
  const recent = palette(page).getByRole('group', { name: 'Recent' });
  await expect(recent.getByRole('option', { name: /sensors/i })).toBeVisible();
  await expect(recent.getByRole('option', { name: /^Events/ })).toBeVisible();
  const stored = await page.evaluate(() => sessionStorage.getItem('oob.palette.recent') ?? '');
  expect(stored).toContain('"/events"');
  expect(stored).not.toContain('severity');
  expect(stored).not.toContain('?');
  await page.keyboard.press('Escape');

  // A page the server does not mark (an error page, /go itself) is never remembered.
  await page.goto('/servers/nope');
  await page.goto('/go');
  expect(await page.evaluate(() => sessionStorage.getItem('oob.palette.recent') ?? '')).not.toMatch(/nope|"\/go"/);

  // Tampered storage is ignored entry by entry: only clean same-origin paths survive.
  await page.evaluate(() => sessionStorage.setItem('oob.palette.recent', JSON.stringify({
    u: document.querySelector('.usermenu .who-n')?.textContent?.trim(),
    items: [{ p: 'https://evil.example/', l: 'Evil' }, { p: '//evil.example', l: 'Evil2' }, { p: '/x?token=1', l: 'Evil3' },
      { p: '/activity', l: 'Activity page' }],
  })));
  await page.goto('/servers');
  await page.keyboard.press('Control+k');
  await expect(recent.getByRole('option')).toHaveText(['Activity page']);
  await page.keyboard.press('Escape');

  await page.locator('details.usermenu summary').click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect(await page.evaluate(() => sessionStorage.getItem('oob.palette.recent'))).toBeNull();
  await ctx.close();
});
