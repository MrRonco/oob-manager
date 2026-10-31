import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { loadState, signIn, freshTotp } from './auth';

type VNCRecord = { keys: { Down: boolean; Sym: number }[] | null; encodings: number[][] | null; updates: number };

// WCAG 2.2 AA scan of the current page (axe-core). Any violation fails the run.
async function expectAccessible(page: Page, label: string) {
  const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
  const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s) — ${v.help}`);
  expect(summary, `accessibility violations on ${label}`).toEqual([]);
}

// One test, one admin login: a second login in the same 30 s step would replay a code.
test('overview, settings (tokens, users, enrolment link, audit) and sign out', async ({ page, browser }) => {
  const st = await loadState();

  await test.step('login with password and TOTP shows the fleet overview', async () => {
    await page.goto('/');
    await expect(page).toHaveURL(/\/login$/);
    await expectAccessible(page, 'login');
    await signIn(page, st);
    await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
    const main = page.locator('section.fleet-sec');
    await expect(main).toBeVisible();
    await expect(main.getByRole('link', { name: 'Storage node R730XD', exact: true })).toBeVisible();
    await expect(main.getByRole('link', { name: 'Edge node R240', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page');
    await page.screenshot({ path: 'test-results/overview.png', fullPage: true });

    await main.getByRole('link', { name: 'Storage node R730XD', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Verdict and exceptions' })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Breadcrumb' })).toContainText('Servers');
  });

  await test.step('Settings: create an API token, shown once, then revoke it', async () => {
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Settings' }).click();
    await expect(page).toHaveURL(/\/settings\/users$/);
    await page.getByRole('navigation', { name: 'Settings' }).getByRole('link', { name: 'API tokens' }).click();
    await page.getByLabel('Name').fill('smoke');
    await page.getByLabel('Expires').selectOption('30');
    await page.getByRole('button', { name: 'Create token' }).click();
    await expect(page.getByRole('heading', { name: 'Token created' })).toBeVisible();
    const token = await page.locator('#secret').inputValue();
    expect(token).toMatch(/^oobk_[A-Za-z0-9_-]{43}$/);
    await page.screenshot({ path: 'test-results/token-reveal.png', fullPage: true });

    await page.getByRole('link', { name: 'Back to API tokens' }).click();
    await expect(page.locator('body')).not.toContainText(token);
    await page.getByRole('link', { name: 'Revoke… smoke' }).click();
    await expect(page.getByRole('heading', { name: 'Revoke token smoke?', level: 1 })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Cancel' })).toBeFocused();
    await page.getByRole('button', { name: 'Revoke token smoke' }).click();
    await expect(page.getByText('Token revoked.')).toBeVisible();
    const row = page.getByRole('row', { name: /smoke/ });
    await expect(row.getByText('Revoked')).toBeVisible();
  });

  await test.step('Settings: create a user, open the enrolment link, enrol and sign in', async () => {
    await page.getByRole('navigation', { name: 'Settings' }).getByRole('link', { name: 'Users' }).click();
    await page.getByLabel('Username').fill('smokeuser');
    await page.getByLabel('Viewer').check();
    await page.getByRole('button', { name: 'Create user and copy setup link' }).click();
    await expect(page.getByRole('heading', { name: 'User created' })).toBeVisible();
    const link = await page.locator('#secret').inputValue();
    expect(link).toMatch(/\/enroll\/[A-Za-z0-9_-]{43}$/);

    const other = await browser.newContext({ ignoreHTTPSErrors: true });
    const newcomer = await other.newPage();
    await newcomer.goto(link);
    await expect(newcomer.getByRole('heading', { name: 'Set up your account' })).toBeVisible();
    await expectAccessible(newcomer, 'enrollment link');
    const password = 'smoke user long password';
    await newcomer.getByLabel(/New password/).fill(password);
    await newcomer.getByLabel('Repeat the password').fill(password);
    await newcomer.getByRole('button', { name: 'Continue' }).click();
    await expect(newcomer.getByRole('heading', { name: 'Scan your authenticator' })).toBeVisible();
    await expectAccessible(newcomer, 'enrollment reveal');
    const secret = (await newcomer.locator('code[data-secret]').getAttribute('data-secret')) ?? '';
    await newcomer.getByLabel('Password').fill(password);
    await newcomer.getByLabel('Current 6-digit code').fill(await freshTotp(secret));
    await newcomer.getByRole('button', { name: 'Confirm authenticator' }).click();
    await expect(newcomer.getByText('Authenticator confirmed')).toBeVisible();

    await signIn(newcomer, st, { username: 'smokeuser', password, secret });
    await expect(newcomer.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
    await expect(newcomer.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Settings' })).toHaveCount(0);
    await other.close();

    await page.goto('/settings/users');
    await expect(page.getByRole('row', { name: /smokeuser/ }).getByText('Active')).toBeVisible();
  });

  await test.step('Settings: verify the audit chain', async () => {
    await page.getByRole('navigation', { name: 'Settings' }).getByRole('link', { name: 'Audit log' }).click();
    await page.getByRole('button', { name: 'Verify chain' }).click();
    await expect(page.getByText('Chain intact.')).toBeVisible();
    await page.screenshot({ path: 'test-results/audit.png', fullPage: true });
  });

  await test.step('graphical console: noVNC shows the fake BMC screen and Ctrl-Alt-Del reaches it', async () => {
    // The sign-in code counts as the step-up, so the console opens without another code.
    await page.goto('/servers/r730xd');
    await expect(page.getByRole('heading', { name: 'Graphical console' })).toBeVisible();
    await page.getByRole('link', { name: 'Open console' }).click();
    await expect(page.getByRole('heading', { name: 'Graphical console: Storage node R730XD', level: 1 })).toBeVisible();
    await expectAccessible(page, 'console page (connect)');
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#console-status')).toHaveText('Connected');

    // The fake BMC answers with a solid red frame; noVNC must have drawn it.
    await expect
      .poll(
        async () =>
          page.evaluate(() => {
            const c = document.querySelector<HTMLCanvasElement>('#console-screen canvas');
            if (!c || c.width < 10) return 'no canvas';
            const d = c.getContext('2d')!.getImageData(Math.floor(c.width / 2), Math.floor(c.height / 2), 1, 1).data;
            return d[0] > 200 && d[1] < 60 && d[2] < 60 ? 'red' : `rgb(${d[0]},${d[1]},${d[2]})`;
          }),
        { timeout: 10_000 },
      )
      .toBe('red');
    await page.screenshot({ path: 'test-results/console.png', fullPage: true });
    await expectAccessible(page, 'console page (connected)');

    await page.getByRole('button', { name: 'Send Ctrl-Alt-Del' }).click();
    const want = [[true, 0xffe3], [true, 0xffe9], [true, 0xffff], [false, 0xffff], [false, 0xffe9], [false, 0xffe3]];
    const vnc = async () => (await (await fetch(st.vnc_debug_url + '/vnc')).json()) as VNCRecord;
    await expect.poll(async () => ((await vnc()).keys ?? []).map((k) => [k.Down, k.Sym])).toEqual(want);
    expect([...((await vnc()).encodings?.[0] ?? [])].sort((a, b) => a - b)).toEqual([-223, 0, 1]); // iDRAC8 safe-encodings quirk

    const viewOnly = page.getByRole('button', { name: 'View only' });
    await viewOnly.click();
    await expect(viewOnly).toHaveAttribute('aria-pressed', 'true');
    await page.getByRole('button', { name: 'Disconnect' }).click();
    await expect(page.locator('#console-status')).toHaveText('Disconnected');
    await expect(page.getByRole('button', { name: 'Reconnect' })).toBeVisible();
  });

  await test.step('serial console: xterm.js echo through the fake BMC, transcript, break and quit', async () => {
    await page.goto('/servers/r730xd');
    await expect(page.getByRole('heading', { name: 'Serial console', exact: true })).toBeVisible();
    await page.getByRole('link', { name: 'Open serial console' }).click();
    await expect(page.getByRole('heading', { name: 'Serial console: Storage node R730XD', level: 1 })).toBeVisible();
    await expectAccessible(page, 'serial page (connect)');
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#serial-status')).toHaveText('Connected');
    const transcript = page.getByRole('log');
    await expect(transcript).toContainText('Connected to Serial Device 2');
    await expect(page.locator('#serial-silent')).toBeHidden();

    // Typed into the terminal, echoed by the fake BMC, shown in the plain-text transcript.
    await page.locator('#serial-term').click();
    await page.keyboard.type('echo-test');
    await page.keyboard.press('Enter');
    await expect(transcript).toContainText('echo-test');
    const ssh = async () => (await (await fetch(st.vnc_debug_url + '/ssh')).json()) as { input: string; requests: string[] };
    await expect.poll(async () => (await ssh()).input).toContain('echo-test\r');
    expect((await ssh()).requests.slice(0, 2)).toEqual(['pty-req', 'exec']);
    await page.screenshot({ path: 'test-results/serial.png', fullPage: true });
    await expectAccessible(page, 'serial page (connected)');

    await page.getByRole('button', { name: 'Send break' }).click();
    await expect(transcript).toContainText('<BREAK>');
    await page.getByRole('button', { name: 'Larger text' }).click();
    await page.getByRole('button', { name: 'Send Ctrl-\\ (end console)' }).click();
    await expect(page.locator('#serial-status')).toHaveText('Console ended');
    await expect(page.getByRole('button', { name: 'Reconnect' })).toBeVisible();
    expect((await ssh()).input.endsWith('\x1c')).toBe(true);
  });

  await test.step('serial console: a silent host shows the BIOS redirection hint', async () => {
    await page.goto('/servers/r240/serial');
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#serial-status')).toHaveText('Connected');
    await expect(page.getByText('Connected, but the host has sent nothing yet.')).toBeVisible({ timeout: 15_000 });
    await expectAccessible(page, 'serial page (silent host)');
    await page.getByRole('button', { name: 'Disconnect' }).click();
    await expect(page.getByRole('button', { name: 'Reconnect' })).toBeVisible();
  });

  await test.step('accessibility: main pages pass WCAG 2.2 AA (axe)', async () => {
    for (const path of ['/', '/servers', '/events', '/settings/users', '/settings/tokens', '/settings/audit', '/about']) {
      await page.goto(path);
      await expectAccessible(page, path);
    }
    // a server detail page, reached through the overview link
    await page.goto('/');
    await page.locator('section.fleet-sec').getByRole('link', { name: 'Storage node R730XD', exact: true }).click();
    await expectAccessible(page, 'server page');
  });

  await test.step('sign out', async () => {
    await page.locator('details.usermenu summary').click();
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/login$/);
  });
});
