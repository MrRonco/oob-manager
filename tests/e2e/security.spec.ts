// BMC security checks (tech_doc §31) in a real browser: the Security tab with its findings
// and what to do, a finding accepted as a risk with a comment and the acceptance removed,
// a re-run (the button then shows why it is unavailable), the fleet table's Security
// column, and axe WCAG 2.2 AA scans of each state at 1440 and 390 px.
import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { expectNoHorizontalScroll } from './overflow';
import { loadState, signIn } from './auth';

async function axe(page: Page, label: string) {
  const r = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
    .analyze();
  const summary = r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(' ')).join(', ')}: ${v.help}`);
  expect(summary, `accessibility violations on ${label}`).toEqual([]);
}

async function axeBoth(page: Page, label: string) {
  await axe(page, label);
  await page.setViewportSize({ width: 390, height: 844 });
  // From the top: on a phone the server's action bar is fixed at the bottom, and a target
  // that happens to sit half under it at the current scroll offset reads as too small.
  await page.evaluate(() => window.scrollTo(0, 0));
  await axe(page, `${label} 390`);
  await expectNoHorizontalScroll(page, label, 390);
  await page.setViewportSize({ width: 1440, height: 900 });
}

const tab = '/servers/r730xd/security';
const flash = (page: Page, text: string) => page.getByRole('status').filter({ hasText: text });

test('security checks: findings, an accepted risk and a re-run', async ({ page }) => {
  const st = await loadState();
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, st);

  await test.step('the first run finishes', async () => {
    // The harness is ready once every BMC was polled; the checks run after that first
    // good poll (Redfish reads, then handshakes spaced 150 ms apart), so reload the tab
    // until the verdict is there.
    await expect
      .poll(
        async () => {
          await page.goto(tab);
          return page.locator('#security .verdict').count();
        },
        { timeout: 60_000, intervals: [1_000] },
      )
      .toBe(1);
  });

  await test.step('the Security tab lists the findings with what to do', async () => {
    await page.goto(tab);
    await expect(page.getByRole('heading', { name: 'BMC security checks', level: 2 })).toBeVisible();
    await expect(page.locator('#security .verdict')).toContainText(/need attention|fail/);
    await expect(page.getByRole('heading', { name: /^TLS and SSH/, level: 2 })).toBeVisible();
    const finding = page.locator('#chk-acct-default_names');
    await expect(finding).toContainText('Enabled with a factory default name: root.');
    await finding.locator('summary', { hasText: 'Why it matters' }).click();
    await expect(finding).toContainText('Dell iDRAC:');
    await axeBoth(page, 'security tab');
  });

  await test.step('accept a finding as a risk, then remove the acceptance', async () => {
    const finding = page.locator('#chk-acct-default_names');
    await finding.locator('summary', { hasText: 'Accept as a risk' }).click();
    await finding.getByLabel('Why is this risk accepted?').fill('Lab BMC; the factory password was changed');
    await finding.getByRole('button', { name: 'Accept risk' }).click();
    await expect(flash(page, 'Finding accepted as a risk.')).toBeVisible();
    await expect(page.locator('#chk-acct-default_names .acked')).toContainText('Lab BMC; the factory password was changed');
    await expect(page.locator('#security .strip')).toContainText('Accepted risk');
    await axeBoth(page, 'security tab with an accepted risk');
    await page.locator('#chk-acct-default_names').getByRole('button', { name: /Remove acceptance/ }).click();
    await expect(flash(page, 'Acceptance removed.')).toBeVisible();
    await expect(page.locator('#chk-acct-default_names .acked')).toHaveCount(0);
  });

  await test.step('re-run the checks', async () => {
    await page.getByRole('button', { name: 'Re-run checks' }).click();
    await expect(flash(page, 'Re-run requested.')).toBeVisible();
    await expect(page.locator('#rerun-why')).toContainText(/available again in|already on its way/);
    await axeBoth(page, 'security tab after a re-run');
  });

  await test.step('the fleet table (Servers page) links to the Security tab', async () => {
    await page.goto('/servers');
    await page.locator(`a[href="${tab}"]`).first().click();
    await expect(page).toHaveURL(new RegExp(`${tab}$`));
    await expect(page.getByRole('heading', { name: 'BMC security checks', level: 2 })).toBeVisible();
  });
});
