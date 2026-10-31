// Renders testdata/showcase/boot-menu.html to boot-menu.png (1024x768, device scale 1):
// the screen the dev harness's fake VNC server shows in showcase mode. Run it from
// tests/e2e after changing the HTML, then commit both files:
//   node showcase/render-frame.mjs
import { chromium } from '@playwright/test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as path from 'node:path';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../testdata/showcase');
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1024, height: 768 }, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(path.join(dir, 'boot-menu.html')).href);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(dir, 'boot-menu.png') });
} finally {
  await browser.close();
}
