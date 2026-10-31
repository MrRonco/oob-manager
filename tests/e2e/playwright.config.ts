// Playwright smoke test for oob-manager. The web server is the Go dev harness
// (bin/e2e.test, built by `make e2e-bin`): two mock BMCs, a temp install and the real
// `serve` command. Sign-in details are written to a temp file and never committed.
import { defineConfig } from '@playwright/test';
import * as os from 'node:os';
import * as path from 'node:path';

const port = process.env.OOB_E2E_PORT ?? '18443';
// The harness binary; `make visual` runs a linux/amd64 build of it inside the container.
const bin = process.env.OOB_E2E_BIN ?? '../../bin/e2e.test';
// A file NAME only: the harness always creates it in the temp directory.
const stateName = `oob-manager-e2e-${port}.json`;
// CI runs the suite in two parts on two runners (ci.yml e2e-ui matrix). OOB_E2E_IGNORE is a
// comma-separated list of spec files to skip, so the "rest" part picks up any new spec by itself.
const ignore = (process.env.OOB_E2E_IGNORE ?? '').split(',').filter(Boolean);
// OOB_SHOWCASE=1 (`make showcase`, showcase.spec.ts) starts the dev server with the README
// screenshot fixtures and the UI's own auto-refresh interval instead of the 3 s test one.
const showcase = process.env.OOB_SHOWCASE === '1';
const devEnv = showcase ? { OOB_DEV_SHOWCASE: '1' } : { OOB_DEV_REFRESH: '3s' };
process.env.OOB_DEV_STATE_FILE = path.join(os.tmpdir(), stateName); // read by the spec

export default defineConfig({
  testDir: '.',
  testIgnore: ignore,
  timeout: 120_000,
  retries: 0,
  workers: 1, // one dev server; TOTP codes are single-use per 30 s step
  forbidOnly: !!process.env.CI,
  reporter: [['list']],
  outputDir: 'test-results',
  // Visual baselines (visual.spec.ts, made only in the pinned container; see README.md).
  // The platform suffix keeps a stray run on another OS from ever matching them.
  snapshotPathTemplate: '{testDir}/visual-baseline/{arg}{-platform}{ext}',
  // threshold is pixelmatch's per-pixel colour distance (YIQ, 0..1): 0.02 catches a tonal
  // shift inside one theme (Graphite --bg against --border is about 0.13; a border moved
  // by 2.6 % OKLCH lightness, about 0.023, failed 37 of 43 dark 1440 images); anti-aliased
  // pixels are ignored by pixelmatch itself, and maxDiffPixelRatio absorbs the rest.
  expect: {
    toHaveScreenshot: { maxDiffPixelRatio: 0.002, threshold: 0.02, animations: 'disabled', caret: 'hide', scale: 'css' },
  },
  globalTeardown: './teardown.ts', // removes auth.ts's TOTP bookkeeping file

  use: {
    baseURL: `https://127.0.0.1:${port}`,
    ignoreHTTPSErrors: true, // self-signed certificate generated per run
    // Plan 04 §7: every spec runs with reduced motion, so no entrance or view transition is
    // half-way when a spec clicks, scans or screenshots; motion.spec.ts opts back in.
    reducedMotion: 'reduce',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  webServer: {
    command: `${bin} -test.run ^TestDevServer$ -test.timeout 0`,
    url: `https://127.0.0.1:${port}/readyz`,
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 120_000,
    // OOB_DEV_REFRESH shortens the opt-in auto-refresh so refresh.spec.ts can watch it.
    env: { OOB_DEV: '1', OOB_DEV_LISTEN: `127.0.0.1:${port}`, OOB_DEV_STATE: stateName, ...devEnv },
  },
});
