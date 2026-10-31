// Shared sign-in helpers for the Playwright specs (test-only): the dev-harness state
// file, the authenticator code and the sign-in, with the timing rules every spec follows.
import { expect, type Page } from '@playwright/test';
import { createHash, createHmac } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';

// What the dev harness (cmd/oob-manager/dev_test.go) writes once every mock BMC was polled.
export type DevState = {
  url: string; username: string; password: string; totp_secret: string; vnc_debug_url: string;
  extra_address: string; extra_user: string; extra_password: string; gelf_tls_address: string;
};

export async function loadState(): Promise<DevState> {
  const file = process.env.OOB_DEV_STATE_FILE ?? '';
  if (file === '') {
    throw new Error('OOB_DEV_STATE_FILE is not set: run the specs through playwright.config.ts (make e2e-ui), which sets it');
  }
  for (let i = 0; i < 100 && !existsSync(file); i++) await new Promise((r) => setTimeout(r, 200));
  return JSON.parse(readFileSync(file, 'utf8')) as DevState;
}

function base32(s: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  return Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
}

function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const mac = createHmac('sha1', base32(secret)).update(counter).digest();
  const off = mac[mac.length - 1] & 0x0f;
  return ((mac.readUInt32BE(off) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
}

// The app stores the last accepted step of each account, so a code is single-use per
// 30 s step, and sign-ins are limited per IP (5/min by default). The specs share one
// admin and one dev server, so the rules live here, where every code and sign-in comes
// from:
//  - one sign-in per step (the two login requests stay under the per-IP limit, as the
//    old per-spec "wait for a fresh step" did), started with at least 10 s left in it;
//  - a code is taken with at least 3 s left in its step, and never twice for the same
//    secret in one step.
// The bookkeeping is a small file next to the state file (one per dev server), not
// module state: Playwright starts a new worker process for every --repeat-each index
// and after a failure, while the app's last-accepted step and its per-IP counters live
// on in the server. Secrets are keyed by a hash; a stale entry from an earlier run on
// the same port costs at most one 30 s wait. The file is read, changed and written back
// without a lock: that is safe only because playwright.config.ts runs the specs with
// `workers: 1` (one process touches it at a time); with parallel workers two specs could
// take the same step. The global teardown (teardown.ts) removes the file at the end of
// the run, so the next run starts clean.
const stepMS = 30_000;
const codeLeadMS = 3_000;
const signInLeadMS = 10_000;

type Book = { signIn: number; codes: Record<string, number> };

const bookFile = (): string => `${process.env.OOB_DEV_STATE_FILE ?? ''}.totp.json`;

function readBook(): Book {
  try {
    return JSON.parse(readFileSync(bookFile(), 'utf8')) as Book;
  } catch {
    return { signIn: -1, codes: {} };
  }
}

function writeBook(b: Book): void {
  const tmp = `${bookFile()}.${process.pid}`;
  writeFileSync(tmp, JSON.stringify(b));
  renameSync(tmp, bookFile());
}

const keyOf = (secret: string): string => createHash('sha256').update(secret).digest('hex').slice(0, 16);

// untilStep waits for a step that has at least lead ms left and that free accepts.
async function untilStep(lead: number, free: (step: number) => boolean): Promise<number> {
  for (;;) {
    const now = Date.now();
    const step = Math.floor(now / stepMS);
    const left = stepMS - (now % stepMS);
    if (left >= lead && free(step)) return step;
    await new Promise((r) => setTimeout(r, left + 250));
  }
}

export async function freshTotp(secret: string): Promise<string> {
  const key = keyOf(secret);
  const step = await untilStep(codeLeadMS, (s) => readBook().codes[key] !== s);
  const b = readBook();
  b.codes[key] = step;
  writeBook(b);
  return totp(secret, step * stepMS);
}

// Login is who signs in (default: the admin of the state file).
export type Login = { username: string; password: string; secret: string };

// signIn runs the password and the authenticator steps on page and waits for the
// Overview heading. The code is taken right before it is entered.
export async function signIn(page: Page, st: DevState, as?: Login): Promise<void> {
  const login = as ?? { username: st.username, password: st.password, secret: st.totp_secret };
  const step = await untilStep(signInLeadMS, (s) => readBook().signIn !== s);
  const b = readBook();
  b.signIn = step;
  writeBook(b);
  await page.goto('/login');
  await page.getByLabel('Username').fill(login.username);
  await page.getByLabel('Password').fill(login.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/login\/totp$/);
  await expect(page.getByText(`Signing in as ${login.username}`)).toBeVisible();
  await page.getByLabel(/6-digit code/).fill(await freshTotp(login.secret));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible();
}
