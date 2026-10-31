// Signs in to the dev harness (password + TOTP) and appends a ZAP replacer rule that
// sends the session cookie on every request (plan 06 §3.2, nightly authenticated scan).
// Usage: node signin.mjs <dev-state.json> <zap-config.prop>
// The cookie goes only into the config file (in run.sh's private temp dir), never to
// stdout or the log.
// The harness is a throwaway install with a self-signed certificate, so the caller runs
// this with NODE_TLS_REJECT_UNAUTHORIZED=0.
import { createHmac } from 'node:crypto';
import { appendFileSync, readFileSync } from 'node:fs';

const [stateFile, propFile] = process.argv.slice(2);
if (!stateFile || !propFile) {
  console.error('usage: node signin.mjs <dev-state.json> <zap-config.prop>');
  process.exit(2);
}
const st = JSON.parse(readFileSync(stateFile, 'utf8'));
const base = st.url.replace(/\/$/, '');
const jar = new Map();

function remember(res) {
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    jar.set(pair.slice(0, i), pair.slice(i + 1));
  }
}
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

async function get(path) {
  const res = await fetch(base + path, { headers: { cookie: cookieHeader() }, redirect: 'manual' });
  remember(res);
  const m = (await res.text()).match(/name="csrf_token" value="([^"]+)"/);
  if (!m) throw new Error(`${path}: no csrf_token (status ${res.status})`);
  return m[1];
}

async function post(path, form, want) {
  const res = await fetch(base + path, {
    method: 'POST', redirect: 'manual', body: new URLSearchParams(form),
    headers: { cookie: cookieHeader(), 'content-type': 'application/x-www-form-urlencoded' },
  });
  remember(res);
  const loc = res.headers.get('location') ?? '';
  if (res.status !== 303 || !loc.endsWith(want)) throw new Error(`${path}: status ${res.status}, location ${loc}`);
}

function base32(s) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  return Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
}

async function totp(secret) {
  if (Date.now() % 30_000 > 26_000) await new Promise((r) => setTimeout(r, 30_000 - (Date.now() % 30_000) + 500));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const mac = createHmac('sha1', base32(secret)).update(counter).digest();
  const off = mac[mac.length - 1] & 0x0f;
  return ((mac.readUInt32BE(off) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
}

await post('/login', { csrf_token: await get('/login'), username: st.username, password: st.password }, '/login/totp');
await post('/login/totp', { csrf_token: await get('/login/totp'), code: await totp(st.totp_secret) }, '/');
const sid = jar.get('__Host-oob_sid');
if (!sid) throw new Error('no session cookie after the TOTP step');
appendFileSync(propFile, [
  'replacer.full_list(0).description=session',
  'replacer.full_list(0).enabled=true',
  'replacer.full_list(0).matchtype=REQ_HEADER',
  'replacer.full_list(0).matchstr=Cookie',
  'replacer.full_list(0).regex=false',
  `replacer.full_list(0).replacement=__Host-oob_sid=${sid}`,
  '',
].join('\n'));
console.log('signed in; session cookie written to the ZAP config');
