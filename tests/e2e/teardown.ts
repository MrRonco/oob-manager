// Global teardown: removes the TOTP bookkeeping file the sign-in helper keeps next to
// the dev-harness state file (auth.ts), so a run never inherits another run's steps.
// The state file itself is the harness's (a temp file it deletes on exit).
import { rmSync } from 'node:fs';

export default function teardown(): void {
  const file = process.env.OOB_DEV_STATE_FILE ?? '';
  if (file !== '') rmSync(`${file}.totp.json`, { force: true });
}
