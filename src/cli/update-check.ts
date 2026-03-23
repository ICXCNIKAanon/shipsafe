import { VERSION } from '../constants.js';

const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const CACHE_KEY = 'shipsafe_last_update_check';

/**
 * Non-blocking update check. Prints a one-liner if a newer version exists.
 * Checks at most once per 24 hours. Never blocks or throws.
 */
export function checkForUpdate(): void {
  // Don't check in MCP server mode or CI
  if (process.env.SHIPSAFE_NO_UPDATE_CHECK || process.env.CI) return;

  // Throttle: check at most once per 24 hours
  try {
    const lastCheck = parseInt(process.env[CACHE_KEY] ?? '0', 10);
    if (Date.now() - lastCheck < CHECK_INTERVAL_MS) return;
  } catch { /* proceed */ }

  // Fire and forget — never blocks CLI startup
  setImmediate(async () => {
    try {
      process.env[CACHE_KEY] = String(Date.now());

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);

      const res = await fetch('https://registry.npmjs.org/@shipsafe/cli/latest', {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
      });
      clearTimeout(timeout);

      if (!res.ok) return;

      const data = await res.json() as { version?: string };
      const latest = data.version;
      if (!latest || latest === VERSION) return;

      // Compare versions
      const current = VERSION.split('.').map(Number);
      const remote = latest.split('.').map(Number);
      const isNewer = remote[0] > current[0] ||
        (remote[0] === current[0] && remote[1] > current[1]) ||
        (remote[0] === current[0] && remote[1] === current[1] && remote[2] > current[2]);

      if (isNewer) {
        console.log(`\n  \x1b[33mUpdate available:\x1b[0m ${VERSION} → \x1b[32m${latest}\x1b[0m`);
        console.log(`  Run \x1b[36mnpm update -g @shipsafe/cli\x1b[0m to update\n`);
      }
    } catch {
      // Network error, timeout, parse error — silently ignore
    }
  });
}
