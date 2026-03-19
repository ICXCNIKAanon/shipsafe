export const SHIPSAFE_DIR = '.shipsafe';
export const CONFIG_FILE = 'shipsafe.config.json';
export const GLOBAL_DIR_NAME = '.shipsafe';
export const CLAUDE_MD_START = '<!-- shipsafe:start -->';
export const CLAUDE_MD_END = '<!-- shipsafe:end -->';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

function readVersion(): string {
  try {
    // Walk up from dist/src/ or src/ to find package.json
    let dir = dirname(fileURLToPath(import.meta.url));
    for (let i = 0; i < 5; i++) {
      try {
        const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8')) as { version: string };
        return pkg.version;
      } catch { /* not found here */ }
      dir = dirname(dir);
    }
  } catch { /* fallback */ }
  return '0.3.1';
}
export const VERSION = readVersion();
export const HOOK_MARKER = '# SHIPSAFE_HOOK';
export const DEFAULT_API_URL = 'https://shipsafe-m9nc6.ondigitalocean.app';

export const EXIT_CODES = {
  SUCCESS: 0,
  SCAN_FAIL: 1,
  TOOL_MISSING: 2,
  CONFIG_ERROR: 3,
} as const;

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const DEFAULT_CONFIG: {
  monitoring: { enabled: boolean; error_sample_rate: number; performance_sample_rate: number };
  scan: { ignore_paths: string[]; ignore_rules: string[]; severity_threshold: string };
} = {
  monitoring: {
    enabled: true,
    error_sample_rate: 1.0,
    performance_sample_rate: 1.0,
  },
  scan: {
    ignore_paths: ['node_modules', 'dist', '.git', 'coverage'],
    ignore_rules: [],
    severity_threshold: 'high',
  },
};
