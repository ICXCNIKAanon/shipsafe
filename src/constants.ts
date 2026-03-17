export const SHIPSAFE_DIR = '.shipsafe';
export const CONFIG_FILE = 'shipsafe.config.json';
export const GLOBAL_DIR_NAME = '.shipsafe';
export const CLAUDE_MD_START = '<!-- shipsafe:start -->';
export const CLAUDE_MD_END = '<!-- shipsafe:end -->';
export const VERSION = '0.1.0';
export const HOOK_MARKER = '# SHIPSAFE_HOOK';
export const DEFAULT_API_URL = 'http://localhost:3747';

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
