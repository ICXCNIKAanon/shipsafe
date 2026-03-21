/**
 * Environment Scanner — detects malicious Claude Code MCP servers, hooks,
 * skills, and prompt-injection in CLAUDE.md files.
 */

import { readFile, readdir, access } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

// ── Types ──────────────────────────────────────────────────────────────────

export type ThreatCategory = 'mcp_server' | 'hook' | 'prompt_injection' | 'skill';
export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ThreatPattern {
  id: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  description: string;
  detect: (content: string) => boolean;
}

export interface EnvironmentThreat {
  id: string;
  category: string;
  severity: string;
  description: string;
  location: string;
  evidence: string;
}

export interface EnvironmentScanResult {
  status: 'pass' | 'fail';
  threats_found: number;
  threats: EnvironmentThreat[];
  scanned: {
    mcp_configs: string[];
    hooks_file: string | null;
    claude_md_files: string[];
    skill_files: string[];
  };
}

// ── Unicode sanitization ──────────────────────────────────────────────────

/** Strip dangerous Unicode characters that could hide malicious instructions. */
export function sanitizeUnicode(text: string): string {
  // Strip zero-width characters
  return text.replace(/[\u200B\u200C\u200D\uFEFF\u200E\u200F]/g, '')
    // Strip bidirectional overrides
    .replace(/[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g, '');
}

// ── Allowlists ─────────────────────────────────────────────────────────────

/** Known-safe MCP package prefixes for npx invocations. */
const SAFE_MCP_NPX_PREFIXES = [
  '@modelcontextprotocol/',
  '@anthropic/',
  '@shipsafe/',
  '@cloudflare/',
  '@supabase/',
  '@prisma/',
  '@sentry/',
  'mcp-server-',
  '@smithery/',
  'firecrawl-mcp',
  'context7',
  '@context7/',
];

// ── Threat patterns ────────────────────────────────────────────────────────

export const MCP_THREAT_PATTERNS: ThreatPattern[] = [
  {
    id: 'MALICIOUS_MCP_CURL_PIPE',
    category: 'mcp_server',
    severity: 'critical',
    description: 'MCP server command contains curl-pipe-shell pattern (remote code execution)',
    detect: (content: string) =>
      /curl\s[^|]*\|\s*(sh|bash|zsh|node)/.test(content) ||
      /wget\s[^|]*\|\s*(sh|bash|zsh|node)/.test(content),
  },
  {
    id: 'MALICIOUS_MCP_NPX_UNKNOWN',
    category: 'mcp_server',
    severity: 'high',
    description: 'MCP server runs an unvetted package via npx (supply chain risk)',
    detect: (content: string) => {
      const match = content.match(/npx\s+(?:-[yY]\s+)?(?:--yes\s+)?(\S+)/);
      if (!match) return false;
      const pkg = match[1];
      return !SAFE_MCP_NPX_PREFIXES.some(
        (prefix) => pkg.startsWith(prefix) || pkg === prefix.replace(/\/$/, ''),
      );
    },
  },
  {
    id: 'MALICIOUS_MCP_ENV_SECRET',
    category: 'mcp_server',
    severity: 'high',
    description: 'MCP server config passes secrets as plain-text command arguments',
    detect: (content: string) =>
      /(?:--(?:api[_-]?key|token|secret|password|auth)\s*[=\s]\s*(?![\$\{])\S{8,})/i.test(content) ||
      /(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[A-Z0-9]{16})/.test(content),
  },
  {
    id: 'MALICIOUS_MCP_REVERSE_SHELL',
    category: 'mcp_server',
    severity: 'critical',
    description: 'MCP server command contains reverse shell pattern',
    detect: (content: string) =>
      /\/dev\/tcp\//.test(content) ||
      /bash\s+-i/.test(content) ||
      /mkfifo\s/.test(content) ||
      /ngrok\s/.test(content),
  },
  {
    id: 'MALICIOUS_MCP_INLINE_SCRIPT',
    category: 'mcp_server',
    severity: 'critical',
    description: 'MCP server uses inline script execution (python -c, ruby -e, perl -e) which could run arbitrary code.',
    detect: (content: string) =>
      /\b(?:python3?|ruby|perl|node)\s+(?:-[ce]|-exec)\s/.test(content),
  },
];

export const HOOK_THREAT_PATTERNS: ThreatPattern[] = [
  {
    id: 'MALICIOUS_HOOK_EXFILTRATION',
    category: 'hook',
    severity: 'critical',
    description: 'Hook contains network exfiltration commands (curl/wget/nc with external targets)',
    detect: (content: string) =>
      /\b(curl|wget)\s+.*https?:\/\/(?!localhost|127\.0\.0\.1)/.test(content) ||
      /\bnc\s+-[a-zA-Z]*\s+\S+\s+\d+/.test(content),
  },
  {
    id: 'MALICIOUS_HOOK_REVERSE_SHELL',
    category: 'hook',
    severity: 'critical',
    description: 'Hook contains reverse shell patterns',
    detect: (content: string) =>
      /\/dev\/tcp\//.test(content) ||
      /bash\s+-i/.test(content) ||
      /mkfifo\s/.test(content) ||
      /\bngrok\b/.test(content),
  },
  {
    id: 'MALICIOUS_HOOK_CREDENTIAL_THEFT',
    category: 'hook',
    severity: 'critical',
    description: 'Hook reads sensitive credential files',
    detect: (content: string) =>
      /~\/\.ssh\//.test(content) ||
      /\$HOME\/\.ssh\//.test(content) ||
      /~\/\.aws\/credentials/.test(content) ||
      /\$HOME\/\.aws\/credentials/.test(content) ||
      /~\/\.npmrc/.test(content) ||
      /\$HOME\/\.npmrc/.test(content) ||
      /~\/\.env\b/.test(content) ||
      /\$HOME\/\.env\b/.test(content),
  },
  {
    id: 'MALICIOUS_HOOK_OBFUSCATED',
    category: 'hook',
    severity: 'high',
    description: 'Hook contains obfuscated code (base64 decode, hex encoding, eval)',
    detect: (content: string) =>
      /base64\s+(-d|--decode)/.test(content) ||
      /eval\s*\$\(echo/.test(content) ||
      /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}/.test(content) ||
      /printf\s+'\\x[0-9a-fA-F]/.test(content),
  },
  {
    id: 'MALICIOUS_HOOK_PERSISTENCE',
    category: 'hook',
    severity: 'high',
    description: 'Hook modifies shell startup files, crontab, or launch agents (persistence mechanism)',
    detect: (content: string) =>
      /\.bashrc|\.zshrc|\.bash_profile|\.profile/.test(content) ||
      /crontab\s/.test(content) ||
      /LaunchAgent|LaunchDaemon/.test(content) ||
      /\/etc\/cron/.test(content),
  },
];

export const PROMPT_INJECTION_PATTERNS: ThreatPattern[] = [
  {
    id: 'PROMPT_INJECTION_OVERRIDE',
    category: 'prompt_injection',
    severity: 'critical',
    description: 'CLAUDE.md contains prompt override/jailbreak instructions',
    detect: (content: string) => {
      const lower = content.toLowerCase();
      return (
        /ignore\s+(all\s+)?previous\s+instructions/i.test(content) ||
        /disregard\s+(all\s+)?(previous\s+)?instructions/i.test(content) ||
        /you\s+are\s+now\s+(a|an|the)\s/i.test(content) ||
        lower.includes('override your instructions') ||
        lower.includes('forget your instructions') ||
        lower.includes('new persona')
      );
    },
  },
  {
    id: 'PROMPT_INJECTION_SILENT_EXEC',
    category: 'prompt_injection',
    severity: 'critical',
    description: 'CLAUDE.md instructs silent/hidden command execution',
    detect: (content: string) => {
      const lower = content.toLowerCase();
      return (
        lower.includes("don't show the user") ||
        lower.includes('do not show the user') ||
        lower.includes('execute silently') ||
        lower.includes('hide output') ||
        lower.includes('hide the output') ||
        lower.includes('run silently') ||
        lower.includes('without the user knowing') ||
        lower.includes('without user knowledge')
      );
    },
  },
  {
    id: 'PROMPT_INJECTION_EXFIL',
    category: 'prompt_injection',
    severity: 'critical',
    description: 'CLAUDE.md references exfiltrating credentials, tokens, keys, or code',
    detect: (content: string) => {
      const lower = content.toLowerCase();
      return (
        (lower.includes('steal') || lower.includes('exfiltrate') || lower.includes('send to')) &&
        (lower.includes('credential') ||
          lower.includes('token') ||
          lower.includes('key') ||
          lower.includes('password') ||
          lower.includes('secret') ||
          lower.includes('source code'))
      );
    },
  },
  {
    id: 'PROMPT_INJECTION_BASE64',
    category: 'prompt_injection',
    severity: 'high',
    description: 'CLAUDE.md contains suspicious base64-encoded content blocks',
    detect: (content: string) =>
      // Match long base64 strings (40+ chars) that look like encoded payloads, not short hashes
      /[A-Za-z0-9+/]{40,}={0,2}/.test(content) &&
      // Exclude common false positives: URLs with long paths, SHA hashes
      !/https?:\/\/\S+/.test(content.match(/[A-Za-z0-9+/]{40,}={0,2}/)?.[0] ?? ''),
  },
  {
    id: 'PROMPT_INJECTION_REMOTE_FETCH',
    category: 'prompt_injection',
    severity: 'high',
    description: 'CLAUDE.md instructs fetching/loading instructions from external URLs',
    detect: (content: string) => {
      const lower = content.toLowerCase();
      return (
        (lower.includes('fetch') || lower.includes('load') || lower.includes('download')) &&
        (lower.includes('instructions from') || lower.includes('prompt from') || lower.includes('config from')) &&
        /https?:\/\/(?!localhost|127\.0\.0\.1)/.test(content)
      );
    },
  },
  {
    id: 'PROMPT_INJECTION_INSTALL_PACKAGES',
    category: 'prompt_injection',
    severity: 'medium',
    description: 'CLAUDE.md instructs installing unexpected packages or modifying unrelated files',
    detect: (content: string) => {
      const lower = content.toLowerCase();
      return (
        (lower.includes('always install') || lower.includes('must install') || lower.includes('secretly install')) &&
        (lower.includes('npm install') || lower.includes('pip install') || lower.includes('apt install'))
      );
    },
  },
  {
    id: 'PROMPT_INJECTION_UNICODE_OBFUSCATION',
    category: 'prompt_injection',
    severity: 'critical',
    description: 'CLAUDE.md contains Unicode obfuscation characters (zero-width spaces, bidirectional overrides) that could hide malicious instructions.',
    detect: (content: string) => /[\u200B\u200C\u200D\u202A-\u202E\u2066-\u2069]/.test(content),
  },
  {
    id: 'PROMPT_INJECTION_BASE64_COMMAND',
    category: 'prompt_injection',
    severity: 'high',
    description: 'CLAUDE.md contains base64 encode/decode shell commands, commonly used for data exfiltration.',
    detect: (content: string) => /\|\s*base64\b|base64\s+-[dD]\b|base64\s+--decode/.test(content),
  },
  {
    id: 'PROMPT_INJECTION_SUSPICIOUS_URL',
    category: 'prompt_injection',
    severity: 'high',
    description: 'CLAUDE.md contains URLs to non-standard domains that could be used for data exfiltration or remote instruction loading.',
    detect: (content: string) => {
      // Find all URLs
      const urls = content.match(/https?:\/\/[^\s'")\]]+/gi) || [];
      const safeHosts = /github\.com|npmjs\.com|anthropic\.com|claude\.ai|vercel\.com|shipsafe\.org|docs\.|stackoverflow\.com|developer\./i;
      return urls.some(url => !safeHosts.test(url));
    },
  },
];

export const SKILL_THREAT_PATTERNS: ThreatPattern[] = [
  {
    id: 'MALICIOUS_SKILL_REMOTE_INSTRUCTIONS',
    category: 'skill',
    severity: 'critical',
    description: 'Skill fetches instructions or prompts from an external URL',
    detect: (content: string) => {
      const lower = content.toLowerCase();
      return (
        (lower.includes('fetch') || lower.includes('curl') || lower.includes('wget') || lower.includes('http')) &&
        (lower.includes('instructions') || lower.includes('prompt') || lower.includes('system message'))
      );
    },
  },
  {
    id: 'MALICIOUS_SKILL_SHELL_INJECTION',
    category: 'skill',
    severity: 'high',
    description: 'Skill executes shell commands with unvalidated user input',
    detect: (content: string) =>
      /\$\{?(?:input|args?|query|user_input|params?)\}?/.test(content) &&
      (/\b(?:exec|spawn|execSync|system)\b/.test(content) ||
        /\bBash\b.*\$\{/.test(content) ||
        /run.*command.*\$\{/.test(content)),
  },
  {
    id: 'MALICIOUS_SKILL_OBFUSCATED',
    category: 'skill',
    severity: 'high',
    description: 'Skill contains obfuscated instructions or encoded content',
    detect: (content: string) =>
      /base64\s+(-d|--decode)/.test(content) ||
      /atob\(/.test(content) ||
      /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}/.test(content) ||
      /eval\s*\(/.test(content),
  },
  {
    id: 'MALICIOUS_SKILL_CREDENTIAL_ACCESS',
    category: 'skill',
    severity: 'critical',
    description: 'Skill instructs reading credential or secret files',
    detect: (content: string) =>
      /read.*\.ssh\//.test(content) ||
      /read.*\.aws\/credentials/.test(content) ||
      /read.*\.env\b/.test(content) ||
      /cat\s+.*\.ssh\//.test(content) ||
      /cat\s+.*\.aws\/credentials/.test(content) ||
      /cat\s+.*\.npmrc/.test(content),
  },
];

export const ALL_THREAT_PATTERNS: ThreatPattern[] = [
  ...MCP_THREAT_PATTERNS,
  ...HOOK_THREAT_PATTERNS,
  ...PROMPT_INJECTION_PATTERNS,
  ...SKILL_THREAT_PATTERNS,
];

// ── File reading helpers ───────────────────────────────────────────────────

async function readFileSafe(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, 'utf-8');
  } catch {
    return null;
  }
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function listDir(dirPath: string): Promise<string[]> {
  try {
    return await readdir(dirPath);
  } catch {
    return [];
  }
}

// ── Scanners ───────────────────────────────────────────────────────────────

function truncateEvidence(text: string, maxLen = 200): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '...';
}

export function runPatterns(
  content: string,
  patterns: ThreatPattern[],
  location: string,
): EnvironmentThreat[] {
  const threats: EnvironmentThreat[] = [];

  // Sanitize Unicode before running regex-based threat patterns so that
  // zero-width characters / bidi overrides cannot break pattern matching.
  // Note: we run Unicode-obfuscation detection on the ORIGINAL content
  // before sanitization so the obfuscation itself is detected.
  const sanitized = sanitizeUnicode(content);

  for (const pattern of patterns) {
    // For Unicode obfuscation detection, test against original content;
    // for everything else, test against sanitized content.
    const testContent = pattern.id === 'PROMPT_INJECTION_UNICODE_OBFUSCATION' ? content : sanitized;
    if (pattern.detect(testContent)) {
      // Extract a brief evidence snippet — first matching line
      const lines = testContent.split('\n');
      const evidenceLine = lines.find((line) => pattern.detect(line)) ?? lines[0];
      threats.push({
        id: pattern.id,
        category: pattern.category,
        severity: pattern.severity,
        description: pattern.description,
        location,
        evidence: truncateEvidence(evidenceLine?.trim() ?? ''),
      });
    }
  }
  return threats;
}

/** Scan MCP server configurations from a JSON config object. */
function scanMcpConfig(
  config: Record<string, unknown>,
  location: string,
): EnvironmentThreat[] {
  const threats: EnvironmentThreat[] = [];

  // Look for mcpServers key (claude.json format) or just iterate entries
  const mcpServers = (config.mcpServers ?? config) as Record<
    string,
    Record<string, unknown>
  >;

  if (typeof mcpServers !== 'object' || mcpServers === null) return threats;

  for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
    if (typeof serverConfig !== 'object' || serverConfig === null) continue;

    const command = String(serverConfig.command ?? '');
    const args = Array.isArray(serverConfig.args)
      ? serverConfig.args.map(String)
      : [];
    const fullCommand = [command, ...args].join(' ');

    const serverThreats = runPatterns(
      fullCommand,
      MCP_THREAT_PATTERNS,
      `${location} -> ${serverName}`,
    );
    threats.push(...serverThreats);

    // Also check env vars for leaked secrets and malicious commands
    const env = serverConfig.env as Record<string, string> | undefined;
    if (env && typeof env === 'object') {
      const envString = Object.entries(env)
        .map(([k, v]) => `${k}=${v}`)
        .join('\n');
      const envThreats = runPatterns(
        envString,
        [MCP_THREAT_PATTERNS[2]], // MALICIOUS_MCP_ENV_SECRET
        `${location} -> ${serverName} (env)`,
      );
      threats.push(...envThreats);

      // Scan env values for malicious commands
      for (const [envKey, envValue] of Object.entries(env)) {
        if (typeof envValue !== 'string') continue;
        const val = envValue;

        // Check for curl|sh, wget|bash, reverse shell patterns
        if (
          /curl\s[^|]*\|\s*(sh|bash|zsh|node)/.test(val) ||
          /wget\s[^|]*\|\s*(sh|bash|zsh|node)/.test(val)
        ) {
          threats.push({
            id: 'MALICIOUS_MCP_ENV_CURL_PIPE',
            category: 'mcp_server',
            severity: 'critical',
            description: 'MCP server env variable contains curl-pipe-shell pattern (remote code execution)',
            location: `${location} -> ${serverName} (env.${envKey})`,
            evidence: truncateEvidence(`${envKey}=${val}`),
          });
        }

        if (
          /\/dev\/tcp\//.test(val) ||
          /bash\s+-i/.test(val) ||
          /mkfifo\s/.test(val)
        ) {
          threats.push({
            id: 'MALICIOUS_MCP_ENV_REVERSE_SHELL',
            category: 'mcp_server',
            severity: 'critical',
            description: 'MCP server env variable contains reverse shell pattern',
            location: `${location} -> ${serverName} (env.${envKey})`,
            evidence: truncateEvidence(`${envKey}=${val}`),
          });
        }

        // Flag NODE_OPTIONS containing --require with non-standard paths
        if (
          envKey === 'NODE_OPTIONS' &&
          /--require\s+/.test(val) &&
          !/--require\s+(?:ts-node|tsconfig-paths|dotenv)/.test(val)
        ) {
          threats.push({
            id: 'MALICIOUS_MCP_ENV_NODE_OPTIONS',
            category: 'mcp_server',
            severity: 'high',
            description: 'MCP server NODE_OPTIONS uses --require with non-standard path (code injection risk)',
            location: `${location} -> ${serverName} (env.${envKey})`,
            evidence: truncateEvidence(`${envKey}=${val}`),
          });
        }

        // Flag env values containing base64, eval, or shell pipe patterns
        if (
          /\bbase64\b/.test(val) ||
          /\beval\b/.test(val) ||
          /\|.*\b(sh|bash|zsh|node)\b/.test(val)
        ) {
          threats.push({
            id: 'MALICIOUS_MCP_ENV_SUSPICIOUS_VALUE',
            category: 'mcp_server',
            severity: 'high',
            description: 'MCP server env variable contains suspicious shell patterns (base64, eval, or pipe to shell)',
            location: `${location} -> ${serverName} (env.${envKey})`,
            evidence: truncateEvidence(`${envKey}=${val}`),
          });
        }
      }
    }
  }

  return threats;
}

/** Scan hook definitions from Claude settings.json. */
function scanHooks(
  settings: Record<string, unknown>,
  location: string,
): EnvironmentThreat[] {
  const threats: EnvironmentThreat[] = [];

  const hooks = settings.hooks as Record<string, unknown> | undefined;
  if (!hooks || typeof hooks !== 'object') return threats;

  for (const [hookName, hookConfig] of Object.entries(hooks)) {
    if (typeof hookConfig !== 'object' || hookConfig === null) continue;
    const hc = hookConfig as Record<string, unknown>;

    // Hooks can have a command string or an array of commands
    const commands: string[] = [];
    if (typeof hc.command === 'string') commands.push(hc.command);
    if (Array.isArray(hc.commands)) {
      for (const cmd of hc.commands) {
        if (typeof cmd === 'string') commands.push(cmd);
        else if (typeof cmd === 'object' && cmd !== null) {
          const cmdObj = cmd as Record<string, unknown>;
          if (typeof cmdObj.command === 'string') commands.push(cmdObj.command);
        }
      }
    }
    // Also check the full JSON representation for patterns
    const hookStr = JSON.stringify(hookConfig);
    commands.push(hookStr);

    for (const cmdContent of commands) {
      const hookThreats = runPatterns(
        cmdContent,
        HOOK_THREAT_PATTERNS,
        `${location} -> hooks.${hookName}`,
      );
      threats.push(...hookThreats);
    }
  }

  return threats;
}

// ── Main scanner ───────────────────────────────────────────────────────────

export interface EnvironmentScanOptions {
  /** Override home directory (for testing). */
  homeDir?: string;
  /** Override project directory (for testing). */
  projectDir?: string;
}

export async function scanEnvironment(
  options: EnvironmentScanOptions = {},
): Promise<EnvironmentScanResult> {
  const home = options.homeDir ?? homedir();
  const projectDir = options.projectDir ?? process.cwd();

  const threats: EnvironmentThreat[] = [];
  const scannedMcpConfigs: string[] = [];
  let scannedHooksFile: string | null = null;
  const scannedClaudeMdFiles: string[] = [];
  const scannedSkillFiles: string[] = [];

  // ── 1. Scan MCP server configurations ──

  // Global ~/.claude.json
  const globalClaudeJson = join(home, '.claude.json');
  const globalClaudeContent = await readFileSafe(globalClaudeJson);
  if (globalClaudeContent) {
    scannedMcpConfigs.push(globalClaudeJson);
    try {
      const config = JSON.parse(globalClaudeContent) as Record<string, unknown>;
      threats.push(...scanMcpConfig(config, globalClaudeJson));
    } catch {
      // Invalid JSON — not a threat, just skip
    }
  }

  // Project-level .mcp.json
  const projectMcpJson = join(projectDir, '.mcp.json');
  const projectMcpContent = await readFileSafe(projectMcpJson);
  if (projectMcpContent) {
    scannedMcpConfigs.push(projectMcpJson);
    try {
      const config = JSON.parse(projectMcpContent) as Record<string, unknown>;
      threats.push(...scanMcpConfig(config, projectMcpJson));
    } catch {
      // Invalid JSON — skip
    }
  }

  // ── 2. Scan Claude Code hooks ──

  const settingsJson = join(home, '.claude', 'settings.json');
  const settingsContent = await readFileSafe(settingsJson);
  if (settingsContent) {
    scannedHooksFile = settingsJson;
    try {
      const settings = JSON.parse(settingsContent) as Record<string, unknown>;
      threats.push(...scanHooks(settings, settingsJson));
    } catch {
      // Invalid JSON — skip
    }
  }

  // Also check project-level .claude/settings.json
  const projectSettingsJson = join(projectDir, '.claude', 'settings.json');
  const projectSettingsContent = await readFileSafe(projectSettingsJson);
  if (projectSettingsContent) {
    if (!scannedHooksFile) scannedHooksFile = projectSettingsJson;
    try {
      const settings = JSON.parse(projectSettingsContent) as Record<string, unknown>;
      threats.push(...scanHooks(settings, projectSettingsJson));
    } catch {
      // Invalid JSON — skip
    }
  }

  // ── 3. Scan CLAUDE.md files for prompt injection ──

  const claudeMdPaths = [
    join(projectDir, 'CLAUDE.md'),
    join(home, 'CLAUDE.md'),
  ];

  for (const mdPath of claudeMdPaths) {
    const mdContent = await readFileSafe(mdPath);
    if (mdContent) {
      scannedClaudeMdFiles.push(mdPath);
      threats.push(...runPatterns(mdContent, PROMPT_INJECTION_PATTERNS, mdPath));
    }
  }

  // ── 4. Scan installed skill files ──

  const skillsDir = join(home, '.claude', 'commands');
  if (await fileExists(skillsDir)) {
    const entries = await listDir(skillsDir);
    for (const entry of entries) {
      const skillPath = join(skillsDir, entry);
      const skillContent = await readFileSafe(skillPath);
      if (skillContent) {
        scannedSkillFiles.push(skillPath);
        threats.push(...runPatterns(skillContent, SKILL_THREAT_PATTERNS, skillPath));
      }
    }
  }

  // Also check project-level commands
  const projectSkillsDir = join(projectDir, '.claude', 'commands');
  if (await fileExists(projectSkillsDir)) {
    const entries = await listDir(projectSkillsDir);
    for (const entry of entries) {
      const skillPath = join(projectSkillsDir, entry);
      const skillContent = await readFileSafe(skillPath);
      if (skillContent) {
        scannedSkillFiles.push(skillPath);
        threats.push(...runPatterns(skillContent, SKILL_THREAT_PATTERNS, skillPath));
      }
    }
  }

  // ── Deduplicate threats (same id + same location) ──
  const seen = new Set<string>();
  const dedupedThreats = threats.filter((t) => {
    const key = `${t.id}:${t.location}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    status: dedupedThreats.length > 0 ? 'fail' : 'pass',
    threats_found: dedupedThreats.length,
    threats: dedupedThreats,
    scanned: {
      mcp_configs: scannedMcpConfigs,
      hooks_file: scannedHooksFile,
      claude_md_files: scannedClaudeMdFiles,
      skill_files: scannedSkillFiles,
    },
  };
}
