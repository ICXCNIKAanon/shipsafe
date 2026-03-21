/**
 * ShipSafe Audit — scan a remote GitHub/GitLab repo for security issues
 * and malicious patterns before installing it.
 *
 * Usage: shipsafe audit <github-url> [--json]
 */

import { Command } from 'commander';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, readFile, readdir, access, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import chalk from 'chalk';
import type { Finding, Severity, SecurityScore } from '../types.js';
import { SEVERITY_ORDER } from '../constants.js';
import {
  runPatterns as runEnvironmentPatterns,
  MCP_THREAT_PATTERNS,
  PROMPT_INJECTION_PATTERNS,
  SKILL_THREAT_PATTERNS,
  HOOK_THREAT_PATTERNS,
  type EnvironmentThreat,
} from '../engines/builtin/environment-scan.js';

// ── Types ──────────────────────────────────────────────────────────────────

type TrustGrade = 'A' | 'B' | 'C' | 'D' | 'F';
type Verdict = 'SAFE' | 'CAUTION' | 'DANGEROUS';

interface AuditFinding {
  severity: Severity;
  category: 'vulnerability' | 'secret' | 'malicious' | 'postinstall' | 'environment';
  description: string;
  file?: string;
  line?: number;
  evidence?: string;
}

interface AuditResult {
  url: string;
  repoSlug: string;
  trustGrade: TrustGrade;
  verdict: Verdict;
  findings: AuditFinding[];
  filesScanned: number;
  scanDurationMs: number;
}

// ── URL validation ─────────────────────────────────────────────────────────

const VALID_HOST_PATTERNS = [
  /^https?:\/\/(www\.)?github\.com\//,
  /^https?:\/\/(www\.)?gitlab\.com\//,
  /^https?:\/\/gitlab\.[a-zA-Z0-9-]+\.[a-zA-Z]+\//,
];

function isValidRepoUrl(url: string): boolean {
  return VALID_HOST_PATTERNS.some((pattern) => pattern.test(url));
}

function extractRepoSlug(url: string): string {
  // Normalize: strip trailing .git, trailing slashes
  const cleaned = url.replace(/\.git\/?$/, '').replace(/\/$/, '');
  try {
    const parsed = new URL(cleaned);
    // e.g. github.com/user/repo
    return parsed.host + parsed.pathname;
  } catch {
    return cleaned;
  }
}

// ── Git clone ──────────────────────────────────────────────────────────────

function gitClone(url: string, destDir: string): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(
      'git',
      ['clone', '--depth', '1', '--single-branch', url, destDir],
      { timeout: 60_000 },
      (error, _stdout, stderr) => {
        if (error) {
          reject(new Error(`git clone failed: ${stderr || error.message}`));
        } else {
          resolve();
        }
      },
    );
  });
}

// ── File counting ──────────────────────────────────────────────────────────

async function countFiles(dir: string): Promise<number> {
  let count = 0;

  async function walk(currentDir: string): Promise<void> {
    let entries: string[];
    try {
      entries = await readdir(currentDir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry === '.git' || entry === 'node_modules') continue;
      const fullPath = join(currentDir, entry);
      try {
        const s = await stat(fullPath);
        if (s.isDirectory()) {
          await walk(fullPath);
        } else {
          count++;
        }
      } catch {
        // skip inaccessible files
      }
    }
  }

  await walk(dir);
  return count;
}

// ── File helpers ───────────────────────────────────────────────────────────

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

// ── Postinstall / package.json scanning ────────────────────────────────────

interface PackageJsonThreats {
  findings: AuditFinding[];
}

const SUSPICIOUS_POSTINSTALL_PATTERNS = [
  { pattern: /\bcurl\b/, desc: 'uses curl' },
  { pattern: /\bwget\b/, desc: 'uses wget' },
  { pattern: /\bfetch\b/, desc: 'uses fetch' },
  { pattern: /\bnode\s+-e\b/, desc: 'runs inline node' },
  { pattern: /\bpython[23]?\s+-c\b/, desc: 'runs inline python' },
  { pattern: /\beval\b/, desc: 'uses eval' },
  { pattern: /\bbase64\b/, desc: 'uses base64 encoding' },
  { pattern: /\|\s*(sh|bash|zsh|node)\b/, desc: 'pipes to shell/node' },
  { pattern: /\/dev\/tcp\//, desc: 'contains reverse shell pattern' },
];

const TYPOSQUAT_INDICATORS = [
  // Common misspellings of popular packages
  { real: 'express', fakes: ['expres', 'expresss', 'exxpress', 'xpress'] },
  { real: 'lodash', fakes: ['lodashs', 'lodahs', 'lod-ash', 'loadash'] },
  { real: 'axios', fakes: ['axois', 'axio', 'axioss'] },
  { real: 'react', fakes: ['raect', 'reactt', 'reakt'] },
  { real: 'chalk', fakes: ['chaulk', 'chalks', 'chlak'] },
  { real: 'commander', fakes: ['comander', 'comanderr'] },
  { real: 'webpack', fakes: ['webpak', 'web-pack', 'webpackk'] },
  { real: 'typescript', fakes: ['typscript', 'typescipt', 'tyepscript'] },
];

function scanPackageJson(content: string, filePath: string): PackageJsonThreats {
  const findings: AuditFinding[] = [];

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return { findings };
  }

  // Check scripts for suspicious patterns
  const scripts = pkg.scripts as Record<string, string> | undefined;
  if (scripts && typeof scripts === 'object') {
    const dangerousScriptNames = ['postinstall', 'preinstall', 'install', 'prepare', 'prepublish'];

    for (const scriptName of dangerousScriptNames) {
      const script = scripts[scriptName];
      if (!script || typeof script !== 'string') continue;

      for (const { pattern, desc } of SUSPICIOUS_POSTINSTALL_PATTERNS) {
        if (pattern.test(script)) {
          const severity: Severity = scriptName.includes('install') ? 'critical' : 'high';
          findings.push({
            severity,
            category: 'postinstall',
            description: `${scriptName} script ${desc}: "${script}"`,
            file: filePath,
            evidence: script,
          });
        }
      }
    }
  }

  // Check dependencies for typosquatting
  const allDeps: Record<string, string> = {
    ...(pkg.dependencies as Record<string, string> | undefined),
    ...(pkg.devDependencies as Record<string, string> | undefined),
    ...(pkg.optionalDependencies as Record<string, string> | undefined),
  };

  for (const depName of Object.keys(allDeps)) {
    for (const { real, fakes } of TYPOSQUAT_INDICATORS) {
      if (fakes.includes(depName)) {
        findings.push({
          severity: 'critical',
          category: 'postinstall',
          description: `Suspected typosquat: "${depName}" may be impersonating "${real}"`,
          file: filePath,
          evidence: depName,
        });
      }
    }
  }

  return { findings };
}

// ── Obfuscation detection ──────────────────────────────────────────────────

const OBFUSCATION_PATTERNS = [
  {
    pattern: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/,
    desc: 'eval() with encoded content',
  },
  {
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/,
    desc: 'long hex-encoded string',
  },
  {
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/,
    desc: 'String.fromCharCode with many character codes',
  },
  {
    pattern: /\['\\x/,
    desc: 'hex-encoded property access',
  },
  {
    pattern: /Function\s*\(\s*['"]return\s/,
    desc: 'Function constructor with return',
  },
];

function scanForObfuscation(content: string, filePath: string): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, desc } of OBFUSCATION_PATTERNS) {
      if (pattern.test(lines[i])) {
        findings.push({
          severity: 'high',
          category: 'malicious',
          description: `Obfuscated code detected: ${desc}`,
          file: filePath,
          line: i + 1,
          evidence: lines[i].trim().slice(0, 200),
        });
      }
    }
  }

  return findings;
}

// ── Environment scan (CLAUDE.md, MCP, skills, hooks in the repo) ───────────

async function scanRepoEnvironment(repoDir: string): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];

  // 1. Scan CLAUDE.md files
  const claudeMdPaths = [
    join(repoDir, 'CLAUDE.md'),
    join(repoDir, '.claude', 'CLAUDE.md'),
  ];

  for (const mdPath of claudeMdPaths) {
    const content = await readFileSafe(mdPath);
    if (!content) continue;

    const threats = runEnvironmentPatterns(content, PROMPT_INJECTION_PATTERNS, mdPath);
    for (const t of threats) {
      findings.push({
        severity: t.severity as Severity,
        category: 'malicious',
        description: `CLAUDE.md: ${t.description}`,
        file: mdPath.replace(repoDir + '/', ''),
        evidence: t.evidence,
      });
    }
  }

  // 2. Scan .claude/ directory for settings, commands
  const claudeDir = join(repoDir, '.claude');
  if (await fileExists(claudeDir)) {
    // Check settings.json for hooks
    const settingsPath = join(claudeDir, 'settings.json');
    const settingsContent = await readFileSafe(settingsPath);
    if (settingsContent) {
      const threats = runEnvironmentPatterns(settingsContent, HOOK_THREAT_PATTERNS, settingsPath);
      for (const t of threats) {
        findings.push({
          severity: t.severity as Severity,
          category: 'malicious',
          description: `Hook: ${t.description}`,
          file: settingsPath.replace(repoDir + '/', ''),
          evidence: t.evidence,
        });
      }
    }

    // Check commands/ directory
    const commandsDir = join(claudeDir, 'commands');
    const commands = await listDir(commandsDir);
    for (const cmd of commands) {
      const cmdPath = join(commandsDir, cmd);
      const content = await readFileSafe(cmdPath);
      if (!content) continue;

      const threats = runEnvironmentPatterns(content, SKILL_THREAT_PATTERNS, cmdPath);
      for (const t of threats) {
        findings.push({
          severity: t.severity as Severity,
          category: 'malicious',
          description: `Skill: ${t.description}`,
          file: cmdPath.replace(repoDir + '/', ''),
          evidence: t.evidence,
        });
      }
    }
  }

  // 3. Scan MCP config files
  const mcpPaths = [
    join(repoDir, '.mcp.json'),
    join(repoDir, 'mcp.json'),
  ];

  for (const mcpPath of mcpPaths) {
    const content = await readFileSafe(mcpPath);
    if (!content) continue;

    const threats = runEnvironmentPatterns(content, MCP_THREAT_PATTERNS, mcpPath);
    for (const t of threats) {
      findings.push({
        severity: t.severity as Severity,
        category: 'malicious',
        description: `MCP config: ${t.description}`,
        file: mcpPath.replace(repoDir + '/', ''),
        evidence: t.evidence,
      });
    }
  }

  // 4. Scan skills/ and commands/ directories at repo root
  const skillDirs = ['skills', 'commands'];
  for (const dirName of skillDirs) {
    const dir = join(repoDir, dirName);
    const files = await listDir(dir);
    for (const file of files) {
      if (!file.endsWith('.md')) continue;
      const filePath = join(dir, file);
      const content = await readFileSafe(filePath);
      if (!content) continue;

      const allPatterns = [...SKILL_THREAT_PATTERNS, ...PROMPT_INJECTION_PATTERNS];
      const threats = runEnvironmentPatterns(content, allPatterns, filePath);
      for (const t of threats) {
        findings.push({
          severity: t.severity as Severity,
          category: 'malicious',
          description: `Skill file: ${t.description}`,
          file: filePath.replace(repoDir + '/', ''),
          evidence: t.evidence,
        });
      }
    }
  }

  return findings;
}

// ── Scan code files for obfuscation ────────────────────────────────────────

const CODE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.rb', '.sh', '.bash',
]);

async function scanRepoCodeFiles(repoDir: string): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];

  async function walk(dir: string): Promise<void> {
    const entries = await listDir(dir);
    for (const entry of entries) {
      if (entry === '.git' || entry === 'node_modules' || entry === 'dist') continue;
      const fullPath = join(dir, entry);
      try {
        const s = await stat(fullPath);
        if (s.isDirectory()) {
          await walk(fullPath);
        } else if (CODE_EXTENSIONS.has(entry.slice(entry.lastIndexOf('.')))) {
          // Only scan small-to-medium files (skip huge bundles)
          if (s.size > 500_000) continue;
          const content = await readFileSafe(fullPath);
          if (content) {
            const obfuscationFindings = scanForObfuscation(content, fullPath.replace(repoDir + '/', ''));
            findings.push(...obfuscationFindings);
          }
        }
      } catch {
        // skip
      }
    }
  }

  await walk(repoDir);
  return findings;
}

// ── Trust scoring ──────────────────────────────────────────────────────────

function computeTrustGrade(findings: AuditFinding[]): TrustGrade {
  if (findings.length === 0) return 'A';

  const severities = new Set(findings.map((f) => f.severity));

  if (severities.has('critical')) return 'F';

  // Any malicious-category finding is automatically F
  if (findings.some((f) => f.category === 'malicious')) return 'F';

  if (severities.has('high')) return 'D';
  if (severities.has('medium')) return 'C';

  // Only low/info
  return 'B';
}

function gradeToVerdict(grade: TrustGrade): Verdict {
  switch (grade) {
    case 'A':
    case 'B':
      return 'SAFE';
    case 'C':
    case 'D':
      return 'CAUTION';
    case 'F':
      return 'DANGEROUS';
  }
}

// ── Formatting ─────────────────────────────────────────────────────────────

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: chalk.red('\u2717'),
  high: chalk.red('\u2717'),
  medium: chalk.yellow('\u26A0'),
  low: chalk.blue('\u2139'),
  info: chalk.gray('\u2139'),
};

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.red,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

function formatDuration(ms: number): string {
  return `${(ms / 1000).toFixed(1)}s`;
}

function printReport(result: AuditResult): void {
  const separator = '\u2501'.repeat(36);

  console.log('');
  console.log(`  ${chalk.bold('ShipSafe Audit:')} ${result.repoSlug}`);
  console.log(`  ${chalk.dim(separator)}`);
  console.log('');

  // Trust score line
  const gradeColor = result.trustGrade === 'A' || result.trustGrade === 'B'
    ? chalk.green
    : result.trustGrade === 'F'
      ? chalk.red
      : chalk.yellow;

  const verdictColor = result.verdict === 'SAFE'
    ? chalk.green
    : result.verdict === 'DANGEROUS'
      ? chalk.red
      : chalk.yellow;

  console.log(`  Trust Score: ${gradeColor(chalk.bold(result.trustGrade))} | ${verdictColor(chalk.bold(result.verdict))}`);
  console.log(`  Scanned ${result.filesScanned} files in ${formatDuration(result.scanDurationMs)}`);
  console.log('');

  if (result.findings.length === 0) {
    console.log(`  ${chalk.green('\u2713')} No vulnerabilities found`);
    console.log(`  ${chalk.green('\u2713')} No hardcoded secrets`);
    console.log(`  ${chalk.green('\u2713')} No malicious patterns`);
    console.log(`  ${chalk.green('\u2713')} No suspicious postinstall scripts`);
    console.log('');
    console.log(chalk.green('  Safe to install.'));
  } else {
    // Group findings by severity for clean output
    const sorted = [...result.findings].sort((a, b) => {
      const orderA = SEVERITY_ORDER[a.severity] ?? 999;
      const orderB = SEVERITY_ORDER[b.severity] ?? 999;
      return orderA - orderB;
    });

    for (const finding of sorted) {
      const icon = SEVERITY_ICONS[finding.severity];
      const colorFn = SEVERITY_COLORS[finding.severity];
      const severityLabel = colorFn(finding.severity.toUpperCase());
      const locationPart = finding.file
        ? chalk.dim(` (${finding.file}${finding.line ? ':' + finding.line : ''})`)
        : '';
      console.log(`  ${icon} ${severityLabel}: ${finding.description}${locationPart}`);
    }

    console.log('');

    if (result.verdict === 'DANGEROUS') {
      console.log(chalk.red(chalk.bold('  DO NOT INSTALL.') + ' This package may be malicious.'));
    } else if (result.verdict === 'CAUTION') {
      console.log(chalk.yellow('  Review the findings above before installing.'));
    }
  }

  console.log('');
}

// ── Main audit function ────────────────────────────────────────────────────

export async function handleAuditAction(
  url: string,
  options: { json?: boolean },
): Promise<void> {
  // 1. Validate URL
  if (!isValidRepoUrl(url)) {
    const msg = `Invalid repository URL. Provide a GitHub or GitLab URL (e.g. https://github.com/user/repo).`;
    if (options.json) {
      console.log(JSON.stringify({ error: msg }));
    } else {
      console.error(chalk.red(`\n  Error: ${msg}\n`));
    }
    process.exitCode = 1;
    return;
  }

  const repoSlug = extractRepoSlug(url);
  const startTime = Date.now();

  if (!options.json) {
    console.log(chalk.dim(`\n  Cloning ${repoSlug}...`));
  }

  // 2. Create temp directory
  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-audit-'));
  const cloneDir = join(tmpDir, 'repo');

  try {
    // 3. Clone the repo
    await gitClone(url, cloneDir);

    if (!options.json) {
      console.log(chalk.dim('  Scanning for security issues...'));
    }

    // 4. Run all scans in parallel
    const { scanSecrets } = await import('../engines/builtin/secrets.js');
    const { scanPatterns } = await import('../engines/builtin/patterns.js');

    const [
      patternFindings,
      secretFindings,
      environmentFindings,
      obfuscationFindings,
      fileCount,
    ] = await Promise.all([
      scanPatterns(cloneDir),
      scanSecrets(cloneDir),
      scanRepoEnvironment(cloneDir),
      scanRepoCodeFiles(cloneDir),
      countFiles(cloneDir),
    ]);

    // 5. Convert pattern/secret findings to AuditFindings
    //    Strip the temp clone directory prefix so paths are repo-relative
    const cloneDirPrefix = cloneDir + '/';
    const stripPrefix = (p: string): string =>
      p.startsWith(cloneDirPrefix) ? p.slice(cloneDirPrefix.length) : p;

    const allFindings: AuditFinding[] = [];

    for (const f of patternFindings) {
      allFindings.push({
        severity: f.severity,
        category: 'vulnerability',
        description: f.description,
        file: stripPrefix(f.file),
        line: f.line,
      });
    }

    for (const f of secretFindings) {
      allFindings.push({
        severity: f.severity,
        category: 'secret',
        description: f.description,
        file: stripPrefix(f.file),
        line: f.line,
      });
    }

    allFindings.push(...environmentFindings);
    allFindings.push(...obfuscationFindings);

    // 6. Scan package.json(s)
    const packageJsonPaths = [join(cloneDir, 'package.json')];
    // Also check nested package.json files in top-level dirs (monorepos)
    const topLevelEntries = await listDir(cloneDir);
    for (const entry of topLevelEntries) {
      if (entry === 'node_modules' || entry === '.git') continue;
      const nested = join(cloneDir, entry, 'package.json');
      if (await fileExists(nested)) {
        packageJsonPaths.push(nested);
      }
    }

    for (const pkgPath of packageJsonPaths) {
      const content = await readFileSafe(pkgPath);
      if (!content) continue;
      const { findings: pkgFindings } = scanPackageJson(content, pkgPath.replace(cloneDir + '/', ''));
      allFindings.push(...pkgFindings);
    }

    // 7. Deduplicate
    const seen = new Set<string>();
    const deduped: AuditFinding[] = [];
    for (const f of allFindings) {
      const key = `${f.category}:${f.severity}:${f.file ?? ''}:${f.line ?? ''}:${f.description}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(f);
      }
    }

    // 8. Compute trust score
    const trustGrade = computeTrustGrade(deduped);
    const verdict = gradeToVerdict(trustGrade);

    const result: AuditResult = {
      url,
      repoSlug,
      trustGrade,
      verdict,
      findings: deduped,
      filesScanned: fileCount,
      scanDurationMs: Date.now() - startTime,
    };

    // 9. Output
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printReport(result);
    }

    // Set exit code for DANGEROUS results
    if (verdict === 'DANGEROUS') {
      process.exitCode = 1;
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (options.json) {
      console.log(JSON.stringify({ error: errorMsg }));
    } else {
      console.error(chalk.red(`\n  Error: ${errorMsg}\n`));
    }
    process.exitCode = 1;
  } finally {
    // 10. Clean up temp directory
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
}

// ── Command registration ───────────────────────────────────────────────────

export function registerAuditCommand(program: Command): void {
  program
    .command('audit <url>')
    .description('Audit a GitHub repo or skill for security before installing')
    .option('--json', 'Output as JSON', false)
    .action(async (url: string, options: { json: boolean }) => {
      await handleAuditAction(url, options);
    });
}
