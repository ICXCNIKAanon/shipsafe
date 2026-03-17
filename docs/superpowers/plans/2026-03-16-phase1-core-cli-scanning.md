# ShipSafe Phase 1: Core CLI + Scanning — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working ShipSafe CLI that scans code for security vulnerabilities using Semgrep, Gitleaks, and Trivy, installs git hooks, exposes MCP tools for AI coding agents, and manages CLAUDE.md injection.

**Architecture:** TypeScript npm package with Commander.js CLI entry point. Pattern engine wraps three external scanning tools as child processes and aggregates results into a unified format. MCP server (stdio transport) exposes scan/status tools. Git hooks are shell scripts installed into `.git/hooks/`. Config stored in `~/.shipsafe/` (global) and `shipsafe.config.json` (project-level).

**Tech Stack:** TypeScript, Commander.js, @modelcontextprotocol/sdk, Vitest, child_process (for Semgrep/Gitleaks/Trivy), chalk (output formatting)

---

## File Structure

```
shipsafe/
├── package.json
├── tsconfig.json
├── tsconfig.build.json
├── vitest.config.ts
├── .gitignore
├── CLAUDE.md
├── bin/
│   └── shipsafe.ts                    # CLI entry point (Commander setup, registers all commands)
├── src/
│   ├── types.ts                       # Shared types: ScanResult, Finding, ScanScope, Config, etc.
│   ├── constants.ts                   # Exit codes, default config values, version
│   ├── config/
│   │   └── manager.ts                 # Read/write ~/.shipsafe/ and project shipsafe.config.json
│   ├── engines/
│   │   └── pattern/
│   │       ├── index.ts               # Orchestrator: runs all scanners, aggregates results
│   │       ├── semgrep.ts             # Semgrep runner: invoke CLI, parse SARIF output
│   │       ├── gitleaks.ts            # Gitleaks runner: invoke CLI, parse JSON output
│   │       └── trivy.ts              # Trivy runner: invoke CLI, parse JSON output
│   ├── cli/
│   │   ├── scan.ts                    # `shipsafe scan` command handler
│   │   ├── setup.ts                   # `shipsafe setup` command handler (hooks + MCP registration)
│   │   ├── status.ts                  # `shipsafe status` command handler
│   │   └── activate.ts               # `shipsafe activate` command handler (license key stub)
│   ├── hooks/
│   │   ├── installer.ts               # Writes hook scripts to .git/hooks/, makes executable
│   │   ├── pre-commit.sh              # Shell script: runs shipsafe scan --scope staged
│   │   └── pre-push.sh               # Shell script: runs shipsafe scan --scope all
│   ├── mcp/
│   │   ├── server.ts                  # MCP server setup (stdio transport, tool registration)
│   │   └── tools/
│   │       ├── scan.ts                # shipsafe_scan tool handler
│   │       └── status.ts             # shipsafe_status tool handler
│   └── claude-md/
│       └── manager.ts                 # Inject/update ShipSafe block in project CLAUDE.md
├── tests/
│   ├── config/
│   │   └── manager.test.ts
│   ├── engines/
│   │   └── pattern/
│   │       ├── semgrep.test.ts
│   │       ├── gitleaks.test.ts
│   │       ├── trivy.test.ts
│   │       └── index.test.ts
│   ├── cli/
│   │   ├── scan.test.ts
│   │   └── setup.test.ts
│   ├── hooks/
│   │   └── installer.test.ts
│   ├── mcp/
│   │   └── tools.test.ts
│   └── claude-md/
│       └── manager.test.ts
```

---

## Chunk 1: Project Scaffold + Types + Config

### Task 1: Project Scaffold

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `tsconfig.build.json`
- Create: `vitest.config.ts`
- Create: `.gitignore`
- Create: `CLAUDE.md`
- Create: `src/types.ts`
- Create: `src/constants.ts`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "shipsafe",
  "version": "0.1.0",
  "description": "Full-lifecycle security and reliability platform for vibe coders",
  "type": "module",
  "bin": {
    "shipsafe": "./dist/bin/shipsafe.js"
  },
  "scripts": {
    "build": "tsc -p tsconfig.build.json",
    "dev": "tsx bin/shipsafe.ts",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "tsc --noEmit"
  },
  "keywords": ["security", "scanning", "mcp", "vibe-coding", "semgrep", "gitleaks"],
  "author": "Connect Holdings LLC",
  "license": "UNLICENSED",
  "engines": {
    "node": ">=20"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0",
    "chalk": "^5.3.0",
    "commander": "^13.0.0",
    "zod": "^3.24.0"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "tsx": "^4.19.0",
    "typescript": "^5.7.0",
    "vitest": "^3.0.0"
  }
}
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": ".",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*", "bin/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

- [ ] **Step 3: Create tsconfig.build.json**

```json
{
  "extends": "./tsconfig.json",
  "exclude": ["node_modules", "dist", "tests"]
}
```

- [ ] **Step 4: Create vitest.config.ts**

```typescript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
    },
  },
});
```

- [ ] **Step 5: Create .gitignore**

```
node_modules/
dist/
*.tsbuildinfo
.env
.env.*
coverage/
.DS_Store
```

- [ ] **Step 6: Create CLAUDE.md**

```markdown
# ShipSafe Development

## Project
ShipSafe CLI — security scanning + MCP server for vibe coders.

## Commands
- `npm run dev -- scan` — run scan command locally
- `npm run dev -- setup` — run setup command locally
- `npm test` — run all tests
- `npm run build` — compile TypeScript

## Architecture
- `bin/shipsafe.ts` — CLI entry point
- `src/engines/pattern/` — wraps Semgrep, Gitleaks, Trivy
- `src/mcp/` — MCP server (stdio transport)
- `src/hooks/` — git hook scripts + installer
- `src/claude-md/` — CLAUDE.md injection manager

## Conventions
- TypeScript strict mode
- ESM modules (type: "module")
- Vitest for testing
- No classes — use plain functions and types
- Errors: throw typed errors, never swallow silently
```

- [ ] **Step 7: Create src/types.ts**

All shared types used across the project: `Finding`, `ScanResult`, `ScanScope`, `ShipSafeConfig`, `ProjectStatus`, `Severity`, etc. See MCP_TOOLS.md for the return type shapes that inform these types.

Key types:
```typescript
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanScope = 'staged' | 'all' | `file:${string}`;
export type Engine = 'pattern' | 'knowledge_graph';
export type ScanStatus = 'pass' | 'fail';
export type SecurityScore = 'A' | 'B' | 'C' | 'D' | 'F';

export interface Finding {
  id: string;
  engine: Engine;
  severity: Severity;
  type: string;
  file: string;
  line: number;
  description: string;
  fix_suggestion: string;
  auto_fixable: boolean;
}

export interface ScanResult {
  status: ScanStatus;
  score: SecurityScore;
  findings: Finding[];
  scan_duration_ms: number;
}

export interface ShipSafeConfig {
  licenseKey?: string;
  projectId?: string;
  monitoring?: {
    enabled: boolean;
    error_sample_rate: number;
    performance_sample_rate: number;
  };
  scan?: {
    ignore_paths: string[];
    ignore_rules: string[];
    severity_threshold: Severity;
  };
}

export interface ProjectStatus {
  project: string;
  security_score: SecurityScore;
  open_issues: number;
  hooks_installed: boolean;
  last_scan?: string;
}
```

- [ ] **Step 8: Create src/constants.ts**

```typescript
export const SHIPSAFE_DIR = '.shipsafe';
export const CONFIG_FILE = 'shipsafe.config.json';
export const GLOBAL_DIR_NAME = '.shipsafe';
export const CLAUDE_MD_START = '<!-- shipsafe:start -->';
export const CLAUDE_MD_END = '<!-- shipsafe:end -->';
export const VERSION = '0.1.0';

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
```

- [ ] **Step 9: Install dependencies**

Run: `npm install`

- [ ] **Step 10: Verify TypeScript compiles**

Run: `npx tsc --noEmit`
Expected: No errors (files have no imports to resolve yet beyond Node built-ins)

- [ ] **Step 11: Commit scaffold**

```bash
git add -A
git commit -m "chore: scaffold ShipSafe project with TypeScript, Vitest, Commander"
```

---

### Task 2: Config Manager

**Files:**
- Create: `src/config/manager.ts`
- Create: `tests/config/manager.test.ts`

The config manager handles two config sources:
1. **Global config** at `~/.shipsafe/config.json` — license key, global preferences
2. **Project config** at `<project>/shipsafe.config.json` — project-specific scan/monitoring settings

Merged with project config overriding global config.

- [ ] **Step 1: Write config manager tests**

Test cases:
- `getGlobalConfigDir()` returns `~/.shipsafe`
- `loadGlobalConfig()` returns defaults when no file exists
- `loadProjectConfig()` returns defaults when no file exists
- `loadConfig()` merges global + project with project taking precedence
- `saveGlobalConfig()` writes JSON to ~/.shipsafe/config.json
- `saveProjectConfig()` writes JSON to ./shipsafe.config.json

Use `vi.spyOn(fs, ...)` to mock file system reads/writes. Use tmp dirs for integration-style tests.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/config/manager.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement config manager**

Functions to implement:
- `getGlobalConfigDir(): string` — returns path to `~/.shipsafe/`
- `loadGlobalConfig(): Promise<ShipSafeConfig>` — reads global config, returns defaults if missing
- `loadProjectConfig(projectDir?: string): Promise<ShipSafeConfig>` — reads project config
- `loadConfig(projectDir?: string): Promise<ShipSafeConfig>` — merges both configs
- `saveGlobalConfig(config: Partial<ShipSafeConfig>): Promise<void>`
- `saveProjectConfig(config: Partial<ShipSafeConfig>, projectDir?: string): Promise<void>`
- `getProjectName(projectDir?: string): string` — derives from package.json name or directory name

Use `node:fs/promises` for file I/O. Use `node:os` for homedir. Use `node:path` for path construction.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/config/manager.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/config/ tests/config/
git commit -m "feat: add config manager for global and project settings"
```

---

## Chunk 2: Pattern Engine (Scanner Runners + Orchestrator)

### Task 3: Semgrep Runner

**Files:**
- Create: `src/engines/pattern/semgrep.ts`
- Create: `tests/engines/pattern/semgrep.test.ts`

Wraps the `semgrep` CLI. Invokes it with `--json` output, parses results into `Finding[]`.

- [ ] **Step 1: Write semgrep runner tests**

Test cases:
- `checkSemgrepInstalled()` returns true/false based on `which semgrep`
- `runSemgrep(targetPath)` executes `semgrep scan --json <path>` and parses output
- `runSemgrep()` maps SARIF severity to ShipSafe severity
- `runSemgrep()` returns empty findings when scan is clean
- `runSemgrep()` handles semgrep not installed gracefully (returns error result, not throw)

Mock `child_process.execFile` to return sample semgrep JSON output.

- [ ] **Step 2: Run tests — expect FAIL**

Run: `npx vitest run tests/engines/pattern/semgrep.test.ts`

- [ ] **Step 3: Implement semgrep runner**

```typescript
// src/engines/pattern/semgrep.ts
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { Finding } from '../../types.js';

const exec = promisify(execFile);

export async function checkSemgrepInstalled(): Promise<boolean> { ... }
export async function runSemgrep(targetPath: string, stagedFiles?: string[]): Promise<Finding[]> { ... }
```

Key implementation details:
- Use `semgrep scan --json --quiet <path>` for full project scan
- For staged files, pass individual file paths: `semgrep scan --json <file1> <file2> ...`
- Parse the `results` array from semgrep JSON output
- Map `extra.severity` → ShipSafe severity
- Generate finding IDs: `semgrep_<rule_id>_<file>_<line>`

- [ ] **Step 4: Run tests — expect PASS**
- [ ] **Step 5: Commit**

```bash
git add src/engines/pattern/semgrep.ts tests/engines/pattern/semgrep.test.ts
git commit -m "feat: add semgrep scanner runner"
```

---

### Task 4: Gitleaks Runner

**Files:**
- Create: `src/engines/pattern/gitleaks.ts`
- Create: `tests/engines/pattern/gitleaks.test.ts`

Same pattern as semgrep runner but for secret detection.

- [ ] **Step 1: Write gitleaks runner tests**

Test cases:
- `checkGitleaksInstalled()` returns true/false
- `runGitleaks(targetPath)` executes `gitleaks detect --report-format json` and parses output
- `runGitleaks()` maps all gitleaks findings to `severity: 'critical'` (secrets are always critical)
- `runGitleaks()` returns empty findings when no secrets found
- `runGitleaks()` handles tool not installed

Mock `child_process.execFile`.

- [ ] **Step 2: Run tests — expect FAIL**
- [ ] **Step 3: Implement gitleaks runner**

```typescript
// src/engines/pattern/gitleaks.ts
export async function checkGitleaksInstalled(): Promise<boolean> { ... }
export async function runGitleaks(targetPath: string, stagedFiles?: string[]): Promise<Finding[]> { ... }
```

Key details:
- Use `gitleaks detect --source <path> --report-format json --report-path /dev/stdout --no-git`
- For staged files, use `gitleaks detect --source <path> --report-format json --report-path /dev/stdout`
- All gitleaks findings are `severity: 'critical'`, `type: 'hardcoded_secret'`
- Parse the JSON array output

- [ ] **Step 4: Run tests — expect PASS**
- [ ] **Step 5: Commit**

```bash
git add src/engines/pattern/gitleaks.ts tests/engines/pattern/gitleaks.test.ts
git commit -m "feat: add gitleaks secret scanner runner"
```

---

### Task 5: Trivy Runner

**Files:**
- Create: `src/engines/pattern/trivy.ts`
- Create: `tests/engines/pattern/trivy.test.ts`

Wraps Trivy for dependency vulnerability scanning.

- [ ] **Step 1: Write trivy runner tests**

Test cases:
- `checkTrivyInstalled()` returns true/false
- `runTrivy(targetPath)` runs `trivy fs --format json` and parses vulnerabilities
- `runTrivy()` maps Trivy severity (CRITICAL/HIGH/MEDIUM/LOW) to ShipSafe severity
- `runTrivy()` returns empty findings when deps are clean
- `runTrivy()` handles tool not installed

- [ ] **Step 2: Run tests — expect FAIL**
- [ ] **Step 3: Implement trivy runner**

```typescript
// src/engines/pattern/trivy.ts
export async function checkTrivyInstalled(): Promise<boolean> { ... }
export async function runTrivy(targetPath: string): Promise<Finding[]> { ... }
```

Key details:
- Use `trivy fs --format json --quiet <path>`
- Parse `Results[].Vulnerabilities[]` from Trivy JSON
- Map `Severity` field to lowercase ShipSafe severity
- Finding type: `'dependency_vulnerability'`
- Include CVE ID in finding description

- [ ] **Step 4: Run tests — expect PASS**
- [ ] **Step 5: Commit**

```bash
git add src/engines/pattern/trivy.ts tests/engines/pattern/trivy.test.ts
git commit -m "feat: add trivy dependency scanner runner"
```

---

### Task 6: Pattern Engine Orchestrator

**Files:**
- Create: `src/engines/pattern/index.ts`
- Create: `tests/engines/pattern/index.test.ts`

Orchestrates all three scanners. Runs them in parallel, aggregates results, computes security score.

- [ ] **Step 1: Write orchestrator tests**

Test cases:
- `runPatternEngine()` runs all three scanners in parallel
- `runPatternEngine()` aggregates findings from all scanners
- `runPatternEngine()` computes security score based on finding severities
- `runPatternEngine()` continues if one scanner is not installed (warns, skips)
- `runPatternEngine()` returns pass/fail status based on severity threshold
- `computeScore(findings)` returns A-F grade
- `getAvailableScanners()` returns list of installed tools

- [ ] **Step 2: Run tests — expect FAIL**
- [ ] **Step 3: Implement orchestrator**

```typescript
// src/engines/pattern/index.ts
export async function runPatternEngine(options: {
  targetPath: string;
  scope: ScanScope;
  stagedFiles?: string[];
}): Promise<ScanResult> { ... }

export function computeScore(findings: Finding[]): SecurityScore { ... }
export async function getAvailableScanners(): Promise<string[]> { ... }
```

Score computation:
- No findings → A
- Only info/low → B
- Any medium → C
- Any high → D
- Any critical → F

`runPatternEngine` flow:
1. Check which scanners are installed
2. Get staged files if scope is 'staged' (via `git diff --cached --name-only`)
3. Run available scanners in parallel with `Promise.allSettled`
4. Merge all findings, sort by severity
5. Compute score, determine pass/fail
6. Return `ScanResult`

- [ ] **Step 4: Run tests — expect PASS**
- [ ] **Step 5: Commit**

```bash
git add src/engines/pattern/index.ts tests/engines/pattern/index.test.ts
git commit -m "feat: add pattern engine orchestrator"
```

---

## Chunk 3: CLI Commands + Git Hooks

### Task 7: CLI Entry Point + Scan Command

**Files:**
- Create: `bin/shipsafe.ts`
- Create: `src/cli/scan.ts`
- Create: `tests/cli/scan.test.ts`

- [ ] **Step 1: Write scan command tests**

Test cases:
- Scan command calls `runPatternEngine` with correct scope
- `--scope staged` passes staged scope
- `--scope all` passes all scope
- `--fix` flag is passed through
- Output is formatted with colors (chalk) showing findings
- Exit code is 1 when critical/high findings exist
- Exit code is 0 when clean

Mock the pattern engine module.

- [ ] **Step 2: Run tests — expect FAIL**
- [ ] **Step 3: Implement scan command**

```typescript
// src/cli/scan.ts
import type { Command } from 'commander';

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan project for security vulnerabilities')
    .option('--scope <scope>', 'Scan scope: staged, all, or file:<path>', 'staged')
    .option('--fix', 'Attempt to auto-fix findings', false)
    .option('--json', 'Output results as JSON', false)
    .action(async (options) => { ... });
}
```

Output format (non-JSON):
```
ShipSafe Scan Results
Score: C | 3 findings | 8.5s

CRITICAL  src/config.ts:12
  Hardcoded Supabase service role key detected
  Fix: Move to .env and reference via process.env.SUPABASE_SERVICE_KEY

HIGH  src/routes/api/submit.ts:15
  SQL injection: user input flows to db.execute without sanitization
  Fix: Add input sanitization in processData
```

- [ ] **Step 4: Create CLI entry point**

```typescript
// bin/shipsafe.ts
#!/usr/bin/env node
import { Command } from 'commander';
import { VERSION } from '../src/constants.js';
import { registerScanCommand } from '../src/cli/scan.js';
import { registerSetupCommand } from '../src/cli/setup.js';
import { registerStatusCommand } from '../src/cli/status.js';
import { registerActivateCommand } from '../src/cli/activate.js';

const program = new Command();
program
  .name('shipsafe')
  .description('Full-lifecycle security and reliability for vibe coders')
  .version(VERSION);

registerScanCommand(program);
registerSetupCommand(program);
registerStatusCommand(program);
registerActivateCommand(program);

program.parse();
```

- [ ] **Step 5: Run tests — expect PASS**
- [ ] **Step 6: Verify CLI works**

Run: `npx tsx bin/shipsafe.ts --help`
Expected: Shows help with scan, setup, status, activate commands

Run: `npx tsx bin/shipsafe.ts scan --scope all --json`
Expected: Returns JSON scan result (may show warnings about missing scanners)

- [ ] **Step 7: Commit**

```bash
git add bin/ src/cli/ tests/cli/
git commit -m "feat: add CLI entry point and scan command"
```

---

### Task 8: Status + Activate Commands

**Files:**
- Create: `src/cli/status.ts`
- Create: `src/cli/activate.ts`

- [ ] **Step 1: Implement status command**

```typescript
// src/cli/status.ts
export function registerStatusCommand(program: Command): void {
  program
    .command('status')
    .description('Show ShipSafe status for current project')
    .action(async () => { ... });
}
```

Shows: project name, security score (from last scan cache), hooks installed status, available scanners, config location.

- [ ] **Step 2: Implement activate command (stub)**

```typescript
// src/cli/activate.ts
export function registerActivateCommand(program: Command): void {
  program
    .command('activate <license-key>')
    .description('Activate ShipSafe Pro with a license key')
    .action(async (licenseKey) => {
      // Phase 1: just save the key locally
      // Phase 6: validate against cloud API
    });
}
```

- [ ] **Step 3: Commit**

```bash
git add src/cli/status.ts src/cli/activate.ts
git commit -m "feat: add status and activate commands"
```

---

### Task 9: Git Hook Installer

**Files:**
- Create: `src/hooks/installer.ts`
- Create: `src/hooks/pre-commit.sh`
- Create: `src/hooks/pre-push.sh`
- Create: `tests/hooks/installer.test.ts`

- [ ] **Step 1: Write hook installer tests**

Test cases:
- `installHooks(projectDir)` creates `.git/hooks/pre-commit` and `.git/hooks/pre-push`
- Hook files are marked executable (mode 0o755)
- `installHooks()` backs up existing hooks by renaming to `.pre-shipsafe`
- `uninstallHooks()` removes ShipSafe hooks and restores backups
- `checkHooksInstalled(projectDir)` returns true if ShipSafe hooks are present
- Fails gracefully if not in a git repo (no `.git/` directory)

Use tmp directories with `git init` for realistic tests.

- [ ] **Step 2: Run tests — expect FAIL**
- [ ] **Step 3: Create pre-commit.sh**

```bash
#!/bin/sh
# ShipSafe pre-commit hook
# Runs security scan on staged files before commit

# Find shipsafe binary
SHIPSAFE=$(command -v shipsafe 2>/dev/null)
if [ -z "$SHIPSAFE" ]; then
  # Try npx as fallback
  SHIPSAFE="npx shipsafe"
fi

echo "ShipSafe: Scanning staged files..."
$SHIPSAFE scan --scope staged

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "ShipSafe: Critical/high security issues found. Fix before committing."
  echo "To bypass (not recommended): git commit --no-verify"
  exit 1
fi

exit 0
```

- [ ] **Step 4: Create pre-push.sh**

```bash
#!/bin/sh
# ShipSafe pre-push hook
# Runs full security scan before push

SHIPSAFE=$(command -v shipsafe 2>/dev/null)
if [ -z "$SHIPSAFE" ]; then
  SHIPSAFE="npx shipsafe"
fi

echo "ShipSafe: Running full scan before push..."
$SHIPSAFE scan --scope all

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "ShipSafe: Critical/high security issues found. Fix before pushing."
  echo "To bypass (not recommended): git push --no-verify"
  exit 1
fi

exit 0
```

- [ ] **Step 5: Implement hook installer**

```typescript
// src/hooks/installer.ts
export async function installHooks(projectDir?: string): Promise<void> { ... }
export async function uninstallHooks(projectDir?: string): Promise<void> { ... }
export async function checkHooksInstalled(projectDir?: string): Promise<boolean> { ... }
```

Implementation:
1. Find `.git/hooks/` directory from projectDir (or cwd)
2. Check if hooks already exist — if so, back up to `<name>.pre-shipsafe`
3. Copy pre-commit.sh and pre-push.sh from package's `src/hooks/` dir
4. `chmod 0o755` both files
5. Each hook has a header comment `# SHIPSAFE_HOOK` for identification

- [ ] **Step 6: Run tests — expect PASS**
- [ ] **Step 7: Commit**

```bash
git add src/hooks/ tests/hooks/
git commit -m "feat: add git hook installer with pre-commit and pre-push scripts"
```

---

### Task 10: Setup Command

**Files:**
- Create: `src/cli/setup.ts`
- Create: `tests/cli/setup.test.ts`

The `shipsafe setup` command does three things:
1. Installs git hooks
2. Registers MCP server in editor configs (Claude Code, Cursor)
3. Injects CLAUDE.md template

- [ ] **Step 1: Write setup command tests**

Test cases:
- `setup` installs git hooks
- `setup` calls CLAUDE.md manager to inject template
- `setup` detects Claude Code and registers MCP server in config
- `setup` shows summary of what was configured
- `setup` is idempotent (running twice doesn't duplicate)

- [ ] **Step 2: Run tests — expect FAIL**
- [ ] **Step 3: Implement setup command**

```typescript
// src/cli/setup.ts
export function registerSetupCommand(program: Command): void {
  program
    .command('setup')
    .description('Set up ShipSafe for current project (hooks, MCP, CLAUDE.md)')
    .option('--skip-hooks', 'Skip git hook installation')
    .option('--skip-mcp', 'Skip MCP server registration')
    .option('--skip-claude-md', 'Skip CLAUDE.md injection')
    .action(async (options) => { ... });
}
```

MCP registration: Write to `~/.claude/claude_desktop_config.json` (Claude Code) and `.cursor/mcp.json` (Cursor). Add shipsafe MCP server entry with stdio transport pointing to `shipsafe mcp-server` command.

- [ ] **Step 4: Run tests — expect PASS**
- [ ] **Step 5: Commit**

```bash
git add src/cli/setup.ts tests/cli/setup.test.ts
git commit -m "feat: add setup command for hooks, MCP, and CLAUDE.md configuration"
```

---

## Chunk 4: CLAUDE.md Manager + MCP Server

### Task 11: CLAUDE.md Manager

**Files:**
- Create: `src/claude-md/manager.ts`
- Create: `tests/claude-md/manager.test.ts`

Injects/updates a ShipSafe instruction block in the project's CLAUDE.md file. Uses sentinel comments to identify the ShipSafe section.

- [ ] **Step 1: Write CLAUDE.md manager tests**

Test cases:
- `injectClaudeMd(projectDir)` creates CLAUDE.md if it doesn't exist, with ShipSafe block
- `injectClaudeMd()` appends ShipSafe block to existing CLAUDE.md without modifying existing content
- `injectClaudeMd()` replaces existing ShipSafe block if already present (update)
- `removeClaudeMd(projectDir)` removes ShipSafe block but preserves rest of CLAUDE.md
- ShipSafe block is wrapped in `<!-- shipsafe:start -->` / `<!-- shipsafe:end -->` sentinel comments
- Template content matches CLAUDE.md.template from spec (kept under 50 lines)

- [ ] **Step 2: Run tests — expect FAIL**
- [ ] **Step 3: Implement CLAUDE.md manager**

```typescript
// src/claude-md/manager.ts
import { CLAUDE_MD_START, CLAUDE_MD_END } from '../constants.js';

const TEMPLATE = `<!-- shipsafe:start -->
# ShipSafe Security & Monitoring Agent
... (content from CLAUDE.md.template, kept under 50 lines)
<!-- shipsafe:end -->`;

export async function injectClaudeMd(projectDir?: string): Promise<void> { ... }
export async function removeClaudeMd(projectDir?: string): Promise<void> { ... }
export async function hasClaudeMdBlock(projectDir?: string): Promise<boolean> { ... }
```

- [ ] **Step 4: Run tests — expect PASS**
- [ ] **Step 5: Commit**

```bash
git add src/claude-md/ tests/claude-md/
git commit -m "feat: add CLAUDE.md manager for template injection"
```

---

### Task 12: MCP Server + Tools

**Files:**
- Create: `src/mcp/server.ts`
- Create: `src/mcp/tools/scan.ts`
- Create: `src/mcp/tools/status.ts`
- Create: `tests/mcp/tools.test.ts`

MCP server using `@modelcontextprotocol/sdk` with stdio transport. Exposes `shipsafe_scan` and `shipsafe_status` tools.

- [ ] **Step 1: Write MCP tool handler tests**

Test cases for scan tool:
- `handleScan({ scope: 'staged' })` calls pattern engine with staged scope
- `handleScan({ scope: 'all' })` calls pattern engine with all scope
- `handleScan({ fix: true })` passes fix flag through
- Returns JSON matching MCP_TOOLS.md response format

Test cases for status tool:
- `handleStatus()` returns project name, score, hooks status, last scan time
- Returns JSON matching MCP_TOOLS.md response format

- [ ] **Step 2: Run tests — expect FAIL**
- [ ] **Step 3: Implement MCP tool handlers**

```typescript
// src/mcp/tools/scan.ts
import { z } from 'zod';

export const scanToolSchema = {
  name: 'shipsafe_scan',
  description: 'Run security scan on the current project',
  inputSchema: z.object({
    scope: z.enum(['staged', 'all']).optional().default('staged'),
    fix: z.boolean().optional().default(false),
  }),
};

export async function handleScan(params: { scope?: string; fix?: boolean }) { ... }
```

```typescript
// src/mcp/tools/status.ts
export const statusToolSchema = {
  name: 'shipsafe_status',
  description: 'Get current project security status',
  inputSchema: z.object({}),
};

export async function handleStatus() { ... }
```

- [ ] **Step 4: Implement MCP server**

```typescript
// src/mcp/server.ts
import { McpServer, StdioServerTransport } from '@modelcontextprotocol/sdk/server/index.js';

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: 'shipsafe',
    version: VERSION,
  });

  // Register tools
  server.tool(scanToolSchema.name, scanToolSchema.description, scanToolSchema.inputSchema, handleScan);
  server.tool(statusToolSchema.name, statusToolSchema.description, statusToolSchema.inputSchema, handleStatus);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
```

- [ ] **Step 5: Add `mcp-server` command to CLI**

In `bin/shipsafe.ts`, add:
```typescript
program
  .command('mcp-server')
  .description('Start ShipSafe MCP server (stdio transport)')
  .action(async () => {
    await startMcpServer();
  });
```

This is the command that editors invoke when starting the MCP server.

- [ ] **Step 6: Run tests — expect PASS**
- [ ] **Step 7: Verify MCP server starts**

Run: `echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}' | npx tsx bin/shipsafe.ts mcp-server`
Expected: JSON response with server capabilities

- [ ] **Step 8: Commit**

```bash
git add src/mcp/ tests/mcp/
git commit -m "feat: add MCP server with shipsafe_scan and shipsafe_status tools"
```

---

## Chunk 5: Integration + Polish

### Task 13: End-to-End Integration

**Files:**
- Modify: `bin/shipsafe.ts` (final wiring)
- Modify: `package.json` (bin field, build scripts)

- [ ] **Step 1: Verify all commands work end-to-end**

Run each command and verify output:
```bash
npx tsx bin/shipsafe.ts --help
npx tsx bin/shipsafe.ts scan --scope all --json
npx tsx bin/shipsafe.ts status
npx tsx bin/shipsafe.ts setup --skip-mcp
```

- [ ] **Step 2: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 3: Build the project**

Run: `npm run build`
Expected: Compiles to `dist/` without errors

- [ ] **Step 4: Test the built binary**

Run: `node dist/bin/shipsafe.js --help`
Expected: Same output as tsx version

- [ ] **Step 5: Add shebang handling for bin**

Ensure `dist/bin/shipsafe.js` has `#!/usr/bin/env node` at top. May need a build step or the TypeScript source already handles this via the `#!/usr/bin/env node` comment at the top of `bin/shipsafe.ts`.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "feat: complete Phase 1 — core CLI, pattern engine, MCP server, git hooks"
```

- [ ] **Step 7: Push to GitHub**

```bash
git push -u origin main
```
