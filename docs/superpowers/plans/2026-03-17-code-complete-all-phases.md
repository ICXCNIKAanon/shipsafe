# Code-Complete All Phases — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every code gap across ShipSafe's 6 build phases so the project is code-complete and ready for npm publish + GitHub App registration.

**Architecture:** Nine focused tasks that fill the remaining holes: wire the `--fix` flag, add an `init` command, implement data-flow taint tracking, fix the default API endpoint, add license tier enforcement, create Docker deployment, prep npm packages, write the README, and push to GitHub.

**Tech Stack:** TypeScript, Commander.js, Vitest, Hono, Docker, tree-sitter queries (existing)

---

## File Structure

New files to create:
```
src/cli/init.ts                          # `shipsafe init` command handler
tests/cli/init.test.ts                   # Tests for init command
src/engines/graph/data-flow.ts           # Taint tracking from sources to sinks
tests/engines/graph/data-flow.test.ts    # Tests for data flow analysis
packages/api/Dockerfile                  # Multi-stage Docker build for API
packages/api/docker-compose.yml          # Local dev compose with API + volume
README.md                               # Project README
```

Files to modify:
```
src/cli/scan.ts                          # Wire --fix flag to autofix
bin/shipsafe.ts                          # Register init command
src/engines/graph/queries.ts             # Add findDataFlow export
src/engines/graph/index.ts               # Run data flow query in engine
src/config/manager.ts                    # SHIPSAFE_API_URL env var support
src/constants.ts                         # DEFAULT_API_URL constant
packages/api/src/routes/license.ts       # Tier-based feature gating
packages/api/src/types.ts                # TierFeatures type
package.json                             # publishConfig, prepublishOnly
packages/monitor/package.json            # publishConfig, files, keywords
packages/api/package.json                # Add start script for Docker
```

---

## Chunk 1: Wire --fix Flag + Init Command (Phase 1)

### Task 1: Wire --fix flag through scan to autofix

The `--fix` flag is accepted by the scan command but never used. Wire it to call the secret fixer for hardcoded_secret findings and the scaffolding recommender for other auto_fixable findings.

**Files:**
- Modify: `src/cli/scan.ts`
- Create: `tests/cli/scan-fix.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/cli/scan-fix.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleScanAction } from '../../src/cli/scan.js';

// Mock the pattern engine
vi.mock('../../src/engines/pattern/index.js', () => ({
  runPatternEngine: vi.fn(),
}));

// Mock the secret fixer
vi.mock('../../src/autofix/secret-fixer.js', () => ({
  fixHardcodedSecret: vi.fn(),
}));

import { runPatternEngine } from '../../src/engines/pattern/index.js';
import { fixHardcodedSecret } from '../../src/autofix/secret-fixer.js';

const mockRunPatternEngine = vi.mocked(runPatternEngine);
const mockFixSecret = vi.mocked(fixHardcodedSecret);

describe('scan --fix', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Prevent process.exit from killing the test
    vi.spyOn(process, 'exit').mockImplementation(() => undefined as never);
  });

  it('calls fixHardcodedSecret for secret findings when --fix is passed', async () => {
    mockRunPatternEngine.mockResolvedValue({
      status: 'fail',
      score: 'F',
      findings: [
        {
          id: 'gitleaks_1',
          engine: 'pattern',
          severity: 'critical',
          type: 'hardcoded_secret',
          file: 'src/config.ts',
          line: 12,
          description: 'Hardcoded API key',
          fix_suggestion: 'Move to .env',
          auto_fixable: true,
        },
      ],
      scan_duration_ms: 100,
    });

    mockFixSecret.mockResolvedValue({
      fixed: true,
      envVar: 'API_KEY',
      filesModified: ['src/config.ts', '.env'],
    });

    // Suppress console output
    vi.spyOn(console, 'log').mockImplementation(() => {});

    await handleScanAction({ scope: 'all', fix: true, json: false });

    expect(mockFixSecret).toHaveBeenCalledTimes(1);
    expect(mockFixSecret).toHaveBeenCalledWith(
      expect.objectContaining({ file: 'src/config.ts', line: 12 }),
    );
  });

  it('does not call fixHardcodedSecret when --fix is not passed', async () => {
    mockRunPatternEngine.mockResolvedValue({
      status: 'fail',
      score: 'F',
      findings: [
        {
          id: 'gitleaks_1',
          engine: 'pattern',
          severity: 'critical',
          type: 'hardcoded_secret',
          file: 'src/config.ts',
          line: 12,
          description: 'Hardcoded API key',
          fix_suggestion: 'Move to .env',
          auto_fixable: true,
        },
      ],
      scan_duration_ms: 100,
    });

    vi.spyOn(console, 'log').mockImplementation(() => {});

    await handleScanAction({ scope: 'all', fix: false, json: false });

    expect(mockFixSecret).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/shipsafe && npx vitest run tests/cli/scan-fix.test.ts`
Expected: FAIL — fixHardcodedSecret not called

- [ ] **Step 3: Wire the --fix flag in scan.ts**

```typescript
// src/cli/scan.ts — add import at top
import { fixHardcodedSecret } from '../autofix/secret-fixer.js';

// In handleScanAction, after getting result and before formatting:
  // Auto-fix if requested
  if (options.fix) {
    for (const finding of result.findings) {
      if (finding.auto_fixable && finding.type === 'hardcoded_secret') {
        try {
          const fixResult = await fixHardcodedSecret(finding);
          if (fixResult.fixed) {
            console.log(chalk.green(`  Fixed: ${finding.file}:${finding.line} → moved to .env as ${fixResult.envVar}`));
          }
        } catch {
          // Fix failed — continue with other findings
        }
      }
    }
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/shipsafe && npx vitest run tests/cli/scan-fix.test.ts`
Expected: PASS

- [ ] **Step 5: Run full test suite for regression**

Run: `cd ~/shipsafe && npx vitest run`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/cli/scan.ts tests/cli/scan-fix.test.ts
git commit -m "feat(cli): wire --fix flag to auto-fix hardcoded secrets during scan"
```

---

### Task 2: Add `shipsafe init` command

Bootstrap a new project with: generate project ID, create `shipsafe.config.json`, run setup (hooks + MCP + CLAUDE.md), and print getting-started instructions.

**Files:**
- Create: `src/cli/init.ts`
- Create: `tests/cli/init.test.ts`
- Modify: `bin/shipsafe.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/cli/init.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleInitAction } from '../../src/cli/init.js';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import os from 'node:os';

// Mock setup command
vi.mock('../../src/cli/setup.js', () => ({
  handleSetupAction: vi.fn().mockResolvedValue(undefined),
}));

import { handleSetupAction } from '../../src/cli/setup.js';

describe('shipsafe init', () => {
  let tmpDir: string;

  beforeEach(async () => {
    vi.clearAllMocks();
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'shipsafe-init-'));
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  it('creates shipsafe.config.json with a project ID', async () => {
    await handleInitAction({ projectDir: tmpDir, skipSetup: true });

    const configPath = path.join(tmpDir, 'shipsafe.config.json');
    const raw = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(raw);

    expect(config.projectId).toBeDefined();
    expect(typeof config.projectId).toBe('string');
    expect(config.projectId.length).toBeGreaterThan(0);
  });

  it('does not overwrite existing config', async () => {
    const configPath = path.join(tmpDir, 'shipsafe.config.json');
    await fs.writeFile(configPath, JSON.stringify({ projectId: 'existing-id' }));

    await handleInitAction({ projectDir: tmpDir, skipSetup: true });

    const raw = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(raw);
    expect(config.projectId).toBe('existing-id');
  });

  it('calls handleSetupAction when skipSetup is false', async () => {
    await handleInitAction({ projectDir: tmpDir, skipSetup: false });

    expect(handleSetupAction).toHaveBeenCalledTimes(1);
  });

  it('does not call handleSetupAction when skipSetup is true', async () => {
    await handleInitAction({ projectDir: tmpDir, skipSetup: true });

    expect(handleSetupAction).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/shipsafe && npx vitest run tests/cli/init.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement init command**

```typescript
// src/cli/init.ts
import { Command } from 'commander';
import chalk from 'chalk';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { CONFIG_FILE } from '../constants.js';
import { getProjectName, loadProjectConfig, saveProjectConfig } from '../config/manager.js';
import { handleSetupAction } from './setup.js';

export interface InitOptions {
  projectDir?: string;
  skipSetup?: boolean;
}

export async function handleInitAction(options: InitOptions): Promise<void> {
  const dir = options.projectDir ?? process.cwd();
  const configPath = path.join(dir, CONFIG_FILE);

  // Check if config already exists
  let existingConfig: Record<string, unknown> | null = null;
  try {
    const raw = await fs.readFile(configPath, 'utf-8');
    existingConfig = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    // No existing config
  }

  if (existingConfig?.projectId) {
    console.log(chalk.yellow(`Project already initialized (ID: ${existingConfig.projectId})`));
    console.log(`Config: ${configPath}\n`);
  } else {
    // Generate project ID and create config
    const projectId = `proj_${randomUUID().slice(0, 12)}`;
    const projectName = getProjectName(dir);

    const config = await loadProjectConfig(dir);
    await saveProjectConfig(
      { ...config, projectId },
      dir,
    );

    console.log(chalk.green(`\nShipSafe initialized for "${projectName}"`));
    console.log(`Project ID: ${projectId}`);
    console.log(`Config: ${configPath}\n`);
  }

  // Run setup unless skipped
  if (!options.skipSetup) {
    await handleSetupAction({});
  }

  // Print getting-started instructions
  console.log(chalk.bold('Next steps:'));
  console.log('  1. Run a scan:          shipsafe scan --scope all');
  console.log('  2. Check status:        shipsafe status');
  console.log('  3. Activate Pro:        shipsafe activate SS-PRO-<key>');
  console.log('  4. Add monitoring:      npm install @shipsafe/monitor');
  console.log('');
}

export function registerInitCommand(program: Command): void {
  program
    .command('init')
    .description('Initialize ShipSafe for the current project')
    .option('--skip-setup', 'Skip hook/MCP/CLAUDE.md setup', false)
    .action(async (options: { skipSetup?: boolean }) => {
      await handleInitAction({ skipSetup: options.skipSetup });
    });
}
```

- [ ] **Step 4: Register init command in bin/shipsafe.ts**

Add import and registration:
```typescript
import { registerInitCommand } from '../src/cli/init.js';
// ... after other registrations:
registerInitCommand(program);
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ~/shipsafe && npx vitest run tests/cli/init.test.ts`
Expected: PASS

- [ ] **Step 6: Run full test suite for regression**

Run: `cd ~/shipsafe && npx vitest run`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add src/cli/init.ts tests/cli/init.test.ts bin/shipsafe.ts
git commit -m "feat(cli): add init command for project bootstrapping"
```

---

## Chunk 2: Data Flow Taint Tracking (Phase 2)

### Task 3: Add data flow analysis to graph engine

Implement `findDataFlow()` that traces tainted data from source functions (user input, request params) through call chains to dangerous sinks (SQL, filesystem, shell).

**Files:**
- Create: `src/engines/graph/data-flow.ts`
- Create: `tests/engines/graph/data-flow.test.ts`
- Modify: `src/engines/graph/index.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/engines/graph/data-flow.test.ts
import { describe, it, expect } from 'vitest';
import { findDataFlows, classifySource, classifySink, type DataFlowResult } from '../../src/engines/graph/data-flow.js';

describe('data-flow classification', () => {
  it('classifies user input sources', () => {
    expect(classifySource('getRequestBody')).toBe('user_input');
    expect(classifySource('req.params')).toBe('user_input');
    expect(classifySource('readLine')).toBe('user_input');
  });

  it('returns null for non-sources', () => {
    expect(classifySource('calculateTotal')).toBeNull();
    expect(classifySource('formatDate')).toBeNull();
  });

  it('classifies dangerous sinks', () => {
    expect(classifySink('query')).toBe('database');
    expect(classifySink('exec')).toBe('shell');
    expect(classifySink('writeFile')).toBe('filesystem');
  });

  it('returns null for non-sinks', () => {
    expect(classifySink('formatDate')).toBeNull();
    expect(classifySink('calculateTotal')).toBeNull();
  });
});

describe('findDataFlows', () => {
  it('returns empty array when no call graph provided', async () => {
    const mockStore = {
      query: async () => [],
      getCallees: async () => [],
      getCallers: async () => [],
    };

    const results = await findDataFlows(mockStore as any);
    expect(results).toEqual([]);
  });

  it('identifies tainted flow from source to sink', async () => {
    // Simulate: handleRequest → processInput → query
    const functions = [
      { name: 'handleRequest', filePath: 'src/api.ts', line: 1, isAsync: true, isExported: true },
      { name: 'processInput', filePath: 'src/api.ts', line: 10, isAsync: false, isExported: false },
      { name: 'query', filePath: 'src/db.ts', line: 5, isAsync: true, isExported: false },
    ];

    const mockStore = {
      query: async () => functions,
      getCallees: async (name: string) => {
        if (name === 'handleRequest') return [{ name: 'processInput', filePath: 'src/api.ts', startLine: 10 }];
        if (name === 'processInput') return [{ name: 'query', filePath: 'src/db.ts', startLine: 5 }];
        return [];
      },
    };

    const results = await findDataFlows(mockStore as any);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].source.name).toBe('handleRequest');
    expect(results[0].sink.name).toBe('query');
    expect(results[0].sink.type).toBe('database');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/shipsafe && npx vitest run tests/engines/graph/data-flow.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement data flow analysis**

```typescript
// src/engines/graph/data-flow.ts
import type { GraphStore } from './store.js';

export interface DataFlowResult {
  source: { name: string; filePath: string; line: number; type: string };
  sink: { name: string; filePath: string; line: number; type: string };
  path: string[];
  hasSanitization: boolean;
}

const SOURCE_PATTERNS: Record<string, string[]> = {
  user_input: ['request', 'req', 'body', 'params', 'query', 'getRequestBody', 'readLine', 'input', 'formData'],
  environment: ['env', 'getenv', 'process.env'],
  file_read: ['readFile', 'createReadStream', 'readFileSync'],
};

const SINK_PATTERNS: Record<string, string[]> = {
  database: ['query', 'execute', 'exec', 'find', 'insert', 'update', 'delete', 'raw', 'sql'],
  filesystem: ['writeFile', 'writeFileSync', 'appendFile', 'createWriteStream', 'unlink'],
  shell: ['exec', 'execSync', 'spawn', 'execFile', 'system'],
  network: ['fetch', 'request', 'http.get', 'axios', 'redirect'],
  eval: ['eval', 'Function', 'setTimeout', 'setInterval'],
};

const SANITIZER_PATTERNS = ['valid', 'sanitiz', 'escape', 'clean', 'encode', 'parameteriz', 'prepare'];

export function classifySource(name: string): string | null {
  const nameLower = name.toLowerCase();
  for (const [type, patterns] of Object.entries(SOURCE_PATTERNS)) {
    for (const pattern of patterns) {
      if (nameLower.includes(pattern.toLowerCase())) {
        return type;
      }
    }
  }
  return null;
}

export function classifySink(name: string): string | null {
  const nameLower = name.toLowerCase();
  for (const [type, patterns] of Object.entries(SINK_PATTERNS)) {
    for (const pattern of patterns) {
      if (nameLower === pattern.toLowerCase() || nameLower.endsWith(pattern.toLowerCase())) {
        return type;
      }
    }
  }
  return null;
}

function isSanitizer(name: string): boolean {
  const nameLower = name.toLowerCase();
  return SANITIZER_PATTERNS.some((p) => nameLower.includes(p));
}

/**
 * Trace data flows from source functions to sink functions through the call graph.
 * Identifies paths where user input may reach dangerous operations without sanitization.
 */
export async function findDataFlows(store: GraphStore): Promise<DataFlowResult[]> {
  const allFunctions = (await store.query(
    'MATCH (fn:Function) RETURN fn.name AS name, fn.filePath AS filePath, fn.startLine AS line, fn.isAsync AS isAsync, fn.isExported AS isExported',
  )) as Array<Record<string, unknown>>;

  if (allFunctions.length === 0) return [];

  const results: DataFlowResult[] = [];

  // Find all functions that are sources (handle user input)
  const sources = allFunctions.filter((fn) => {
    const name = fn['name'] as string;
    return classifySource(name) !== null;
  });

  for (const source of sources) {
    const sourceName = source['name'] as string;
    const sourceType = classifySource(sourceName)!;

    // BFS from source, looking for sinks
    const visited = new Set<string>();
    const queue: Array<{ name: string; path: string[] }> = [
      { name: sourceName, path: [sourceName] },
    ];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current.name)) continue;
      visited.add(current.name);

      // Max depth 8
      if (current.path.length > 8) continue;

      const callees = await store.getCallees(current.name, 1);

      for (const callee of callees) {
        const sinkType = classifySink(callee.name);
        const newPath = [...current.path, callee.name];

        if (sinkType) {
          // Found a source → sink path
          results.push({
            source: {
              name: sourceName,
              filePath: source['filePath'] as string,
              line: source['line'] as number,
              type: sourceType,
            },
            sink: {
              name: callee.name,
              filePath: callee.filePath,
              line: callee.startLine,
              type: sinkType,
            },
            path: newPath,
            hasSanitization: newPath.some((n) => isSanitizer(n)),
          });
        }

        if (!visited.has(callee.name)) {
          queue.push({ name: callee.name, path: newPath });
        }
      }
    }
  }

  return results;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/shipsafe && npx vitest run tests/engines/graph/data-flow.test.ts`
Expected: PASS

- [ ] **Step 5: Wire data flow into graph engine**

In `src/engines/graph/index.ts`, add:

```typescript
import { findDataFlows } from './data-flow.js';
```

After the existing `queryResultsToFindings` call, add data flow findings:

```typescript
    // Run data flow analysis
    const dataFlows = await findDataFlows(store);

    // Convert data flows to findings
    for (const flow of dataFlows) {
      if (!flow.hasSanitization) {
        findings.push({
          id: `kg-data-flow-${findings.length + 1}`,
          engine: 'knowledge_graph',
          severity: flow.sink.type === 'shell' || flow.sink.type === 'eval' ? 'critical' : 'high',
          type: 'tainted_data_flow',
          file: flow.source.filePath,
          line: flow.source.line,
          description: `Unsanitized ${flow.source.type} flows from ${flow.source.name} to ${flow.sink.name} (${flow.sink.type}): ${flow.path.join(' → ')}`,
          fix_suggestion: `Add input validation/sanitization between ${flow.source.name} and ${flow.sink.name}`,
          auto_fixable: false,
        });
      }
    }
```

- [ ] **Step 6: Run full test suite for regression**

Run: `cd ~/shipsafe && npx vitest run`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add src/engines/graph/data-flow.ts tests/engines/graph/data-flow.test.ts src/engines/graph/index.ts
git commit -m "feat(graph): add data flow taint tracking from sources to sinks"
```

---

## Chunk 3: API Endpoint + License Enforcement (Phase 4 + 6)

### Task 4: Fix default API endpoint with env var support

Replace the hardcoded `https://ingest.shipsafe.org` with `SHIPSAFE_API_URL` env var support and a localhost fallback for development.

**Files:**
- Modify: `src/constants.ts`
- Modify: `src/config/manager.ts`
- Create: `tests/config/api-endpoint.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// tests/config/api-endpoint.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getApiEndpoint } from '../../src/config/manager.js';

describe('getApiEndpoint', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('returns SHIPSAFE_API_URL env var when set', () => {
    process.env.SHIPSAFE_API_URL = 'https://custom.api.example.com';
    expect(getApiEndpoint()).toBe('https://custom.api.example.com');
  });

  it('returns config apiEndpoint when env var not set', () => {
    delete process.env.SHIPSAFE_API_URL;
    expect(getApiEndpoint({ apiEndpoint: 'https://my.api.com' })).toBe('https://my.api.com');
  });

  it('returns default when neither env var nor config set', () => {
    delete process.env.SHIPSAFE_API_URL;
    expect(getApiEndpoint()).toBe('http://localhost:3747');
  });

  it('env var takes precedence over config', () => {
    process.env.SHIPSAFE_API_URL = 'https://env.example.com';
    expect(getApiEndpoint({ apiEndpoint: 'https://config.example.com' })).toBe('https://env.example.com');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/shipsafe && npx vitest run tests/config/api-endpoint.test.ts`
Expected: FAIL — getApiEndpoint not found

- [ ] **Step 3: Add DEFAULT_API_URL to constants.ts**

```typescript
// Add to src/constants.ts
export const DEFAULT_API_URL = 'http://localhost:3747';
```

- [ ] **Step 4: Add getApiEndpoint to config manager**

```typescript
// Add to src/config/manager.ts
import { DEFAULT_API_URL } from '../constants.js';

/**
 * Resolve the API endpoint. Priority: env var > config > default.
 */
export function getApiEndpoint(config?: Partial<ShipSafeConfig>): string {
  return process.env.SHIPSAFE_API_URL ?? config?.apiEndpoint ?? DEFAULT_API_URL;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ~/shipsafe && npx vitest run tests/config/api-endpoint.test.ts`
Expected: PASS

- [ ] **Step 6: Run full test suite for regression**

Run: `cd ~/shipsafe && npx vitest run`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add src/constants.ts src/config/manager.ts tests/config/api-endpoint.test.ts
git commit -m "feat(config): add SHIPSAFE_API_URL env var with localhost default"
```

---

### Task 5: Add license tier enforcement

Extend the license validation to return tier-specific feature limits and add a middleware for the API.

**Files:**
- Modify: `packages/api/src/types.ts`
- Modify: `packages/api/src/routes/license.ts`
- Create: `packages/api/tests/routes/license-tiers.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/api/tests/routes/license-tiers.test.ts
import { describe, it, expect } from 'vitest';
import app from '../../src/index.js';

describe('license tier enforcement', () => {
  it('returns free tier limits for free license', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-FREE-abc12345' }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.tier).toBe('free');
    expect(data.project_limit).toBe(1);
    expect(data.features).toBeDefined();
    expect(data.features.graph_engine).toBe(false);
    expect(data.features.auto_fix_pr).toBe(false);
    expect(data.features.github_app).toBe(false);
  });

  it('returns pro tier limits for pro license', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-PRO-abc12345' }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.tier).toBe('pro');
    expect(data.project_limit).toBe(5);
    expect(data.features.graph_engine).toBe(true);
    expect(data.features.auto_fix_pr).toBe(true);
    expect(data.features.github_app).toBe(false);
  });

  it('returns team tier limits for team license', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-TEAM-abc12345' }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.tier).toBe('team');
    expect(data.project_limit).toBe(20);
    expect(data.features.github_app).toBe(true);
  });

  it('returns agency tier limits for agency license', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-AGENCY-abc12345' }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.tier).toBe('agency');
    expect(data.project_limit).toBe(100);
    expect(data.features.github_app).toBe(true);
    expect(data.features.priority_support).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/shipsafe/packages/api && npx vitest run tests/routes/license-tiers.test.ts`
Expected: FAIL — features property missing

- [ ] **Step 3: Add TierFeatures type**

```typescript
// Add to packages/api/src/types.ts
export interface TierFeatures {
  pattern_engine: boolean;
  graph_engine: boolean;
  auto_fix_pr: boolean;
  github_app: boolean;
  monitoring: boolean;
  priority_support: boolean;
  custom_rules: boolean;
}

// Update LicenseInfo to include features
export interface LicenseInfo {
  valid: boolean;
  tier: LicenseTier;
  expires_at: string;
  project_limit: number;
  features: TierFeatures;
}
```

- [ ] **Step 4: Update license route with tier features**

```typescript
// packages/api/src/routes/license.ts — update TIER_MAP
const TIER_MAP: Record<string, { tier: LicenseTier; projectLimit: number; features: TierFeatures }> = {
  FREE: {
    tier: 'free',
    projectLimit: 1,
    features: {
      pattern_engine: true,
      graph_engine: false,
      auto_fix_pr: false,
      github_app: false,
      monitoring: true,
      priority_support: false,
      custom_rules: false,
    },
  },
  PRO: {
    tier: 'pro',
    projectLimit: 5,
    features: {
      pattern_engine: true,
      graph_engine: true,
      auto_fix_pr: true,
      github_app: false,
      monitoring: true,
      priority_support: false,
      custom_rules: true,
    },
  },
  TEAM: {
    tier: 'team',
    projectLimit: 20,
    features: {
      pattern_engine: true,
      graph_engine: true,
      auto_fix_pr: true,
      github_app: true,
      monitoring: true,
      priority_support: false,
      custom_rules: true,
    },
  },
  AGENCY: {
    tier: 'agency',
    projectLimit: 100,
    features: {
      pattern_engine: true,
      graph_engine: true,
      auto_fix_pr: true,
      github_app: true,
      monitoring: true,
      priority_support: true,
      custom_rules: true,
    },
  },
};

// Update validateLicenseKey to include features in return
function validateLicenseKey(key: string): LicenseInfo | null {
  if (!key || typeof key !== 'string') return null;

  const match = key.match(/^SS-(FREE|PRO|TEAM|AGENCY)-[a-zA-Z0-9]{8,}$/);
  if (!match) return null;

  const tierKey = match[1];
  const tierInfo = TIER_MAP[tierKey];
  if (!tierInfo) return null;

  const expiresAt = new Date();
  expiresAt.setFullYear(expiresAt.getFullYear() + 1);

  return {
    valid: true,
    tier: tierInfo.tier,
    expires_at: expiresAt.toISOString(),
    project_limit: tierInfo.projectLimit,
    features: tierInfo.features,
  };
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ~/shipsafe/packages/api && npx vitest run tests/routes/license-tiers.test.ts`
Expected: PASS

- [ ] **Step 6: Run all API tests for regression**

Run: `cd ~/shipsafe/packages/api && npx vitest run`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add packages/api/src/types.ts packages/api/src/routes/license.ts packages/api/tests/routes/license-tiers.test.ts
git commit -m "feat(api): add license tier feature enforcement (free/pro/team/agency)"
```

---

## Chunk 4: Docker + npm Publish Prep (Phase 6)

### Task 6: Add Dockerfile and docker-compose for the API

**Files:**
- Create: `packages/api/Dockerfile`
- Create: `packages/api/docker-compose.yml`
- Modify: `packages/api/package.json`

- [ ] **Step 1: Add start script to API package.json**

Add to `packages/api/package.json` scripts:
```json
"start": "node dist/serve.js"
```

- [ ] **Step 2: Create Dockerfile**

```dockerfile
# packages/api/Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

ENV NODE_ENV=production
ENV PORT=3747
ENV SHIPSAFE_DB_PATH=/data/shipsafe.db

EXPOSE 3747

VOLUME /data

CMD ["node", "dist/serve.js"]
```

- [ ] **Step 3: Create serve.ts entry point for the API**

```typescript
// packages/api/src/serve.ts
import { serve } from '@hono/node-server';
import app from './index.js';

const port = parseInt(process.env.PORT ?? '3747', 10);

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`ShipSafe API running on http://localhost:${info.port}`);
});
```

- [ ] **Step 4: Add @hono/node-server dependency**

Run: `cd ~/shipsafe/packages/api && npm install @hono/node-server`

- [ ] **Step 5: Create docker-compose.yml**

```yaml
# packages/api/docker-compose.yml
version: "3.8"

services:
  api:
    build: .
    ports:
      - "3747:3747"
    volumes:
      - shipsafe-data:/data
    environment:
      - NODE_ENV=production
      - PORT=3747
      - SHIPSAFE_DB_PATH=/data/shipsafe.db

volumes:
  shipsafe-data:
```

- [ ] **Step 6: Verify Docker build works**

Run: `cd ~/shipsafe/packages/api && docker build -t shipsafe-api .`
Expected: Build succeeds

- [ ] **Step 7: Commit**

```bash
git add packages/api/Dockerfile packages/api/docker-compose.yml packages/api/src/serve.ts packages/api/package.json
git commit -m "feat(api): add Dockerfile, docker-compose, and node server entry point"
```

---

### Task 7: npm publish preparation for both packages

Configure `package.json` files for both `shipsafe` CLI and `@shipsafe/monitor` to be publish-ready.

**Files:**
- Modify: `package.json`
- Modify: `packages/monitor/package.json`

- [ ] **Step 1: Update root package.json for CLI publish**

Add/update these fields:

```json
{
  "repository": {
    "type": "git",
    "url": "git+https://github.com/jakewlittle-cs/shipsafe.git"
  },
  "homepage": "https://shipsafe.org",
  "bugs": {
    "url": "https://github.com/jakewlittle-cs/shipsafe/issues"
  },
  "files": [
    "dist/",
    "README.md",
    "LICENSE"
  ],
  "publishConfig": {
    "access": "public"
  },
  "scripts": {
    "prepublishOnly": "npm run build && npm test"
  }
}
```

- [ ] **Step 2: Update monitor package.json for publish**

Add/update these fields:

```json
{
  "repository": {
    "type": "git",
    "url": "git+https://github.com/jakewlittle-cs/shipsafe.git",
    "directory": "packages/monitor"
  },
  "homepage": "https://shipsafe.org",
  "bugs": {
    "url": "https://github.com/jakewlittle-cs/shipsafe/issues"
  },
  "files": [
    "dist/",
    "README.md"
  ],
  "publishConfig": {
    "access": "public"
  },
  "scripts": {
    "prepublishOnly": "npm run build && npm test"
  },
  "keywords": [
    "monitoring",
    "error-tracking",
    "performance",
    "shipsafe",
    "vibe-coding",
    "production-errors"
  ]
}
```

- [ ] **Step 3: Verify builds work**

Run: `cd ~/shipsafe && npm run build && cd packages/monitor && npm run build`
Expected: Both builds succeed

- [ ] **Step 4: Commit**

```bash
git add package.json packages/monitor/package.json
git commit -m "chore: configure npm publish settings for shipsafe and @shipsafe/monitor"
```

---

## Chunk 5: README + Push to GitHub (Phase 6)

### Task 8: Write README.md

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write the README**

````markdown
# ShipSafe

Full-lifecycle security and reliability for vibe coders.

ShipSafe scans your code for vulnerabilities, monitors production errors, and auto-fixes issues — all wired into your AI coding agent via MCP.

## Install

```bash
npm install -g shipsafe
```

## Quick Start

```bash
# Initialize in your project
shipsafe init

# Run a security scan
shipsafe scan --scope all

# Check project status
shipsafe status
```

## What It Does

**Scan** — Runs Semgrep (SAST), Gitleaks (secrets), and Trivy (dependency CVEs) in parallel. Scores your project A through F.

**Knowledge Graph** — Parses your TypeScript/JavaScript/Python with tree-sitter, builds a call graph in KuzuDB, and finds attack paths, missing auth, and tainted data flows.

**MCP Server** — Exposes 7 tools to AI coding agents (Claude Code, Cursor, etc.):
- `shipsafe_scan` — run security scan
- `shipsafe_status` — project security status
- `shipsafe_graph_query` — query code relationships
- `shipsafe_production_errors` — fetch production errors
- `shipsafe_fix` — auto-fix findings
- `shipsafe_verify_resolution` — check if errors are resolved
- `shipsafe_check_package` — vet npm packages before installing

**Git Hooks** — Pre-commit scans staged files, pre-push scans everything.

**Auto-Fix** — Moves hardcoded secrets to `.env`, generates fix PRs for 10+ common error patterns.

**Production Monitoring** — `@shipsafe/monitor` captures errors and performance metrics with PII scrubbing, batching, and framework adapters for Express, Next.js, and React.

**GitHub Integration** — PR scanning via GitHub Checks API with inline annotations.

## Production Monitoring

```bash
npm install @shipsafe/monitor
```

```typescript
import { ShipSafeClient } from '@shipsafe/monitor';

const monitor = new ShipSafeClient({
  projectId: 'your-project-id',
  environment: 'production',
});
```

### Framework Adapters

```typescript
// Express
import { errorHandler } from '@shipsafe/monitor/node';
app.use(errorHandler(monitor));

// Next.js
import { setupNextjs } from '@shipsafe/monitor';
setupNextjs(monitor);

// React
import { createErrorHandler } from '@shipsafe/monitor';
const onError = createErrorHandler(monitor);
```

## Self-Hosted API

```bash
cd packages/api
docker compose up -d
```

The API runs on port 3747. Set `SHIPSAFE_API_URL` to point your CLI and monitor at it:

```bash
export SHIPSAFE_API_URL=http://localhost:3747
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `shipsafe init` | Initialize ShipSafe for current project |
| `shipsafe scan` | Scan for vulnerabilities |
| `shipsafe scan --fix` | Scan and auto-fix what's possible |
| `shipsafe status` | Show security score and project info |
| `shipsafe setup` | Install hooks, register MCP, inject CLAUDE.md |
| `shipsafe activate <key>` | Activate a license |
| `shipsafe connect` | Connect GitHub App |
| `shipsafe upload-sourcemaps` | Upload source maps for error resolution |
| `shipsafe config list` | Show all config values |
| `shipsafe mcp-server` | Start MCP server (used by editors) |

## Configuration

**Global config:** `~/.shipsafe/config.json`
**Project config:** `shipsafe.config.json`

```json
{
  "projectId": "proj_abc123",
  "scan": {
    "ignore_paths": ["node_modules", "dist"],
    "severity_threshold": "high"
  },
  "monitoring": {
    "enabled": true,
    "error_sample_rate": 1.0,
    "performance_sample_rate": 0.1
  }
}
```

## License Tiers

| Feature | Free | Pro | Team | Agency |
|---------|------|-----|------|--------|
| Pattern Engine | Yes | Yes | Yes | Yes |
| Knowledge Graph | - | Yes | Yes | Yes |
| Auto-Fix PRs | - | Yes | Yes | Yes |
| GitHub App | - | - | Yes | Yes |
| Monitoring | Yes | Yes | Yes | Yes |
| Custom Rules | - | Yes | Yes | Yes |
| Priority Support | - | - | - | Yes |
| Projects | 1 | 5 | 20 | 100 |

## Requirements

- Node.js >= 20
- Optional: [Semgrep](https://semgrep.dev), [Gitleaks](https://github.com/gitleaks/gitleaks), [Trivy](https://trivy.dev) (installed separately)

## License

UNLICENSED — Copyright Connect Holdings LLC
````

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README with install, usage, and configuration guide"
```

---

### Task 9: Push to GitHub

- [ ] **Step 1: Run full test suite one final time**

Run: `cd ~/shipsafe && npm test`
Expected: All tests pass

- [ ] **Step 2: Verify build**

Run: `cd ~/shipsafe && npm run build`
Expected: Build succeeds

- [ ] **Step 3: Push to GitHub**

```bash
cd ~/shipsafe && git push -u origin main
```
Expected: All commits pushed to jakewlittle-cs/shipsafe (private repo)
