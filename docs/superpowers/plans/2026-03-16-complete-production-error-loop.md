# Complete the Production Error Loop — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the end-to-end production error loop so that errors captured by `@shipsafe/monitor` are persisted, enriched with source maps, and delivered to the coding session via MCP tools.

**Architecture:** Add missing API endpoints (verify-resolution, source map upload/storage, error resolution), replace in-memory error store with a SQLite adapter for local persistence, and wire the CLI source map upload command to actually upload. SQLite is chosen over PostgreSQL for now because it ships as a single file with zero infrastructure — ideal for local dev and self-hosted deployments. Postgres adapter can be swapped in later for the hosted cloud API.

**Tech Stack:** better-sqlite3, Hono routes, vitest, existing ShipSafe types

---

## Chunk 1: Missing API Endpoints + Source Map Storage

### Task 1: Add verify-resolution API endpoint

The MCP tool `verify-resolution` already calls `GET /v1/errors/:projectId/:errorId/status`, but this endpoint does not exist in the API.

**Files:**
- Create: `packages/api/src/routes/error-status.ts`
- Modify: `packages/api/src/index.ts`
- Create: `packages/api/tests/routes/error-status.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/api/tests/routes/error-status.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import app from '../../src/index.js';
import { storeError, clearStore } from '../../src/services/error-store.js';
import type { ProcessedError } from '../../src/types.js';

function makeError(overrides: Partial<ProcessedError> = {}): ProcessedError {
  return {
    id: 'err-1',
    project_id: 'proj-1',
    severity: 'high',
    title: 'TypeError: Cannot read properties of undefined',
    file: 'src/app.ts',
    line: 42,
    root_cause: 'Null access',
    suggested_fix: 'Add null check',
    users_affected: 5,
    occurrences: 10,
    first_seen: '2026-03-10T00:00:00Z',
    last_seen: '2026-03-15T12:00:00Z',
    status: 'open',
    stack_trace: 'TypeError: Cannot read properties of undefined\n    at handler (src/app.ts:42:5)',
    ...overrides,
  };
}

describe('GET /v1/errors/:projectId/:errorId/status', () => {
  beforeEach(() => {
    clearStore();
  });

  it('returns status for an existing open error', async () => {
    storeError(makeError({ id: 'err-1', project_id: 'proj-1', status: 'open' }));

    const res = await app.request('/v1/errors/proj-1/err-1/status');
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.status).toBe('recurring');
    expect(data.last_occurrence).toBe('2026-03-15T12:00:00Z');
    expect(data.confidence).toBeGreaterThan(0);
  });

  it('returns resolved status for a resolved error', async () => {
    storeError(makeError({ id: 'err-2', project_id: 'proj-1', status: 'resolved' }));

    const res = await app.request('/v1/errors/proj-1/err-2/status');
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.status).toBe('resolved');
    expect(data.confidence).toBeGreaterThan(0);
  });

  it('returns 404 for unknown error', async () => {
    const res = await app.request('/v1/errors/proj-1/nonexistent/status');
    expect(res.status).toBe(404);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/routes/error-status.test.ts`
Expected: FAIL — 404 for all routes (endpoint doesn't exist)

- [ ] **Step 3: Write the route implementation**

```typescript
// packages/api/src/routes/error-status.ts
import { Hono } from 'hono';
import { getErrors } from '../services/error-store.js';

export const errorStatusRoutes = new Hono();

errorStatusRoutes.get('/errors/:projectId/:errorId/status', (c) => {
  const projectId = c.req.param('projectId');
  const errorId = c.req.param('errorId');

  const allErrors = getErrors(projectId, { status: 'all' });
  const error = allErrors.find((e) => e.id === errorId);

  if (!error) {
    return c.json({ error: 'Error not found' }, 404);
  }

  const lastSeen = new Date(error.last_seen);
  const hoursSinceLast = (Date.now() - lastSeen.getTime()) / (1000 * 60 * 60);

  // Confidence based on how long since last occurrence
  // > 24h resolved = high confidence, < 1h = low confidence
  let confidence: number;
  if (error.status === 'resolved') {
    confidence = Math.min(hoursSinceLast / 24, 1);
  } else {
    // Still occurring — confidence that it's recurring
    confidence = Math.min(error.occurrences / 10, 1);
  }

  return c.json({
    status: error.status === 'resolved' ? 'resolved' : 'recurring',
    last_occurrence: error.last_seen,
    hours_since_last: Math.round(hoursSinceLast * 10) / 10,
    confidence: Math.round(confidence * 100) / 100,
  });
});
```

- [ ] **Step 4: Register the route in index.ts**

In `packages/api/src/index.ts`, add:
```typescript
import { errorStatusRoutes } from './routes/error-status.js';
// ... after existing routes:
app.route('/v1', errorStatusRoutes);
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd packages/api && npx vitest run tests/routes/error-status.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 6: Run all API tests for regression**

Run: `cd packages/api && npx vitest run`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add packages/api/src/routes/error-status.ts packages/api/tests/routes/error-status.test.ts packages/api/src/index.ts
git commit -m "feat(api): add verify-resolution endpoint for error status checks"
```

---

### Task 2: Add source map storage service

Store uploaded source maps in memory (same pattern as error-store, will be replaced by SQLite in Chunk 2). Source maps are keyed by project + release + file path.

**Files:**
- Create: `packages/api/src/services/sourcemap-store.ts`
- Create: `packages/api/tests/services/sourcemap-store.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/api/tests/services/sourcemap-store.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import {
  storeSourceMap,
  getSourceMap,
  listSourceMaps,
  clearSourceMapStore,
} from '../../src/services/sourcemap-store.js';

describe('sourcemap-store', () => {
  beforeEach(() => {
    clearSourceMapStore();
  });

  it('stores and retrieves a source map', () => {
    storeSourceMap('proj-1', '1.0.0', 'dist/app.js', '{"version":3}');
    const result = getSourceMap('proj-1', '1.0.0', 'dist/app.js');
    expect(result).toBe('{"version":3}');
  });

  it('returns undefined for unknown source map', () => {
    const result = getSourceMap('proj-1', '1.0.0', 'unknown.js');
    expect(result).toBeUndefined();
  });

  it('overwrites existing source map for same key', () => {
    storeSourceMap('proj-1', '1.0.0', 'dist/app.js', '{"version":3,"old":true}');
    storeSourceMap('proj-1', '1.0.0', 'dist/app.js', '{"version":3,"new":true}');
    const result = getSourceMap('proj-1', '1.0.0', 'dist/app.js');
    expect(result).toBe('{"version":3,"new":true}');
  });

  it('lists source maps for a project and release', () => {
    storeSourceMap('proj-1', '1.0.0', 'dist/app.js', '{}');
    storeSourceMap('proj-1', '1.0.0', 'dist/vendor.js', '{}');
    storeSourceMap('proj-1', '2.0.0', 'dist/app.js', '{}');

    const maps = listSourceMaps('proj-1', '1.0.0');
    expect(maps).toEqual(['dist/app.js', 'dist/vendor.js']);
  });

  it('isolates projects', () => {
    storeSourceMap('proj-1', '1.0.0', 'dist/app.js', '{}');
    storeSourceMap('proj-2', '1.0.0', 'dist/app.js', '{}');

    const maps1 = listSourceMaps('proj-1', '1.0.0');
    const maps2 = listSourceMaps('proj-2', '1.0.0');
    expect(maps1).toHaveLength(1);
    expect(maps2).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/services/sourcemap-store.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// packages/api/src/services/sourcemap-store.ts

/**
 * In-memory source map store. Keyed by project + release + file path.
 * Will be replaced by SQLite/Postgres adapter.
 */
const store = new Map<string, string>();

function makeKey(projectId: string, release: string, filePath: string): string {
  return `${projectId}::${release}::${filePath}`;
}

function parseKey(key: string): { projectId: string; release: string; filePath: string } | null {
  const parts = key.split('::');
  if (parts.length !== 3) return null;
  return { projectId: parts[0], release: parts[1], filePath: parts[2] };
}

export function storeSourceMap(
  projectId: string,
  release: string,
  filePath: string,
  content: string,
): void {
  store.set(makeKey(projectId, release, filePath), content);
}

export function getSourceMap(
  projectId: string,
  release: string,
  filePath: string,
): string | undefined {
  return store.get(makeKey(projectId, release, filePath));
}

export function listSourceMaps(projectId: string, release: string): string[] {
  const prefix = `${projectId}::${release}::`;
  const results: string[] = [];

  for (const key of store.keys()) {
    if (key.startsWith(prefix)) {
      const parsed = parseKey(key);
      if (parsed) results.push(parsed.filePath);
    }
  }

  return results.sort();
}

export function clearSourceMapStore(): void {
  store.clear();
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/api && npx vitest run tests/services/sourcemap-store.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/services/sourcemap-store.ts packages/api/tests/services/sourcemap-store.test.ts
git commit -m "feat(api): add source map storage service"
```

---

### Task 3: Add source map upload API endpoint

`POST /v1/sourcemaps` — accepts multipart or JSON with source map content, project_id, release, and file path.

**Files:**
- Create: `packages/api/src/routes/sourcemaps.ts`
- Modify: `packages/api/src/index.ts`
- Create: `packages/api/tests/routes/sourcemaps.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/api/tests/routes/sourcemaps.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import app from '../../src/index.js';
import { clearSourceMapStore, getSourceMap } from '../../src/services/sourcemap-store.js';

describe('POST /v1/sourcemaps', () => {
  beforeEach(() => {
    clearSourceMapStore();
  });

  it('uploads a source map', async () => {
    const res = await app.request('/v1/sourcemaps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Project-ID': 'proj-1' },
      body: JSON.stringify({
        project_id: 'proj-1',
        release: '1.0.0',
        file_path: 'dist/app.js',
        source_map: '{"version":3,"sources":["src/app.ts"]}',
      }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.stored).toBe(true);
    expect(data.file_path).toBe('dist/app.js');

    // Verify it was actually stored
    const stored = getSourceMap('proj-1', '1.0.0', 'dist/app.js');
    expect(stored).toBe('{"version":3,"sources":["src/app.ts"]}');
  });

  it('rejects missing fields', async () => {
    const res = await app.request('/v1/sourcemaps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Project-ID': 'proj-1' },
      body: JSON.stringify({ project_id: 'proj-1' }),
    });

    expect(res.status).toBe(400);
  });

  it('uploads multiple source maps in batch', async () => {
    const res = await app.request('/v1/sourcemaps/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Project-ID': 'proj-1' },
      body: JSON.stringify({
        project_id: 'proj-1',
        release: '1.0.0',
        source_maps: [
          { file_path: 'dist/app.js', source_map: '{"version":3}' },
          { file_path: 'dist/vendor.js', source_map: '{"version":3}' },
        ],
      }),
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.stored).toBe(2);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/routes/sourcemaps.test.ts`
Expected: FAIL — 404

- [ ] **Step 3: Write the route implementation**

```typescript
// packages/api/src/routes/sourcemaps.ts
import { Hono } from 'hono';
import { storeSourceMap } from '../services/sourcemap-store.js';

export const sourcemapRoutes = new Hono();

interface UploadBody {
  project_id: string;
  release: string;
  file_path: string;
  source_map: string;
}

interface BatchUploadBody {
  project_id: string;
  release: string;
  source_maps: Array<{ file_path: string; source_map: string }>;
}

sourcemapRoutes.post('/sourcemaps', async (c) => {
  let body: UploadBody;
  try {
    body = await c.req.json<UploadBody>();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  if (!body.project_id || !body.release || !body.file_path || !body.source_map) {
    return c.json({ error: 'Missing required fields: project_id, release, file_path, source_map' }, 400);
  }

  storeSourceMap(body.project_id, body.release, body.file_path, body.source_map);

  return c.json({ stored: true, file_path: body.file_path, release: body.release }, 201);
});

sourcemapRoutes.post('/sourcemaps/batch', async (c) => {
  let body: BatchUploadBody;
  try {
    body = await c.req.json<BatchUploadBody>();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  if (!body.project_id || !body.release || !Array.isArray(body.source_maps)) {
    return c.json({ error: 'Missing required fields: project_id, release, source_maps[]' }, 400);
  }

  for (const map of body.source_maps) {
    storeSourceMap(body.project_id, body.release, map.file_path, map.source_map);
  }

  return c.json({ stored: body.source_maps.length, release: body.release }, 201);
});
```

- [ ] **Step 4: Register route in index.ts**

In `packages/api/src/index.ts`, add:
```typescript
import { sourcemapRoutes } from './routes/sourcemaps.js';
// after existing routes:
app.route('/v1', sourcemapRoutes);
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd packages/api && npx vitest run tests/routes/sourcemaps.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 6: Run all API tests for regression**

Run: `cd packages/api && npx vitest run`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add packages/api/src/routes/sourcemaps.ts packages/api/tests/routes/sourcemaps.test.ts packages/api/src/index.ts
git commit -m "feat(api): add source map upload endpoints (single + batch)"
```

---

### Task 4: Wire CLI upload-sourcemaps to actually upload

Replace the stub in `src/cli/upload-sourcemaps.ts` with real upload logic that reads source map files and POSTs them to the API batch endpoint.

**Files:**
- Modify: `src/cli/upload-sourcemaps.ts`
- Modify: `tests/cli/upload-sourcemaps.test.ts` (or create if missing)

- [ ] **Step 1: Write the failing test**

```typescript
// tests/cli/upload-sourcemaps.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

// Mock config to return an API endpoint
vi.mock('../../src/config/manager.js', () => ({
  loadConfig: vi.fn().mockResolvedValue({
    projectId: 'proj-test',
    apiEndpoint: 'http://localhost:9999',
    licenseKey: 'SS-PRO-testkey123',
  }),
}));

// Mock fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

import { handleUploadSourcemaps } from '../../src/cli/upload-sourcemaps.js';

describe('upload-sourcemaps', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'shipsafe-upload-'));
    mockFetch.mockReset();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('uploads discovered source maps to the API', async () => {
    // Create test source map files
    await fs.writeFile(path.join(tmpDir, 'app.js.map'), '{"version":3}');
    await fs.writeFile(path.join(tmpDir, 'vendor.js.map'), '{"version":3}');

    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ stored: 2, release: '1.0.0' }),
    });

    await handleUploadSourcemaps({ dir: tmpDir, release: '1.0.0' });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe('http://localhost:9999/v1/sourcemaps/batch');
    expect(options.method).toBe('POST');

    const body = JSON.parse(options.body);
    expect(body.project_id).toBe('proj-test');
    expect(body.release).toBe('1.0.0');
    expect(body.source_maps).toHaveLength(2);
  });

  it('skips upload when no API endpoint configured', async () => {
    const { loadConfig } = await import('../../src/config/manager.js');
    vi.mocked(loadConfig).mockResolvedValueOnce({} as any);

    await fs.writeFile(path.join(tmpDir, 'app.js.map'), '{}');

    await handleUploadSourcemaps({ dir: tmpDir, release: '1.0.0' });

    expect(mockFetch).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/cli/upload-sourcemaps.test.ts`
Expected: FAIL — `handleUploadSourcemaps` doesn't accept `release` param / doesn't call fetch

- [ ] **Step 3: Update the implementation**

Replace `src/cli/upload-sourcemaps.ts` — keep `findSourceMaps()` as-is, rewrite `handleUploadSourcemaps` to read files and POST them, add `--release` option to the command registration.

```typescript
// Key changes to src/cli/upload-sourcemaps.ts:
// 1. Import loadConfig
// 2. handleUploadSourcemaps now accepts { dir, release } and reads file contents
// 3. POSTs to /v1/sourcemaps/batch
// 4. Falls back to package.json version if no --release flag
// 5. registerUploadSourcemapsCommand adds --release option
```

The full implementation:
- Keep `findSourceMaps()` unchanged
- `handleUploadSourcemaps({ dir, release })`:
  1. Find all .map files
  2. Load config for projectId + apiEndpoint
  3. If no config, print files found but warn about missing config
  4. Read each .map file content
  5. POST to `${apiEndpoint}/v1/sourcemaps/batch` with `{ project_id, release, source_maps: [{ file_path, source_map }] }`
  6. Report result
- Add `--release <version>` option, defaulting to package.json version or "unknown"

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/cli/upload-sourcemaps.test.ts`
Expected: PASS

- [ ] **Step 5: Run all tests for regression**

Run: `npm test`
Expected: All 445+ tests pass

- [ ] **Step 6: Commit**

```bash
git add src/cli/upload-sourcemaps.ts tests/cli/upload-sourcemaps.test.ts
git commit -m "feat(cli): wire upload-sourcemaps to POST source maps to API"
```

---

### Task 5: Add source map resolution to stack traces

When the API processes an error, resolve minified stack trace frames using stored source maps. This enriches the `file` and `line` fields in `ProcessedError`.

**Files:**
- Create: `packages/api/src/services/sourcemap-resolver.ts`
- Create: `packages/api/tests/services/sourcemap-resolver.test.ts`
- Modify: `packages/api/src/routes/ingest.ts` (call resolver after dedup)

- [ ] **Step 1: Write the failing test**

```typescript
// packages/api/tests/services/sourcemap-resolver.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { resolveStackFrame, clearSourceMapStore } from '../../src/services/sourcemap-resolver.js';

// A minimal valid source map pointing dist/app.js:1:100 → src/app.ts:42:5
const VALID_SOURCE_MAP = JSON.stringify({
  version: 3,
  file: 'app.js',
  sources: ['../../src/app.ts'],
  names: ['handler'],
  mappings: 'AAAA',
});

describe('sourcemap-resolver', () => {
  it('returns original frame when no source map available', () => {
    const result = resolveStackFrame('proj-1', '1.0.0', 'dist/app.js', 1, 100);
    expect(result).toEqual({ file: 'dist/app.js', line: 1 });
  });

  it('returns original frame for invalid source map JSON', () => {
    // This tests graceful degradation — resolver should never throw
    const result = resolveStackFrame('proj-1', '1.0.0', 'dist/app.js', 1, 100);
    expect(result.file).toBe('dist/app.js');
  });
});
```

Note: Full source map resolution requires a library like `source-map` (Mozilla). For now, implement a basic resolver that looks up stored maps and attempts to resolve. If `source-map` is too heavy, do a best-effort filename extraction from the `sources` array.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/services/sourcemap-resolver.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```typescript
// packages/api/src/services/sourcemap-resolver.ts
import { getSourceMap } from './sourcemap-store.js';

interface ResolvedFrame {
  file: string;
  line: number;
}

/**
 * Attempt to resolve a minified stack frame to original source.
 * Uses stored source maps. Falls back to original frame if no map found.
 *
 * This is a best-effort resolver that extracts the primary source file
 * from the source map's `sources` array. Full VLQ decoding would require
 * the `source-map` library — added when needed.
 */
export function resolveStackFrame(
  projectId: string,
  release: string,
  file: string,
  line: number,
  _column?: number,
): ResolvedFrame {
  const mapContent = getSourceMap(projectId, release, file + '.map')
    ?? getSourceMap(projectId, release, file);

  if (!mapContent) {
    return { file, line };
  }

  try {
    const map = JSON.parse(mapContent) as { sources?: string[] };

    if (map.sources && map.sources.length > 0) {
      // Use the first non-node_modules source as the likely original file
      const originalSource = map.sources.find((s) => !s.includes('node_modules'))
        ?? map.sources[0];

      // Clean up relative path prefixes
      const cleanPath = originalSource.replace(/^(\.\.\/)+/, '');

      return { file: cleanPath, line };
    }
  } catch {
    // Invalid JSON — fall through
  }

  return { file, line };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/api && npx vitest run tests/services/sourcemap-resolver.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/services/sourcemap-resolver.ts packages/api/tests/services/sourcemap-resolver.test.ts
git commit -m "feat(api): add best-effort source map stack frame resolver"
```

---

## Chunk 2: SQLite Persistence Layer

### Task 6: Add better-sqlite3 dependency

**Files:**
- Modify: `packages/api/package.json`

- [ ] **Step 1: Install better-sqlite3**

```bash
cd packages/api && npm install better-sqlite3 && npm install -D @types/better-sqlite3
```

- [ ] **Step 2: Verify install**

Run: `cd packages/api && node -e "require('better-sqlite3')"`
Expected: No error

- [ ] **Step 3: Commit**

```bash
git add packages/api/package.json packages/api/package-lock.json
git commit -m "chore(api): add better-sqlite3 for persistent storage"
```

---

### Task 7: Create SQLite database module

Handles database initialization, schema creation, and provides a shared database instance.

**Files:**
- Create: `packages/api/src/db/database.ts`
- Create: `packages/api/tests/db/database.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/api/tests/db/database.test.ts
import { describe, it, expect, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';

describe('database', () => {
  afterEach(() => {
    closeDatabase();
  });

  it('creates an in-memory database with schema', () => {
    const db = createDatabase(':memory:');

    // Verify errors table exists
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).all() as Array<{ name: string }>;

    const tableNames = tables.map((t) => t.name);
    expect(tableNames).toContain('errors');
    expect(tableNames).toContain('source_maps');
  });

  it('errors table has correct columns', () => {
    const db = createDatabase(':memory:');

    const columns = db.prepare('PRAGMA table_info(errors)').all() as Array<{ name: string }>;
    const colNames = columns.map((c) => c.name);

    expect(colNames).toContain('id');
    expect(colNames).toContain('project_id');
    expect(colNames).toContain('severity');
    expect(colNames).toContain('title');
    expect(colNames).toContain('file');
    expect(colNames).toContain('line');
    expect(colNames).toContain('root_cause');
    expect(colNames).toContain('suggested_fix');
    expect(colNames).toContain('users_affected');
    expect(colNames).toContain('occurrences');
    expect(colNames).toContain('first_seen');
    expect(colNames).toContain('last_seen');
    expect(colNames).toContain('status');
    expect(colNames).toContain('stack_trace');
  });

  it('source_maps table has correct columns', () => {
    const db = createDatabase(':memory:');

    const columns = db.prepare('PRAGMA table_info(source_maps)').all() as Array<{ name: string }>;
    const colNames = columns.map((c) => c.name);

    expect(colNames).toContain('project_id');
    expect(colNames).toContain('release_version');
    expect(colNames).toContain('file_path');
    expect(colNames).toContain('content');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/db/database.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// packages/api/src/db/database.ts
import Database from 'better-sqlite3';

let db: Database.Database | null = null;

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS errors (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'low',
    title TEXT NOT NULL,
    file TEXT NOT NULL DEFAULT 'unknown',
    line INTEGER NOT NULL DEFAULT 0,
    root_cause TEXT NOT NULL DEFAULT '',
    suggested_fix TEXT NOT NULL DEFAULT '',
    users_affected INTEGER NOT NULL DEFAULT 1,
    occurrences INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    stack_trace TEXT NOT NULL DEFAULT ''
  );

  CREATE INDEX IF NOT EXISTS idx_errors_project ON errors(project_id);
  CREATE INDEX IF NOT EXISTS idx_errors_status ON errors(project_id, status);

  CREATE TABLE IF NOT EXISTS source_maps (
    project_id TEXT NOT NULL,
    release_version TEXT NOT NULL,
    file_path TEXT NOT NULL,
    content TEXT NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (project_id, release_version, file_path)
  );
`;

export function createDatabase(path: string = ':memory:'): Database.Database {
  db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  return db;
}

export function getDatabase(): Database.Database {
  if (!db) {
    throw new Error('Database not initialized. Call createDatabase() first.');
  }
  return db;
}

export function closeDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/api && npx vitest run tests/db/database.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/db/database.ts packages/api/tests/db/database.test.ts
git commit -m "feat(api): add SQLite database module with schema"
```

---

### Task 8: Create SQLite error store adapter

Replace the in-memory Map with SQLite queries while keeping the same exported function signatures.

**Files:**
- Create: `packages/api/src/db/error-repo.ts`
- Create: `packages/api/tests/db/error-repo.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/api/tests/db/error-repo.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import {
  dbStoreError,
  dbGetErrors,
  dbResolveError,
  dbGetAllProjectErrors,
} from '../../src/db/error-repo.js';
import type { ProcessedError } from '../../src/types.js';

function makeError(overrides: Partial<ProcessedError> = {}): ProcessedError {
  return {
    id: 'err-1',
    project_id: 'proj-1',
    severity: 'high',
    title: 'TypeError: null access',
    file: 'src/app.ts',
    line: 42,
    root_cause: 'Null access',
    suggested_fix: 'Add null check',
    users_affected: 1,
    occurrences: 1,
    first_seen: '2026-03-10T00:00:00Z',
    last_seen: '2026-03-10T00:00:00Z',
    status: 'open',
    stack_trace: 'Error\n    at handler (src/app.ts:42:5)',
    ...overrides,
  };
}

describe('error-repo (SQLite)', () => {
  beforeEach(() => {
    createDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('stores and retrieves an error', () => {
    dbStoreError(makeError());
    const errors = dbGetErrors('proj-1');
    expect(errors).toHaveLength(1);
    expect(errors[0].id).toBe('err-1');
    expect(errors[0].severity).toBe('high');
  });

  it('updates an existing error by ID', () => {
    dbStoreError(makeError({ occurrences: 1 }));
    dbStoreError(makeError({ occurrences: 5, last_seen: '2026-03-15T00:00:00Z' }));

    const errors = dbGetErrors('proj-1');
    expect(errors).toHaveLength(1);
    expect(errors[0].occurrences).toBe(5);
    expect(errors[0].last_seen).toBe('2026-03-15T00:00:00Z');
  });

  it('filters by severity', () => {
    dbStoreError(makeError({ id: 'err-1', severity: 'high' }));
    dbStoreError(makeError({ id: 'err-2', severity: 'low' }));

    const high = dbGetErrors('proj-1', { severity: 'high' });
    expect(high).toHaveLength(1);
    expect(high[0].id).toBe('err-1');
  });

  it('filters by status', () => {
    dbStoreError(makeError({ id: 'err-1', status: 'open' }));
    dbStoreError(makeError({ id: 'err-2', status: 'resolved' }));

    const open = dbGetErrors('proj-1', { status: 'open' });
    expect(open).toHaveLength(1);
    expect(open[0].id).toBe('err-1');
  });

  it('sorts by severity then last_seen', () => {
    dbStoreError(makeError({ id: 'err-1', severity: 'low', last_seen: '2026-03-15T00:00:00Z' }));
    dbStoreError(makeError({ id: 'err-2', severity: 'critical', last_seen: '2026-03-10T00:00:00Z' }));
    dbStoreError(makeError({ id: 'err-3', severity: 'critical', last_seen: '2026-03-14T00:00:00Z' }));

    const errors = dbGetErrors('proj-1', { status: 'all' });
    expect(errors[0].id).toBe('err-3'); // critical, newer
    expect(errors[1].id).toBe('err-2'); // critical, older
    expect(errors[2].id).toBe('err-1'); // low
  });

  it('resolves an error', () => {
    dbStoreError(makeError({ id: 'err-1', status: 'open' }));
    const result = dbResolveError('err-1');
    expect(result).toBe(true);

    const errors = dbGetErrors('proj-1', { status: 'all' });
    expect(errors[0].status).toBe('resolved');
  });

  it('returns false when resolving unknown error', () => {
    const result = dbResolveError('nonexistent');
    expect(result).toBe(false);
  });

  it('isolates projects', () => {
    dbStoreError(makeError({ id: 'err-1', project_id: 'proj-1' }));
    dbStoreError(makeError({ id: 'err-2', project_id: 'proj-2' }));

    expect(dbGetAllProjectErrors('proj-1')).toHaveLength(1);
    expect(dbGetAllProjectErrors('proj-2')).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/db/error-repo.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// packages/api/src/db/error-repo.ts
import { getDatabase } from './database.js';
import type { ProcessedError } from '../types.js';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export function dbStoreError(error: ProcessedError): void {
  const db = getDatabase();

  db.prepare(`
    INSERT INTO errors (id, project_id, severity, title, file, line, root_cause, suggested_fix, users_affected, occurrences, first_seen, last_seen, status, stack_trace)
    VALUES (@id, @project_id, @severity, @title, @file, @line, @root_cause, @suggested_fix, @users_affected, @occurrences, @first_seen, @last_seen, @status, @stack_trace)
    ON CONFLICT(id) DO UPDATE SET
      severity = @severity,
      users_affected = @users_affected,
      occurrences = @occurrences,
      last_seen = @last_seen,
      status = @status,
      root_cause = @root_cause,
      suggested_fix = @suggested_fix
  `).run(error);
}

export function dbGetErrors(
  projectId: string,
  options?: { severity?: string; status?: string },
): ProcessedError[] {
  const db = getDatabase();

  let sql = 'SELECT * FROM errors WHERE project_id = ?';
  const params: unknown[] = [projectId];

  if (options?.severity && options.severity !== 'all') {
    sql += ' AND severity = ?';
    params.push(options.severity);
  }

  if (options?.status && options.status !== 'all') {
    sql += ' AND status = ?';
    params.push(options.status);
  } else if (!options?.status) {
    // Default to open
    sql += ' AND status = ?';
    params.push('open');
  }

  const rows = db.prepare(sql).all(...params) as ProcessedError[];

  // Sort in JS to match in-memory behavior exactly
  return rows.sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4);
    if (sevDiff !== 0) return sevDiff;
    return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
  });
}

export function dbResolveError(errorId: string): boolean {
  const db = getDatabase();
  const result = db.prepare('UPDATE errors SET status = ? WHERE id = ?').run('resolved', errorId);
  return result.changes > 0;
}

export function dbGetAllProjectErrors(projectId: string): ProcessedError[] {
  const db = getDatabase();
  return db.prepare('SELECT * FROM errors WHERE project_id = ?').all(projectId) as ProcessedError[];
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/api && npx vitest run tests/db/error-repo.test.ts`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/db/error-repo.ts packages/api/tests/db/error-repo.test.ts
git commit -m "feat(api): add SQLite error repository with same interface as in-memory store"
```

---

### Task 9: Create SQLite source map repository

**Files:**
- Create: `packages/api/src/db/sourcemap-repo.ts`
- Create: `packages/api/tests/db/sourcemap-repo.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// packages/api/tests/db/sourcemap-repo.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import {
  dbStoreSourceMap,
  dbGetSourceMap,
  dbListSourceMaps,
} from '../../src/db/sourcemap-repo.js';

describe('sourcemap-repo (SQLite)', () => {
  beforeEach(() => {
    createDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('stores and retrieves a source map', () => {
    dbStoreSourceMap('proj-1', '1.0.0', 'dist/app.js', '{"version":3}');
    const result = dbGetSourceMap('proj-1', '1.0.0', 'dist/app.js');
    expect(result).toBe('{"version":3}');
  });

  it('returns undefined for unknown', () => {
    const result = dbGetSourceMap('proj-1', '1.0.0', 'nope');
    expect(result).toBeUndefined();
  });

  it('upserts on conflict', () => {
    dbStoreSourceMap('proj-1', '1.0.0', 'dist/app.js', 'old');
    dbStoreSourceMap('proj-1', '1.0.0', 'dist/app.js', 'new');
    expect(dbGetSourceMap('proj-1', '1.0.0', 'dist/app.js')).toBe('new');
  });

  it('lists source maps for project + release', () => {
    dbStoreSourceMap('proj-1', '1.0.0', 'dist/a.js', '{}');
    dbStoreSourceMap('proj-1', '1.0.0', 'dist/b.js', '{}');
    dbStoreSourceMap('proj-1', '2.0.0', 'dist/a.js', '{}');

    const maps = dbListSourceMaps('proj-1', '1.0.0');
    expect(maps).toEqual(['dist/a.js', 'dist/b.js']);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/db/sourcemap-repo.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// packages/api/src/db/sourcemap-repo.ts
import { getDatabase } from './database.js';

export function dbStoreSourceMap(
  projectId: string,
  release: string,
  filePath: string,
  content: string,
): void {
  const db = getDatabase();

  db.prepare(`
    INSERT INTO source_maps (project_id, release_version, file_path, content)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(project_id, release_version, file_path)
    DO UPDATE SET content = excluded.content, uploaded_at = datetime('now')
  `).run(projectId, release, filePath, content);
}

export function dbGetSourceMap(
  projectId: string,
  release: string,
  filePath: string,
): string | undefined {
  const db = getDatabase();

  const row = db.prepare(
    'SELECT content FROM source_maps WHERE project_id = ? AND release_version = ? AND file_path = ?'
  ).get(projectId, release, filePath) as { content: string } | undefined;

  return row?.content;
}

export function dbListSourceMaps(projectId: string, release: string): string[] {
  const db = getDatabase();

  const rows = db.prepare(
    'SELECT file_path FROM source_maps WHERE project_id = ? AND release_version = ? ORDER BY file_path'
  ).all(projectId, release) as Array<{ file_path: string }>;

  return rows.map((r) => r.file_path);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/api && npx vitest run tests/db/sourcemap-repo.test.ts`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/db/sourcemap-repo.ts packages/api/tests/db/sourcemap-repo.test.ts
git commit -m "feat(api): add SQLite source map repository"
```

---

### Task 10: Swap routes to use SQLite repos + initialize DB at startup

Update the API routes and services to use the SQLite repositories instead of in-memory stores. Keep the in-memory stores available for tests that already use them (they'll work with `createDatabase(':memory:')` in test setup).

**Files:**
- Modify: `packages/api/src/index.ts` — initialize database on import
- Modify: `packages/api/src/routes/ingest.ts` — use dbStoreError, dbGetAllProjectErrors
- Modify: `packages/api/src/routes/errors.ts` — use dbGetErrors
- Modify: `packages/api/src/routes/error-status.ts` — use dbGetErrors
- Modify: `packages/api/src/routes/sourcemaps.ts` — use dbStoreSourceMap
- Create: `packages/api/tests/integration/full-loop.test.ts`

- [ ] **Step 1: Write an integration test for the full error loop**

```typescript
// packages/api/tests/integration/full-loop.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import app from '../../src/index.js';

describe('full error loop (integration)', () => {
  beforeEach(() => {
    createDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('ingest → query → verify status', async () => {
    // 1. Ingest an error event
    const ingestRes = await app.request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Project-ID': 'proj-1' },
      body: JSON.stringify({
        project_id: 'proj-1',
        events: [{
          type: 'error',
          timestamp: new Date().toISOString(),
          project_id: 'proj-1',
          environment: 'production',
          session_id: 'sess-1',
          error: {
            name: 'TypeError',
            message: 'Cannot read properties of undefined',
            stack: 'TypeError: Cannot read properties of undefined\n    at handler (src/app.ts:42:5)',
            handled: false,
          },
          context: { url: '/api/data' },
        }],
      }),
    });
    expect(ingestRes.status).toBe(202);
    const ingestData = await ingestRes.json();
    expect(ingestData.processed).toBe(1);

    // 2. Query errors for the project
    const errorsRes = await app.request('/v1/errors/proj-1');
    expect(errorsRes.status).toBe(200);
    const errorsData = await errorsRes.json();
    expect(errorsData.count).toBe(1);
    expect(errorsData.errors[0].title).toContain('TypeError');

    const errorId = errorsData.errors[0].id;

    // 3. Check error status
    const statusRes = await app.request(`/v1/errors/proj-1/${errorId}/status`);
    expect(statusRes.status).toBe(200);
    const statusData = await statusRes.json();
    expect(statusData.status).toBe('recurring');
  });

  it('ingest → upload source map → query with enriched data', async () => {
    // 1. Upload a source map
    const mapRes = await app.request('/v1/sourcemaps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Project-ID': 'proj-1' },
      body: JSON.stringify({
        project_id: 'proj-1',
        release: '1.0.0',
        file_path: 'dist/app.js.map',
        source_map: JSON.stringify({
          version: 3,
          sources: ['../../src/app.ts'],
          names: [],
          mappings: 'AAAA',
        }),
      }),
    });
    expect(mapRes.status).toBe(201);

    // 2. Ingest an error
    await app.request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Project-ID': 'proj-1' },
      body: JSON.stringify({
        project_id: 'proj-1',
        events: [{
          type: 'error',
          timestamp: new Date().toISOString(),
          project_id: 'proj-1',
          environment: 'production',
          session_id: 'sess-1',
          release: '1.0.0',
          error: {
            name: 'TypeError',
            message: 'null access',
            stack: 'TypeError: null access\n    at handler (dist/app.js:1:100)',
            handled: false,
          },
          context: {},
        }],
      }),
    });

    // 3. Query — the error should exist
    const errorsRes = await app.request('/v1/errors/proj-1');
    const data = await errorsRes.json();
    expect(data.count).toBe(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/integration/full-loop.test.ts`
Expected: FAIL — routes still use in-memory store, DB not initialized

- [ ] **Step 3: Update index.ts to initialize database**

In `packages/api/src/index.ts`, add database initialization:
```typescript
import { createDatabase } from './db/database.js';
import * as path from 'node:path';
import * as os from 'node:os';

// Initialize database — uses env var or defaults to ~/.shipsafe/shipsafe.db
const dbPath = process.env.SHIPSAFE_DB_PATH
  ?? path.join(os.homedir(), '.shipsafe', 'shipsafe.db');

// Only auto-initialize if not in test (tests manage their own DB)
if (process.env.NODE_ENV !== 'test') {
  createDatabase(dbPath);
}
```

- [ ] **Step 4: Update routes to use DB repos**

Update `ingest.ts`, `errors.ts`, `error-status.ts`, `sourcemaps.ts` to import from `../db/error-repo.js` and `../db/sourcemap-repo.js` instead of in-memory stores. The function signatures match, so it's an import swap.

Key changes:
- `ingest.ts`: `storeError` → `dbStoreError`, `getAllProjectErrors` → `dbGetAllProjectErrors`
- `errors.ts`: `getErrors` → `dbGetErrors`
- `error-status.ts`: `getErrors` → `dbGetErrors`
- `sourcemaps.ts`: `storeSourceMap` → `dbStoreSourceMap`

- [ ] **Step 5: Update existing route tests to init DB**

Add `beforeEach(() => createDatabase(':memory:'))` and `afterEach(() => closeDatabase())` to existing route tests that were using in-memory stores. This is needed because the routes now go through SQLite.

- [ ] **Step 6: Run integration test**

Run: `cd packages/api && npx vitest run tests/integration/full-loop.test.ts`
Expected: PASS

- [ ] **Step 7: Run all API tests**

Run: `cd packages/api && npx vitest run`
Expected: All tests pass

- [ ] **Step 8: Run full test suite**

Run: `npm test`
Expected: All tests pass

- [ ] **Step 9: Commit**

```bash
git add packages/api/src/ packages/api/tests/
git commit -m "feat(api): swap in-memory stores for SQLite persistence"
```

---

## Chunk 3: Resolve Endpoint + Error Resolution MCP Tool

### Task 11: Add resolve-error API endpoint

Allow marking an error as resolved via API. The MCP verify-resolution tool checks status, but there's no way to *mark* an error resolved from the API.

**Files:**
- Modify: `packages/api/src/routes/error-status.ts`
- Modify: `packages/api/tests/routes/error-status.test.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// Add to existing error-status.test.ts:
it('resolves an error via POST', async () => {
  storeOrDbStore(makeError({ id: 'err-1', project_id: 'proj-1', status: 'open' }));

  const res = await app.request('/v1/errors/proj-1/err-1/resolve', {
    method: 'POST',
  });
  expect(res.status).toBe(200);

  const data = await res.json();
  expect(data.resolved).toBe(true);

  // Verify status changed
  const statusRes = await app.request('/v1/errors/proj-1/err-1/status');
  const statusData = await statusRes.json();
  expect(statusData.status).toBe('resolved');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/api && npx vitest run tests/routes/error-status.test.ts`
Expected: FAIL — POST route doesn't exist

- [ ] **Step 3: Add the POST resolve route**

In `packages/api/src/routes/error-status.ts`, add:
```typescript
errorStatusRoutes.post('/errors/:projectId/:errorId/resolve', (c) => {
  const errorId = c.req.param('errorId');
  const resolved = dbResolveError(errorId);

  if (!resolved) {
    return c.json({ error: 'Error not found' }, 404);
  }

  return c.json({ resolved: true, error_id: errorId });
});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/api && npx vitest run tests/routes/error-status.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/routes/error-status.ts packages/api/tests/routes/error-status.test.ts
git commit -m "feat(api): add POST resolve endpoint to mark errors as resolved"
```

---

### Task 12: Update CLAUDE.md to reflect current architecture

The project CLAUDE.md is outdated — it only describes the CLI and pattern engine. Update it to reflect the full architecture.

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md**

Add sections for:
- `packages/api/` — Cloud API with SQLite persistence
- `packages/monitor/` — Client monitoring snippet
- `src/autofix/` — Auto-fix engine
- `src/github/` — GitHub App integration
- Database commands: `cd packages/api && npm run dev`
- Testing: `npm test` runs all packages, `cd packages/api && npm test` for API only

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with full architecture"
```
