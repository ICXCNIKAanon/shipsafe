import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createGraphStore, type GraphStore } from '../../../src/engines/graph/store.js';
import type { ParsedFile } from '../../../src/types.js';

// ── Fixtures ──

const mockParsedFiles: ParsedFile[] = [
  {
    filePath: 'src/routes/api.ts',
    language: 'typescript',
    functions: [
      {
        name: 'handleRequest',
        filePath: 'src/routes/api.ts',
        startLine: 10,
        endLine: 25,
        params: ['req', 'res'],
        isAsync: true,
        isExported: true,
      },
      {
        name: 'validateInput',
        filePath: 'src/routes/api.ts',
        startLine: 30,
        endLine: 40,
        params: ['data'],
        isAsync: false,
        isExported: false,
      },
    ],
    classes: [],
    imports: [
      {
        source: 'express',
        specifiers: ['Request', 'Response'],
        filePath: 'src/routes/api.ts',
        line: 1,
      },
    ],
    exports: [
      {
        name: 'handleRequest',
        filePath: 'src/routes/api.ts',
        line: 10,
        type: 'function',
      },
    ],
    callSites: [
      {
        callerName: 'handleRequest',
        calleeName: 'validateInput',
        filePath: 'src/routes/api.ts',
        line: 15,
      },
    ],
  },
  {
    filePath: 'src/db/queries.ts',
    language: 'typescript',
    functions: [
      {
        name: 'runQuery',
        filePath: 'src/db/queries.ts',
        startLine: 5,
        endLine: 15,
        params: ['sql', 'params'],
        isAsync: true,
        isExported: true,
      },
    ],
    classes: [],
    imports: [
      {
        source: 'pg',
        specifiers: ['Pool'],
        filePath: 'src/db/queries.ts',
        line: 1,
      },
    ],
    exports: [
      {
        name: 'runQuery',
        filePath: 'src/db/queries.ts',
        line: 5,
        type: 'function',
      },
    ],
    callSites: [],
  },
];

const mockWithClasses: ParsedFile[] = [
  {
    filePath: 'src/controllers/user.ts',
    language: 'typescript',
    functions: [
      {
        name: 'getUser',
        filePath: 'src/controllers/user.ts',
        startLine: 5,
        endLine: 15,
        params: ['req', 'res'],
        isAsync: true,
        isExported: true,
        className: 'UserController',
      },
      {
        name: 'deleteUser',
        filePath: 'src/controllers/user.ts',
        startLine: 20,
        endLine: 30,
        params: ['req', 'res'],
        isAsync: true,
        isExported: true,
        className: 'UserController',
      },
      {
        name: 'helperFn',
        filePath: 'src/controllers/user.ts',
        startLine: 35,
        endLine: 40,
        params: [],
        isAsync: false,
        isExported: false,
      },
    ],
    classes: [
      {
        name: 'UserController',
        filePath: 'src/controllers/user.ts',
        startLine: 3,
        endLine: 32,
        methods: ['getUser', 'deleteUser'],
        isExported: true,
      },
    ],
    imports: [
      {
        source: 'express',
        specifiers: ['Request', 'Response'],
        filePath: 'src/controllers/user.ts',
        line: 1,
      },
    ],
    exports: [
      {
        name: 'UserController',
        filePath: 'src/controllers/user.ts',
        line: 3,
        type: 'class',
      },
    ],
    callSites: [
      {
        callerName: 'getUser',
        calleeName: 'helperFn',
        filePath: 'src/controllers/user.ts',
        line: 10,
      },
    ],
  },
];

// Three-level call chain: alpha -> beta -> gamma (for depth testing)
const mockCallChain: ParsedFile[] = [
  {
    filePath: 'src/chain.ts',
    language: 'typescript',
    functions: [
      {
        name: 'alpha',
        filePath: 'src/chain.ts',
        startLine: 1,
        endLine: 5,
        params: [],
        isAsync: false,
        isExported: true,
      },
      {
        name: 'beta',
        filePath: 'src/chain.ts',
        startLine: 10,
        endLine: 15,
        params: [],
        isAsync: false,
        isExported: false,
      },
      {
        name: 'gamma',
        filePath: 'src/chain.ts',
        startLine: 20,
        endLine: 25,
        params: [],
        isAsync: false,
        isExported: false,
      },
    ],
    classes: [],
    imports: [],
    exports: [],
    callSites: [
      {
        callerName: 'alpha',
        calleeName: 'beta',
        filePath: 'src/chain.ts',
        line: 3,
      },
      {
        callerName: 'beta',
        calleeName: 'gamma',
        filePath: 'src/chain.ts',
        line: 12,
      },
    ],
  },
];

// Same-named functions in different files
const mockDuplicateNames: ParsedFile[] = [
  {
    filePath: 'src/a.ts',
    language: 'typescript',
    functions: [
      {
        name: 'init',
        filePath: 'src/a.ts',
        startLine: 1,
        endLine: 5,
        params: [],
        isAsync: false,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [],
    callSites: [],
  },
  {
    filePath: 'src/b.ts',
    language: 'typescript',
    functions: [
      {
        name: 'init',
        filePath: 'src/b.ts',
        startLine: 1,
        endLine: 10,
        params: ['config'],
        isAsync: true,
        isExported: false,
      },
    ],
    classes: [],
    imports: [],
    exports: [],
    callSites: [],
  },
];

// ── Tests ──
// Each describe block uses a single shared store to minimise KuzuDB
// native-module churn (creating/destroying many Database objects can
// trigger SIGSEGV during garbage collection in some environments).

describe('GraphStore — basic functions', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore(':memory:');
    await store.buildGraph(mockParsedFiles);
  });

  afterAll(async () => {
    await store.close();
  });

  it('createGraphStore returns a store with all expected methods', () => {
    expect(store).toBeDefined();
    expect(store.buildGraph).toBeTypeOf('function');
    expect(store.getFunction).toBeTypeOf('function');
    expect(store.getCallers).toBeTypeOf('function');
    expect(store.getCallees).toBeTypeOf('function');
    expect(store.getImportsOf).toBeTypeOf('function');
    expect(store.query).toBeTypeOf('function');
    expect(store.close).toBeTypeOf('function');
  });

  it('inserts function nodes from parsed files', async () => {
    const rows = await store.query('MATCH (f:Function) RETURN f.name ORDER BY f.name');
    const names = (rows as Array<Record<string, unknown>>).map((r) => r['f.name']);
    expect(names).toContain('handleRequest');
    expect(names).toContain('validateInput');
    expect(names).toContain('runQuery');
  });

  it('stores function properties correctly', async () => {
    const fn = await store.getFunction('handleRequest');
    expect(fn).not.toBeNull();
    expect(fn!.name).toBe('handleRequest');
    expect(fn!.filePath).toBe('src/routes/api.ts');
    expect(fn!.startLine).toBe(10);
    expect(fn!.endLine).toBe(25);
    expect(fn!.isAsync).toBe(true);
    expect(fn!.isExported).toBe(true);
  });

  it('getFunction retrieves a function by name', async () => {
    const fn = await store.getFunction('validateInput');
    expect(fn).not.toBeNull();
    expect(fn!.name).toBe('validateInput');
    expect(fn!.startLine).toBe(30);
    expect(fn!.endLine).toBe(40);
    expect(fn!.isAsync).toBe(false);
    expect(fn!.isExported).toBe(false);
  });

  it('getFunction returns null for non-existent function', async () => {
    const fn = await store.getFunction('nonExistent');
    expect(fn).toBeNull();
  });

  it('creates CALLS edges for call sites', async () => {
    const rows = await store.query(
      'MATCH (a:Function)-[:CALLS]->(b:Function) RETURN a.name, b.name',
    );
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row['a.name']).toBe('handleRequest');
    expect(row['b.name']).toBe('validateInput');
  });

  it('creates CONTAINS edges (file -> function)', async () => {
    const rows = await store.query(
      "MATCH (f:File)-[:CONTAINS]->(fn:Function) WHERE f.path = 'src/routes/api.ts' RETURN fn.name ORDER BY fn.name",
    );
    const names = (rows as Array<Record<string, unknown>>).map((r) => r['fn.name']);
    expect(names).toContain('handleRequest');
    expect(names).toContain('validateInput');
  });

  it('creates IMPORTS edges (file -> module)', async () => {
    const rows = await store.query(
      'MATCH (f:File)-[r:IMPORTS]->(m:Module) RETURN f.path, m.name, r.specifiers ORDER BY m.name',
    );
    expect(rows.length).toBeGreaterThanOrEqual(2);

    const expressImport = (rows as Array<Record<string, unknown>>).find(
      (r) => r['m.name'] === 'express',
    );
    expect(expressImport).toBeDefined();
    expect(expressImport!['f.path']).toBe('src/routes/api.ts');
  });

  it('getCallers returns functions that call the target', async () => {
    const callers = await store.getCallers('validateInput');
    expect(callers).toHaveLength(1);
    expect(callers[0].name).toBe('handleRequest');
  });

  it('getCallers returns empty array when no callers exist', async () => {
    const callers = await store.getCallers('handleRequest');
    expect(callers).toHaveLength(0);
  });

  it('getCallees returns functions called by the target', async () => {
    const callees = await store.getCallees('handleRequest');
    expect(callees).toHaveLength(1);
    expect(callees[0].name).toBe('validateInput');
  });

  it('getCallees returns empty array when no callees exist', async () => {
    const callees = await store.getCallees('validateInput');
    expect(callees).toHaveLength(0);
  });

  it('getImportsOf returns files that import a given module', async () => {
    const imports = await store.getImportsOf('express');
    expect(imports).toHaveLength(1);
    expect(imports[0].filePath).toBe('src/routes/api.ts');
    expect(imports[0].source).toBe('express');
    expect(imports[0].specifiers).toContain('Request');
    expect(imports[0].specifiers).toContain('Response');
  });

  it('getImportsOf returns empty array for unknown module', async () => {
    const imports = await store.getImportsOf('nonexistent-pkg');
    expect(imports).toHaveLength(0);
  });

  it('query executes raw Cypher queries', async () => {
    const rows = await store.query('MATCH (f:File) RETURN f.path ORDER BY f.path');
    const paths = (rows as Array<Record<string, unknown>>).map((r) => r['f.path']);
    expect(paths).toContain('src/routes/api.ts');
    expect(paths).toContain('src/db/queries.ts');
  });

  it('query supports parameterized queries', async () => {
    const rows = await store.query(
      'MATCH (f:Function) WHERE f.name = $name RETURN f.filePath',
      { name: 'handleRequest' },
    );
    expect(rows).toHaveLength(1);
    expect((rows[0] as Record<string, unknown>)['f.filePath']).toBe('src/routes/api.ts');
  });
});

describe('GraphStore — classes and methods', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore(':memory:');
    await store.buildGraph(mockWithClasses);
  });

  afterAll(async () => {
    await store.close();
  });

  it('inserts class nodes', async () => {
    const rows = await store.query('MATCH (c:Class) RETURN c.name');
    expect(rows).toHaveLength(1);
    expect((rows[0] as Record<string, unknown>)['c.name']).toBe('UserController');
  });

  it('stores class properties correctly', async () => {
    const rows = await store.query(
      "MATCH (c:Class) WHERE c.name = 'UserController' RETURN c.name, c.filePath, c.startLine, c.endLine, c.isExported",
    );
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row['c.filePath']).toBe('src/controllers/user.ts');
    expect(row['c.startLine']).toBe(3);
    expect(row['c.endLine']).toBe(32);
    expect(row['c.isExported']).toBe(true);
  });

  it('creates CONTAINS_CLASS edges (file -> class)', async () => {
    const rows = await store.query(
      'MATCH (f:File)-[:CONTAINS_CLASS]->(c:Class) RETURN f.path, c.name',
    );
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row['f.path']).toBe('src/controllers/user.ts');
    expect(row['c.name']).toBe('UserController');
  });

  it('creates HAS_METHOD edges (class -> function)', async () => {
    const rows = await store.query(
      "MATCH (c:Class)-[:HAS_METHOD]->(fn:Function) WHERE c.name = 'UserController' RETURN fn.name ORDER BY fn.name",
    );
    const names = (rows as Array<Record<string, unknown>>).map((r) => r['fn.name']);
    expect(names).toContain('getUser');
    expect(names).toContain('deleteUser');
    expect(names).not.toContain('helperFn');
  });

  it('getFunction retrieves a class method by name', async () => {
    const fn = await store.getFunction('getUser');
    expect(fn).not.toBeNull();
    expect(fn!.name).toBe('getUser');
    expect(fn!.className).toBe('UserController');
  });

  it('creates CALLS edges for calls from class methods', async () => {
    const rows = await store.query(
      'MATCH (a:Function)-[:CALLS]->(b:Function) RETURN a.name, b.name',
    );
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(row['a.name']).toBe('getUser');
    expect(row['b.name']).toBe('helperFn');
  });
});

describe('GraphStore — transitive call chains', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore(':memory:');
    await store.buildGraph(mockCallChain);
  });

  afterAll(async () => {
    await store.close();
  });

  it('getCallers with depth=1 returns only direct callers', async () => {
    const directCallers = await store.getCallers('gamma', 1);
    expect(directCallers).toHaveLength(1);
    expect(directCallers[0].name).toBe('beta');
  });

  it('getCallers with depth=2 returns transitive callers', async () => {
    const transitiveCallers = await store.getCallers('gamma', 2);
    const names = transitiveCallers.map((c) => c.name);
    expect(names).toContain('alpha');
    expect(names).toContain('beta');
    expect(transitiveCallers).toHaveLength(2);
  });

  it('getCallees with depth=1 returns only direct callees', async () => {
    const directCallees = await store.getCallees('alpha', 1);
    expect(directCallees).toHaveLength(1);
    expect(directCallees[0].name).toBe('beta');
  });

  it('getCallees with depth=2 returns transitive callees', async () => {
    const transitiveCallees = await store.getCallees('alpha', 2);
    const names = transitiveCallees.map((c) => c.name);
    expect(names).toContain('beta');
    expect(names).toContain('gamma');
    expect(transitiveCallees).toHaveLength(2);
  });
});

describe('GraphStore — duplicate function names', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore(':memory:');
    await store.buildGraph(mockDuplicateNames);
  });

  afterAll(async () => {
    await store.close();
  });

  it('handles multiple files with same-named functions via unique IDs', async () => {
    const rows = await store.query(
      "MATCH (f:Function) WHERE f.name = 'init' RETURN f.id, f.filePath ORDER BY f.filePath",
    );
    expect(rows).toHaveLength(2);

    const row0 = rows[0] as Record<string, unknown>;
    const row1 = rows[1] as Record<string, unknown>;
    expect(row0['f.id']).toBe('src/a.ts::init');
    expect(row1['f.id']).toBe('src/b.ts::init');
    expect(row0['f.filePath']).toBe('src/a.ts');
    expect(row1['f.filePath']).toBe('src/b.ts');
  });
});

describe('GraphStore — close', () => {
  it('cleans up resources without error', async () => {
    const store = await createGraphStore(':memory:');
    await store.buildGraph(mockParsedFiles);
    await expect(store.close()).resolves.toBeUndefined();
  });
});
