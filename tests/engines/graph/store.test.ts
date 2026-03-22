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

describe('GraphStore — basic functions', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore();
    await store.buildGraph(mockParsedFiles);
  });

  afterAll(async () => {
    await store.close();
  });

  it('createGraphStore returns a store with function nodes', async () => {
    const allFns = store.getAllFunctions();
    expect(allFns.length).toBeGreaterThan(0);
  });

  it('inserts function nodes from parsed files', () => {
    const allFns = store.getAllFunctions();
    const names = allFns.map((f) => f.name);
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
    const callees = await store.getCallees('handleRequest');
    expect(callees).toHaveLength(1);
    expect(callees[0].name).toBe('validateInput');
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

  it('getAllFunctions returns all function nodes', () => {
    const allFns = store.getAllFunctions();
    expect(allFns.length).toBe(3); // handleRequest, validateInput, runQuery
  });
});

describe('GraphStore — classes and methods', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore();
    await store.buildGraph(mockWithClasses);
  });

  afterAll(async () => {
    await store.close();
  });

  it('getFunction retrieves a class method by name', async () => {
    const fn = await store.getFunction('getUser');
    expect(fn).not.toBeNull();
    expect(fn!.name).toBe('getUser');
    expect(fn!.className).toBe('UserController');
  });

  it('creates CALLS edges for calls from class methods', async () => {
    const callees = await store.getCallees('getUser');
    expect(callees).toHaveLength(1);
    expect(callees[0].name).toBe('helperFn');
  });

  it('query returns class nodes', async () => {
    const rows = await store.query('MATCH (c:Class) RETURN c.name');
    expect(rows).toHaveLength(1);
    expect((rows[0] as Record<string, unknown>)['c.name']).toBe('UserController');
  });

  it('query returns class properties', async () => {
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
});

describe('GraphStore — transitive call chains', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore();
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
    store = await createGraphStore();
    await store.buildGraph(mockDuplicateNames);
  });

  afterAll(async () => {
    await store.close();
  });

  it('handles multiple files with same-named functions', () => {
    const allFns = store.getAllFunctions();
    const initFns = allFns.filter((f) => f.name === 'init');
    expect(initFns).toHaveLength(2);
    const paths = initFns.map((f) => f.filePath).sort();
    expect(paths).toEqual(['src/a.ts', 'src/b.ts']);
  });
});

describe('GraphStore — close', () => {
  it('cleans up resources without error', async () => {
    const store = await createGraphStore();
    await store.buildGraph(mockParsedFiles);
    await expect(store.close()).resolves.toBeUndefined();
  });
});

describe('GraphStore — module imports', () => {
  it('handles module names with single quotes', async () => {
    const store = await createGraphStore();
    const files: ParsedFile[] = [
      {
        filePath: 'src/app.ts',
        language: 'typescript',
        functions: [],
        classes: [],
        imports: [
          { source: "o'reilly-sdk", specifiers: ['Client'], filePath: 'src/app.ts', line: 1 },
        ],
        exports: [],
        callSites: [],
      },
    ];
    await store.buildGraph(files);

    const imports = await store.getImportsOf("o'reilly-sdk");
    expect(imports).toHaveLength(1);
    expect(imports[0].source).toBe("o'reilly-sdk");
    await store.close();
  });

  it('handles module names with backslashes', async () => {
    const store = await createGraphStore();
    const files: ParsedFile[] = [
      {
        filePath: 'src/app.ts',
        language: 'typescript',
        functions: [],
        classes: [],
        imports: [
          { source: 'path\\to\\module', specifiers: ['util'], filePath: 'src/app.ts', line: 1 },
        ],
        exports: [],
        callSites: [],
      },
    ];
    await store.buildGraph(files);

    const imports = await store.getImportsOf('path\\to\\module');
    expect(imports).toHaveLength(1);
    expect(imports[0].source).toBe('path\\to\\module');
    await store.close();
  });
});
