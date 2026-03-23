import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createGraphStore, type GraphStore } from '../../../src/engines/graph/store.js';
import {
  classifySource,
  classifySink,
  findDataFlows,
  type DataFlowResult,
} from '../../../src/engines/graph/data-flow.js';
import type { ParsedFile } from '../../../src/types.js';

// ── Pure unit tests (no graph store) ──

describe('classifySource', () => {
  it('returns user_input for getRequestBody', () => {
    expect(classifySource('getRequestBody')).toBe('user_input');
  });

  it('returns user_input for parseRequest', () => {
    expect(classifySource('parseRequest')).toBe('user_input');
  });

  it('returns user_input for functions containing "getBody"', () => {
    expect(classifySource('getBody')).toBe('user_input');
  });

  it('returns user_input for readInput', () => {
    expect(classifySource('readInput')).toBe('user_input');
  });

  it('returns user_input for functions containing "formData"', () => {
    expect(classifySource('parseFormData')).toBe('user_input');
  });

  it('returns null for calculateTotal', () => {
    expect(classifySource('calculateTotal')).toBe(null);
  });

  it('returns null for unrelated names', () => {
    expect(classifySource('formatDate')).toBe(null);
    expect(classifySource('renderPage')).toBe(null);
  });
});

describe('classifySink', () => {
  it('returns database for executeQuery', () => {
    expect(classifySink('executeQuery')).toBe('database');
  });

  it('returns shell for exec', () => {
    expect(classifySink('exec')).toBe('shell');
  });

  it('returns filesystem for writeFile', () => {
    expect(classifySink('writeFile')).toBe('filesystem');
  });

  it('returns eval for eval', () => {
    expect(classifySink('eval')).toBe('eval');
  });

  it('returns null for formatDate', () => {
    expect(classifySink('formatDate')).toBe(null);
  });

  it('returns null for unrelated names', () => {
    expect(classifySink('calculateTotal')).toBe(null);
    expect(classifySink('renderPage')).toBe(null);
  });
});

// ── Graph-based tests ──

// Graph fixture:
//
// File: src/api/users.ts
//   - getRequestBody() [exported] -- SOURCE (user_input)
//   - processUserInput() [exported] -- calls getRequestBody, then calls buildQuery
//   - buildQuery() [exported] -- calls executeQuery (SINK)
//
// File: src/db/db.ts
//   - executeQuery() -- SINK (database)
//
// File: src/api/safe.ts
//   - readInput() [exported] -- SOURCE (user_input)
//   - sanitizeInput() [exported] -- SANITIZER -- called by safeHandler
//   - safeHandler() [exported] -- calls readInput, calls sanitizeInput, calls execSync (SINK)
//
// File: src/utils/shell.ts
//   - execSync() -- SINK (shell)

const mockParsedFiles: ParsedFile[] = [
  {
    filePath: 'src/api/users.ts',
    language: 'typescript',
    functions: [
      {
        name: 'getRequestBody',
        filePath: 'src/api/users.ts',
        startLine: 5,
        endLine: 10,
        params: [],
        isAsync: false,
        isExported: true,
      },
      {
        name: 'processUserInput',
        filePath: 'src/api/users.ts',
        startLine: 15,
        endLine: 30,
        params: [],
        isAsync: false,
        isExported: true,
      },
      {
        name: 'buildQuery',
        filePath: 'src/api/users.ts',
        startLine: 35,
        endLine: 50,
        params: [],
        isAsync: false,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'getRequestBody', filePath: 'src/api/users.ts', line: 5, type: 'function' },
      { name: 'processUserInput', filePath: 'src/api/users.ts', line: 15, type: 'function' },
      { name: 'buildQuery', filePath: 'src/api/users.ts', line: 35, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'processUserInput',
        calleeName: 'getRequestBody',
        filePath: 'src/api/users.ts',
        line: 18,
      },
      {
        callerName: 'processUserInput',
        calleeName: 'buildQuery',
        filePath: 'src/api/users.ts',
        line: 22,
      },
      {
        callerName: 'buildQuery',
        calleeName: 'executeQuery',
        filePath: 'src/api/users.ts',
        line: 40,
      },
    ],
  },
  {
    filePath: 'src/db/db.ts',
    language: 'typescript',
    functions: [
      {
        name: 'executeQuery',
        filePath: 'src/db/db.ts',
        startLine: 10,
        endLine: 20,
        params: ['sql'],
        isAsync: true,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [{ name: 'executeQuery', filePath: 'src/db/db.ts', line: 10, type: 'function' }],
    callSites: [],
  },
  {
    filePath: 'src/api/safe.ts',
    language: 'typescript',
    functions: [
      {
        name: 'readInput',
        filePath: 'src/api/safe.ts',
        startLine: 5,
        endLine: 10,
        params: [],
        isAsync: false,
        isExported: true,
      },
      {
        name: 'sanitizeInput',
        filePath: 'src/api/safe.ts',
        startLine: 15,
        endLine: 25,
        params: ['data'],
        isAsync: false,
        isExported: true,
      },
      {
        name: 'safeHandler',
        filePath: 'src/api/safe.ts',
        startLine: 30,
        endLine: 50,
        params: [],
        isAsync: false,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'readInput', filePath: 'src/api/safe.ts', line: 5, type: 'function' },
      { name: 'sanitizeInput', filePath: 'src/api/safe.ts', line: 15, type: 'function' },
      { name: 'safeHandler', filePath: 'src/api/safe.ts', line: 30, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'safeHandler',
        calleeName: 'readInput',
        filePath: 'src/api/safe.ts',
        line: 33,
      },
      {
        callerName: 'safeHandler',
        calleeName: 'sanitizeInput',
        filePath: 'src/api/safe.ts',
        line: 36,
      },
      {
        callerName: 'safeHandler',
        calleeName: 'execSync',
        filePath: 'src/api/safe.ts',
        line: 40,
      },
    ],
  },
  {
    filePath: 'src/utils/shell.ts',
    language: 'typescript',
    functions: [
      {
        name: 'execSync',
        filePath: 'src/utils/shell.ts',
        startLine: 5,
        endLine: 15,
        params: ['cmd'],
        isAsync: false,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [{ name: 'execSync', filePath: 'src/utils/shell.ts', line: 5, type: 'function' }],
    callSites: [],
  },
];

describe('findDataFlows (graph-based)', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore();
    await store.buildGraph(mockParsedFiles);
  });

  afterAll(async () => {
    await store.close();
  });

  it('returns empty array when no functions exist', async () => {
    // Use a fresh store with no data
    const emptyStore = await createGraphStore();
    const flows = await findDataFlows(emptyStore);
    expect(flows).toEqual([]);
    await emptyStore.close();
  });

  it('identifies tainted flow from source to sink through call chain', async () => {
    const flows = await findDataFlows(store);

    expect(flows.length).toBeGreaterThan(0);

    // Find the flow from getRequestBody to executeQuery
    const dbFlow = flows.find(
      (f) => f.source.name === 'getRequestBody' && f.sink.name === 'executeQuery',
    );
    expect(dbFlow).toBeDefined();
    expect(dbFlow!.source.type).toBe('user_input');
    expect(dbFlow!.sink.type).toBe('database');
    expect(dbFlow!.path).toContain('getRequestBody');
    expect(dbFlow!.path).toContain('executeQuery');
    expect(dbFlow!.hasSanitization).toBe(false);
  });

  it('marks flows with sanitizers as hasSanitization: true', async () => {
    const flows = await findDataFlows(store);

    // readInput (source) -> safeHandler calls sanitizeInput (sanitizer) and execSync (sink)
    // The path readInput -> safeHandler -> execSync contains sanitizeInput in the call chain
    const shellFlow = flows.find(
      (f) => f.source.name === 'readInput' && f.sink.name === 'execSync',
    );
    expect(shellFlow).toBeDefined();
    expect(shellFlow!.hasSanitization).toBe(true);
  });
});
