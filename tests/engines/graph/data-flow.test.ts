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

  it('returns user_input for req-prefixed names', () => {
    expect(classifySource('reqData')).toBe('user_input');
  });

  it('returns user_input for functions containing "body"', () => {
    expect(classifySource('parseBody')).toBe('user_input');
  });

  it('returns user_input for functions containing "params"', () => {
    expect(classifySource('getParams')).toBe('user_input');
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
  it('returns database for query', () => {
    expect(classifySink('query')).toBe('database');
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
//   - getRequestBody() [exported] — SOURCE (user_input)
//   - processUserInput() [exported] — calls getRequestBody, then calls buildQuery
//   - buildQuery() [exported] — calls query (SINK)
//
// File: src/db/db.ts
//   - query() — SINK (database)
//
// File: src/api/safe.ts
//   - readLine() [exported] — SOURCE (user_input)
//   - sanitizeInput() [exported] — SANITIZER — called by safeHandler
//   - safeHandler() [exported] — calls readLine, calls sanitizeInput, calls exec (SINK)
//
// File: src/utils/shell.ts
//   - exec() — SINK (shell)

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
        calleeName: 'query',
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
        name: 'query',
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
    exports: [{ name: 'query', filePath: 'src/db/db.ts', line: 10, type: 'function' }],
    callSites: [],
  },
  {
    filePath: 'src/api/safe.ts',
    language: 'typescript',
    functions: [
      {
        name: 'readLine',
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
      { name: 'readLine', filePath: 'src/api/safe.ts', line: 5, type: 'function' },
      { name: 'sanitizeInput', filePath: 'src/api/safe.ts', line: 15, type: 'function' },
      { name: 'safeHandler', filePath: 'src/api/safe.ts', line: 30, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'safeHandler',
        calleeName: 'readLine',
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
        calleeName: 'exec',
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
        name: 'exec',
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
    exports: [{ name: 'exec', filePath: 'src/utils/shell.ts', line: 5, type: 'function' }],
    callSites: [],
  },
];

describe('findDataFlows (graph-based)', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore(':memory:');
    await store.buildGraph(mockParsedFiles);
  });

  afterAll(async () => {
    await store.close();
  });

  it('returns empty array when no functions exist', async () => {
    // Use a fresh store with no data
    const emptyStore = await createGraphStore(':memory:');
    const flows = await findDataFlows(emptyStore);
    expect(flows).toEqual([]);
    await emptyStore.close();
  });

  it('identifies tainted flow from source to sink through call chain', async () => {
    const flows = await findDataFlows(store);

    // getRequestBody -> processUserInput -> buildQuery -> query
    // processUserInput calls getRequestBody (source) and buildQuery which calls query (sink)
    // But sources are identified by name pattern — getRequestBody is a source
    // The BFS goes: getRequestBody -> callers -> ... to find if it reaches a sink
    // Actually, BFS from source functions following *callees* to reach sinks.
    // getRequestBody is the source. Its callers (processUserInput) call buildQuery which calls query.
    // Wait - we BFS from source following callees. getRequestBody itself doesn't call anyone.
    // The flow is: processUserInput calls getRequestBody (so processUserInput uses user input)
    // processUserInput also calls buildQuery, which calls query.
    // The taint flows: getRequestBody tainted data -> passed into processUserInput context
    //   -> processUserInput calls buildQuery -> buildQuery calls query
    //
    // For BFS on "callers of source then their callees", we need a different approach.
    // Based on task description: "traces tainted data from source functions through call chains to sinks"
    // This means: find source functions, then BFS following callees to find if they eventually call a sink.
    // But a source function is a leaf that returns tainted data.
    //
    // The simpler interpretation: for each function that calls a source,
    // check if it (or its callee chain) also calls a sink.
    // That is: a function that directly/indirectly calls both a source and a sink is a tainted flow.
    //
    // Actually the simplest BFS interpretation from the task:
    // "BFS from each source function, following callees up to depth 8"
    // This means: treat source function itself as a source node, BFS its callees.
    // If source has callees that are sinks, that's a flow.
    // But in our fixture, getRequestBody has no callees.
    //
    // Let's reconsider: In the fixture, processUserInput CALLS getRequestBody.
    // processUserInput is the function that touches user input (it calls getRequestBody).
    // Then processUserInput calls buildQuery, which calls query (sink).
    //
    // The correct BFS interpretation:
    //   For each function in the graph, check if it calls a source (directly or transitively).
    //   If it does, it's "tainted". Then check if it also calls a sink (directly or transitively).
    //   If both: it's a tainted data flow.
    //
    // Based on the task requirements and looking at how queries.ts works with findAttackPaths:
    // The BFS starts from source functions and follows callees.
    // So if getRequestBody is a source, we BFS getRequestBody's callees.
    // getRequestBody has no callees — so no direct flows from getRequestBody.
    //
    // BUT: the task says "from source functions (user input, request params) through call chains to sinks"
    // This could mean: the function that handles user input is the entry point, and it calls sinks.
    //
    // Looking at the fixture more carefully:
    // - processUserInput calls getRequestBody (it's the one that uses the tainted data)
    // - processUserInput calls buildQuery -> query
    //
    // For BFS from source *callers*: find functions that call a source, then trace their callees to sinks.
    // This is equivalent to: getCallers(source) gives us [processUserInput],
    // then we BFS processUserInput's callees to find [buildQuery, query].
    // query is a sink -> tainted flow!
    //
    // This makes more practical sense. Let's verify the fixture supports this.
    // processUserInput calls getRequestBody (so processUserInput is a "tainted" function)
    // processUserInput calls buildQuery which calls query (sink)
    // -> DataFlow: source=getRequestBody, sink=query, path=[getRequestBody, processUserInput, buildQuery, query]

    expect(flows.length).toBeGreaterThan(0);

    // Find the flow from getRequestBody to query
    const dbFlow = flows.find(
      (f) => f.source.name === 'getRequestBody' && f.sink.name === 'query',
    );
    expect(dbFlow).toBeDefined();
    expect(dbFlow!.source.type).toBe('user_input');
    expect(dbFlow!.sink.type).toBe('database');
    expect(dbFlow!.path).toContain('getRequestBody');
    expect(dbFlow!.path).toContain('query');
    expect(dbFlow!.hasSanitization).toBe(false);
  });

  it('marks flows with sanitizers as hasSanitization: true', async () => {
    const flows = await findDataFlows(store);

    // readLine (source) -> safeHandler calls sanitizeInput (sanitizer) and exec (sink)
    // The path readLine -> safeHandler -> exec contains sanitizeInput in the call chain
    const shellFlow = flows.find(
      (f) => f.source.name === 'readLine' && f.sink.name === 'exec',
    );
    expect(shellFlow).toBeDefined();
    expect(shellFlow!.hasSanitization).toBe(true);
  });
});
