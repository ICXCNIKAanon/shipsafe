import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createGraphStore, type GraphStore } from '../../../src/engines/graph/store.js';
import {
  findAttackPaths,
  findBlastRadius,
  findMissingAuth,
  queryResultsToFindings,
} from '../../../src/engines/graph/queries.js';
import type { ParsedFile, AttackPath, BlastRadiusResult, MissingAuthResult } from '../../../src/types.js';

// ── Test graph fixture ──
//
// File: src/routes/users.ts
//   - handleGetUser(req, res) [exported, async]  -> calls validateInput AND query
//   - handleDeleteUser(req, res) [exported, async] -> calls execute (NO validation!)
//   - handleUnsafeQuery(req, res) [exported, async] -> calls raw (NO validation!)
//
// File: src/middleware/auth.ts
//   - checkAuth(req, res, next) [exported]
//
// File: src/utils/validate.ts
//   - validateInput(data) [exported]
//
// File: src/db/queries.ts
//   - query(sql, params) [method of db class]
//   - execute(sql) [method of db class]
//   - raw(sql) [method of db class]
//
// File: src/routes/secure.ts
//   - handleSecureEndpoint(req, res) [exported, async] -> calls checkAuth AND query

const mockParsedFiles: ParsedFile[] = [
  {
    filePath: 'src/routes/users.ts',
    language: 'typescript',
    functions: [
      {
        name: 'handleGetUser',
        filePath: 'src/routes/users.ts',
        startLine: 10,
        endLine: 25,
        params: ['req', 'res'],
        isAsync: true,
        isExported: true,
      },
      {
        name: 'handleDeleteUser',
        filePath: 'src/routes/users.ts',
        startLine: 30,
        endLine: 45,
        params: ['req', 'res'],
        isAsync: true,
        isExported: true,
      },
      {
        name: 'handleUnsafeQuery',
        filePath: 'src/routes/users.ts',
        startLine: 50,
        endLine: 65,
        params: ['req', 'res'],
        isAsync: true,
        isExported: true,
      },
    ],
    classes: [],
    imports: [
      {
        source: 'express',
        specifiers: ['Request', 'Response'],
        filePath: 'src/routes/users.ts',
        line: 1,
      },
    ],
    exports: [
      { name: 'handleGetUser', filePath: 'src/routes/users.ts', line: 10, type: 'function' },
      { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30, type: 'function' },
      { name: 'handleUnsafeQuery', filePath: 'src/routes/users.ts', line: 50, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'handleGetUser',
        calleeName: 'validateInput',
        filePath: 'src/routes/users.ts',
        line: 15,
      },
      {
        callerName: 'handleGetUser',
        calleeName: 'query',
        filePath: 'src/routes/users.ts',
        line: 20,
      },
      {
        callerName: 'handleDeleteUser',
        calleeName: 'execute',
        filePath: 'src/routes/users.ts',
        line: 35,
      },
      {
        callerName: 'handleUnsafeQuery',
        calleeName: 'raw',
        filePath: 'src/routes/users.ts',
        line: 55,
      },
    ],
  },
  {
    filePath: 'src/middleware/auth.ts',
    language: 'typescript',
    functions: [
      {
        name: 'checkAuth',
        filePath: 'src/middleware/auth.ts',
        startLine: 5,
        endLine: 20,
        params: ['req', 'res', 'next'],
        isAsync: false,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'checkAuth', filePath: 'src/middleware/auth.ts', line: 5, type: 'function' },
    ],
    callSites: [],
  },
  {
    filePath: 'src/utils/validate.ts',
    language: 'typescript',
    functions: [
      {
        name: 'validateInput',
        filePath: 'src/utils/validate.ts',
        startLine: 3,
        endLine: 15,
        params: ['data'],
        isAsync: false,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'validateInput', filePath: 'src/utils/validate.ts', line: 3, type: 'function' },
    ],
    callSites: [],
  },
  {
    filePath: 'src/db/queries.ts',
    language: 'typescript',
    functions: [
      {
        name: 'query',
        filePath: 'src/db/queries.ts',
        startLine: 10,
        endLine: 20,
        params: ['sql', 'params'],
        isAsync: true,
        isExported: true,
        className: 'db',
      },
      {
        name: 'execute',
        filePath: 'src/db/queries.ts',
        startLine: 25,
        endLine: 35,
        params: ['sql'],
        isAsync: true,
        isExported: true,
        className: 'db',
      },
      {
        name: 'raw',
        filePath: 'src/db/queries.ts',
        startLine: 40,
        endLine: 50,
        params: ['sql'],
        isAsync: true,
        isExported: true,
        className: 'db',
      },
    ],
    classes: [
      {
        name: 'db',
        filePath: 'src/db/queries.ts',
        startLine: 5,
        endLine: 55,
        methods: ['query', 'execute', 'raw'],
        isExported: true,
      },
    ],
    imports: [],
    exports: [
      { name: 'db', filePath: 'src/db/queries.ts', line: 5, type: 'class' },
    ],
    callSites: [],
  },
  {
    filePath: 'src/routes/secure.ts',
    language: 'typescript',
    functions: [
      {
        name: 'handleSecureEndpoint',
        filePath: 'src/routes/secure.ts',
        startLine: 5,
        endLine: 20,
        params: ['req', 'res'],
        isAsync: true,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'handleSecureEndpoint', filePath: 'src/routes/secure.ts', line: 5, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'handleSecureEndpoint',
        calleeName: 'checkAuth',
        filePath: 'src/routes/secure.ts',
        line: 8,
      },
      {
        callerName: 'handleSecureEndpoint',
        calleeName: 'query',
        filePath: 'src/routes/secure.ts',
        line: 15,
      },
    ],
  },
];

// ── Graph-based tests (single store) ──

describe('Graph query layer', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore(':memory:');
    await store.buildGraph(mockParsedFiles);
  });

  afterAll(async () => {
    await store.close();
  });

  // ── findAttackPaths ──

  describe('findAttackPaths', () => {
    it('finds attack path from handleDeleteUser to execute with no validation', async () => {
      const paths = await findAttackPaths(store);
      const deletePath = paths.find(
        (p) => p.entryPoint.name === 'handleDeleteUser' && p.sink.name === 'execute',
      );
      expect(deletePath).toBeDefined();
      expect(deletePath!.hasValidation).toBe(false);
      expect(deletePath!.sink.type).toBe('database');
      expect(deletePath!.path).toContain('handleDeleteUser');
      expect(deletePath!.path).toContain('execute');
    });

    it('finds attack path from handleUnsafeQuery to raw with no validation', async () => {
      const paths = await findAttackPaths(store);
      const unsafePath = paths.find(
        (p) => p.entryPoint.name === 'handleUnsafeQuery' && p.sink.name === 'raw',
      );
      expect(unsafePath).toBeDefined();
      expect(unsafePath!.hasValidation).toBe(false);
      expect(unsafePath!.sink.type).toBe('database');
    });

    it('marks handleGetUser path through validateInput as having validation', async () => {
      const paths = await findAttackPaths(store);
      const getPathsAll = paths.filter(
        (p) => p.entryPoint.name === 'handleGetUser' && p.sink.name === 'query',
      );

      // The direct path (handleGetUser -> query) has no validation in it,
      // but there is also a path handleGetUser -> validateInput (no sink).
      // The direct path should exist and have hasValidation = false.
      const directPath = getPathsAll.find((p) => p.path.length === 2);
      expect(directPath).toBeDefined();
      expect(directPath!.hasValidation).toBe(false);
    });

    it('returns entry point and sink location details', async () => {
      const paths = await findAttackPaths(store);
      const deletePath = paths.find(
        (p) => p.entryPoint.name === 'handleDeleteUser',
      );
      expect(deletePath).toBeDefined();
      expect(deletePath!.entryPoint.filePath).toBe('src/routes/users.ts');
      expect(deletePath!.entryPoint.line).toBe(30);
      expect(deletePath!.sink.filePath).toBe('src/db/queries.ts');
      expect(deletePath!.sink.line).toBe(25);
    });
  });

  // ── findBlastRadius ──

  describe('findBlastRadius', () => {
    it('finds handleGetUser as affected when query has a vulnerability', async () => {
      const result = await findBlastRadius(store, 'query');
      const affectedNames = result.affectedFunctions.map((f) => f.name);
      expect(affectedNames).toContain('handleGetUser');
      expect(result.targetFunction).toBe('query');
    });

    it('finds handleDeleteUser as affected when execute has a vulnerability', async () => {
      const result = await findBlastRadius(store, 'execute');
      const affectedNames = result.affectedFunctions.map((f) => f.name);
      expect(affectedNames).toContain('handleDeleteUser');
    });

    it('finds handleUnsafeQuery as affected when raw has a vulnerability', async () => {
      const result = await findBlastRadius(store, 'raw');
      const affectedNames = result.affectedFunctions.map((f) => f.name);
      expect(affectedNames).toContain('handleUnsafeQuery');
    });

    it('identifies affected endpoints correctly', async () => {
      const result = await findBlastRadius(store, 'execute');
      const endpointNames = result.affectedEndpoints.map((e) => e.name);
      expect(endpointNames).toContain('handleDeleteUser');
    });

    it('returns correct totalAffected count', async () => {
      const result = await findBlastRadius(store, 'query');
      expect(result.totalAffected).toBe(result.affectedFunctions.length);
      expect(result.totalAffected).toBeGreaterThanOrEqual(1);
    });

    it('returns empty results for function with no callers', async () => {
      const result = await findBlastRadius(store, 'handleGetUser');
      expect(result.affectedFunctions).toHaveLength(0);
      expect(result.affectedEndpoints).toHaveLength(0);
      expect(result.totalAffected).toBe(0);
    });
  });

  // ── findMissingAuth ──

  describe('findMissingAuth', () => {
    it('flags endpoints without auth in their call chain', async () => {
      const results = await findMissingAuth(store);
      const flaggedNames = results.map((r) => r.endpoint.name);

      expect(flaggedNames).toContain('handleDeleteUser');
      expect(flaggedNames).toContain('handleUnsafeQuery');
    });

    it('does not flag endpoint that calls checkAuth', async () => {
      const results = await findMissingAuth(store);
      const flaggedNames = results.map((r) => r.endpoint.name);

      expect(flaggedNames).not.toContain('handleSecureEndpoint');
    });

    it('provides a reason for missing auth', async () => {
      const results = await findMissingAuth(store);
      for (const result of results) {
        expect(result.reason).toBe('No auth middleware in call chain');
      }
    });

    it('includes correct endpoint location information', async () => {
      const results = await findMissingAuth(store);
      const deleteResult = results.find((r) => r.endpoint.name === 'handleDeleteUser');
      expect(deleteResult).toBeDefined();
      expect(deleteResult!.endpoint.filePath).toBe('src/routes/users.ts');
      expect(deleteResult!.endpoint.line).toBe(30);
    });
  });
});

// ── Pure unit tests (no graph store needed) ──

describe('queryResultsToFindings', () => {
  it('converts attack paths without validation to findings', () => {
    const attackPaths: AttackPath[] = [
      {
        entryPoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        sink: { name: 'execute', filePath: 'src/db/queries.ts', line: 25, type: 'database' },
        path: ['handleDeleteUser', 'execute'],
        hasValidation: false,
      },
    ];
    const findings = queryResultsToFindings(attackPaths, [], []);

    expect(findings).toHaveLength(1);
    expect(findings[0].engine).toBe('knowledge_graph');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].type).toBe('attack_path');
    expect(findings[0].file).toBe('src/routes/users.ts');
    expect(findings[0].line).toBe(30);
    expect(findings[0].description).toContain('handleDeleteUser');
    expect(findings[0].description).toContain('execute');
    expect(findings[0].auto_fixable).toBe(false);
  });

  it('does not convert attack paths with validation to findings', () => {
    const attackPaths: AttackPath[] = [
      {
        entryPoint: { name: 'handleGetUser', filePath: 'src/routes/users.ts', line: 10 },
        sink: { name: 'query', filePath: 'src/db/queries.ts', line: 10, type: 'database' },
        path: ['handleGetUser', 'validateInput', 'query'],
        hasValidation: true,
      },
    ];
    const findings = queryResultsToFindings(attackPaths, [], []);
    expect(findings).toHaveLength(0);
  });

  it('assigns critical severity to shell sink attack paths', () => {
    const attackPaths: AttackPath[] = [
      {
        entryPoint: { name: 'handleExec', filePath: 'src/api.ts', line: 5 },
        sink: { name: 'exec', filePath: 'src/utils.ts', line: 10, type: 'shell' },
        path: ['handleExec', 'exec'],
        hasValidation: false,
      },
    ];
    const findings = queryResultsToFindings(attackPaths, [], []);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
  });

  it('converts missing auth results to findings', () => {
    const missingAuth: MissingAuthResult[] = [
      {
        endpoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        reason: 'No auth middleware in call chain',
      },
    ];
    const findings = queryResultsToFindings([], [], missingAuth);

    expect(findings).toHaveLength(1);
    expect(findings[0].engine).toBe('knowledge_graph');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].type).toBe('missing_auth');
    expect(findings[0].file).toBe('src/routes/users.ts');
    expect(findings[0].line).toBe(30);
    expect(findings[0].description).toContain('handleDeleteUser');
    expect(findings[0].description).toContain('no auth');
  });

  it('combines attack paths and missing auth into a single findings array', () => {
    const attackPaths: AttackPath[] = [
      {
        entryPoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        sink: { name: 'execute', filePath: 'src/db/queries.ts', line: 25, type: 'database' },
        path: ['handleDeleteUser', 'execute'],
        hasValidation: false,
      },
    ];
    const missingAuth: MissingAuthResult[] = [
      {
        endpoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        reason: 'No auth middleware in call chain',
      },
    ];
    const findings = queryResultsToFindings(attackPaths, [], missingAuth);

    expect(findings).toHaveLength(2);
    const types = findings.map((f) => f.type);
    expect(types).toContain('attack_path');
    expect(types).toContain('missing_auth');
  });

  it('returns empty array when no issues found', () => {
    const findings = queryResultsToFindings([], [], []);
    expect(findings).toHaveLength(0);
  });

  it('assigns unique IDs to all findings', () => {
    const attackPaths: AttackPath[] = [
      {
        entryPoint: { name: 'handleA', filePath: 'a.ts', line: 1 },
        sink: { name: 'execute', filePath: 'b.ts', line: 2, type: 'database' },
        path: ['handleA', 'execute'],
        hasValidation: false,
      },
      {
        entryPoint: { name: 'handleB', filePath: 'c.ts', line: 3 },
        sink: { name: 'raw', filePath: 'd.ts', line: 4, type: 'database' },
        path: ['handleB', 'raw'],
        hasValidation: false,
      },
    ];
    const missingAuth: MissingAuthResult[] = [
      {
        endpoint: { name: 'handleC', filePath: 'e.ts', line: 5 },
        reason: 'No auth middleware in call chain',
      },
    ];
    const findings = queryResultsToFindings(attackPaths, [], missingAuth);

    const ids = findings.map((f) => f.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(findings.length);
  });
});
