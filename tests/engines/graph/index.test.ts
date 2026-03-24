import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Finding, ParsedFile, ScanScope } from '../../../src/types.js';

// ── Mock dependencies ──

vi.mock('../../../src/engines/graph/parser.js', () => ({
  initParser: vi.fn(),
  parseProject: vi.fn(),
}));

vi.mock('../../../src/engines/graph/store.js', () => ({
  createGraphStore: vi.fn(),
}));

vi.mock('../../../src/engines/graph/queries.js', () => ({
  findAttackPaths: vi.fn(),
  findBlastRadius: vi.fn(),
  findMissingAuth: vi.fn(),
  queryResultsToFindings: vi.fn(),
}));

import {
  runGraphEngine,
  isGraphEngineAvailable,
} from '../../../src/engines/graph/index.js';

import { initParser, parseProject } from '../../../src/engines/graph/parser.js';
import { createGraphStore } from '../../../src/engines/graph/store.js';
import {
  findAttackPaths,
  findBlastRadius,
  findMissingAuth,
  queryResultsToFindings,
} from '../../../src/engines/graph/queries.js';

const mockedInitParser = vi.mocked(initParser);
const mockedParseProject = vi.mocked(parseProject);
const mockedCreateGraphStore = vi.mocked(createGraphStore);
const mockedFindAttackPaths = vi.mocked(findAttackPaths);
const mockedFindBlastRadius = vi.mocked(findBlastRadius);
const mockedFindMissingAuth = vi.mocked(findMissingAuth);
const mockedQueryResultsToFindings = vi.mocked(queryResultsToFindings);

// ── Test fixtures ──

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
    ],
    classes: [],
    imports: [],
    exports: [],
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
    ],
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
    ],
    classes: [
      {
        name: 'db',
        filePath: 'src/db/queries.ts',
        startLine: 5,
        endLine: 40,
        methods: ['query', 'execute'],
        isExported: true,
      },
    ],
    imports: [],
    exports: [],
    callSites: [],
  },
];

function makeMockStore() {
  return {
    buildGraph: vi.fn().mockResolvedValue(undefined),
    getFunction: vi.fn().mockResolvedValue(null),
    getCallers: vi.fn().mockResolvedValue([]),
    getCallees: vi.fn().mockResolvedValue([]),
    getCallEdgesFrom: vi.fn().mockReturnValue([]),
    getImportsOf: vi.fn().mockResolvedValue([]),
    query: vi.fn().mockResolvedValue([]),
    getAllFunctions: vi.fn().mockReturnValue([]),
    close: vi.fn().mockResolvedValue(undefined),
  };
}

// ── Tests ──

describe('isGraphEngineAvailable', () => {
  it('returns true (web-tree-sitter is bundled)', () => {
    expect(isGraphEngineAvailable()).toBe(true);
  });
});

describe('runGraphEngine', () => {
  let mockStore: ReturnType<typeof makeMockStore>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockStore = makeMockStore();
    mockedInitParser.mockResolvedValue(undefined);
    mockedParseProject.mockResolvedValue(mockParsedFiles);
    mockedCreateGraphStore.mockResolvedValue(mockStore as any);
    mockedFindAttackPaths.mockResolvedValue([]);
    mockedFindBlastRadius.mockResolvedValue({
      targetFunction: '',
      affectedFunctions: [],
      affectedEndpoints: [],
      totalAffected: 0,
    });
    mockedFindMissingAuth.mockResolvedValue([]);
    mockedQueryResultsToFindings.mockReturnValue([]);
  });

  it('initializes the parser', async () => {
    await runGraphEngine({ targetPath: '/project', scope: 'all' });
    expect(mockedInitParser).toHaveBeenCalledOnce();
  });

  it('parses the project at the target path', async () => {
    await runGraphEngine({ targetPath: '/my/project', scope: 'all' });
    expect(mockedParseProject).toHaveBeenCalledWith('/my/project');
  });

  it('creates a graph store and builds the graph', async () => {
    await runGraphEngine({ targetPath: '/project', scope: 'all' });
    expect(mockedCreateGraphStore).toHaveBeenCalledOnce();
    expect(mockStore.buildGraph).toHaveBeenCalledWith(mockParsedFiles);
  });

  it('runs findAttackPaths', async () => {
    await runGraphEngine({ targetPath: '/project', scope: 'all' });
    expect(mockedFindAttackPaths).toHaveBeenCalledWith(mockStore);
  });

  it('runs findMissingAuth', async () => {
    await runGraphEngine({ targetPath: '/project', scope: 'all' });
    expect(mockedFindMissingAuth).toHaveBeenCalledWith(mockStore);
  });

  it('calls queryResultsToFindings with query results', async () => {
    const mockAttackPaths = [
      {
        entryPoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        sink: { name: 'execute', filePath: 'src/db/queries.ts', line: 25, type: 'database' },
        path: ['handleDeleteUser', 'execute'],
        hasValidation: false,
      },
    ];
    const mockMissingAuth = [
      {
        endpoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        reason: 'No auth middleware in call chain',
      },
    ];

    mockedFindAttackPaths.mockResolvedValue(mockAttackPaths);
    mockedFindMissingAuth.mockResolvedValue(mockMissingAuth);

    await runGraphEngine({ targetPath: '/project', scope: 'all' });

    expect(mockedQueryResultsToFindings).toHaveBeenCalledOnce();
    const [attackPaths, , missingAuth] = mockedQueryResultsToFindings.mock.calls[0];
    expect(attackPaths).toEqual(mockAttackPaths);
    expect(missingAuth).toEqual(mockMissingAuth);
  });

  it('runs findBlastRadius for unvalidated attack path sinks', async () => {
    const mockAttackPaths = [
      {
        entryPoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        sink: { name: 'execute', filePath: 'src/db/queries.ts', line: 25, type: 'database' },
        path: ['handleDeleteUser', 'execute'],
        hasValidation: false,
      },
    ];
    mockedFindAttackPaths.mockResolvedValue(mockAttackPaths);

    await runGraphEngine({ targetPath: '/project', scope: 'all' });

    expect(mockedFindBlastRadius).toHaveBeenCalledWith(mockStore, 'execute');
  });

  it('does not run findBlastRadius for validated attack paths', async () => {
    const mockAttackPaths = [
      {
        entryPoint: { name: 'handleGetUser', filePath: 'src/routes/users.ts', line: 10 },
        sink: { name: 'query', filePath: 'src/db/queries.ts', line: 10, type: 'database' },
        path: ['handleGetUser', 'validateInput', 'query'],
        hasValidation: true,
      },
    ];
    mockedFindAttackPaths.mockResolvedValue(mockAttackPaths);

    await runGraphEngine({ targetPath: '/project', scope: 'all' });

    expect(mockedFindBlastRadius).not.toHaveBeenCalled();
  });

  it('returns findings from queryResultsToFindings', async () => {
    const mockFindings: Finding[] = [
      {
        id: 'kg-attack-path-1',
        engine: 'knowledge_graph',
        severity: 'high',
        type: 'attack_path',
        file: 'src/routes/users.ts',
        line: 30,
        description: 'Unvalidated path from handleDeleteUser to execute',
        fix_suggestion: 'Add input validation',
        auto_fixable: false,
      },
    ];
    mockedQueryResultsToFindings.mockReturnValue(mockFindings);

    const result = await runGraphEngine({ targetPath: '/project', scope: 'all' });

    expect(result.findings).toEqual(mockFindings);
  });

  it('returns correct stats', async () => {
    const result = await runGraphEngine({ targetPath: '/project', scope: 'all' });

    expect(result.stats.filesScanned).toBe(2);
    expect(result.stats.functionsFound).toBe(4); // 2 in users.ts + 2 in db/queries.ts
    expect(result.stats.classesFound).toBe(1); // db class
    expect(result.stats.callEdges).toBe(3); // 3 call sites
    expect(result.stats.attackPathsFound).toBe(0); // no attack paths (mocked to empty)
  });

  it('returns correct stats with attack paths', async () => {
    const mockAttackPaths = [
      {
        entryPoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        sink: { name: 'execute', filePath: 'src/db/queries.ts', line: 25, type: 'database' },
        path: ['handleDeleteUser', 'execute'],
        hasValidation: false,
      },
      {
        entryPoint: { name: 'handleGetUser', filePath: 'src/routes/users.ts', line: 10 },
        sink: { name: 'query', filePath: 'src/db/queries.ts', line: 10, type: 'database' },
        path: ['handleGetUser', 'query'],
        hasValidation: false,
      },
    ];
    mockedFindAttackPaths.mockResolvedValue(mockAttackPaths);

    const result = await runGraphEngine({ targetPath: '/project', scope: 'all' });

    expect(result.stats.attackPathsFound).toBe(2);
  });

  it('returns timing info (duration_ms)', async () => {
    const result = await runGraphEngine({ targetPath: '/project', scope: 'all' });

    expect(result.duration_ms).toBeTypeOf('number');
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('closes the graph store after processing', async () => {
    await runGraphEngine({ targetPath: '/project', scope: 'all' });
    expect(mockStore.close).toHaveBeenCalledOnce();
  });

  it('closes the graph store even if queries throw', async () => {
    mockedFindAttackPaths.mockRejectedValue(new Error('query failed'));

    await expect(
      runGraphEngine({ targetPath: '/project', scope: 'all' }),
    ).rejects.toThrow('query failed');

    expect(mockStore.close).toHaveBeenCalledOnce();
  });

  it('returns empty findings when project has no files', async () => {
    mockedParseProject.mockResolvedValue([]);

    const result = await runGraphEngine({ targetPath: '/empty-project', scope: 'all' });

    expect(result.findings).toEqual([]);
    expect(result.stats.filesScanned).toBe(0);
    expect(result.stats.functionsFound).toBe(0);
    expect(result.stats.classesFound).toBe(0);
    expect(result.stats.callEdges).toBe(0);
  });
});

// ── Integration with pattern engine ──

describe('Graph engine integration into pattern engine', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('runGraphEngine and isGraphEngineAvailable are importable', async () => {
    // This test verifies the exports exist and are callable
    expect(typeof runGraphEngine).toBe('function');
    expect(typeof isGraphEngineAvailable).toBe('function');
  });
});

// ── handleGraphQuery tests ──

// We need separate mocks for the graph-query module
vi.mock('../../../src/engines/graph/parser.js', () => ({
  initParser: vi.fn().mockResolvedValue(undefined),
  parseProject: vi.fn().mockResolvedValue([]),
}));

import { handleGraphQuery } from '../../../src/mcp/tools/graph-query.js';

describe('handleGraphQuery', () => {
  let mockStore: ReturnType<typeof makeMockStore>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockStore = makeMockStore();
    mockedInitParser.mockResolvedValue(undefined);
    mockedParseProject.mockResolvedValue([]);
    mockedCreateGraphStore.mockResolvedValue(mockStore as any);
    mockedFindAttackPaths.mockResolvedValue([]);
    mockedFindMissingAuth.mockResolvedValue([]);
  });

  it('returns attack paths for query_type "attack_paths"', async () => {
    const mockAttackPaths = [
      {
        entryPoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        sink: { name: 'execute', filePath: 'src/db/queries.ts', line: 25, type: 'database' },
        path: ['handleDeleteUser', 'execute'],
        hasValidation: false,
      },
    ];
    mockedFindAttackPaths.mockResolvedValue(mockAttackPaths);

    const result = await handleGraphQuery({ query_type: 'attack_paths' }) as any;

    expect(result.query_type).toBe('attack_paths');
    expect(result.results).toHaveLength(1);
    expect(result.results[0].entryPoint.name).toBe('handleDeleteUser');
    expect(result.total).toBe(1);
  });

  it('returns blast radius for query_type "blast_radius"', async () => {
    mockedFindBlastRadius.mockResolvedValue({
      targetFunction: 'execute',
      affectedFunctions: [
        { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
      ],
      affectedEndpoints: [
        { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
      ],
      totalAffected: 1,
    });

    const result = await handleGraphQuery({
      query_type: 'blast_radius',
      target: 'execute',
    }) as any;

    expect(result.query_type).toBe('blast_radius');
    expect(result.target).toBe('execute');
    expect(result.totalAffected).toBe(1);
    expect(result.affectedFunctions).toHaveLength(1);
  });

  it('returns callers for query_type "callers"', async () => {
    mockStore.getCallers.mockResolvedValue([
      {
        id: 'src/routes/users.ts::handleGetUser',
        name: 'handleGetUser',
        filePath: 'src/routes/users.ts',
        startLine: 10,
        endLine: 25,
        isAsync: true,
        isExported: true,
        className: '',
      },
    ]);

    const result = await handleGraphQuery({
      query_type: 'callers',
      target: 'query',
      depth: 2,
    }) as any;

    expect(result.query_type).toBe('callers');
    expect(result.target).toBe('query');
    expect(result.depth).toBe(2);
    expect(result.results).toHaveLength(1);
    expect(result.results[0].name).toBe('handleGetUser');
  });

  it('returns callees for query_type "callees"', async () => {
    mockStore.getCallees.mockResolvedValue([
      {
        id: 'src/db/queries.ts::db.query',
        name: 'query',
        filePath: 'src/db/queries.ts',
        startLine: 10,
        endLine: 20,
        isAsync: true,
        isExported: true,
        className: 'db',
      },
    ]);

    const result = await handleGraphQuery({
      query_type: 'callees',
      target: 'handleGetUser',
    }) as any;

    expect(result.query_type).toBe('callees');
    expect(result.target).toBe('handleGetUser');
    expect(result.results).toHaveLength(1);
    expect(result.results[0].name).toBe('query');
  });

  it('returns auth chain for query_type "auth_chain"', async () => {
    mockedFindMissingAuth.mockResolvedValue([
      {
        endpoint: { name: 'handleDeleteUser', filePath: 'src/routes/users.ts', line: 30 },
        reason: 'No auth middleware in call chain',
      },
    ]);

    const result = await handleGraphQuery({ query_type: 'auth_chain' }) as any;

    expect(result.query_type).toBe('auth_chain');
    expect(result.results).toHaveLength(1);
    expect(result.results[0].endpoint.name).toBe('handleDeleteUser');
    expect(result.total).toBe(1);
  });

  it('returns error when target is missing for callers query', async () => {
    const result = await handleGraphQuery({ query_type: 'callers' }) as any;
    expect(result.error).toBeDefined();
    expect(result.error).toContain('target is required');
  });

  it('returns error when target is missing for callees query', async () => {
    const result = await handleGraphQuery({ query_type: 'callees' }) as any;
    expect(result.error).toBeDefined();
    expect(result.error).toContain('target is required');
  });

  it('returns error when target is missing for blast_radius query', async () => {
    const result = await handleGraphQuery({ query_type: 'blast_radius' }) as any;
    expect(result.error).toBeDefined();
    expect(result.error).toContain('target is required');
  });

  it('returns data_flow combining callers and callees', async () => {
    mockStore.getCallers.mockResolvedValue([
      {
        id: 'src/a.ts::caller',
        name: 'caller',
        filePath: 'src/a.ts',
        startLine: 1,
        endLine: 5,
        isAsync: false,
        isExported: true,
        className: '',
      },
    ]);
    mockStore.getCallees.mockResolvedValue([
      {
        id: 'src/b.ts::callee',
        name: 'callee',
        filePath: 'src/b.ts',
        startLine: 10,
        endLine: 15,
        isAsync: false,
        isExported: false,
        className: '',
      },
    ]);

    const result = await handleGraphQuery({
      query_type: 'data_flow',
      target: 'myFunc',
    }) as any;

    expect(result.query_type).toBe('data_flow');
    expect(result.target).toBe('myFunc');
    expect(result.callers).toHaveLength(1);
    expect(result.callees).toHaveLength(1);
    expect(result.callers[0].name).toBe('caller');
    expect(result.callees[0].name).toBe('callee');
  });

  it('cleans up graph store after query', async () => {
    await handleGraphQuery({ query_type: 'attack_paths' });
    expect(mockStore.close).toHaveBeenCalledOnce();
  });

  it('cleans up graph store even if query throws', async () => {
    mockedFindAttackPaths.mockRejectedValue(new Error('boom'));

    await expect(
      handleGraphQuery({ query_type: 'attack_paths' }),
    ).rejects.toThrow('boom');

    expect(mockStore.close).toHaveBeenCalledOnce();
  });
});
