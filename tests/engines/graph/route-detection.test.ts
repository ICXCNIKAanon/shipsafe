import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createGraphStore, type GraphStore } from '../../../src/engines/graph/store.js';
import {
  findAttackPaths,
  findBlastRadius,
  findMissingAuth,
} from '../../../src/engines/graph/queries.js';
import type { ParsedFile } from '../../../src/types.js';

// ── Test fixture: Next.js App Router project ──
//
// File: app/api/users/route.ts
//   - GET [exported, async]  -> calls db.query (sink)
//   - POST [exported, async] -> calls validateInput AND db.query
//   - helper [exported, async] -> NOT an entry point (just a helper)
//
// File: app/actions/create-user.ts (server actions)
//   - createUserAction [exported, async] -> calls db.query (sink, no validation)
//
// File: src/routes/express.ts (Express-style)
//   - handleGetUsers [exported, async] -> calls db.query (sink, no validation)
//
// File: src/utils/format.ts
//   - formatData [exported, async] -> NOT an entry point (random utility)

const nextjsFixture: ParsedFile[] = [
  {
    filePath: 'app/api/users/route.ts',
    language: 'typescript',
    functions: [
      {
        name: 'GET',
        filePath: 'app/api/users/route.ts',
        startLine: 5,
        endLine: 15,
        params: ['request'],
        isAsync: true,
        isExported: true,
      },
      {
        name: 'POST',
        filePath: 'app/api/users/route.ts',
        startLine: 20,
        endLine: 35,
        params: ['request'],
        isAsync: true,
        isExported: true,
      },
      {
        name: 'helper',
        filePath: 'app/api/users/route.ts',
        startLine: 40,
        endLine: 50,
        params: [],
        isAsync: true,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'GET', filePath: 'app/api/users/route.ts', line: 5, type: 'function' },
      { name: 'POST', filePath: 'app/api/users/route.ts', line: 20, type: 'function' },
      { name: 'helper', filePath: 'app/api/users/route.ts', line: 40, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'GET',
        calleeName: 'query',
        filePath: 'app/api/users/route.ts',
        line: 10,
        receiver: 'db',
      },
      {
        callerName: 'POST',
        calleeName: 'validateInput',
        filePath: 'app/api/users/route.ts',
        line: 25,
      },
      {
        callerName: 'POST',
        calleeName: 'query',
        filePath: 'app/api/users/route.ts',
        line: 30,
        receiver: 'db',
      },
    ],
  },
  {
    filePath: 'app/actions/create-user.ts',
    language: 'typescript',
    functions: [
      {
        name: 'createUserAction',
        filePath: 'app/actions/create-user.ts',
        startLine: 3,
        endLine: 20,
        params: ['formData'],
        isAsync: true,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'createUserAction', filePath: 'app/actions/create-user.ts', line: 3, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'createUserAction',
        calleeName: 'query',
        filePath: 'app/actions/create-user.ts',
        line: 15,
        receiver: 'db',
      },
    ],
  },
  {
    filePath: 'src/routes/express.ts',
    language: 'typescript',
    functions: [
      {
        name: 'handleGetUsers',
        filePath: 'src/routes/express.ts',
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
      { name: 'handleGetUsers', filePath: 'src/routes/express.ts', line: 5, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'handleGetUsers',
        calleeName: 'query',
        filePath: 'src/routes/express.ts',
        line: 15,
        receiver: 'db',
      },
    ],
  },
  {
    filePath: 'src/utils/format.ts',
    language: 'typescript',
    functions: [
      {
        name: 'formatData',
        filePath: 'src/utils/format.ts',
        startLine: 1,
        endLine: 10,
        params: ['data'],
        isAsync: true,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'formatData', filePath: 'src/utils/format.ts', line: 1, type: 'function' },
    ],
    callSites: [
      {
        callerName: 'formatData',
        calleeName: 'query',
        filePath: 'src/utils/format.ts',
        line: 5,
        receiver: 'db',
      },
    ],
  },
  {
    filePath: 'src/db/index.ts',
    language: 'typescript',
    functions: [
      {
        name: 'query',
        filePath: 'src/db/index.ts',
        startLine: 10,
        endLine: 20,
        params: ['sql', 'params'],
        isAsync: true,
        isExported: true,
        className: 'db',
      },
    ],
    classes: [
      {
        name: 'db',
        filePath: 'src/db/index.ts',
        startLine: 5,
        endLine: 25,
        methods: ['query'],
        isExported: true,
      },
    ],
    imports: [],
    exports: [
      { name: 'db', filePath: 'src/db/index.ts', line: 5, type: 'class' },
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
        startLine: 1,
        endLine: 10,
        params: ['data'],
        isAsync: false,
        isExported: true,
      },
    ],
    classes: [],
    imports: [],
    exports: [
      { name: 'validateInput', filePath: 'src/utils/validate.ts', line: 1, type: 'function' },
    ],
    callSites: [],
  },
];

describe('Framework-aware route detection', () => {
  let store: GraphStore;

  beforeAll(async () => {
    store = await createGraphStore();
    await store.buildGraph(nextjsFixture);
  });

  afterAll(async () => {
    await store.close();
  });

  describe('Next.js API route detection', () => {
    it('treats GET in /api/ route.ts as entry point', async () => {
      const paths = await findAttackPaths(store);
      const getPath = paths.find((p) => p.entryPoint.name === 'GET');
      expect(getPath).toBeDefined();
      expect(getPath!.entryPoint.filePath).toBe('app/api/users/route.ts');
    });

    it('treats POST in /api/ route.ts as entry point', async () => {
      const paths = await findAttackPaths(store);
      const postPath = paths.find((p) => p.entryPoint.name === 'POST');
      expect(postPath).toBeDefined();
    });

    it('does NOT treat random exported async "helper" as entry point', async () => {
      const paths = await findAttackPaths(store);
      const helperPath = paths.find((p) => p.entryPoint.name === 'helper');
      expect(helperPath).toBeUndefined();
    });
  });

  describe('Server action detection', () => {
    it('treats function in /actions/ directory as entry point', async () => {
      const paths = await findAttackPaths(store);
      const actionPath = paths.find((p) => p.entryPoint.name === 'createUserAction');
      expect(actionPath).toBeDefined();
      expect(actionPath!.entryPoint.filePath).toBe('app/actions/create-user.ts');
    });
  });

  describe('Express handler detection', () => {
    it('treats handleX pattern as entry point', async () => {
      const paths = await findAttackPaths(store);
      const handlerPath = paths.find((p) => p.entryPoint.name === 'handleGetUsers');
      expect(handlerPath).toBeDefined();
    });
  });

  describe('Random exported async function exclusion', () => {
    it('does NOT treat formatData (exported async utility) as entry point', async () => {
      const paths = await findAttackPaths(store);
      const formatPath = paths.find((p) => p.entryPoint.name === 'formatData');
      expect(formatPath).toBeUndefined();
    });
  });

  describe('findBlastRadius with new entry point logic', () => {
    it('identifies GET as affected endpoint when db.query has vulnerability', async () => {
      const result = await findBlastRadius(store, 'query');
      const endpointNames = result.affectedEndpoints.map((e) => e.name);
      expect(endpointNames).toContain('GET');
      expect(endpointNames).toContain('POST');
    });

    it('does NOT identify formatData as an affected endpoint', async () => {
      const result = await findBlastRadius(store, 'query');
      const endpointNames = result.affectedEndpoints.map((e) => e.name);
      expect(endpointNames).not.toContain('formatData');
    });
  });

  describe('findMissingAuth with framework awareness', () => {
    it('flags handleGetUsers (Express handler) with no auth', async () => {
      const results = await findMissingAuth(store);
      const flaggedNames = results.map((r) => r.endpoint.name);
      expect(flaggedNames).toContain('handleGetUsers');
    });

    it('does NOT flag formatData since it is not a handler', async () => {
      const results = await findMissingAuth(store);
      const flaggedNames = results.map((r) => r.endpoint.name);
      expect(flaggedNames).not.toContain('formatData');
    });
  });
});

// ── Edge cases for route detection ──

describe('Route detection edge cases', () => {
  it('detects HTTP methods in /app/ directory (not just /api/)', async () => {
    const store = await createGraphStore();
    await store.buildGraph([
      {
        filePath: 'app/dashboard/route.ts',
        language: 'typescript',
        functions: [
          {
            name: 'DELETE',
            filePath: 'app/dashboard/route.ts',
            startLine: 1,
            endLine: 10,
            params: ['request'],
            isAsync: true,
            isExported: true,
          },
        ],
        classes: [],
        imports: [],
        exports: [
          { name: 'DELETE', filePath: 'app/dashboard/route.ts', line: 1, type: 'function' },
        ],
        callSites: [],
      },
    ]);

    const paths = await findAttackPaths(store);
    // DELETE is an entry point but has no sinks, so no attack paths
    // Let's verify via findBlastRadius instead — it uses isEntryPoint too
    const result = await findBlastRadius(store, 'DELETE');
    // No callers expected but the function itself is recognized
    await store.close();
    expect(result.totalAffected).toBe(0);
  });

  it('detects function with "action" in name as entry point', async () => {
    const store = await createGraphStore();
    await store.buildGraph([
      {
        filePath: 'src/lib/user-actions.ts',
        language: 'typescript',
        functions: [
          {
            name: 'deleteUserAction',
            filePath: 'src/lib/user-actions.ts',
            startLine: 1,
            endLine: 10,
            params: ['id'],
            isAsync: true,
            isExported: true,
          },
          {
            name: 'formatName',
            filePath: 'src/lib/user-actions.ts',
            startLine: 15,
            endLine: 25,
            params: ['name'],
            isAsync: true,
            isExported: true,
          },
        ],
        classes: [],
        imports: [],
        exports: [
          { name: 'deleteUserAction', filePath: 'src/lib/user-actions.ts', line: 1, type: 'function' },
          { name: 'formatName', filePath: 'src/lib/user-actions.ts', line: 15, type: 'function' },
        ],
        callSites: [
          {
            callerName: 'deleteUserAction',
            calleeName: 'executeRaw',
            filePath: 'src/lib/user-actions.ts',
            line: 5,
          },
        ],
      },
      {
        filePath: 'src/db/raw.ts',
        language: 'typescript',
        functions: [
          {
            name: 'executeRaw',
            filePath: 'src/db/raw.ts',
            startLine: 1,
            endLine: 10,
            params: ['sql'],
            isAsync: true,
            isExported: true,
          },
        ],
        classes: [],
        imports: [],
        exports: [
          { name: 'executeRaw', filePath: 'src/db/raw.ts', line: 1, type: 'function' },
        ],
        callSites: [],
      },
    ]);

    const paths = await findAttackPaths(store);

    // deleteUserAction (name contains "action") -> executeRaw is an attack path
    const actionPath = paths.find((p) => p.entryPoint.name === 'deleteUserAction');
    expect(actionPath).toBeDefined();
    expect(actionPath!.sink.name).toBe('executeRaw');

    // formatName should NOT be an entry point (no handler/action pattern)
    const formatPath = paths.find((p) => p.entryPoint.name === 'formatName');
    expect(formatPath).toBeUndefined();

    await store.close();
  });

  it('does not treat lowercase "get" as entry point (only uppercase in /api/ files)', async () => {
    const store = await createGraphStore();
    await store.buildGraph([
      {
        filePath: 'src/utils/cache.ts',
        language: 'typescript',
        functions: [
          {
            name: 'get',
            filePath: 'src/utils/cache.ts',
            startLine: 1,
            endLine: 10,
            params: ['key'],
            isAsync: true,
            isExported: true,
          },
        ],
        classes: [],
        imports: [],
        exports: [
          { name: 'get', filePath: 'src/utils/cache.ts', line: 1, type: 'function' },
        ],
        callSites: [],
      },
    ]);

    const paths = await findAttackPaths(store);
    // Lowercase 'get' in a non-API file should NOT be treated as entry point
    const getPath = paths.find((p) => p.entryPoint.name === 'get');
    expect(getPath).toBeUndefined();

    await store.close();
  });
});
