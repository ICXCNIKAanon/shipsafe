import type { GraphStore, GraphFunction } from './store.js';
import type { Finding, AttackPath, BlastRadiusResult, MissingAuthResult } from '../../types.js';

// ── Constants ──

const ENTRY_POINT_PATTERNS = ['handle', 'route', 'controller', 'endpoint'];

// Receiver-aware sink patterns.
// If `receivers` is specified, the method is only a sink when called on one of those receivers.
// If `receivers` is omitted, any call to that method name is treated as a sink.
interface SinkPattern {
  method: string;
  receivers?: string[];
}

const SINK_PATTERNS: Record<string, SinkPattern[]> = {
  database: [
    { method: 'query', receivers: ['db', 'pool', 'client', 'connection', 'knex', 'sequelize', 'prisma'] },
    { method: 'execute', receivers: ['db', 'pool', 'client', 'connection', 'cursor', 'stmt'] },
    { method: 'exec', receivers: ['db', 'connection'] },
    { method: 'run', receivers: ['db', 'sqlite', 'better-sqlite'] },
    { method: 'raw', receivers: ['knex', 'db'] },
    { method: 'find', receivers: ['collection', 'model', 'db'] },
    { method: 'findOne', receivers: ['collection', 'model', 'db'] },
    { method: 'insert', receivers: ['collection', 'db', 'knex'] },
    { method: 'update', receivers: ['collection', 'db', 'knex'] },
    { method: 'delete', receivers: ['collection', 'db', 'knex'] },
    // Always-dangerous patterns (no receiver needed — name is specific enough)
    { method: 'executeQuery' },
    { method: 'executeRaw' },
    { method: 'executeSql' },
    { method: 'queryRaw' },
    { method: 'queryRawUnsafe' },
    { method: '$queryRaw' },
    { method: '$queryRawUnsafe' },
    { method: '$executeRaw' },
    { method: '$executeRawUnsafe' },
    { method: 'rawQuery' },
    { method: 'runQuery' },
  ],
  filesystem: [
    { method: 'readFile' },
    { method: 'readFileSync' },
    { method: 'writeFile' },
    { method: 'writeFileSync' },
    { method: 'createReadStream' },
    { method: 'createWriteStream' },
    { method: 'unlink' },
    { method: 'unlinkSync' },
  ],
  shell: [
    { method: 'exec', receivers: ['child_process', 'cp'] },
    { method: 'execSync', receivers: ['child_process', 'cp'] },
    { method: 'execSync' },  // also match bare execSync (imported directly)
    { method: 'spawn', receivers: ['child_process', 'cp'] },
    { method: 'execFile', receivers: ['child_process', 'cp'] },
    { method: 'execFileSync' },
    { method: 'spawnSync' },
  ],
  network: [
    { method: 'fetch' },
    { method: 'get', receivers: ['axios', 'http', 'https', 'got', 'request'] },
    { method: 'post', receivers: ['axios', 'http', 'https', 'got', 'request'] },
    { method: 'request', receivers: ['http', 'https'] },
  ],
  eval: [
    { method: 'eval' },
    { method: 'Function' },
  ],
  redirect: [
    { method: 'redirect', receivers: ['res', 'response'] },
  ],
};

const VALIDATOR_PATTERNS = ['valid', 'sanitiz', 'escape', 'clean', 'verify', 'auth', 'protect', 'guard', 'middleware'];

// ── Helpers ──

function isEntryPoint(fn: GraphFunction): boolean {
  const nameLower = fn.name.toLowerCase();
  // Must be exported AND match a handler-like name pattern
  // Plain async functions are NOT entry points (too broad for Next.js apps)
  if (!fn.isExported) return false;
  return ENTRY_POINT_PATTERNS.some((p) => nameLower.includes(p)) ||
    // Also match common HTTP method handlers
    /^(get|post|put|patch|delete|head|options)$/i.test(fn.name) ||
    // Next.js API route handlers
    /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(fn.name);
}

/**
 * Classify a function call as a sink type, with optional receiver awareness.
 * If receiver is provided, patterns with a `receivers` list will only match
 * when the receiver is in that list. Patterns without `receivers` always match.
 */
function classifySink(name: string, receiver?: string): string | null {
  const nameLower = name.toLowerCase();
  const receiverLower = receiver?.toLowerCase();
  for (const [type, patterns] of Object.entries(SINK_PATTERNS)) {
    for (const pattern of patterns) {
      if (nameLower === pattern.method.toLowerCase()) {
        if (pattern.receivers) {
          // Receiver-gated: only match if receiver is in the allowed list
          if (receiverLower && pattern.receivers.some((r) => receiverLower === r.toLowerCase())) {
            return type;
          }
          // No receiver or receiver not in list: skip this pattern (but continue checking others)
          continue;
        }
        // No receiver restriction: always match
        return type;
      }
    }
  }
  return null;
}

function isValidator(name: string): boolean {
  const nameLower = name.toLowerCase();
  return VALIDATOR_PATTERNS.some((p) => nameLower.includes(p));
}

function isSink(name: string, receiver?: string): boolean {
  return classifySink(name, receiver) !== null;
}

function isHandlerLike(name: string): boolean {
  const nameLower = name.toLowerCase();
  return ENTRY_POINT_PATTERNS.some((p) => nameLower.includes(p));
}

// ── findAttackPaths ──

/**
 * Find paths from entry point functions to dangerous sink functions.
 * Uses BFS via getCallEdgesFrom to trace call chains with receiver awareness.
 */
export async function findAttackPaths(store: GraphStore): Promise<AttackPath[]> {
  // Step 1: Get all functions to identify entry points
  const allFunctions = store.getAllFunctions();

  const entryPoints = allFunctions.filter((fn) => isEntryPoint(fn));

  const attackPaths: AttackPath[] = [];

  // Step 2: For each entry point, trace call chains to find sinks
  for (const entry of entryPoints) {
    const entryName = entry.name;

    // Get direct call edges (with receiver info) from this entry point
    const directEdges = store.getCallEdgesFrom(entryName);

    for (const edge of directEdges) {
      const calleeFn = await store.getFunction(edge.calleeName);
      if (!calleeFn) continue;

      if (isSink(edge.calleeName, edge.receiver)) {
        // Direct path: entry -> sink
        const pathNames = [entryName, edge.calleeName];
        attackPaths.push({
          entryPoint: {
            name: entryName,
            filePath: entry.filePath,
            line: entry.startLine,
          },
          sink: {
            name: edge.calleeName,
            filePath: calleeFn.filePath,
            line: calleeFn.startLine,
            type: classifySink(edge.calleeName, edge.receiver)!,
          },
          path: pathNames,
          hasValidation: pathNames.some((n) => isValidator(n)),
        });
      } else {
        // Check if this intermediate callee leads to a sink (depth 2-5)
        // Use BFS with receiver awareness
        const visited = new Set<string>([entryName, edge.calleeName]);
        const queue: Array<{ name: string; pathSoFar: string[]; depth: number }> = [
          { name: edge.calleeName, pathSoFar: [entryName, edge.calleeName], depth: 1 },
        ];

        while (queue.length > 0) {
          const current = queue.shift()!;
          if (current.depth >= 5) continue;

          const innerEdges = store.getCallEdgesFrom(current.name);
          for (const innerEdge of innerEdges) {
            if (visited.has(innerEdge.calleeName)) continue;
            visited.add(innerEdge.calleeName);

            const innerCalleeFn = await store.getFunction(innerEdge.calleeName);
            if (!innerCalleeFn) continue;

            const newPath = [...current.pathSoFar, innerEdge.calleeName];

            if (isSink(innerEdge.calleeName, innerEdge.receiver)) {
              attackPaths.push({
                entryPoint: {
                  name: entryName,
                  filePath: entry.filePath,
                  line: entry.startLine,
                },
                sink: {
                  name: innerEdge.calleeName,
                  filePath: innerCalleeFn.filePath,
                  line: innerCalleeFn.startLine,
                  type: classifySink(innerEdge.calleeName, innerEdge.receiver)!,
                },
                path: newPath,
                hasValidation: newPath.some((n) => isValidator(n)),
              });
            } else {
              queue.push({
                name: innerEdge.calleeName,
                pathSoFar: newPath,
                depth: current.depth + 1,
              });
            }
          }
        }
      }
    }
  }

  return attackPaths;
}

// ── findBlastRadius ──

export async function findBlastRadius(
  store: GraphStore,
  functionName: string,
): Promise<BlastRadiusResult> {
  // Find all transitive callers of the target function
  const callers = await store.getCallers(functionName, 10);

  const affectedFunctions: BlastRadiusResult['affectedFunctions'] = callers.map((fn) => ({
    name: fn.name,
    filePath: fn.filePath,
    line: fn.startLine,
  }));

  // Identify which callers are endpoints (exported + handler-like or async)
  const affectedEndpoints: BlastRadiusResult['affectedEndpoints'] = callers
    .filter((fn) => isEntryPoint(fn))
    .map((fn) => ({
      name: fn.name,
      filePath: fn.filePath,
      line: fn.startLine,
    }));

  return {
    targetFunction: functionName,
    affectedFunctions,
    affectedEndpoints,
    totalAffected: affectedFunctions.length,
  };
}

// ── findMissingAuth ──

export async function findMissingAuth(store: GraphStore): Promise<MissingAuthResult[]> {
  // Find all exported endpoint-like functions
  const allFunctions = store.getAllFunctions();

  const results: MissingAuthResult[] = [];

  for (const fn of allFunctions) {
    // Only check endpoint-like functions (handler/route/controller/api pattern AND async)
    if (!fn.isExported || !fn.isAsync || !isHandlerLike(fn.name)) continue;

    // Check if any function in the call chain (callees) has 'auth' in the name
    const callees = await store.getCallees(fn.name, 10);
    const hasAuth = callees.some((callee) => callee.name.toLowerCase().includes('auth'));

    if (!hasAuth) {
      results.push({
        endpoint: {
          name: fn.name,
          filePath: fn.filePath,
          line: fn.startLine,
        },
        reason: 'No auth middleware in call chain',
      });
    }
  }

  return results;
}

// ── queryResultsToFindings ──

export function queryResultsToFindings(
  attackPaths: AttackPath[],
  blastRadius: BlastRadiusResult[],
  missingAuth: MissingAuthResult[],
): Finding[] {
  const findings: Finding[] = [];
  let idCounter = 0;

  // Attack paths without validation are findings
  for (const ap of attackPaths) {
    if (!ap.hasValidation) {
      idCounter++;
      findings.push({
        id: `kg-attack-path-${idCounter}`,
        engine: 'knowledge_graph',
        severity: ap.sink.type === 'shell' ? 'critical' : 'high',
        type: 'attack_path',
        file: ap.entryPoint.filePath,
        line: ap.entryPoint.line,
        description: `Unvalidated path from ${ap.entryPoint.name} to ${ap.sink.name} (${ap.sink.type} sink): ${ap.path.join(' -> ')}`,
        fix_suggestion: `Add input validation or sanitization in the call chain between ${ap.entryPoint.name} and ${ap.sink.name}`,
        auto_fixable: false,
      });
    }
  }

  // Missing auth findings
  for (const ma of missingAuth) {
    idCounter++;
    findings.push({
      id: `kg-missing-auth-${idCounter}`,
      engine: 'knowledge_graph',
      severity: 'high',
      type: 'missing_auth',
      file: ma.endpoint.filePath,
      line: ma.endpoint.line,
      description: `Endpoint ${ma.endpoint.name} has no auth middleware in call chain`,
      fix_suggestion: `Add authentication middleware (e.g., checkAuth) to the call chain for ${ma.endpoint.name}`,
      auto_fixable: false,
    });
  }

  return findings;
}
