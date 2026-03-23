import type { GraphStore, GraphFunction } from './store.js';
import type { Finding, AttackPath, BlastRadiusResult, MissingAuthResult } from '../../types.js';

// ── Constants ──

const ENTRY_POINT_PATTERNS = ['handle', 'route', 'controller', 'endpoint'];

// Sinks must be specific enough to avoid matching common JS methods like Array.find()
const SINK_PATTERNS: Record<string, string[]> = {
  database: [
    // Must include receiver context — plain "find"/"delete" are too generic
    'executeQuery', 'executeRaw', 'executeSql',
    'queryRaw', 'queryRawUnsafe', '$queryRaw', '$queryRawUnsafe',
    '$executeRaw', '$executeRawUnsafe',
    'rawQuery', 'runQuery',
  ],
  filesystem: ['readFileSync', 'writeFileSync', 'readFile', 'writeFile', 'unlinkSync', 'createReadStream', 'createWriteStream'],
  shell: ['execSync', 'execFileSync', 'spawnSync', 'childExec', 'childSpawn'],
  network: ['fetchUrl', 'httpGet', 'httpPost', 'axiosGet', 'axiosPost'],
  eval: ['eval', 'Function'],
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

function classifySink(name: string): string | null {
  const nameLower = name.toLowerCase();
  for (const [type, patterns] of Object.entries(SINK_PATTERNS)) {
    for (const pattern of patterns) {
      if (nameLower === pattern.toLowerCase()) {
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

function isSink(name: string): boolean {
  return classifySink(name) !== null;
}

function isHandlerLike(name: string): boolean {
  const nameLower = name.toLowerCase();
  return ENTRY_POINT_PATTERNS.some((p) => nameLower.includes(p));
}

// ── findAttackPaths ──

/**
 * Find paths from entry point functions to dangerous sink functions.
 * Uses BFS via getCallees to trace call chains without native path queries.
 */
export async function findAttackPaths(store: GraphStore): Promise<AttackPath[]> {
  // Step 1: Get all functions to identify entry points
  const allFunctions = store.getAllFunctions();

  const entryPoints = allFunctions.filter((fn) => isEntryPoint(fn));

  const attackPaths: AttackPath[] = [];

  // Step 2: For each entry point, trace call chains to find sinks
  for (const entry of entryPoints) {
    const entryName = entry.name;

    // Get all direct callees (depth 1 only to build specific paths)
    const directCallees = await store.getCallees(entryName, 1);

    for (const callee of directCallees) {
      if (isSink(callee.name)) {
        // Direct path: entry -> sink
        const pathNames = [entryName, callee.name];
        attackPaths.push({
          entryPoint: {
            name: entryName,
            filePath: entry.filePath,
            line: entry.startLine,
          },
          sink: {
            name: callee.name,
            filePath: callee.filePath,
            line: callee.startLine,
            type: classifySink(callee.name)!,
          },
          path: pathNames,
          hasValidation: pathNames.some((n) => isValidator(n)),
        });
      } else {
        // Check if this intermediate callee leads to a sink (depth 2-5)
        const deepCallees = await store.getCallees(callee.name, 4);
        for (const deepCallee of deepCallees) {
          if (isSink(deepCallee.name)) {
            const pathNames = [entryName, callee.name, deepCallee.name];
            attackPaths.push({
              entryPoint: {
                name: entryName,
                filePath: entry.filePath,
                line: entry.startLine,
              },
              sink: {
                name: deepCallee.name,
                filePath: deepCallee.filePath,
                line: deepCallee.startLine,
                type: classifySink(deepCallee.name)!,
              },
              path: pathNames,
              hasValidation: pathNames.some((n) => isValidator(n)),
            });
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
