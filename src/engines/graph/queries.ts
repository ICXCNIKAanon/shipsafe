import type { GraphStore, GraphFunction } from './store.js';
import type { Finding, AttackPath, BlastRadiusResult, MissingAuthResult } from '../../types.js';

// ── Constants ──

const ENTRY_POINT_PATTERNS = ['handle', 'route', 'controller', 'api', 'endpoint'];

const SINK_PATTERNS: Record<string, string[]> = {
  database: ['query', 'execute', 'exec', 'find', 'insert', 'update', 'delete', 'raw'],
  filesystem: ['readFile', 'writeFile', 'unlink', 'createReadStream', 'open'],
  shell: ['exec', 'execSync', 'spawn', 'execFile'],
  network: ['fetch', 'axios', 'request', 'http.get'],
};

const VALIDATOR_PATTERNS = ['valid', 'sanitiz', 'escape', 'clean', 'check', 'verify', 'auth'];

// ── Helpers ──

function isEntryPoint(fn: GraphFunction): boolean {
  const nameLower = fn.name.toLowerCase();
  return (
    fn.isExported &&
    (ENTRY_POINT_PATTERNS.some((p) => nameLower.includes(p)) || fn.isAsync)
  );
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
  const allFunctions = (await store.query(
    'MATCH (fn:Function) RETURN fn.name AS name, fn.filePath AS filePath, fn.startLine AS line, fn.isAsync AS isAsync, fn.isExported AS isExported',
  )) as Array<Record<string, unknown>>;

  const entryPoints = allFunctions.filter((fn) => {
    const name = fn['name'] as string;
    const isExported = fn['isExported'] as boolean;
    const isAsync = fn['isAsync'] as boolean;
    return isExported && (isHandlerLike(name) || isAsync);
  });

  const attackPaths: AttackPath[] = [];

  // Step 2: For each entry point, trace call chains to find sinks
  for (const entry of entryPoints) {
    const entryName = entry['name'] as string;

    // Get all direct callees (depth 1 only to build specific paths)
    const directCallees = await store.getCallees(entryName, 1);

    for (const callee of directCallees) {
      if (isSink(callee.name)) {
        // Direct path: entry -> sink
        const pathNames = [entryName, callee.name];
        attackPaths.push({
          entryPoint: {
            name: entryName,
            filePath: entry['filePath'] as string,
            line: entry['line'] as number,
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
                filePath: entry['filePath'] as string,
                line: entry['line'] as number,
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
  const allFunctions = (await store.query(
    'MATCH (fn:Function) RETURN fn.name AS name, fn.filePath AS filePath, fn.startLine AS line, fn.isAsync AS isAsync, fn.isExported AS isExported',
  )) as Array<Record<string, unknown>>;

  const results: MissingAuthResult[] = [];

  for (const fn of allFunctions) {
    const name = fn['name'] as string;
    const isExported = fn['isExported'] as boolean;
    const isAsync = fn['isAsync'] as boolean;

    // Only check endpoint-like functions (handler/route/controller/api pattern AND async)
    if (!isExported || !isAsync || !isHandlerLike(name)) continue;

    // Check if any function in the call chain (callees) has 'auth' in the name
    const callees = await store.getCallees(name, 10);
    const hasAuth = callees.some((callee) => callee.name.toLowerCase().includes('auth'));

    if (!hasAuth) {
      results.push({
        endpoint: {
          name,
          filePath: fn['filePath'] as string,
          line: fn['line'] as number,
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
