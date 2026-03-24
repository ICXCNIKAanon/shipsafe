import type { GraphStore, GraphFunction } from './store.js';

// ── Constants ──

const SOURCE_PATTERNS = [
  'parserequest',
  'getbody',
  'getrequestbody',
  'readinput',
  'parseformdata',
  'parseinput',
  'readuserinput',
];

// Receiver-aware sink patterns for data-flow taint analysis.
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
    // Always-dangerous patterns (no receiver needed)
    { method: 'executeQuery' },
    { method: 'executeRaw' },
    { method: 'executeSql' },
    { method: 'queryRaw' },
    { method: 'queryRawUnsafe' },
    { method: 'runQuery' },
  ],
  filesystem: [
    { method: 'writeFile' },
    { method: 'writeFileSync' },
    { method: 'createWriteStream' },
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
  eval: [
    { method: 'eval' },
  ],
};

const SANITIZER_PATTERNS = ['valid', 'sanitiz', 'escape', 'clean', 'encode', 'parameteriz', 'prepare', 'guard', 'protect'];

const MAX_DEPTH = 8;

// ── Public types ──

export interface DataFlowResult {
  source: {
    name: string;
    filePath: string;
    line: number;
    type: string; // e.g. 'user_input'
  };
  sink: {
    name: string;
    filePath: string;
    line: number;
    type: string; // e.g. 'database', 'shell', 'filesystem', 'eval'
  };
  path: string[]; // function names in order from source caller to sink
  hasSanitization: boolean;
}

// ── Exported classifier functions ──

/** Classify a function name as a taint source type, or null if not a source. */
export function classifySource(name: string): string | null {
  const nameLower = name.toLowerCase();
  for (const pattern of SOURCE_PATTERNS) {
    if (nameLower.includes(pattern)) {
      return 'user_input';
    }
  }
  return null;
}

/**
 * Classify a function call as a taint sink type, with optional receiver awareness.
 * If receiver is provided, patterns with a `receivers` list will only match
 * when the receiver is in that list. Patterns without `receivers` always match.
 */
export function classifySink(name: string, receiver?: string): string | null {
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

function isSanitizer(name: string): boolean {
  const nameLower = name.toLowerCase();
  return SANITIZER_PATTERNS.some((p) => nameLower.includes(p));
}

// ── findDataFlows ──

/**
 * Trace tainted data from source functions (user input, request params) through
 * call chains to dangerous sinks (SQL, filesystem, shell) using BFS on the knowledge graph.
 *
 * Algorithm:
 * 1. Find all functions in the graph.
 * 2. Identify source functions (by name pattern).
 * 3. For each source, find all callers (functions that call the source).
 *    These callers handle tainted data.
 * 4. BFS from each tainted caller, following callees up to depth MAX_DEPTH.
 * 5. If BFS reaches a sink, record a DataFlowResult.
 * 6. Mark as hasSanitization=true if any function in the path is a sanitizer.
 */
export async function findDataFlows(store: GraphStore): Promise<DataFlowResult[]> {
  // Step 1: Get all functions
  const allFunctions = store.getAllFunctions();

  if (allFunctions.length === 0) {
    return [];
  }

  // Step 2: Identify source functions
  const sourceFunctions = allFunctions.filter((fn) => classifySource(fn.name) !== null);

  const results: DataFlowResult[] = [];
  // Track source+sink pairs to avoid duplicates
  const seen = new Set<string>();

  // Step 3 & 4: For each source, find callers and BFS their callees to find sinks
  for (const sourceFn of sourceFunctions) {
    const sourceName = sourceFn.name;
    const sourceType = classifySource(sourceName)!;

    // Find all functions that call this source (i.e., functions that handle tainted data)
    const callers = await store.getCallers(sourceName, 1);

    for (const caller of callers) {
      // Pre-compute whether any function reachable from caller (within MAX_DEPTH)
      // is a sanitizer. This captures sibling calls like:
      //   safeHandler -> sanitizeInput (sanitizer)
      //   safeHandler -> exec (sink)
      // Even though sanitizeInput is not on the path to exec, it shows sanitization intent.
      const allCalleesOfCaller = await store.getCallees(caller.name, MAX_DEPTH);
      const callerHasSanitizerInScope =
        isSanitizer(caller.name) ||
        allCalleesOfCaller.some((fn) => isSanitizer(fn.name));

      // BFS from caller, following call edges (with receiver info) up to MAX_DEPTH
      interface BFSNode {
        fn: GraphFunction;
        path: string[]; // function names from source to current
        depth: number;
      }

      const queue: BFSNode[] = [
        {
          fn: caller,
          path: [sourceName, caller.name],
          depth: 1,
        },
      ];

      const visited = new Set<string>();
      visited.add(sourceName);
      visited.add(caller.name);

      while (queue.length > 0) {
        const node = queue.shift()!;
        const { fn, path, depth } = node;

        if (depth >= MAX_DEPTH) continue;

        // Get direct call edges from current function (with receiver info)
        const edges = store.getCallEdgesFrom(fn.name);
        for (const edge of edges) {
          if (visited.has(edge.calleeName)) continue;
          visited.add(edge.calleeName);

          const calleeSinkType = classifySink(edge.calleeName, edge.receiver);
          const newPath = [...path, edge.calleeName];

          if (calleeSinkType !== null) {
            // Found a sink!
            const calleeFn = await store.getFunction(edge.calleeName);
            const key = `${sourceName}:${edge.calleeName}`;
            if (!seen.has(key)) {
              seen.add(key);
              results.push({
                source: {
                  name: sourceName,
                  filePath: sourceFn.filePath,
                  line: sourceFn.startLine,
                  type: sourceType,
                },
                sink: {
                  name: edge.calleeName,
                  filePath: calleeFn?.filePath ?? edge.filePath,
                  line: calleeFn?.startLine ?? edge.line,
                  type: calleeSinkType,
                },
                path: newPath,
                hasSanitization: callerHasSanitizerInScope,
              });
            }
          } else {
            const calleeFn = await store.getFunction(edge.calleeName);
            if (calleeFn) {
              queue.push({
                fn: calleeFn,
                path: newPath,
                depth: depth + 1,
              });
            }
          }
        }
      }
    }
  }

  return results;
}
