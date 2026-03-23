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

const SINK_PATTERNS: Record<string, string[]> = {
  database: ['executequery', 'executeraw', 'executesql', 'queryraw', 'queryrawunsafe', 'runquery'],
  filesystem: ['writefilesync', 'writefile', 'createwritestream'],
  shell: ['execsync', 'execfilesync', 'spawnsync'],
  eval: ['eval'],
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

/** Classify a function name as a taint sink type, or null if not a sink. */
export function classifySink(name: string): string | null {
  const nameLower = name.toLowerCase();

  // Prioritize more specific types: eval > shell > filesystem > database
  // Check eval first
  if (nameLower === 'eval' || nameLower === 'function') {
    return 'eval';
  }

  // shell: spawn, exec (but not execute/execSync -- those go to database/shell)
  // exec is both shell and database -- shell takes priority
  if (nameLower === 'exec' || nameLower === 'execsync' || nameLower === 'spawn' || nameLower === 'execfile') {
    return 'shell';
  }

  // filesystem
  if (nameLower === 'writefile') {
    return 'filesystem';
  }

  // database
  for (const pattern of SINK_PATTERNS['database']!) {
    if (nameLower === pattern.toLowerCase()) {
      return 'database';
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

      // BFS from caller, following callees up to MAX_DEPTH
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

        // Check if current function is itself a sink
        const sinkType = classifySink(fn.name);
        if (sinkType !== null) {
          const key = `${sourceName}:${fn.name}`;
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
                name: fn.name,
                filePath: fn.filePath,
                line: fn.startLine,
                type: sinkType,
              },
              path,
              hasSanitization: callerHasSanitizerInScope,
            });
          }
          // Don't continue BFS past a sink
          continue;
        }

        if (depth >= MAX_DEPTH) continue;

        // Get direct callees of current function
        const callees = await store.getCallees(fn.name, 1);
        for (const callee of callees) {
          if (visited.has(callee.name)) continue;
          visited.add(callee.name);

          const calleeSinkType = classifySink(callee.name);
          const newPath = [...path, callee.name];

          if (calleeSinkType !== null) {
            // Found a sink!
            const key = `${sourceName}:${callee.name}`;
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
                  name: callee.name,
                  filePath: callee.filePath,
                  line: callee.startLine,
                  type: calleeSinkType,
                },
                path: newPath,
                hasSanitization: callerHasSanitizerInScope,
              });
            }
          } else {
            queue.push({
              fn: callee,
              path: newPath,
              depth: depth + 1,
            });
          }
        }
      }
    }
  }

  return results;
}
