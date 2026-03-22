import type { Finding, ScanScope } from '../../types.js';
import { initParser, parseProject } from './parser.js';
import { createGraphStore } from './store.js';
import {
  findAttackPaths,
  findBlastRadius,
  findMissingAuth,
  queryResultsToFindings,
} from './queries.js';
import { findDataFlows } from './data-flow.js';

// ── Public types ──

export interface GraphEngineResult {
  findings: Finding[];
  stats: {
    filesScanned: number;
    functionsFound: number;
    classesFound: number;
    callEdges: number;
    attackPathsFound: number;
  };
  duration_ms: number;
}

// ── Public API ──

/** Check if graph engine dependencies are available (tree-sitter, etc.) */
export function isGraphEngineAvailable(): boolean {
  try {
    // web-tree-sitter is a bundled dependency, so if we got here it's available
    return true;
  } catch {
    return false;
  }
}

/** Run the full Knowledge Graph analysis on a project. */
export async function runGraphEngine(options: {
  targetPath: string;
  scope: ScanScope;
}): Promise<GraphEngineResult> {
  const startTime = Date.now();
  const { targetPath } = options;

  // 1. Initialize the parser
  await initParser();

  // 2. Parse project files
  const parsedFiles = await parseProject(targetPath);

  // 3. Create an in-memory graph store (no temp directories needed)
  const store = await createGraphStore();

  try {
    // 4. Build the graph from parsed files
    await store.buildGraph(parsedFiles);

    // 5. Compute stats
    const totalFunctions = parsedFiles.reduce((sum, f) => sum + f.functions.length, 0);
    const totalClasses = parsedFiles.reduce((sum, f) => sum + f.classes.length, 0);
    const totalCallEdges = parsedFiles.reduce((sum, f) => sum + f.callSites.length, 0);

    // 6. Run all security queries
    const attackPaths = await findAttackPaths(store);

    // Find blast radius for any known-vulnerable functions (sinks)
    const sinkNames = new Set<string>();
    for (const ap of attackPaths) {
      if (!ap.hasValidation) {
        sinkNames.add(ap.sink.name);
      }
    }
    const blastRadiusResults = [];
    for (const sinkName of sinkNames) {
      const br = await findBlastRadius(store, sinkName);
      blastRadiusResults.push(br);
    }

    const missingAuth = await findMissingAuth(store);

    // 7. Convert query results to findings
    const findings = queryResultsToFindings(attackPaths, blastRadiusResults, missingAuth);

    // 8. Run data flow taint analysis and add tainted_data_flow findings
    const dataFlows = await findDataFlows(store);
    let dfIdCounter = 0;
    for (const flow of dataFlows) {
      if (flow.hasSanitization) continue; // sanitized flows are not findings

      dfIdCounter++;
      const severity =
        flow.sink.type === 'shell' || flow.sink.type === 'eval' ? 'critical' : 'high';

      findings.push({
        id: `kg-tainted-flow-${dfIdCounter}`,
        engine: 'knowledge_graph',
        severity,
        type: 'tainted_data_flow',
        file: flow.source.filePath,
        line: flow.source.line,
        description: `Tainted data flows from ${flow.source.name} (${flow.source.type}) to ${flow.sink.name} (${flow.sink.type} sink): ${flow.path.join(' -> ')}`,
        fix_suggestion: `Add input sanitization or parameterization between ${flow.source.name} and ${flow.sink.name}`,
        auto_fixable: false,
      });
    }

    // 9. Return findings with stats and timing
    return {
      findings,
      stats: {
        filesScanned: parsedFiles.length,
        functionsFound: totalFunctions,
        classesFound: totalClasses,
        callEdges: totalCallEdges,
        attackPathsFound: attackPaths.length,
      },
      duration_ms: Date.now() - startTime,
    };
  } finally {
    // 10. Close the store (no-op for in-memory, but maintains interface contract)
    await store.close();
  }
}
