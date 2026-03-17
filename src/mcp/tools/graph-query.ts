import os from 'node:os';
import path from 'node:path';
import { rm, mkdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { initParser, parseProject } from '../../engines/graph/parser.js';
import { createGraphStore } from '../../engines/graph/store.js';
import {
  findAttackPaths,
  findBlastRadius,
  findMissingAuth,
} from '../../engines/graph/queries.js';

// ── Types ──

export interface GraphQueryParams {
  query_type: 'callers' | 'callees' | 'data_flow' | 'attack_paths' | 'blast_radius' | 'auth_chain';
  target?: string;
  depth?: number;
}

// ── Handler ──

export async function handleGraphQuery(params: GraphQueryParams): Promise<object> {
  const { query_type, target, depth } = params;
  const projectDir = process.cwd();

  // Initialize parser
  await initParser();

  // Parse the project
  const parsedFiles = await parseProject(projectDir);

  // Create a temporary graph store
  const tmpDir = path.join(os.tmpdir(), `shipsafe-graph-query-${randomUUID()}`);
  await mkdir(tmpDir, { recursive: true });
  const store = await createGraphStore(tmpDir);

  try {
    // Build the graph
    await store.buildGraph(parsedFiles);

    switch (query_type) {
      case 'callers': {
        if (!target) {
          return { error: 'target is required for callers query' };
        }
        const callers = await store.getCallers(target, depth ?? 3);
        return {
          query_type,
          target,
          depth: depth ?? 3,
          results: callers.map((fn) => ({
            name: fn.name,
            filePath: fn.filePath,
            startLine: fn.startLine,
            endLine: fn.endLine,
            isAsync: fn.isAsync,
            isExported: fn.isExported,
            className: fn.className || undefined,
          })),
        };
      }

      case 'callees': {
        if (!target) {
          return { error: 'target is required for callees query' };
        }
        const callees = await store.getCallees(target, depth ?? 3);
        return {
          query_type,
          target,
          depth: depth ?? 3,
          results: callees.map((fn) => ({
            name: fn.name,
            filePath: fn.filePath,
            startLine: fn.startLine,
            endLine: fn.endLine,
            isAsync: fn.isAsync,
            isExported: fn.isExported,
            className: fn.className || undefined,
          })),
        };
      }

      case 'data_flow': {
        if (!target) {
          return { error: 'target is required for data_flow query' };
        }
        // data_flow combines callers + callees for a complete picture
        const dfCallers = await store.getCallers(target, depth ?? 5);
        const dfCallees = await store.getCallees(target, depth ?? 5);
        return {
          query_type,
          target,
          depth: depth ?? 5,
          callers: dfCallers.map((fn) => ({
            name: fn.name,
            filePath: fn.filePath,
            startLine: fn.startLine,
          })),
          callees: dfCallees.map((fn) => ({
            name: fn.name,
            filePath: fn.filePath,
            startLine: fn.startLine,
          })),
        };
      }

      case 'attack_paths': {
        const attackPaths = await findAttackPaths(store);
        return {
          query_type,
          results: attackPaths.map((ap) => ({
            entryPoint: ap.entryPoint,
            sink: ap.sink,
            path: ap.path,
            hasValidation: ap.hasValidation,
          })),
          total: attackPaths.length,
        };
      }

      case 'blast_radius': {
        if (!target) {
          return { error: 'target is required for blast_radius query' };
        }
        const br = await findBlastRadius(store, target);
        return {
          query_type,
          target,
          affectedFunctions: br.affectedFunctions,
          affectedEndpoints: br.affectedEndpoints,
          totalAffected: br.totalAffected,
        };
      }

      case 'auth_chain': {
        const missingAuth = await findMissingAuth(store);
        return {
          query_type,
          results: missingAuth.map((ma) => ({
            endpoint: ma.endpoint,
            reason: ma.reason,
          })),
          total: missingAuth.length,
        };
      }

      default:
        return { error: `Unknown query_type: ${query_type}` };
    }
  } finally {
    // Clean up
    await store.close();
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  }
}
