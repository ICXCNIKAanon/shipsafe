/**
 * In-Memory Call Map for ShipSafe Cross-File FP Reduction
 *
 * Builds a lightweight call graph from parsed files (via tree-sitter)
 * to enable cross-file analysis without a full graph database.
 *
 * Used to suppress false positives by checking:
 * - Whether a function is called from an auth context
 * - Whether a function has validation in its call chain
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { extname, join, resolve, relative, dirname } from 'node:path';
import { initParser, parseFile, detectLanguage } from '../graph/parser.js';
import type { ParsedFile } from '../../types.js';

// ── Types ──

export interface FunctionNode {
  name: string;
  file: string;
  line: number;
  isExported: boolean;
  isAsync: boolean;
  callees: Set<string>;   // function names this function calls
  callers: Set<string>;   // function names that call this function
}

export interface CallMap {
  functions: Map<string, FunctionNode>;   // key: "file:functionName"
  fileImports: Map<string, string[]>;     // file -> imported modules

  // Queries
  getCallers(funcKey: string, depth?: number): string[];
  getCallees(funcKey: string, depth?: number): string[];
  isCalledFromAuthContext(funcKey: string): boolean;
  hasValidationInCallChain(funcKey: string): boolean;
}

// ── Auth / validation name patterns ──

const AUTH_NAME_PATTERN = /auth|authenticate|protect|guard|verify|authorize|requireAuth|isAuthenticated|withAuth|checkAuth|middleware/i;
const VALIDATION_NAME_PATTERN = /validate|sanitize|check|verify|parse|escape|purify|clean|filter|whitelist|allowlist/i;

// ── Ignored directories ──

const IGNORED_DIRS = new Set([
  'node_modules', 'dist', 'build', '.git', '.next', '.nuxt',
  'coverage', '__pycache__', '.venv', 'venv', '.turbo',
]);

const SCANNABLE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx']);

// ── File discovery ──

async function discoverFiles(targetPath: string): Promise<string[]> {
  const results: string[] = [];

  async function walk(dir: string): Promise<void> {
    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (IGNORED_DIRS.has(entry)) continue;
      const fullPath = join(dir, entry);

      let stats;
      try {
        stats = await stat(fullPath);
      } catch {
        continue;
      }

      if (stats.isDirectory()) {
        await walk(fullPath);
      } else if (stats.isFile() && SCANNABLE_EXTENSIONS.has(extname(fullPath))) {
        results.push(fullPath);
      }
    }
  }

  await walk(targetPath);
  return results;
}

// ── Import resolution ──

/**
 * Resolve a relative import source to an absolute file path.
 * Handles ./foo, ../bar patterns. Returns null for package imports.
 */
function resolveImportPath(importSource: string, importingFile: string): string | null {
  if (!importSource.startsWith('.')) return null;

  const dir = dirname(importingFile);
  let resolved = resolve(dir, importSource);

  // Try common extensions if no extension provided
  const ext = extname(resolved);
  if (!ext) {
    // Return without extension — we'll match by prefix later
    return resolved;
  }
  return resolved;
}

// ── Core: Build the call map ──

export async function buildCallMap(targetPath: string, files?: string[]): Promise<CallMap> {
  const filesToScan = files ?? await discoverFiles(targetPath);

  // Initialize tree-sitter parser
  await initParser();

  // Phase 1: Parse all files
  const parsedFiles: ParsedFile[] = [];

  for (const filePath of filesToScan) {
    const lang = detectLanguage(filePath);
    if (!lang) continue;

    try {
      const content = await readFile(filePath, 'utf-8');
      const parsed = await parseFile(filePath, content);
      parsedFiles.push(parsed);
    } catch {
      // Skip files that fail to parse
    }
  }

  // Phase 2: Build function nodes and edges
  const functions = new Map<string, FunctionNode>();
  const fileImports = new Map<string, string[]>();

  // Index: function name -> set of keys that define that function name
  const nameIndex = new Map<string, Set<string>>();

  // Index: file -> exported function names
  const fileExports = new Map<string, Set<string>>();

  for (const parsed of parsedFiles) {
    // Track imports per file
    const importSources = parsed.imports.map(imp => imp.source);
    fileImports.set(parsed.filePath, importSources);

    // Track exports per file
    const exports = new Set<string>();
    for (const exp of parsed.exports) {
      exports.add(exp.name);
    }
    fileExports.set(parsed.filePath, exports);

    // Create function nodes
    for (const func of parsed.functions) {
      const key = `${parsed.filePath}:${func.name}`;
      const node: FunctionNode = {
        name: func.name,
        file: parsed.filePath,
        line: func.startLine,
        isExported: func.isExported,
        isAsync: func.isAsync,
        callees: new Set<string>(),
        callers: new Set<string>(),
      };
      functions.set(key, node);

      // Add to name index
      if (!nameIndex.has(func.name)) {
        nameIndex.set(func.name, new Set());
      }
      nameIndex.get(func.name)!.add(key);
    }

    // Build callee edges from call sites
    for (const callSite of parsed.callSites) {
      const callerKey = `${parsed.filePath}:${callSite.callerName}`;
      const callerNode = functions.get(callerKey);
      if (callerNode) {
        callerNode.callees.add(callSite.calleeName);
      }
    }
  }

  // Phase 3: Resolve cross-file references and build caller edges
  for (const parsed of parsedFiles) {
    for (const imp of parsed.imports) {
      const resolvedPath = resolveImportPath(imp.source, parsed.filePath);
      if (!resolvedPath) continue;

      // Find the target file that matches this import
      for (const [filePath, exports] of fileExports) {
        // Match by resolved path (with or without extension)
        const fileWithoutExt = filePath.replace(/\.[^.]+$/, '');
        if (filePath === resolvedPath || fileWithoutExt === resolvedPath ||
            filePath === resolvedPath + '/index.ts' || filePath === resolvedPath + '/index.js') {
          // For each imported specifier, if it's exported from the target file,
          // resolve caller/callee edges
          for (const specifier of imp.specifiers) {
            if (exports.has(specifier)) {
              const targetKey = `${filePath}:${specifier}`;
              const targetNode = functions.get(targetKey);
              if (!targetNode) continue;

              // Find all functions in the importing file that call this specifier
              for (const func of parsed.functions) {
                const callerKey = `${parsed.filePath}:${func.name}`;
                const callerNode = functions.get(callerKey);
                if (callerNode && callerNode.callees.has(specifier)) {
                  targetNode.callers.add(callerKey);
                }
              }
            }
          }
        }
      }
    }
  }

  // Also build caller edges for same-file calls
  for (const [key, node] of functions) {
    for (const calleeName of node.callees) {
      // Check same-file first
      const sameFileKey = `${node.file}:${calleeName}`;
      const calleeNode = functions.get(sameFileKey);
      if (calleeNode) {
        calleeNode.callers.add(key);
      }
    }
  }

  // Phase 4: Build the CallMap object with query methods
  const callMap: CallMap = {
    functions,
    fileImports,

    getCallers(funcKey: string, depth = 3): string[] {
      const visited = new Set<string>();
      const result: string[] = [];

      function walk(key: string, currentDepth: number): void {
        if (currentDepth <= 0 || visited.has(key)) return;
        visited.add(key);

        const node = functions.get(key);
        if (!node) return;

        for (const callerKey of node.callers) {
          result.push(callerKey);
          walk(callerKey, currentDepth - 1);
        }
      }

      walk(funcKey, depth);
      return result;
    },

    getCallees(funcKey: string, depth = 3): string[] {
      const visited = new Set<string>();
      const result: string[] = [];

      function walk(key: string, currentDepth: number): void {
        if (currentDepth <= 0 || visited.has(key)) return;
        visited.add(key);

        const node = functions.get(key);
        if (!node) return;

        for (const calleeName of node.callees) {
          // Find all keys matching this callee name
          const sameFileKey = `${node.file}:${calleeName}`;
          const calleeNode = functions.get(sameFileKey);
          if (calleeNode) {
            result.push(sameFileKey);
            walk(sameFileKey, currentDepth - 1);
          } else {
            // Check cross-file by name
            const keys = nameIndex.get(calleeName);
            if (keys) {
              for (const k of keys) {
                result.push(k);
                walk(k, currentDepth - 1);
              }
            }
          }
        }
      }

      walk(funcKey, depth);
      return result;
    },

    isCalledFromAuthContext(funcKey: string): boolean {
      const callers = callMap.getCallers(funcKey, 5);
      for (const callerKey of callers) {
        const node = functions.get(callerKey);
        if (node && AUTH_NAME_PATTERN.test(node.name)) {
          return true;
        }
      }
      // Also check the function's own name
      const selfNode = functions.get(funcKey);
      if (selfNode && AUTH_NAME_PATTERN.test(selfNode.name)) {
        return true;
      }
      return false;
    },

    hasValidationInCallChain(funcKey: string): boolean {
      const callees = callMap.getCallees(funcKey, 5);
      for (const calleeKey of callees) {
        const node = functions.get(calleeKey);
        if (node && VALIDATION_NAME_PATTERN.test(node.name)) {
          return true;
        }
        // Also check the callee name directly (may not be in functions map)
        const name = calleeKey.split(':').pop();
        if (name && VALIDATION_NAME_PATTERN.test(name)) {
          return true;
        }
      }
      return false;
    },
  };

  return callMap;
}

/**
 * Build a call map with a timeout. Returns null if building exceeds the timeout.
 */
export async function buildCallMapWithTimeout(
  targetPath: string,
  files?: string[],
  timeoutMs = 5000,
): Promise<CallMap | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const map = await Promise.race([
      buildCallMap(targetPath, files),
      new Promise<null>((_, reject) => {
        controller.signal.addEventListener('abort', () => {
          reject(new Error('Call map build timed out'));
        });
      }),
    ]);
    return map;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Look up the function key for a finding based on file and line number.
 * Returns the key "file:functionName" or null if not found.
 */
export function findFunctionKeyForLine(
  callMap: CallMap,
  file: string,
  line: number,
): string | null {
  for (const [key, node] of callMap.functions) {
    if (node.file === file && node.line <= line) {
      // This is a rough match — the function that starts at or before this line
      // and is in the same file. We pick the closest one.
      return key;
    }
  }
  return null;
}

/**
 * Find the best matching function key for a file:line pair.
 * Returns the function whose start line is closest to (but not after) the target line.
 */
export function findClosestFunctionKey(
  callMap: CallMap,
  file: string,
  line: number,
): string | null {
  let bestKey: string | null = null;
  let bestLine = -1;

  for (const [key, node] of callMap.functions) {
    if (node.file === file && node.line <= line && node.line > bestLine) {
      bestKey = key;
      bestLine = node.line;
    }
  }

  return bestKey;
}
