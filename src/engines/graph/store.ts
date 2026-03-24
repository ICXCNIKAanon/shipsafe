import type {
  ParsedFile,
  FunctionNode,
  ClassNode,
  ImportNode,
  CallSite,
} from '../../types.js';

// ── Public types ──

export interface GraphFunction {
  id: string;
  name: string;
  filePath: string;
  startLine: number;
  endLine: number;
  isAsync: boolean;
  isExported: boolean;
  className: string;
}

export interface GraphClass {
  id: string;
  name: string;
  filePath: string;
  startLine: number;
  endLine: number;
  isExported: boolean;
}

export interface GraphFile {
  path: string;
  language: string;
}

export interface GraphModule {
  name: string;
}

export interface GraphImport {
  source: string;
  filePath: string;
  line: number;
  specifiers: string[];
}

/** A resolved call edge with receiver information from the call site. */
export interface CallEdgeInfo {
  callerId: string;
  callerName: string;
  calleeId: string;
  calleeName: string;
  receiver?: string;
  filePath: string;
  line: number;
}

export interface GraphStore {
  /** Populate the graph from parsed files. */
  buildGraph(parsedFiles: ParsedFile[]): Promise<void>;

  /** Retrieve a function node by name. Returns the first match. */
  getFunction(name: string): Promise<GraphFunction | null>;

  /** Find functions that call the target (transitive up to depth). */
  getCallers(functionName: string, depth?: number): Promise<GraphFunction[]>;

  /** Find functions called by the target (transitive up to depth). */
  getCallees(functionName: string, depth?: number): Promise<GraphFunction[]>;

  /** Get direct call edges originating from a given function (by name).
   *  Returns edges with receiver info for receiver-aware sink classification. */
  getCallEdgesFrom(functionName: string): CallEdgeInfo[];

  /** Get all files that import a given module path. */
  getImportsOf(modulePath: string): Promise<GraphImport[]>;

  /** Execute a structured query against the in-memory graph.
   *  Returns rows as Record<string, unknown>[].
   *  Supports a subset of patterns used internally. */
  query(pattern: string, params?: Record<string, unknown>): Promise<unknown[]>;

  /** Get all functions in the graph. */
  getAllFunctions(): GraphFunction[];

  /** Close the store and release resources. No-op for in-memory. */
  close(): Promise<void>;
}

// ── Helpers ──

function makeFunctionId(fn: FunctionNode): string {
  if (fn.className) {
    return `${fn.filePath}::${fn.className}.${fn.name}`;
  }
  return `${fn.filePath}::${fn.name}`;
}

function makeClassId(cls: ClassNode): string {
  return `${cls.filePath}::${cls.name}`;
}

// ── In-memory implementation ──

export async function createGraphStore(_dbPath?: string): Promise<GraphStore> {
  // Node storage
  const functions = new Map<string, GraphFunction>(); // id -> GraphFunction
  const classes = new Map<string, GraphClass>();       // id -> GraphClass
  const files = new Map<string, GraphFile>();           // path -> GraphFile
  const modules = new Map<string, GraphModule>();       // name -> GraphModule

  // Edge storage
  const callEdges: Array<{ callerId: string; calleeId: string; receiver?: string; filePath: string; line: number }> = [];
  const containsEdges: Array<{ filePath: string; functionId: string }> = [];
  const containsClassEdges: Array<{ filePath: string; classId: string }> = [];
  const hasMethodEdges: Array<{ classId: string; functionId: string }> = [];
  const importEdges: Array<{ filePath: string; moduleName: string; line: number; specifiers: string }> = [];

  // Indexes for fast lookup
  const functionsByName = new Map<string, GraphFunction[]>(); // name -> GraphFunction[]
  const callerIndex = new Map<string, Set<string>>();          // calleeId -> Set<callerId>
  const calleeIndex = new Map<string, Set<string>>();          // callerId -> Set<calleeId>
  // Index for call edges by caller function name (for receiver-aware queries)
  const callEdgesByCallerName = new Map<string, CallEdgeInfo[]>();

  function addToNameIndex(fn: GraphFunction): void {
    const list = functionsByName.get(fn.name) ?? [];
    list.push(fn);
    functionsByName.set(fn.name, list);
  }

  // ── buildGraph ──

  async function buildGraph(parsedFiles: ParsedFile[]): Promise<void> {
    // Collect all function IDs for call-site resolution
    const functionNameToId = new Map<string, string>(); // name -> id (first match)
    const methodQualifiedToId = new Map<string, string>(); // "ClassName.method" -> id

    // Pass 1: Insert nodes
    for (const file of parsedFiles) {
      // Insert File node
      files.set(file.filePath, { path: file.filePath, language: file.language });

      // Insert Function nodes
      for (const fn of file.functions) {
        const id = makeFunctionId(fn);
        const gf: GraphFunction = {
          id,
          name: fn.name,
          filePath: fn.filePath,
          startLine: fn.startLine,
          endLine: fn.endLine,
          isAsync: fn.isAsync,
          isExported: fn.isExported,
          className: fn.className ?? '',
        };
        functions.set(id, gf);
        addToNameIndex(gf);

        // Index for call resolution
        if (!functionNameToId.has(fn.name)) {
          functionNameToId.set(fn.name, id);
        }

        // Index methods by className.methodName
        if (fn.className) {
          const qualifiedName = `${fn.className}.${fn.name}`;
          if (!methodQualifiedToId.has(qualifiedName)) {
            methodQualifiedToId.set(qualifiedName, id);
          }
        }

        // Create CONTAINS edge (File -> Function)
        containsEdges.push({ filePath: file.filePath, functionId: id });
      }

      // Insert Class nodes
      for (const cls of file.classes) {
        const id = makeClassId(cls);
        classes.set(id, {
          id,
          name: cls.name,
          filePath: cls.filePath,
          startLine: cls.startLine,
          endLine: cls.endLine,
          isExported: cls.isExported,
        });

        // Create CONTAINS_CLASS edge (File -> Class)
        containsClassEdges.push({ filePath: file.filePath, classId: id });

        // Create HAS_METHOD edges (Class -> Function)
        for (const methodName of cls.methods) {
          const methodFnId = `${cls.filePath}::${cls.name}.${methodName}`;
          hasMethodEdges.push({ classId: id, functionId: methodFnId });
        }
      }

      // Insert Module nodes and IMPORTS edges
      for (const imp of file.imports) {
        if (!modules.has(imp.source)) {
          modules.set(imp.source, { name: imp.source });
        }
        importEdges.push({
          filePath: file.filePath,
          moduleName: imp.source,
          line: imp.line,
          specifiers: imp.specifiers.join(','),
        });
      }
    }

    // Pass 2: Resolve call sites into CALLS edges
    for (const file of parsedFiles) {
      for (const call of file.callSites) {
        // Find the caller function ID
        const callerFn = file.functions.find((fn) => fn.name === call.callerName);
        if (!callerFn) continue;
        const callerId = makeFunctionId(callerFn);

        // Find the callee function ID
        let calleeId: string | undefined;

        if (call.receiver) {
          // Method call: try receiver.calleeName
          const qualifiedName = `${call.receiver}.${call.calleeName}`;
          calleeId = methodQualifiedToId.get(qualifiedName);
        }

        // Fallback to plain name lookup
        if (!calleeId) {
          calleeId = functionNameToId.get(call.calleeName);
        }

        if (!calleeId) continue; // External or unresolved call

        callEdges.push({ callerId, calleeId, receiver: call.receiver, filePath: call.filePath, line: call.line });

        // Update indexes
        if (!callerIndex.has(calleeId)) {
          callerIndex.set(calleeId, new Set());
        }
        callerIndex.get(calleeId)!.add(callerId);

        if (!calleeIndex.has(callerId)) {
          calleeIndex.set(callerId, new Set());
        }
        calleeIndex.get(callerId)!.add(calleeId);

        // Build call-edge-by-caller-name index
        const callerFnObj = functions.get(callerId);
        const calleeFnObj = functions.get(calleeId);
        if (callerFnObj && calleeFnObj) {
          const edgeInfo: CallEdgeInfo = {
            callerId,
            callerName: callerFnObj.name,
            calleeId,
            calleeName: calleeFnObj.name,
            receiver: call.receiver,
            filePath: call.filePath,
            line: call.line,
          };
          const existingEdges = callEdgesByCallerName.get(callerFnObj.name) ?? [];
          existingEdges.push(edgeInfo);
          callEdgesByCallerName.set(callerFnObj.name, existingEdges);
        }
      }
    }
  }

  // ── getFunction ──

  async function getFunction(name: string): Promise<GraphFunction | null> {
    const list = functionsByName.get(name);
    if (!list || list.length === 0) return null;
    return list[0];
  }

  // ── getCallers (BFS) ──

  async function getCallers(
    functionName: string,
    depth: number = 1,
  ): Promise<GraphFunction[]> {
    // Find all function IDs matching this name
    const targetFunctions = functionsByName.get(functionName);
    if (!targetFunctions || targetFunctions.length === 0) return [];

    const result: GraphFunction[] = [];
    const visited = new Set<string>();

    // Seed the BFS with target function IDs
    let currentLevel = new Set<string>();
    for (const tf of targetFunctions) {
      currentLevel.add(tf.id);
      visited.add(tf.id);
    }

    for (let d = 0; d < depth; d++) {
      const nextLevel = new Set<string>();
      for (const nodeId of currentLevel) {
        const callerIds = callerIndex.get(nodeId);
        if (!callerIds) continue;
        for (const callerId of callerIds) {
          if (visited.has(callerId)) continue;
          visited.add(callerId);
          const fn = functions.get(callerId);
          if (fn) {
            result.push(fn);
            nextLevel.add(callerId);
          }
        }
      }
      if (nextLevel.size === 0) break;
      currentLevel = nextLevel;
    }

    return result;
  }

  // ── getCallees (BFS) ──

  async function getCallees(
    functionName: string,
    depth: number = 1,
  ): Promise<GraphFunction[]> {
    // Find all function IDs matching this name
    const targetFunctions = functionsByName.get(functionName);
    if (!targetFunctions || targetFunctions.length === 0) return [];

    const result: GraphFunction[] = [];
    const visited = new Set<string>();

    // Seed the BFS with target function IDs
    let currentLevel = new Set<string>();
    for (const tf of targetFunctions) {
      currentLevel.add(tf.id);
      visited.add(tf.id);
    }

    for (let d = 0; d < depth; d++) {
      const nextLevel = new Set<string>();
      for (const nodeId of currentLevel) {
        const calleeIds = calleeIndex.get(nodeId);
        if (!calleeIds) continue;
        for (const calleeId of calleeIds) {
          if (visited.has(calleeId)) continue;
          visited.add(calleeId);
          const fn = functions.get(calleeId);
          if (fn) {
            result.push(fn);
            nextLevel.add(calleeId);
          }
        }
      }
      if (nextLevel.size === 0) break;
      currentLevel = nextLevel;
    }

    return result;
  }

  // ── getImportsOf ──

  async function getImportsOf(modulePath: string): Promise<GraphImport[]> {
    return importEdges
      .filter((edge) => edge.moduleName === modulePath)
      .map((edge) => ({
        source: edge.moduleName,
        filePath: edge.filePath,
        line: edge.line,
        specifiers: edge.specifiers.split(',').filter(Boolean),
      }));
  }

  // ── getAllFunctions ──

  function getAllFunctions(): GraphFunction[] {
    return Array.from(functions.values());
  }

  // ── query (structured query for compatibility) ──
  // Supports common patterns used by queries.ts, data-flow.ts, and tests.
  // This is NOT a full Cypher engine — it handles the specific patterns
  // used in the ShipSafe codebase.

  async function queryFn(
    pattern: string,
    params?: Record<string, unknown>,
  ): Promise<unknown[]> {
    // Pattern: MATCH (fn:Function) RETURN ...
    if (/MATCH\s+\(fn:Function\)/i.test(pattern)) {
      const allFns = Array.from(functions.values());

      // Filter: WHERE fn.name = $name or WHERE fn.name = 'xxx'
      let filtered = allFns;
      const nameParam = params?.['name'] as string | undefined;
      if (nameParam !== undefined) {
        filtered = filtered.filter((fn) => fn.name === nameParam);
      }

      return filtered.map((fn) => ({
        'fn.id': fn.id,
        'fn.name': fn.name,
        'fn.filePath': fn.filePath,
        'fn.startLine': fn.startLine,
        'fn.endLine': fn.endLine,
        'fn.isAsync': fn.isAsync,
        'fn.isExported': fn.isExported,
        'fn.className': fn.className,
        'name': fn.name,
        'filePath': fn.filePath,
        'line': fn.startLine,
        'isAsync': fn.isAsync,
        'isExported': fn.isExported,
      }));
    }

    // Pattern: MATCH (f:Function) WHERE f.name = $name RETURN f.filePath
    if (/MATCH\s+\(f:Function\)/i.test(pattern)) {
      const allFns = Array.from(functions.values());
      let filtered = allFns;
      const nameParam = params?.['name'] as string | undefined;
      if (nameParam !== undefined) {
        filtered = filtered.filter((fn) => fn.name === nameParam);
      }
      return filtered.map((fn) => ({
        'f.id': fn.id,
        'f.name': fn.name,
        'f.filePath': fn.filePath,
        'f.startLine': fn.startLine,
        'f.endLine': fn.endLine,
        'f.isAsync': fn.isAsync,
        'f.isExported': fn.isExported,
        'f.className': fn.className,
      }));
    }

    // Pattern: MATCH (c:Class) ...
    if (/MATCH\s+\(c:Class\)/i.test(pattern)) {
      let allClasses = Array.from(classes.values());

      // Filter by name if WHERE clause present
      const classNameMatch = pattern.match(/WHERE\s+c\.name\s*=\s*'([^']+)'/);
      if (classNameMatch) {
        allClasses = allClasses.filter((c) => c.name === classNameMatch[1]);
      }

      return allClasses.map((c) => ({
        'c.id': c.id,
        'c.name': c.name,
        'c.filePath': c.filePath,
        'c.startLine': c.startLine,
        'c.endLine': c.endLine,
        'c.isExported': c.isExported,
      }));
    }

    // Pattern: MATCH (f:File) RETURN f.path ...
    if (/MATCH\s+\(f:File\)\s+RETURN\s+f\.path/i.test(pattern)) {
      return Array.from(files.values()).map((f) => ({
        'f.path': f.path,
      }));
    }

    // Pattern: MATCH (n) RETURN count(n) AS total
    if (/count\(n\)/i.test(pattern)) {
      const total = functions.size + classes.size + files.size + modules.size;
      return [{ total }];
    }

    // Pattern: MATCH (a:Function)-[:CALLS]->(b:Function) RETURN a.name, b.name
    if (/CALLS/i.test(pattern) && /a:Function.*b:Function/i.test(pattern)) {
      return callEdges.map((edge) => {
        const a = functions.get(edge.callerId);
        const b = functions.get(edge.calleeId);
        return {
          'a.name': a?.name ?? '',
          'b.name': b?.name ?? '',
          'a.filePath': a?.filePath ?? '',
          'b.filePath': b?.filePath ?? '',
        };
      });
    }

    // Pattern: MATCH (f:File)-[:CONTAINS]->(fn:Function) WHERE f.path = '...' RETURN fn.name
    if (/CONTAINS.*fn:Function/i.test(pattern) && !(/CONTAINS_CLASS/i.test(pattern))) {
      let filtered = containsEdges;
      const pathMatch = pattern.match(/f\.path\s*=\s*'([^']+)'/);
      if (pathMatch) {
        filtered = filtered.filter((e) => e.filePath === pathMatch[1]);
      }
      return filtered
        .map((edge) => {
          const fn = functions.get(edge.functionId);
          if (!fn) return null;
          return {
            'fn.name': fn.name,
            'fn.id': fn.id,
            'fn.filePath': fn.filePath,
            'f.path': edge.filePath,
          };
        })
        .filter(Boolean) as unknown[];
    }

    // Pattern: MATCH (f:File)-[:CONTAINS_CLASS]->(c:Class) RETURN f.path, c.name
    if (/CONTAINS_CLASS/i.test(pattern)) {
      return containsClassEdges.map((edge) => {
        const c = classes.get(edge.classId);
        return {
          'f.path': edge.filePath,
          'c.name': c?.name ?? '',
        };
      });
    }

    // Pattern: MATCH (c:Class)-[:HAS_METHOD]->(fn:Function) WHERE c.name = '...' RETURN fn.name
    if (/HAS_METHOD/i.test(pattern)) {
      let filtered = hasMethodEdges;
      const classNameMatch = pattern.match(/c\.name\s*=\s*'([^']+)'/);
      if (classNameMatch) {
        const targetClassIds = Array.from(classes.values())
          .filter((c) => c.name === classNameMatch[1])
          .map((c) => c.id);
        filtered = filtered.filter((e) => targetClassIds.includes(e.classId));
      }
      return filtered
        .map((edge) => {
          const fn = functions.get(edge.functionId);
          if (!fn) return null;
          return {
            'fn.name': fn.name,
            'fn.id': fn.id,
          };
        })
        .filter(Boolean) as unknown[];
    }

    // Pattern: MATCH (f:File)-[r:IMPORTS]->(m:Module) ...
    if (/IMPORTS/i.test(pattern)) {
      let filtered = importEdges;
      const moduleNameMatch = pattern.match(/m\.name\s*=\s*'([^'\\]*(?:\\.[^'\\]*)*)'/);
      if (moduleNameMatch) {
        const modName = moduleNameMatch[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\');
        filtered = filtered.filter((e) => e.moduleName === modName);
      }
      return filtered.map((edge) => ({
        'f.path': edge.filePath,
        'm.name': edge.moduleName,
        'r.line': edge.line,
        'r.specifiers': edge.specifiers,
      }));
    }

    // Pattern: MATCH (m:Module) RETURN m.name
    if (/MATCH\s+\(m:Module\)/i.test(pattern)) {
      let allModules = Array.from(modules.values());
      const nameMatch = pattern.match(/m\.name\s*=\s*'([^'\\]*(?:\\.[^'\\]*)*)'/);
      if (nameMatch) {
        const modName = nameMatch[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\');
        allModules = allModules.filter((m) => m.name === modName);
      }
      return allModules.map((m) => ({
        'm.name': m.name,
      }));
    }

    // Fallback: return empty
    return [];
  }

  // ── getCallEdgesFrom ──

  function getCallEdgesFrom(functionName: string): CallEdgeInfo[] {
    return callEdgesByCallerName.get(functionName) ?? [];
  }

  // ── close ──

  async function close(): Promise<void> {
    // No-op for in-memory store
  }

  return {
    buildGraph,
    getFunction,
    getCallers,
    getCallees,
    getCallEdgesFrom,
    getImportsOf,
    query: queryFn,
    getAllFunctions,
    close,
  };
}
