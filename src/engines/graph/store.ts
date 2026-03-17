import kuzu from 'kuzu';
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

export interface GraphImport {
  source: string;
  filePath: string;
  line: number;
  specifiers: string[];
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

  /** Get all files that import a given module path. */
  getImportsOf(modulePath: string): Promise<GraphImport[]>;

  /** Execute a raw Cypher query. */
  query(cypher: string, params?: Record<string, unknown>): Promise<unknown[]>;

  /** Close the database and release resources. */
  close(): Promise<void>;
}

// ── Helpers ──

function functionId(fn: FunctionNode): string {
  if (fn.className) {
    return `${fn.filePath}::${fn.className}.${fn.name}`;
  }
  return `${fn.filePath}::${fn.name}`;
}

function classId(cls: ClassNode): string {
  return `${cls.filePath}::${cls.name}`;
}

/** Normalise a QueryResult (which may be a single result or array) into a single result. */
function unwrapResult(result: kuzu.QueryResult | kuzu.QueryResult[]): kuzu.QueryResult {
  if (Array.isArray(result)) {
    return result[0];
  }
  return result;
}

// ── Schema creation ──

const SCHEMA_STATEMENTS = [
  // Node tables
  `CREATE NODE TABLE IF NOT EXISTS Function(
    id STRING,
    name STRING,
    filePath STRING,
    startLine INT64,
    endLine INT64,
    isAsync BOOLEAN,
    isExported BOOLEAN,
    className STRING,
    PRIMARY KEY(id)
  )`,
  `CREATE NODE TABLE IF NOT EXISTS Class(
    id STRING,
    name STRING,
    filePath STRING,
    startLine INT64,
    endLine INT64,
    isExported BOOLEAN,
    PRIMARY KEY(id)
  )`,
  `CREATE NODE TABLE IF NOT EXISTS File(
    path STRING,
    language STRING,
    PRIMARY KEY(path)
  )`,
  `CREATE NODE TABLE IF NOT EXISTS Module(
    name STRING,
    PRIMARY KEY(name)
  )`,
  // Relationship tables
  `CREATE REL TABLE IF NOT EXISTS CALLS(FROM Function TO Function)`,
  `CREATE REL TABLE IF NOT EXISTS CONTAINS(FROM File TO Function)`,
  `CREATE REL TABLE IF NOT EXISTS CONTAINS_CLASS(FROM File TO Class)`,
  `CREATE REL TABLE IF NOT EXISTS HAS_METHOD(FROM Class TO Function)`,
  `CREATE REL TABLE IF NOT EXISTS IMPORTS(FROM File TO Module, line INT64, specifiers STRING)`,
];

// ── Implementation ──

export async function createGraphStore(dbPath: string): Promise<GraphStore> {
  const db = new kuzu.Database(dbPath);
  const conn = new kuzu.Connection(db);

  // Ensure schema exists
  for (const stmt of SCHEMA_STATEMENTS) {
    await conn.query(stmt);
  }

  // Pre-prepare reusable statements
  const insertFunctionStmt = await conn.prepare(
    'CREATE (:Function {id: $id, name: $name, filePath: $filePath, startLine: $startLine, endLine: $endLine, isAsync: $isAsync, isExported: $isExported, className: $className})',
  );
  const insertClassStmt = await conn.prepare(
    'CREATE (:Class {id: $id, name: $name, filePath: $filePath, startLine: $startLine, endLine: $endLine, isExported: $isExported})',
  );
  const insertFileStmt = await conn.prepare(
    'CREATE (:File {path: $path, language: $language})',
  );

  const insertContainsStmt = await conn.prepare(
    'MATCH (f:File), (fn:Function) WHERE f.path = $filePath AND fn.id = $fnId CREATE (f)-[:CONTAINS]->(fn)',
  );
  const insertContainsClassStmt = await conn.prepare(
    'MATCH (f:File), (c:Class) WHERE f.path = $filePath AND c.id = $classId CREATE (f)-[:CONTAINS_CLASS]->(c)',
  );
  const insertHasMethodStmt = await conn.prepare(
    'MATCH (c:Class), (fn:Function) WHERE c.id = $classId AND fn.id = $fnId CREATE (c)-[:HAS_METHOD]->(fn)',
  );
  const insertCallsStmt = await conn.prepare(
    'MATCH (a:Function), (b:Function) WHERE a.id = $callerId AND b.id = $calleeId CREATE (a)-[:CALLS]->(b)',
  );

  // ── buildGraph ──

  async function buildGraph(parsedFiles: ParsedFile[]): Promise<void> {
    // Collect all function IDs for call-site resolution
    const functionIndex = new Map<string, string>(); // name -> id (first match)
    // For methods with receivers: "receiver.method" -> id
    const methodIndex = new Map<string, string>();

    // Pass 1: Insert nodes
    for (const file of parsedFiles) {
      // Insert File node
      await conn.execute(insertFileStmt, {
        path: file.filePath,
        language: file.language,
      });

      // Insert Function nodes
      for (const fn of file.functions) {
        const id = functionId(fn);
        await conn.execute(insertFunctionStmt, {
          id,
          name: fn.name,
          filePath: fn.filePath,
          startLine: fn.startLine,
          endLine: fn.endLine,
          isAsync: fn.isAsync,
          isExported: fn.isExported,
          className: fn.className ?? '',
        });

        // Index for call resolution
        if (!functionIndex.has(fn.name)) {
          functionIndex.set(fn.name, id);
        }

        // Index methods by className.methodName
        if (fn.className) {
          const qualifiedName = `${fn.className}.${fn.name}`;
          if (!methodIndex.has(qualifiedName)) {
            methodIndex.set(qualifiedName, id);
          }
        }

        // Create CONTAINS edge (File -> Function)
        await conn.execute(insertContainsStmt, {
          filePath: file.filePath,
          fnId: id,
        });
      }

      // Insert Class nodes
      for (const cls of file.classes) {
        const id = classId(cls);
        await conn.execute(insertClassStmt, {
          id,
          name: cls.name,
          filePath: cls.filePath,
          startLine: cls.startLine,
          endLine: cls.endLine,
          isExported: cls.isExported,
        });

        // Create CONTAINS_CLASS edge (File -> Class)
        await conn.execute(insertContainsClassStmt, {
          filePath: file.filePath,
          classId: id,
        });

        // Create HAS_METHOD edges (Class -> Function)
        for (const methodName of cls.methods) {
          const methodFnId = `${cls.filePath}::${cls.name}.${methodName}`;
          await conn.execute(insertHasMethodStmt, {
            classId: id,
            fnId: methodFnId,
          });
        }
      }

      // Insert Module nodes and IMPORTS edges
      for (const imp of file.imports) {
        // MERGE Module node (idempotent)
        await conn.query(`MERGE (:Module {name: '${escapeCypher(imp.source)}'})`);

        // Create IMPORTS edge with metadata
        const importStmt = await conn.prepare(
          'MATCH (f:File), (m:Module) WHERE f.path = $filePath AND m.name = $moduleName CREATE (f)-[:IMPORTS {line: $line, specifiers: $specifiers}]->(m)',
        );
        await conn.execute(importStmt, {
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
        const callerFn = file.functions.find((fn) => {
          if (fn.className) {
            return fn.name === call.callerName;
          }
          return fn.name === call.callerName;
        });
        if (!callerFn) continue;
        const callerId = functionId(callerFn);

        // Find the callee function ID
        let calleeId: string | undefined;

        if (call.receiver) {
          // Method call: try receiver.calleeName
          const qualifiedName = `${call.receiver}.${call.calleeName}`;
          calleeId = methodIndex.get(qualifiedName);
        }

        // Fallback to plain name lookup
        if (!calleeId) {
          calleeId = functionIndex.get(call.calleeName);
        }

        if (!calleeId) continue; // External or unresolved call

        await conn.execute(insertCallsStmt, {
          callerId,
          calleeId,
        });
      }
    }
  }

  // ── getFunction ──

  async function getFunction(name: string): Promise<GraphFunction | null> {
    const stmt = await conn.prepare(
      'MATCH (f:Function) WHERE f.name = $name RETURN f.id, f.name, f.filePath, f.startLine, f.endLine, f.isAsync, f.isExported, f.className LIMIT 1',
    );
    const result = unwrapResult(await conn.execute(stmt, { name }));
    const rows = await result.getAll();
    if (rows.length === 0) return null;

    const row = rows[0];
    return {
      id: row['f.id'] as string,
      name: row['f.name'] as string,
      filePath: row['f.filePath'] as string,
      startLine: row['f.startLine'] as number,
      endLine: row['f.endLine'] as number,
      isAsync: row['f.isAsync'] as boolean,
      isExported: row['f.isExported'] as boolean,
      className: row['f.className'] as string,
    };
  }

  // ── getCallers ──

  async function getCallers(
    functionName: string,
    depth: number = 1,
  ): Promise<GraphFunction[]> {
    const stmt = await conn.prepare(
      `MATCH (caller:Function)-[:CALLS*1..${depth}]->(target:Function) WHERE target.name = $name RETURN DISTINCT caller.id, caller.name, caller.filePath, caller.startLine, caller.endLine, caller.isAsync, caller.isExported, caller.className`,
    );
    const result = unwrapResult(await conn.execute(stmt, { name: functionName }));
    const rows = await result.getAll();

    return rows.map((row) => ({
      id: row['caller.id'] as string,
      name: row['caller.name'] as string,
      filePath: row['caller.filePath'] as string,
      startLine: row['caller.startLine'] as number,
      endLine: row['caller.endLine'] as number,
      isAsync: row['caller.isAsync'] as boolean,
      isExported: row['caller.isExported'] as boolean,
      className: row['caller.className'] as string,
    }));
  }

  // ── getCallees ──

  async function getCallees(
    functionName: string,
    depth: number = 1,
  ): Promise<GraphFunction[]> {
    const stmt = await conn.prepare(
      `MATCH (target:Function)-[:CALLS*1..${depth}]->(callee:Function) WHERE target.name = $name RETURN DISTINCT callee.id, callee.name, callee.filePath, callee.startLine, callee.endLine, callee.isAsync, callee.isExported, callee.className`,
    );
    const result = unwrapResult(await conn.execute(stmt, { name: functionName }));
    const rows = await result.getAll();

    return rows.map((row) => ({
      id: row['callee.id'] as string,
      name: row['callee.name'] as string,
      filePath: row['callee.filePath'] as string,
      startLine: row['callee.startLine'] as number,
      endLine: row['callee.endLine'] as number,
      isAsync: row['callee.isAsync'] as boolean,
      isExported: row['callee.isExported'] as boolean,
      className: row['callee.className'] as string,
    }));
  }

  // ── getImportsOf ──

  async function getImportsOf(modulePath: string): Promise<GraphImport[]> {
    const stmt = await conn.prepare(
      'MATCH (f:File)-[r:IMPORTS]->(m:Module) WHERE m.name = $name RETURN f.path, r.line, r.specifiers, m.name',
    );
    const result = unwrapResult(await conn.execute(stmt, { name: modulePath }));
    const rows = await result.getAll();

    return rows.map((row) => ({
      source: row['m.name'] as string,
      filePath: row['f.path'] as string,
      line: row['r.line'] as number,
      specifiers: (row['r.specifiers'] as string).split(',').filter(Boolean),
    }));
  }

  // ── query (raw Cypher) ──

  async function rawQuery(
    cypher: string,
    params?: Record<string, unknown>,
  ): Promise<unknown[]> {
    let result: kuzu.QueryResult | kuzu.QueryResult[];
    if (params && Object.keys(params).length > 0) {
      const stmt = await conn.prepare(cypher);
      result = await conn.execute(stmt, params as Record<string, kuzu.KuzuValue>);
    } else {
      result = await conn.query(cypher);
    }
    const qr = unwrapResult(result);
    return await qr.getAll();
  }

  // ── close ──

  async function close(): Promise<void> {
    await conn.close();
    await db.close();
  }

  return {
    buildGraph,
    getFunction,
    getCallers,
    getCallees,
    getImportsOf,
    query: rawQuery,
    close,
  };
}

// ── Internal helpers ──

function escapeCypher(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
