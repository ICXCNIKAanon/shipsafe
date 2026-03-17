import Parser from 'web-tree-sitter';
import { createRequire } from 'node:module';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import type {
  SupportedLanguage,
  ParsedFile,
  FunctionNode,
  ClassNode,
  ImportNode,
  ExportNode,
  CallSite,
} from '../../types.js';

const require = createRequire(import.meta.url);

// ── Module state ──

let parserInstance: Parser | null = null;
const languageCache = new Map<string, Parser.Language>();

// ── Public API ──

/** Initialize tree-sitter. Must be called once before parsing. */
export async function initParser(): Promise<void> {
  await Parser.init();
  parserInstance = new Parser();
}

/** Detect language from file extension. Returns null for unsupported files. */
export function detectLanguage(filePath: string): SupportedLanguage | null {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.ts':
    case '.tsx':
      return 'typescript';
    case '.js':
    case '.jsx':
    case '.mjs':
    case '.cjs':
      return 'javascript';
    case '.py':
      return 'python';
    default:
      return null;
  }
}

/** Parse a single file and extract structural nodes. */
export async function parseFile(filePath: string, content: string): Promise<ParsedFile> {
  if (!parserInstance) {
    throw new Error('Parser not initialized. Call initParser() first.');
  }

  const language = detectLanguage(filePath);
  if (!language) {
    throw new Error(`Unsupported file type: ${filePath}`);
  }

  const lang = await loadLanguage(language);
  parserInstance.setLanguage(lang);

  const tree = parserInstance.parse(content);
  const root = tree.rootNode;

  const result: ParsedFile = {
    filePath,
    language,
    functions: [],
    classes: [],
    imports: [],
    exports: [],
    callSites: [],
  };

  if (language === 'python') {
    extractPython(root, filePath, result);
  } else {
    extractTypeScriptOrJavaScript(root, filePath, result);
  }

  return result;
}

/** Parse all supported files in a directory. */
export async function parseProject(
  projectDir: string,
  options?: { include?: string[]; exclude?: string[] },
): Promise<ParsedFile[]> {
  if (!parserInstance) {
    throw new Error('Parser not initialized. Call initParser() first.');
  }

  const defaultExclude = ['node_modules', 'dist', '.git', 'coverage'];
  const excludePatterns = options?.exclude ?? [];
  const includePatterns = options?.include ?? [];

  const files = await collectFiles(projectDir, defaultExclude, excludePatterns, includePatterns);
  const results: ParsedFile[] = [];

  for (const file of files) {
    const lang = detectLanguage(file);
    if (!lang) continue;

    try {
      const content = await readFile(file, 'utf-8');
      const parsed = await parseFile(file, content);
      results.push(parsed);
    } catch {
      // Skip files that fail to parse (e.g. binary files with wrong extensions)
    }
  }

  return results;
}

// ── Language loading ──

async function loadLanguage(language: SupportedLanguage): Promise<Parser.Language> {
  // Map language to WASM filename
  const wasmName = getWasmName(language);
  const cached = languageCache.get(wasmName);
  if (cached) return cached;

  const wasmPath = require.resolve(`tree-sitter-wasms/out/${wasmName}`);
  const lang = await Parser.Language.load(wasmPath);
  languageCache.set(wasmName, lang);
  return lang;
}

function getWasmName(language: SupportedLanguage): string {
  switch (language) {
    case 'typescript':
      return 'tree-sitter-typescript.wasm';
    case 'javascript':
      return 'tree-sitter-javascript.wasm';
    case 'python':
      return 'tree-sitter-python.wasm';
  }
}

// ── File collection ──

async function collectFiles(
  dir: string,
  defaultExclude: string[],
  excludePatterns: string[],
  includePatterns: string[],
): Promise<string[]> {
  const results: string[] = [];
  await walkDir(dir, results, defaultExclude, excludePatterns, includePatterns, dir);
  return results;
}

async function walkDir(
  dir: string,
  results: string[],
  defaultExclude: string[],
  excludePatterns: string[],
  includePatterns: string[],
  rootDir: string,
): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry);

    // Check default exclusions by directory name
    if (defaultExclude.includes(entry)) continue;

    let stats;
    try {
      stats = await stat(fullPath);
    } catch {
      continue;
    }

    if (stats.isDirectory()) {
      await walkDir(fullPath, results, defaultExclude, excludePatterns, includePatterns, rootDir);
    } else if (stats.isFile()) {
      const lang = detectLanguage(fullPath);
      if (!lang) continue;

      const relativePath = path.relative(rootDir, fullPath);

      // Check exclude patterns (glob-like)
      if (excludePatterns.some((pat) => matchGlob(relativePath, pat))) continue;

      // Check include patterns (if specified, file must match at least one)
      if (includePatterns.length > 0) {
        if (!includePatterns.some((pat) => matchGlob(relativePath, pat))) continue;
      }

      results.push(fullPath);
    }
  }
}

/** Simple glob matcher supporting ** and * patterns. */
function matchGlob(filePath: string, pattern: string): boolean {
  // Convert glob pattern to regex
  // Handle **/ which should match zero or more path segments
  const regexStr = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*\//g, '(?:.*/)?')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*');
  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(filePath);
}

// ── TypeScript / JavaScript extraction ──

function extractTypeScriptOrJavaScript(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  extractTSImports(root, filePath, result);
  extractTSClassesAndMethods(root, filePath, result);
  extractTSFunctions(root, filePath, result);
  extractTSArrowFunctions(root, filePath, result);
  extractTSExports(root, filePath, result);
  extractTSCallSites(root, filePath, result);
}

function extractTSImports(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const importNodes = root.descendantsOfType('import_statement');
  for (const imp of importNodes) {
    const sourceNode = imp.childForFieldName('source');
    if (!sourceNode) continue;

    // Extract the string content (strip quotes)
    const source = extractStringContent(sourceNode);
    if (!source) continue;

    const specifiers: string[] = [];
    const importClause = imp.children.find((c) => c.type === 'import_clause');
    if (importClause) {
      const namedImports = importClause.descendantsOfType('import_specifier');
      for (const spec of namedImports) {
        const nameNode = spec.childForFieldName('name');
        if (nameNode) specifiers.push(nameNode.text);
      }
      // Handle default import
      const defaultIdent = importClause.children.find(
        (c) => c.type === 'identifier',
      );
      if (defaultIdent) specifiers.push(defaultIdent.text);
      // Handle namespace import: import * as foo from 'bar'
      const nsImport = importClause.descendantsOfType('namespace_import');
      if (nsImport.length > 0) {
        const alias = nsImport[0].children.find((c) => c.type === 'identifier');
        if (alias) specifiers.push(alias.text);
      }
    }

    result.imports.push({
      source,
      specifiers,
      filePath,
      line: imp.startPosition.row + 1,
    });
  }
}

function extractTSClassesAndMethods(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const classDeclNodes = root.descendantsOfType('class_declaration');
  for (const cls of classDeclNodes) {
    const nameNode = cls.childForFieldName('name');
    if (!nameNode) continue;

    const className = nameNode.text;
    const isExported = cls.parent?.type === 'export_statement';

    const bodyNode = cls.childForFieldName('body');
    const methodNames: string[] = [];

    if (bodyNode) {
      const methods = bodyNode.descendantsOfType('method_definition');
      for (const method of methods) {
        const methodNameNode = method.childForFieldName('name');
        if (!methodNameNode) continue;

        const methodName = methodNameNode.text;
        methodNames.push(methodName);

        // Check if method is async
        const isAsync = method.children.some((c) => c.type === 'async');

        // Extract parameters
        const params = extractTSParams(method);

        result.functions.push({
          name: methodName,
          filePath,
          startLine: method.startPosition.row + 1,
          endLine: method.endPosition.row + 1,
          params,
          isAsync,
          isExported,
          className,
        });
      }
    }

    result.classes.push({
      name: className,
      filePath,
      startLine: cls.startPosition.row + 1,
      endLine: cls.endPosition.row + 1,
      methods: methodNames,
      isExported,
    });
  }
}

function extractTSFunctions(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const funcNodes = root.descendantsOfType('function_declaration');
  for (const func of funcNodes) {
    const nameNode = func.childForFieldName('name');
    if (!nameNode) continue;

    const isExported = func.parent?.type === 'export_statement';
    const isAsync = func.children.some((c) => c.type === 'async');
    const params = extractTSParams(func);

    result.functions.push({
      name: nameNode.text,
      filePath,
      startLine: func.startPosition.row + 1,
      endLine: func.endPosition.row + 1,
      params,
      isAsync,
      isExported,
    });
  }
}

function extractTSArrowFunctions(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const arrowFns = root.descendantsOfType('arrow_function');
  for (const arrow of arrowFns) {
    // Only capture arrow functions assigned to named variables
    // The parent should be a variable_declarator
    const parent = arrow.parent;
    if (!parent || parent.type !== 'variable_declarator') continue;

    const nameNode = parent.childForFieldName('name');
    if (!nameNode || nameNode.type !== 'identifier') continue;

    // Check if exported: variable_declarator -> lexical_declaration -> export_statement
    const lexDecl = parent.parent;
    const isExported = lexDecl?.parent?.type === 'export_statement';

    const isAsync = arrow.children.some((c) => c.type === 'async');
    const params = extractTSParams(arrow);

    result.functions.push({
      name: nameNode.text,
      filePath,
      startLine: arrow.startPosition.row + 1,
      endLine: arrow.endPosition.row + 1,
      params,
      isAsync,
      isExported,
    });
  }
}

function extractTSExports(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const exportStatements = root.descendantsOfType('export_statement');
  for (const exp of exportStatements) {
    const declaration = exp.childForFieldName('declaration');
    if (!declaration) continue;

    let name: string | null = null;
    let exportType: ExportNode['type'] = 'variable';

    switch (declaration.type) {
      case 'function_declaration': {
        name = declaration.childForFieldName('name')?.text ?? null;
        exportType = 'function';
        break;
      }
      case 'class_declaration': {
        name = declaration.childForFieldName('name')?.text ?? null;
        exportType = 'class';
        break;
      }
      case 'lexical_declaration':
      case 'variable_declaration': {
        const declarator = declaration.descendantsOfType('variable_declarator')[0];
        name = declarator?.childForFieldName('name')?.text ?? null;
        exportType = 'variable';
        break;
      }
    }

    if (name) {
      result.exports.push({
        name,
        filePath,
        line: exp.startPosition.row + 1,
        type: exportType,
      });
    }
  }
}

function extractTSCallSites(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const callExprs = root.descendantsOfType('call_expression');
  for (const call of callExprs) {
    const funcNode = call.childForFieldName('function');
    if (!funcNode) continue;

    let calleeName: string;
    let receiver: string | undefined;

    if (funcNode.type === 'member_expression') {
      const objectNode = funcNode.childForFieldName('object');
      const propertyNode = funcNode.childForFieldName('property');
      calleeName = propertyNode?.text ?? funcNode.text;
      receiver = objectNode?.text;
    } else if (funcNode.type === 'identifier') {
      calleeName = funcNode.text;
    } else {
      // Skip complex expressions (e.g. IIFE, computed calls)
      continue;
    }

    // Find the enclosing function
    const callerName = findEnclosingFunctionName(call);
    if (!callerName) continue; // Skip top-level calls (no enclosing function)

    result.callSites.push({
      callerName,
      calleeName,
      filePath,
      line: call.startPosition.row + 1,
      receiver,
    });
  }
}

function extractTSParams(node: Parser.SyntaxNode): string[] {
  const paramsNode = node.childForFieldName('parameters');
  if (!paramsNode) return [];

  const params: string[] = [];
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    if (param.type === 'required_parameter' || param.type === 'optional_parameter') {
      const pattern = param.childForFieldName('pattern');
      if (pattern) params.push(pattern.text);
    } else if (param.type === 'identifier') {
      params.push(param.text);
    }
  }
  return params;
}

// ── Python extraction ──

function extractPython(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  extractPythonImports(root, filePath, result);
  extractPythonClassesAndMethods(root, filePath, result);
  extractPythonStandaloneFunctions(root, filePath, result);
  extractPythonCallSites(root, filePath, result);
}

function extractPythonImports(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  // from X import Y, Z
  const importFromNodes = root.descendantsOfType('import_from_statement');
  for (const imp of importFromNodes) {
    const moduleNode = imp.childForFieldName('module_name');
    if (!moduleNode) continue;

    const source = moduleNode.text;
    const nameNodes = imp.childrenForFieldName('name');
    const specifiers = nameNodes.map((n) => n.text);

    result.imports.push({
      source,
      specifiers,
      filePath,
      line: imp.startPosition.row + 1,
    });
  }

  // import X
  const importNodes = root.descendantsOfType('import_statement');
  for (const imp of importNodes) {
    // In Python, 'import_statement' is for bare `import X`
    // Skip import_from_statement which are already handled
    if (imp.type !== 'import_statement') continue;

    const nameNodes = imp.childrenForFieldName('name');
    for (const nameNode of nameNodes) {
      result.imports.push({
        source: nameNode.text,
        specifiers: [nameNode.text],
        filePath,
        line: imp.startPosition.row + 1,
      });
    }
  }
}

function extractPythonClassesAndMethods(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const classNodes = root.descendantsOfType('class_definition');
  for (const cls of classNodes) {
    const nameNode = cls.childForFieldName('name');
    if (!nameNode) continue;

    const className = nameNode.text;
    const bodyNode = cls.childForFieldName('body');
    const methodNames: string[] = [];

    if (bodyNode) {
      const funcDefs = bodyNode.descendantsOfType('function_definition');
      for (const fn of funcDefs) {
        const fnNameNode = fn.childForFieldName('name');
        if (!fnNameNode) continue;

        const fnName = fnNameNode.text;
        methodNames.push(fnName);

        const isAsync = fn.children.some((c) => c.type === 'async');
        const params = extractPythonParams(fn, true);

        result.functions.push({
          name: fnName,
          filePath,
          startLine: fn.startPosition.row + 1,
          endLine: fn.endPosition.row + 1,
          params,
          isAsync,
          isExported: false, // Python doesn't have explicit exports
          className,
        });
      }
    }

    result.classes.push({
      name: className,
      filePath,
      startLine: cls.startPosition.row + 1,
      endLine: cls.endPosition.row + 1,
      methods: methodNames,
      isExported: false,
    });
  }
}

function extractPythonStandaloneFunctions(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const funcNodes = root.descendantsOfType('function_definition');
  for (const fn of funcNodes) {
    // Skip methods (functions inside a class body)
    if (isInsidePythonClass(fn)) continue;

    const nameNode = fn.childForFieldName('name');
    if (!nameNode) continue;

    const isAsync = fn.children.some((c) => c.type === 'async');
    const params = extractPythonParams(fn, false);

    // Check if decorated
    const parentIsDecorated = fn.parent?.type === 'decorated_definition';
    const actualNode = parentIsDecorated ? fn.parent! : fn;

    result.functions.push({
      name: nameNode.text,
      filePath,
      startLine: actualNode.startPosition.row + 1,
      endLine: actualNode.endPosition.row + 1,
      params,
      isAsync,
      isExported: false,
    });
  }
}

function extractPythonCallSites(
  root: Parser.SyntaxNode,
  filePath: string,
  result: ParsedFile,
): void {
  const callNodes = root.descendantsOfType('call');
  for (const call of callNodes) {
    const funcNode = call.childForFieldName('function');
    if (!funcNode) continue;

    let calleeName: string;
    let receiver: string | undefined;

    if (funcNode.type === 'attribute') {
      const objectNode = funcNode.childForFieldName('object');
      const attrNode = funcNode.childForFieldName('attribute');
      calleeName = attrNode?.text ?? funcNode.text;
      receiver = objectNode?.text;
    } else if (funcNode.type === 'identifier') {
      calleeName = funcNode.text;
    } else {
      continue;
    }

    const callerName = findEnclosingPythonFunctionName(call);
    if (!callerName) continue;

    result.callSites.push({
      callerName,
      calleeName,
      filePath,
      line: call.startPosition.row + 1,
      receiver,
    });
  }
}

function extractPythonParams(node: Parser.SyntaxNode, isMethod: boolean): string[] {
  const paramsNode = node.childForFieldName('parameters');
  if (!paramsNode) return [];

  const params: string[] = [];
  for (let i = 0; i < paramsNode.namedChildCount; i++) {
    const param = paramsNode.namedChild(i);
    if (!param) continue;

    const name = param.type === 'identifier'
      ? param.text
      : param.type === 'typed_parameter'
        ? param.childForFieldName('name')?.text ?? param.children[0]?.text ?? null
        : param.type === 'default_parameter'
          ? param.childForFieldName('name')?.text ?? param.children[0]?.text ?? null
          : null;

    if (!name) continue;
    // Skip 'self' and 'cls' for methods
    if (isMethod && (name === 'self' || name === 'cls')) continue;
    params.push(name);
  }
  return params;
}

// ── Shared helpers ──

function isInsidePythonClass(node: Parser.SyntaxNode): boolean {
  let current = node.parent;
  while (current) {
    if (current.type === 'class_definition') return true;
    current = current.parent;
  }
  return false;
}

function findEnclosingFunctionName(node: Parser.SyntaxNode): string | null {
  let current = node.parent;
  while (current) {
    switch (current.type) {
      case 'function_declaration': {
        return current.childForFieldName('name')?.text ?? null;
      }
      case 'method_definition': {
        return current.childForFieldName('name')?.text ?? null;
      }
      case 'arrow_function': {
        // Check if assigned to a variable
        const parent = current.parent;
        if (parent?.type === 'variable_declarator') {
          const nameNode = parent.childForFieldName('name');
          if (nameNode?.type === 'identifier') return nameNode.text;
        }
        break;
      }
    }
    current = current.parent;
  }
  return null;
}

function findEnclosingPythonFunctionName(node: Parser.SyntaxNode): string | null {
  let current = node.parent;
  while (current) {
    if (current.type === 'function_definition') {
      return current.childForFieldName('name')?.text ?? null;
    }
    current = current.parent;
  }
  return null;
}

function extractStringContent(node: Parser.SyntaxNode): string | null {
  // The string node contains: quote, string_fragment, quote
  const fragment = node.descendantsOfType('string_fragment');
  if (fragment.length > 0) return fragment[0].text;

  // Fallback: strip surrounding quotes
  const text = node.text;
  if ((text.startsWith("'") && text.endsWith("'")) || (text.startsWith('"') && text.endsWith('"'))) {
    return text.slice(1, -1);
  }
  return null;
}
