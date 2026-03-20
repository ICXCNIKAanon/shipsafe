/**
 * AST Context Analysis for ShipSafe Pattern Scanner
 *
 * Uses tree-sitter to provide structural context about flagged lines,
 * enabling the pattern scanner to suppress false positives by understanding
 * code structure (function calls, tagged templates, variable assignments, etc.).
 *
 * This module is intentionally lightweight — it answers "is this value sanitized?"
 * and "is this a safe pattern?" without full semantic analysis.
 */

import Parser from 'web-tree-sitter';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// ── Module state ──

let parserInstance: Parser | null = null;
let initPromise: Promise<void> | null = null;
const languageCache = new Map<string, Parser.Language>();

// ── Types ──

export interface AstContext {
  /** Is this line inside a call to a function with the given name? */
  isInsideFunctionCall(name: string): boolean;
  /** What function is being called on this line? Returns the callee name or null. */
  getCallExpression(): string | null;
  /** If this expression is an argument to a function, returns the function name. Otherwise null. */
  getArgumentOf(): string | null;
  /** Is the flagged expression wrapped by a function whose name matches? (e.g., sanitize, purify) */
  isWrappedBy(functionNamePattern: RegExp): boolean;
  /** What was a variable assigned from? Returns the RHS text or null. */
  getVariableAssignment(varName: string): string | null;
  /** Is this a tagged template literal? (e.g., sql`...`, html`...`) */
  isTaggedTemplate(): boolean;
  /** Get the tag name of a tagged template literal, or null. */
  getTaggedTemplateName(): string | null;
  /** What's the parent AST node type? */
  getParentExpression(): string | null;
  /** Get the receiver of a method call (e.g., "redis" for redis.eval()). */
  getMethodCallReceiver(methodName: string): string | null;
  /** Is the argument at this position a string literal? */
  isArgumentStringLiteral(): boolean;
  /** Get the full text of the smallest node at the target line. */
  getNodeTextAtLine(): string | null;
}

export type AstFileType = 'typescript' | 'tsx' | 'javascript' | 'python';

// ── Initialization ──

async function ensureParser(): Promise<Parser> {
  if (parserInstance) return parserInstance;

  if (!initPromise) {
    initPromise = (async () => {
      await Parser.init();
      parserInstance = new Parser();
    })();
  }

  await initPromise;
  return parserInstance!;
}

async function loadLanguage(language: AstFileType): Promise<Parser.Language> {
  const wasmName = getWasmName(language);
  const cached = languageCache.get(wasmName);
  if (cached) return cached;

  const wasmPath = require.resolve(`tree-sitter-wasms/out/${wasmName}`);
  const lang = await Parser.Language.load(wasmPath);
  languageCache.set(wasmName, lang);
  return lang;
}

function getWasmName(language: AstFileType): string {
  switch (language) {
    case 'typescript':
      return 'tree-sitter-typescript.wasm';
    case 'tsx':
      return 'tree-sitter-tsx.wasm';
    case 'javascript':
      return 'tree-sitter-javascript.wasm';
    case 'python':
      return 'tree-sitter-python.wasm';
  }
}

// ── File type detection ──

export function detectAstFileType(filePath: string): AstFileType | null {
  const ext = filePath.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'ts':
      return 'typescript';
    case 'tsx':
      return 'tsx';
    case 'js':
    case 'jsx':
    case 'mjs':
    case 'cjs':
      return 'javascript';
    case 'py':
      return 'python';
    default:
      return null;
  }
}

// ── Parsed tree cache ──

interface CachedTree {
  tree: Parser.Tree;
  content: string;
}

const treeCache = new Map<string, CachedTree>();

/** Clear the AST cache (call between scan batches if needed). */
export function clearAstCache(): void {
  treeCache.clear();
}

// ── Core: parse file and build context ──

/**
 * Parse a file with tree-sitter and return an AstContext for the given line.
 * Returns null if the file type is unsupported or parsing fails.
 *
 * The parsed tree is cached per file content, so multiple calls for different
 * lines in the same file only parse once.
 */
export async function getAstContext(
  fileContent: string,
  lineNumber: number,
  filePath: string,
): Promise<AstContext | null> {
  const fileType = detectAstFileType(filePath);
  if (!fileType) return null;

  let tree: Parser.Tree;

  try {
    const cached = treeCache.get(filePath);
    if (cached && cached.content === fileContent) {
      tree = cached.tree;
    } else {
      const parser = await ensureParser();
      const lang = await loadLanguage(fileType);
      parser.setLanguage(lang);
      tree = parser.parse(fileContent);
      treeCache.set(filePath, { tree, content: fileContent });
    }
  } catch {
    return null;
  }

  const root = tree.rootNode;
  // tree-sitter uses 0-based rows
  const targetRow = lineNumber - 1;

  return buildContext(root, targetRow, fileContent);
}

// ── Context builder ──

function buildContext(
  root: Parser.SyntaxNode,
  targetRow: number,
  fileContent: string,
): AstContext {
  // Find the smallest named node that covers the target line
  const targetNode = findSmallestNodeAtRow(root, targetRow);

  return {
    isInsideFunctionCall(name: string): boolean {
      if (!targetNode) return false;
      let current: Parser.SyntaxNode | null = targetNode;
      while (current) {
        if (current.type === 'call_expression') {
          const funcNode = current.childForFieldName('function');
          if (funcNode && funcNode.text === name) return true;
          // Also check member expressions like obj.func()
          if (funcNode?.type === 'member_expression') {
            const prop = funcNode.childForFieldName('property');
            if (prop && prop.text === name) return true;
          }
        }
        // Python call nodes
        if (current.type === 'call') {
          const funcNode = current.childForFieldName('function');
          if (funcNode && funcNode.text === name) return true;
          if (funcNode?.type === 'attribute') {
            const attr = funcNode.childForFieldName('attribute');
            if (attr && attr.text === name) return true;
          }
        }
        current = current.parent;
      }
      return false;
    },

    getCallExpression(): string | null {
      if (!targetNode) return null;
      // Find the nearest call_expression on or containing the target line
      const callNode = findAncestorOrSelfOfType(targetNode, ['call_expression', 'call']);
      if (!callNode) {
        // Also check if a call_expression starts on this line
        const calls = findNodesOfTypeAtRow(root, ['call_expression', 'call'], targetRow);
        if (calls.length > 0) {
          const funcNode = calls[0].childForFieldName('function');
          return funcNode ? extractCalleeName(funcNode) : null;
        }
        return null;
      }
      const funcNode = callNode.childForFieldName('function');
      return funcNode ? extractCalleeName(funcNode) : null;
    },

    getArgumentOf(): string | null {
      if (!targetNode) return null;
      let current: Parser.SyntaxNode | null = targetNode;
      while (current) {
        const parent: Parser.SyntaxNode | null = current.parent;
        if (!parent) break;

        // Check if parent is an argument list (arguments node in JS/TS)
        if (parent.type === 'arguments' || parent.type === 'argument_list') {
          const callNode = parent.parent;
          if (callNode && (callNode.type === 'call_expression' || callNode.type === 'call')) {
            const funcNode = callNode.childForFieldName('function');
            return funcNode ? extractCalleeName(funcNode) : null;
          }
        }
        current = parent;
      }
      return null;
    },

    isWrappedBy(functionNamePattern: RegExp): boolean {
      // Strategy 1: Walk up from the smallest node at the target line
      if (targetNode) {
        let current: Parser.SyntaxNode | null = targetNode;
        while (current) {
          if (current.type === 'call_expression' || current.type === 'call') {
            const funcNode = current.childForFieldName('function');
            if (funcNode) {
              const callee = extractCalleeName(funcNode);
              if (callee && functionNamePattern.test(callee)) return true;
            }
          }
          current = current.parent;
        }
      }
      // Strategy 2: Search for any call_expression on this line that matches
      // This catches cases where the smallest node is a leaf that isn't inside the call
      const calls = findNodesOfTypeAtRow(root, ['call_expression', 'call'], targetRow);
      for (const call of calls) {
        const funcNode = call.childForFieldName('function');
        if (funcNode) {
          const callee = extractCalleeName(funcNode);
          if (callee && functionNamePattern.test(callee)) return true;
        }
      }
      return false;
    },

    getVariableAssignment(varName: string): string | null {
      // Search the file for `const/let/var varName = <something>`
      const nodes = root.descendantsOfType('variable_declarator');
      for (const decl of nodes) {
        const nameNode = decl.childForFieldName('name');
        if (nameNode && nameNode.text === varName) {
          const valueNode = decl.childForFieldName('value');
          return valueNode ? valueNode.text : null;
        }
      }
      // Python assignment
      const assignments = root.descendantsOfType('assignment');
      for (const assign of assignments) {
        const left = assign.childForFieldName('left');
        if (left && left.text === varName) {
          const right = assign.childForFieldName('right');
          return right ? right.text : null;
        }
      }
      return null;
    },

    isTaggedTemplate(): boolean {
      if (!targetNode) return false;
      // Look for template strings on this line that are tagged
      const templates = findNodesOfTypeAtRow(root, ['call_expression'], targetRow);
      for (const tmpl of templates) {
        // In tree-sitter, tagged templates appear as call_expression with template_string
        const funcNode = tmpl.childForFieldName('function');
        const args = tmpl.childForFieldName('arguments');
        if (funcNode && args?.type === 'template_string') return true;
      }

      // Direct check: find template_string nodes on this row
      const templateStrings = findNodesOfTypeAtRow(root, ['template_string'], targetRow);
      for (const ts of templateStrings) {
        const parent = ts.parent;
        // Tagged template: parent is call_expression and template_string is not inside arguments
        if (parent?.type === 'call_expression') {
          const funcNode = parent.childForFieldName('function');
          // If the template_string is the "arguments" portion (tagged template syntax)
          if (funcNode && ts !== funcNode) return true;
        }
      }

      return false;
    },

    getTaggedTemplateName(): string | null {
      if (!targetNode) return null;
      // Find template_string nodes on this row
      const templateStrings = findNodesOfTypeAtRow(root, ['template_string'], targetRow);
      for (const ts of templateStrings) {
        const parent = ts.parent;
        if (parent?.type === 'call_expression') {
          const funcNode = parent.childForFieldName('function');
          if (funcNode && ts !== funcNode) {
            return extractCalleeName(funcNode);
          }
        }
      }
      return null;
    },

    getParentExpression(): string | null {
      if (!targetNode) return null;
      return targetNode.parent?.type ?? null;
    },

    getMethodCallReceiver(methodName: string): string | null {
      if (!targetNode) return null;
      // Find call expressions on this line
      const calls = findNodesOfTypeAtRow(root, ['call_expression', 'call'], targetRow);
      for (const call of calls) {
        const funcNode = call.childForFieldName('function');
        if (!funcNode) continue;

        // JS/TS: member_expression
        if (funcNode.type === 'member_expression') {
          const prop = funcNode.childForFieldName('property');
          if (prop && prop.text === methodName) {
            const obj = funcNode.childForFieldName('object');
            return obj ? obj.text : null;
          }
        }
        // Python: attribute
        if (funcNode.type === 'attribute') {
          const attr = funcNode.childForFieldName('attribute');
          if (attr && attr.text === methodName) {
            const obj = funcNode.childForFieldName('object');
            return obj ? obj.text : null;
          }
        }
      }
      return null;
    },

    isArgumentStringLiteral(): boolean {
      if (!targetNode) return false;
      // Check if we're inside a call_expression and the first argument is a string
      const callNode = findAncestorOrSelfOfType(targetNode, ['call_expression', 'call']);
      if (!callNode) return false;

      const args = callNode.childForFieldName('arguments');
      if (!args) return false;

      const firstArg = args.namedChild(0);
      if (!firstArg) return false;

      return firstArg.type === 'string' || firstArg.type === 'template_string';
    },

    getNodeTextAtLine(): string | null {
      return targetNode?.text ?? null;
    },
  };
}

// ── Helper functions ──

/**
 * Find the smallest named node whose range covers the target row.
 */
function findSmallestNodeAtRow(
  root: Parser.SyntaxNode,
  targetRow: number,
): Parser.SyntaxNode | null {
  let best: Parser.SyntaxNode | null = null;

  function visit(node: Parser.SyntaxNode): void {
    if (node.startPosition.row > targetRow || node.endPosition.row < targetRow) {
      return; // Node doesn't cover target row
    }

    // This node covers the target row. Is it smaller than our current best?
    if (!best || nodeSize(node) < nodeSize(best)) {
      best = node;
    }

    // Check children for a tighter fit
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) visit(child);
    }
  }

  visit(root);
  return best;
}

function nodeSize(node: Parser.SyntaxNode): number {
  return node.endIndex - node.startIndex;
}

/**
 * Find all nodes of the specified types that start on the target row.
 */
function findNodesOfTypeAtRow(
  root: Parser.SyntaxNode,
  types: string[],
  targetRow: number,
): Parser.SyntaxNode[] {
  const results: Parser.SyntaxNode[] = [];

  function visit(node: Parser.SyntaxNode): void {
    // Skip nodes that end before or start after our target row
    if (node.endPosition.row < targetRow || node.startPosition.row > targetRow) {
      return;
    }

    if (types.includes(node.type) && node.startPosition.row <= targetRow && node.endPosition.row >= targetRow) {
      results.push(node);
    }

    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) visit(child);
    }
  }

  visit(root);
  return results;
}

/**
 * Walk up from a node to find the nearest ancestor (or self) of the given type(s).
 */
function findAncestorOrSelfOfType(
  node: Parser.SyntaxNode,
  types: string[],
): Parser.SyntaxNode | null {
  let current: Parser.SyntaxNode | null = node;
  while (current) {
    if (types.includes(current.type)) return current;
    current = current.parent;
  }
  return null;
}

/**
 * Extract the callee name from a function node (identifier or member expression).
 */
function extractCalleeName(funcNode: Parser.SyntaxNode): string | null {
  if (funcNode.type === 'identifier') {
    return funcNode.text;
  }
  if (funcNode.type === 'member_expression') {
    const prop = funcNode.childForFieldName('property');
    return prop ? prop.text : funcNode.text;
  }
  // Python attribute access
  if (funcNode.type === 'attribute') {
    const attr = funcNode.childForFieldName('attribute');
    return attr ? attr.text : funcNode.text;
  }
  return funcNode.text;
}
