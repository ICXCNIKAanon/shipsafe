import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type { Finding } from '../types.js';

export interface SqlFixResult {
  fixed: boolean;
  originalLine: string;
  fixedLine: string;
  params: string[];
  paramStyle: '?' | '$n';
}

export interface SqlFileFix {
  file: string;
  line: number;
  originalLine: string;
  fixedLine: string;
  params: string[];
  paramStyle: '?' | '$n';
  filesModified: string[];
}

/**
 * Detect the param style based on project dependencies.
 * If the project uses `pg` (node-postgres), use $1, $2 style.
 * Otherwise use ? style (mysql, sqlite, etc.).
 */
export function detectParamStyle(projectDeps?: string[]): '?' | '$n' {
  if (!projectDeps) return '?';
  const pgDeps = ['pg', 'pg-pool', 'pg-promise', 'postgres', 'pg-native', '@neondatabase/serverless'];
  for (const dep of pgDeps) {
    if (projectDeps.includes(dep)) return '$n';
  }
  return '?';
}

/**
 * Build a placeholder for the given index and style.
 */
function placeholder(index: number, style: '?' | '$n'): string {
  return style === '$n' ? `$${index}` : '?';
}

/**
 * Fix a SQL injection vulnerability in a single line of code.
 *
 * Handles:
 * - Pattern 1: String concatenation (query("SELECT ... " + variable))
 * - Pattern 2: Template literal (query(`SELECT ... ${variable}`))
 * - Pattern 3: Multiple interpolations in template literals
 * - Pattern 4: pg-style $1, $2 placeholders when pg is detected
 *
 * Returns null if the line does not match any fixable pattern.
 */
export function fixSqlInjection(line: string, projectDeps?: string[]): SqlFixResult | null {
  const style = detectParamStyle(projectDeps);

  // Try template literal fix first (more specific pattern)
  const templateResult = fixTemplateLiteral(line, style);
  if (templateResult) return templateResult;

  // Try string concatenation fix
  const concatResult = fixStringConcat(line, style);
  if (concatResult) return concatResult;

  return null;
}

/**
 * Fix template literal SQL injection.
 * Matches patterns like:
 *   db.query(`SELECT * FROM users WHERE id = ${userId}`)
 *   const sql = `SELECT * FROM users WHERE name = '${name}' AND age = ${age}`
 */
function fixTemplateLiteral(line: string, style: '?' | '$n'): SqlFixResult | null {
  // Match a template literal containing SQL keywords and at least one ${...} interpolation
  // The template literal can be preceded by a method call or a variable assignment
  const templateRegex = /`([^`]*\$\{[^`]*)`/;
  const match = line.match(templateRegex);
  if (!match) return null;

  const templateContent = match[1];

  // Verify this is actually SQL (contains SQL keywords)
  if (!/\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b/i.test(templateContent)) {
    return null;
  }

  // Extract all ${...} interpolations and build the parameterized SQL
  const interpolationRegex = /\$\{([^}]+)\}/g;
  const params: string[] = [];
  let paramIndex = 0;

  // Build the fixed SQL by manually replacing interpolations
  // (avoid String.replace with $n in replacement which acts as backreference)
  let fixedSql = '';
  let lastIndex = 0;
  let interpMatch: RegExpExecArray | null;
  while ((interpMatch = interpolationRegex.exec(templateContent)) !== null) {
    paramIndex++;
    params.push(interpMatch[1].trim());
    fixedSql += templateContent.substring(lastIndex, interpMatch.index);
    fixedSql += placeholder(paramIndex, style);
    lastIndex = interpMatch.index + interpMatch[0].length;
  }
  fixedSql += templateContent.substring(lastIndex);

  if (params.length === 0) return null;

  // Remove any surrounding single quotes around placeholders that were around interpolations
  // e.g., '?' should become just ? (the DB driver handles quoting)
  if (style === '?') {
    fixedSql = fixedSql.replace(/'(\?)'/g, '$1');
  } else {
    // For $n style, use a function replacement to avoid backreference issues
    fixedSql = fixedSql.replace(/'(\$\d+)'/g, (_m, p1) => p1);
  }

  // Replace the template literal with a regular string + params array
  // Use indexOf/substring instead of regex .replace to avoid $n backreference issues
  const backtickStart = line.indexOf('`');
  const backtickEnd = line.indexOf('`', backtickStart + 1);
  if (backtickStart === -1 || backtickEnd === -1) return null;

  const replacement = `"${fixedSql}", [${params.join(', ')}]`;
  const fixedLine = line.substring(0, backtickStart) + replacement + line.substring(backtickEnd + 1);

  return {
    fixed: true,
    originalLine: line,
    fixedLine,
    params,
    paramStyle: style,
  };
}

/**
 * Fix string concatenation SQL injection.
 * Matches patterns like:
 *   db.query("SELECT * FROM users WHERE id = " + userId)
 *   db.query("SELECT * FROM users WHERE id = " + userId + " AND name = " + name)
 */
function fixStringConcat(line: string, style: '?' | '$n'): SqlFixResult | null {
  // Match a string (single or double quote) followed by concatenation with +
  // The SQL string must contain SQL keywords
  const sqlStringWithConcatRegex = /(['"])((?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^'"]*)\1\s*\+/i;
  const match = line.match(sqlStringWithConcatRegex);
  if (!match) return null;

  const quote = match[1];
  const sqlStart = match[2];

  // Now parse the full concatenation chain from the position of the first SQL string
  // Find where the SQL string + concatenation starts in the line
  const sqlStringStart = line.indexOf(`${quote}${sqlStart}${quote}`);
  if (sqlStringStart === -1) return null;

  const concatPart = line.substring(sqlStringStart);

  // Parse the concatenation chain: "sql part" + var + "sql part" + var ...
  // We need to extract all string parts and variable parts
  const segments = parseConcatChain(concatPart, quote);
  if (!segments || segments.variables.length === 0) return null;

  // Build the parameterized query string
  let parameterizedSql = '';
  const params: string[] = [];

  for (let i = 0; i < segments.strings.length; i++) {
    parameterizedSql += segments.strings[i];
    if (i < segments.variables.length) {
      params.push(segments.variables[i]);
      parameterizedSql += placeholder(i + 1, style);
    }
  }

  // Clean up: remove trailing whitespace from SQL, remove surrounding quotes artifacts
  parameterizedSql = parameterizedSql.trim();

  // Remove any surrounding single quotes around placeholders
  parameterizedSql = parameterizedSql.replace(/'(\?|\$\d+)'/g, '$1');

  // Build the replacement: "parameterized sql", [params]
  const replacement = `"${parameterizedSql}", [${params.join(', ')}]`;

  // Replace the concatenation chain in the original line
  const fixedLine = line.substring(0, sqlStringStart) + replacement + segments.remainder;

  return {
    fixed: true,
    originalLine: line,
    fixedLine,
    params,
    paramStyle: style,
  };
}

interface ConcatSegments {
  strings: string[];
  variables: string[];
  remainder: string; // anything after the concat chain (e.g., closing paren)
}

/**
 * Parse a concatenation chain like: "SELECT ... " + var1 + " AND ..." + var2)
 * Returns the string parts and variable parts separately.
 */
function parseConcatChain(input: string, quote: string): ConcatSegments | null {
  const strings: string[] = [];
  const variables: string[] = [];
  let pos = 0;
  const len = input.length;

  // Parse first string segment
  const firstStr = parseStringLiteral(input, pos, quote);
  if (!firstStr) return null;
  strings.push(firstStr.value);
  pos = firstStr.endPos;

  // Now expect alternating: + variable [+ string ...]
  while (pos < len) {
    // Skip whitespace
    pos = skipWhitespace(input, pos);

    // Expect +
    if (input[pos] !== '+') break;
    pos++;
    pos = skipWhitespace(input, pos);

    // Parse the variable expression (identifier, possibly with . access or [] etc.)
    const varExpr = parseVariableExpression(input, pos);
    if (!varExpr) break;
    variables.push(varExpr.value);
    pos = varExpr.endPos;

    pos = skipWhitespace(input, pos);

    // Optionally expect + "more sql"
    if (pos < len && input[pos] === '+') {
      const nextPos = skipWhitespace(input, pos + 1);
      const nextStr = parseStringLiteral(input, nextPos, quote);
      if (nextStr) {
        strings.push(nextStr.value);
        pos = nextStr.endPos;
      } else {
        // The + leads to another variable, not a string
        // We'll add an empty string segment and loop again
        strings.push('');
      }
    }
  }

  // The remainder is everything after the parsed chain
  const remainder = input.substring(pos);

  if (variables.length === 0) return null;

  return { strings, variables, remainder };
}

function skipWhitespace(input: string, pos: number): number {
  while (pos < input.length && /\s/.test(input[pos])) pos++;
  return pos;
}

function parseStringLiteral(input: string, pos: number, quote: string): { value: string; endPos: number } | null {
  if (pos >= input.length || input[pos] !== quote) return null;
  pos++; // skip opening quote
  let value = '';
  while (pos < input.length && input[pos] !== quote) {
    if (input[pos] === '\\') {
      value += input[pos + 1] || '';
      pos += 2;
    } else {
      value += input[pos];
      pos++;
    }
  }
  if (pos >= input.length) return null; // no closing quote
  pos++; // skip closing quote
  return { value, endPos: pos };
}

function parseVariableExpression(input: string, pos: number): { value: string; endPos: number } | null {
  // Parse a variable expression: an identifier possibly followed by .prop, [index], or ()
  // Stops at whitespace, +, ), comma, semicolon
  const start = pos;
  if (pos >= input.length) return null;

  // Must start with a letter, _, or $
  if (!/[a-zA-Z_$]/.test(input[pos])) return null;

  while (pos < input.length) {
    const ch = input[pos];
    if (/[a-zA-Z0-9_$.]/.test(ch)) {
      pos++;
    } else if (ch === '[') {
      // Skip to matching ]
      let depth = 1;
      pos++;
      while (pos < input.length && depth > 0) {
        if (input[pos] === '[') depth++;
        else if (input[pos] === ']') depth--;
        pos++;
      }
    } else if (ch === '(') {
      // Function call — skip to matching )
      let depth = 1;
      pos++;
      while (pos < input.length && depth > 0) {
        if (input[pos] === '(') depth++;
        else if (input[pos] === ')') depth--;
        pos++;
      }
    } else {
      break;
    }
  }

  if (pos === start) return null;
  return { value: input.substring(start, pos).trim(), endPos: pos };
}

/**
 * Read project dependencies from package.json to determine param style.
 */
export async function readProjectDeps(projectDir: string): Promise<string[]> {
  try {
    const pkgPath = path.join(projectDir, 'package.json');
    const content = await fs.readFile(pkgPath, 'utf-8');
    const pkg = JSON.parse(content);
    return [
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ];
  } catch {
    return [];
  }
}

/**
 * Apply a SQL injection fix to a file at the specified line.
 * Reads the file, fixes the line, writes it back.
 */
export async function fixSqlInjectionInFile(
  finding: Finding,
  projectDir?: string,
): Promise<SqlFileFix> {
  const dir = projectDir ?? process.cwd();
  const filePath = path.resolve(dir, finding.file);
  const filesModified: string[] = [];

  // 1. Read the file
  const content = await fs.readFile(filePath, 'utf-8');
  const lines = content.split('\n');
  const targetLine = lines[finding.line - 1];

  if (!targetLine) {
    throw new Error(`Line ${finding.line} not found in ${finding.file}`);
  }

  // 2. Read project deps for param style detection
  const deps = await readProjectDeps(dir);

  // 3. Attempt the fix
  const result = fixSqlInjection(targetLine, deps);
  if (!result || !result.fixed) {
    throw new Error(
      `Could not auto-fix SQL injection on line ${finding.line} in ${finding.file}. ` +
      `The pattern may be too complex for automatic fixing. Apply the fix manually: ${finding.fix_suggestion}`,
    );
  }

  // 4. Write the fixed file
  lines[finding.line - 1] = result.fixedLine;
  await fs.writeFile(filePath, lines.join('\n'), 'utf-8');
  filesModified.push(finding.file);

  return {
    file: finding.file,
    line: finding.line,
    originalLine: result.originalLine,
    fixedLine: result.fixedLine,
    params: result.params,
    paramStyle: result.paramStyle,
    filesModified,
  };
}
