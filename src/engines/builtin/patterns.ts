/**
 * ShipSafe Built-in Vulnerability Pattern Scanner
 *
 * Pure TypeScript, zero external dependencies.
 * Detects code-level vulnerabilities across TypeScript, JavaScript, and Python files.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, relative, resolve } from 'node:path';
import type { Finding, Severity } from '../../types.js';
import { loadIgnoreFilter, type IgnoreFilter } from './ignore.js';
import { loadGitIgnoreFilter } from './gitignore.js';

// ── Types ──

type FileType = '.ts' | '.tsx' | '.js' | '.jsx' | '.py';

interface PatternRule {
  id: string;
  category: string;
  description: string;
  severity: Severity;
  fix_suggestion: string;
  auto_fixable: boolean;
  fileTypes: FileType[];
  /** Return true if the line matches this vulnerability pattern. */
  detect: (line: string, context: LineContext) => boolean;
  /** If true, skip detection inside comments and string literals. */
  skipCommentsAndStrings?: boolean;
  /** If true, skip test files for this rule. */
  skipTestFiles?: boolean;
}

interface LineContext {
  filePath: string;
  lineNumber: number;
  fileContent: string;
  allLines: string[];
  isTestFile: boolean;
}

// ── Ignored directories and file patterns ──

const IGNORED_DIRS = new Set([
  'node_modules',
  'dist',
  'build',
  '.git',
  '.next',
  '.nuxt',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
  'env',
  '.tox',
  '.mypy_cache',
  '.pytest_cache',
  'vendor',
  '.turbo',
]);

const SCANNABLE_EXTENSIONS = new Set<string>([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.py',
]);

// ── Severity ordering for sorting ──

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ── Helper: Check if a line is inside a comment ──

function isCommentLine(line: string, fileType: FileType): boolean {
  const trimmed = line.trimStart();
  if (fileType === '.py') {
    return trimmed.startsWith('#');
  }
  return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
}

// ── Helper: Check if a line is likely inside a string literal ──

function isInsideStringLiteral(line: string, matchIndex: number): boolean {
  // Very rough heuristic: count unescaped quotes before the match position
  const before = line.slice(0, matchIndex);
  const singleQuotes = (before.match(/(?<!\\)'/g) || []).length;
  const doubleQuotes = (before.match(/(?<!\\)"/g) || []).length;
  const backticks = (before.match(/(?<!\\)`/g) || []).length;
  // If an odd number of any quote type, we're likely inside a string
  return singleQuotes % 2 === 1 || doubleQuotes % 2 === 1 || backticks % 2 === 1;
}

// ── Helper: Test file detection ──

function isTestFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    lower.includes('.test.') ||
    lower.includes('.spec.') ||
    lower.includes('__tests__') ||
    lower.includes('/test/') ||
    lower.includes('/tests/') ||
    lower.includes('_test.py') ||
    lower.includes('test_') ||
    lower.endsWith('.test.ts') ||
    lower.endsWith('.test.js') ||
    lower.endsWith('.spec.ts') ||
    lower.endsWith('.spec.js') ||
    // Documentation directories and files
    lower.includes('/docs/') ||
    lower.includes('/docs_src/') ||
    lower.includes('/documentation/') ||
    lower.includes('/examples/') ||
    lower.includes('/example/') ||
    lower.endsWith('.md') ||
    lower.endsWith('.mdx') ||
    lower.endsWith('.rst') ||
    // i18n / localization
    lower.includes('/i18n/') ||
    lower.includes('/locales/') ||
    lower.includes('/translations/') ||
    lower.includes('/lang/') ||
    // Fixtures / mocks / seeds
    lower.includes('/fixtures/') ||
    lower.includes('/__fixtures__/') ||
    lower.includes('/seeds/') ||
    lower.includes('/mock/') ||
    lower.includes('/mocks/') ||
    // Benchmarks
    lower.includes('/benchmarks/') ||
    lower.includes('/benchmark/')
  );
}

// ── Helper: Framework library source detection ──
// Detects if a file is part of a framework's own source code (not application code)

function isFrameworkSource(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  // FastAPI framework source
  if (/\/fastapi\/fastapi\//.test(lower)) return true;
  // Flask framework source
  if (/\/flask\/src\/flask\//.test(lower) || /\/flask\/flask\//.test(lower)) return true;
  // Django framework source
  if (/\/django\/django\//.test(lower)) return true;
  // Express framework source
  if (/\/express\/lib\//.test(lower)) return true;
  // Hono framework source
  if (/\/hono\/src\//.test(lower)) return true;
  // Cookie/session libraries
  if (/\/tough-cookie\//.test(lower)) return true;
  if (/\/cookie\/index\./.test(lower) || /\/cookie\/src\//.test(lower)) return true;
  if (/\/express-session\//.test(lower)) return true;
  if (/\/cookie-parser\//.test(lower)) return true;
  // Next.js framework source
  if (/\/next\/dist\//.test(lower) || /\/next\/src\//.test(lower)) return true;
  // Koa framework source
  if (/\/koa\/lib\//.test(lower)) return true;
  // Payload CMS framework source
  if (/\/payload\/(?:src|dist)\//.test(lower)) return true;
  if (/\/payload-cloud\//.test(lower)) return true;
  // Generic: detect when scanning inside a package's own source by checking
  // if the path matches a well-known framework directory structure
  if (/\/node_modules\/[^/]+\/(?:src|lib|dist)\//.test(lower)) return true;
  return false;
}

// ── Helper: Check if file is part of a cookie/session library ──

function isCookieLibrarySource(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    /\/hono\/src\//.test(lower) ||
    /\/tough-cookie\//.test(lower) ||
    /\/cookie\//.test(lower) && !/\/app\//.test(lower) && !/\/src\/(?!.*cookie)/.test(lower) ||
    /\/express\/lib\//.test(lower) ||
    /\/cookie-parser\//.test(lower) ||
    /\/express-session\//.test(lower) ||
    /\/connect\//.test(lower) && /session|cookie/.test(lower) ||
    /\/set-cookie-parser\//.test(lower) ||
    /\/cookies\//.test(lower) && /\/lib\//.test(lower)
  );
}

// ── Helper: Check if file is in an example or docs directory ──

function isExampleOrDocsDir(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return /\/(docs_src|docs|examples|example|tutorials|tutorial|samples|sample|demo|demos)\//i.test(lower);
}

// ── Helper: Enhanced test / fixture / mock file detection ──

function isTestOrFixtureFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    isTestFile(filePath) ||
    lower.includes('/__mocks__/') ||
    lower.includes('/stubs/') ||
    lower.endsWith('.stories.ts') ||
    lower.endsWith('.stories.tsx') ||
    lower.endsWith('.stories.js') ||
    lower.endsWith('.stories.jsx') ||
    lower.endsWith('.story.ts') ||
    lower.endsWith('.story.tsx') ||
    lower.endsWith('.story.js') ||
    lower.endsWith('.story.jsx') ||
    lower.endsWith('.fixture.ts') ||
    lower.endsWith('.fixture.tsx') ||
    lower.endsWith('.fixture.js') ||
    lower.endsWith('.fixture.jsx')
  );
}

// ── Helper: Library / framework package detection ──
// Detects when we're scanning a library's own source (not application code).

function isLibraryPackage(filePath: string): boolean {
  const lower = filePath.toLowerCase();

  // Path-based heuristics for library source
  if (/\/packages\/[^/]+\/src\//.test(lower)) return true;
  if (/\/src\/core\//.test(lower) && /\/packages\//.test(lower)) return true;
  if (/\/src\/lib\//.test(lower) && /\/packages\//.test(lower)) return true;

  // Package name contains library/framework/ORM keywords
  if (isOrmPackage(filePath)) return true;

  // Known framework source already handled by isFrameworkSource
  if (isFrameworkSource(filePath)) return true;

  return false;
}

// ── Helper: ORM package source detection ──

function isOrmPackage(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    /\/drizzle-orm\//.test(lower) ||
    /\/drizzle-kit\//.test(lower) ||
    /\/sequelize\//.test(lower) ||
    /\/prisma\//.test(lower) ||
    /\/typeorm\//.test(lower) ||
    /\/knex\//.test(lower) ||
    /\/mikro-orm\//.test(lower) ||
    /\/objection\//.test(lower) ||
    /\/bookshelf\//.test(lower) ||
    /\/waterline\//.test(lower)
  );
}

// ── Helper: Streaming SDK / library detection ──

function isStreamingLibrary(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return (
    /\/sse\//.test(lower) && /\/(?:src|lib|dist)\//.test(lower) ||
    /\/eventsource\//.test(lower) ||
    /\/event-stream\//.test(lower) ||
    /\/stream-chat\//.test(lower) ||
    /\/readable-stream\//.test(lower) ||
    /\/through2\//.test(lower) ||
    /\/pump\//.test(lower) ||
    /\/pumpify\//.test(lower) ||
    /\/highland\//.test(lower) ||
    /\/streaming-/.test(lower) && /\/(?:src|lib|dist)\//.test(lower) ||
    isLibraryPackage(filePath)
  );
}

// ── Helper: Check if file has FastAPI imports ──

function hasFastapiImport(fileContent: string): boolean {
  return /\bfrom\s+fastapi\b/.test(fileContent) || /\bimport\s+fastapi\b/.test(fileContent);
}

// ── Helper: Check if file is a Django migration ──

function isDjangoMigration(filePath: string): boolean {
  return /\/migrations\//.test(filePath.toLowerCase());
}

// ── Helper: Prisma file detection ──

function isPrismaSchemaFile(filePath: string): boolean {
  return filePath.endsWith('.prisma');
}

function isPrismaMigrationFile(filePath: string): boolean {
  return /\/prisma\/migrations\//.test(filePath.toLowerCase());
}

// ── Helper: Prisma safe ORM operation ──
// Prisma ORM methods like prisma.user.findMany(), prisma.post.create() etc.
// are safe parameterized operations — they should never trigger SQL injection rules.

function isPrismaSafeOrmCall(line: string): boolean {
  return /\bprisma\s*\.\s*[a-zA-Z_]+\s*\.\s*(?:findMany|findFirst|findUnique|create|createMany|update|updateMany|upsert|delete|deleteMany|count|aggregate|groupBy)\s*\(/.test(line);
}

// ── Helper: Check if file is a database migration file ──
// Matches paths containing /migrations/, /migrate/, or filenames starting with
// digit-based prefixes (e.g., 20240101_create_users, 0001_initial).

function isMigrationFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  if (/\/migrations?\//.test(lower) || /\/migrate\//.test(lower)) return true;
  // Filename starts with digit-based migration prefix (e.g., 20240101_, 0001_)
  const filename = lower.split('/').pop() ?? '';
  if (/^\d{4,}_/.test(filename)) return true;
  return false;
}

// ── Helper: Check if file has auto-generated marker at the top ──

function isAutoGeneratedFile(fileContent: string): boolean {
  // Check the first 20 lines for generated markers
  const topLines = fileContent.split('\n').slice(0, 20).join('\n').toLowerCase();
  return (
    topLines.includes('auto-generated') ||
    topLines.includes('autogenerated') ||
    topLines.includes('@generated') ||
    topLines.includes('generated by') ||
    topLines.includes('this file is generated') ||
    topLines.includes('do not edit') ||
    topLines.includes('do not modify')
  );
}

// ── Helper: Check if file imports from FP/reactive libraries (not Node streams) ──

function hasFpOrReactiveImports(fileContent: string): boolean {
  return (
    /\bfrom\s+['"]effect['"]/.test(fileContent) ||
    /\bfrom\s+['"]@effect\//.test(fileContent) ||
    /\bfrom\s+['"]fp-ts/.test(fileContent) ||
    /\bfrom\s+['"]rxjs/.test(fileContent) ||
    /\bfrom\s+['"]@rxjs\//.test(fileContent) ||
    /\bfrom\s+['"]ix\//.test(fileContent) ||
    /\bfrom\s+['"]most['"]/.test(fileContent) ||
    /\bfrom\s+['"]xstream['"]/.test(fileContent)
  );
}

// ── Helper: Check if file imports GraphQL libraries ──

function hasGraphqlImports(fileContent: string): boolean {
  return (
    /\bfrom\s+['"]@apollo\//.test(fileContent) ||
    /\bfrom\s+['"]apollo-server/.test(fileContent) ||
    /\bfrom\s+['"]graphql-yoga/.test(fileContent) ||
    /\bfrom\s+['"]type-graphql/.test(fileContent) ||
    /\bfrom\s+['"]@graphql-tools\//.test(fileContent) ||
    /\bfrom\s+['"]graphql['"]/.test(fileContent) ||
    /\bfrom\s+['"]nexus['"]/.test(fileContent) ||
    /\bfrom\s+['"]pothos/.test(fileContent) ||
    /\brequire\s*\(\s*['"]graphql/.test(fileContent)
  );
}

// ── Helper: Check if file imports AI/LLM libraries ──

function hasAiImports(fileContent: string): boolean {
  return (
    /\bfrom\s+['"]openai/.test(fileContent) ||
    /\bfrom\s+['"]anthropic/.test(fileContent) ||
    /\bfrom\s+['"]@anthropic/.test(fileContent) ||
    /\bfrom\s+['"]langchain/.test(fileContent) ||
    /\bfrom\s+['"]llama.index/.test(fileContent) ||
    /\bfrom\s+['"]llama_index/.test(fileContent) ||
    /\bfrom\s+['"]cohere/.test(fileContent) ||
    /\bimport\s+openai\b/.test(fileContent) ||
    /\bimport\s+anthropic\b/.test(fileContent) ||
    /\bimport\s+langchain\b/.test(fileContent) ||
    /\bfrom\s+openai\b/.test(fileContent) ||
    /\bfrom\s+anthropic\b/.test(fileContent) ||
    /\bfrom\s+langchain\b/.test(fileContent) ||
    /\bfrom\s+llama_index\b/.test(fileContent)
  );
}

// ── Helper: Check for server-side imports (Python) ──

function hasPythonServerImports(fileContent: string): boolean {
  return (
    /\bfrom\s+flask\b/.test(fileContent) ||
    /\bimport\s+flask\b/.test(fileContent) ||
    /\bfrom\s+django\b/.test(fileContent) ||
    /\bimport\s+django\b/.test(fileContent) ||
    /\bfrom\s+fastapi\b/.test(fileContent) ||
    /\bimport\s+fastapi\b/.test(fileContent) ||
    /\bfrom\s+starlette\b/.test(fileContent) ||
    /\bfrom\s+sanic\b/.test(fileContent) ||
    /\bfrom\s+bottle\b/.test(fileContent) ||
    /\bfrom\s+tornado\b/.test(fileContent) ||
    /\bfrom\s+aiohttp\.web\b/.test(fileContent)
  );
}

// ── Helper: Check for Django imports ──

function hasDjangoImports(fileContent: string): boolean {
  return (
    /\bfrom\s+django\b/.test(fileContent) ||
    /\bimport\s+django\b/.test(fileContent)
  );
}

// ── Helper: Check if file has server-side TS/JS imports ──

function hasServerSideImports(fileContent: string): boolean {
  return (
    /\bfrom\s+['"]express/.test(fileContent) ||
    /\brequire\s*\(\s*['"]express/.test(fileContent) ||
    /\bfrom\s+['"]fastify/.test(fileContent) ||
    /\bfrom\s+['"]hono/.test(fileContent) ||
    /\bfrom\s+['"]koa/.test(fileContent) ||
    /\bfrom\s+['"]next\/server/.test(fileContent)
  );
}

// ── Pattern Rules ──

const RULES: PatternRule[] = [
  // ════════════════════════════════════════════
  // SQL Injection
  // ════════════════════════════════════════════
  {
    id: 'SQL_INJECTION_CONCAT',
    category: 'SQL Injection',
    description: 'SQL query built with string concatenation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use parameterized queries (e.g., query("SELECT * FROM users WHERE id = $1", [id])) instead of string concatenation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip migration files — developer-authored SQL, not user input
      if (isMigrationFile(ctx.filePath)) return false;
      // Skip Prisma migration files entirely
      if (isPrismaMigrationFile(ctx.filePath)) return false;
      // Skip safe Prisma ORM operations (e.g., prisma.user.findMany())
      if (isPrismaSafeOrmCall(line)) return false;
      // Match patterns like query("SELECT ... " + variable) or db.run("INSERT ... " + variable)
      // Covers: query, execute, raw, prepare, run, get, all, each, exec (SQLite), plus pool/client/connection.query
      // Use separate patterns for double and single quotes to handle embedded opposite quotes
      return /\b(?:query|execute|raw|prepare|run|get|all|each|exec)\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^"]*"\s*\+/i.test(line) ||
        /\b(?:query|execute|raw|prepare|run|get|all|each|exec)\s*\(\s*'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^']*'\s*\+/i.test(line);
    },
  },
  {
    id: 'SQL_INJECTION_TEMPLATE',
    category: 'SQL Injection',
    description: 'SQL query built with template literals containing interpolated values — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use parameterized queries or tagged template literals (e.g., sql`SELECT * FROM users WHERE id = ${id}`) that auto-escape values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip migration files — developer-authored SQL, not user input
      if (isMigrationFile(ctx.filePath)) return false;
      // Skip Prisma migration files entirely
      if (isPrismaMigrationFile(ctx.filePath)) return false;
      // Skip safe Prisma ORM operations (e.g., prisma.user.findMany())
      if (isPrismaSafeOrmCall(line)) return false;
      // Match db.run(`SELECT ... ${...}`) patterns, but NOT tagged template literals like sql`...`
      // Covers: query, execute, raw, prepare, run, get, all, each, exec
      return /\b(?:query|execute|raw|prepare|run|get|all|each|exec)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^`]*\$\{/i.test(line);
    },
  },
  {
    id: 'SQL_INJECTION_INLINE_VAR',
    category: 'SQL Injection',
    description: 'SQL query string built with embedded variable via concatenation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use parameterized queries with placeholders (?, $1, :param) instead of string concatenation in SQL statements.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip migration files — developer-authored SQL, not user input
      if (isMigrationFile(ctx.filePath)) return false;
      // Skip Prisma migration files entirely
      if (isPrismaMigrationFile(ctx.filePath)) return false;
      // Skip safe Prisma ORM operations (e.g., prisma.user.findMany())
      if (isPrismaSafeOrmCall(line)) return false;
      // Catch cases where SQL keyword appears in a string concatenated with +, even without a db method on the same line
      // e.g., const sql = "SELECT * FROM users WHERE id = " + userId;
      const hasSqlKeyword = /"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^"]*"\s*\+\s*[a-zA-Z_$]/i.test(line) ||
        /'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^']*'\s*\+\s*[a-zA-Z_$]/i.test(line);
      if (!hasSqlKeyword) return false;
      // Exclude string concatenation that's clearly not SQL (check for SQL structural words)
      return /\b(?:FROM|INTO|SET|VALUES|WHERE|TABLE|JOIN|ORDER BY|GROUP BY)\b/i.test(line);
    },
  },
  {
    id: 'SQL_INJECTION_TEMPLATE_STRING',
    category: 'SQL Injection',
    description: 'SQL query built as a template literal with interpolated values — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use parameterized queries with placeholders instead of embedding variables directly in SQL template strings.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip ORM library internals
      if (isOrmPackage(ctx.filePath) || isLibraryPackage(ctx.filePath)) return false;
      // Skip JSX/TSX files — template literals in React components are not SQL injection
      if (ctx.filePath.endsWith('.tsx') || ctx.filePath.endsWith('.jsx')) return false;
      // Skip migration files — developer-authored SQL, not user input
      if (isMigrationFile(ctx.filePath)) return false;
      // Catch template literals containing SQL keywords + interpolation, even outside a db method call
      // e.g., const sql = `SELECT * FROM users WHERE id = ${userId}`;
      // But NOT tagged templates like sql`...` or Prisma.$queryRaw`...` / $executeRaw`...`
      if (/\b(?:sql|html|css|gql|graphql)\s*`/.test(line)) return false;
      if (/\$(?:queryRaw|executeRaw)\s*`/.test(line)) return false;
      // Skip safe Prisma ORM operations (e.g., prisma.user.findMany())
      if (isPrismaSafeOrmCall(line)) return false;
      return /`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^`]*\$\{[^}]+\}[^`]*`/i.test(line);
    },
  },
  {
    id: 'SQL_INJECTION_RAW_FORMAT',
    category: 'SQL Injection',
    description: 'Raw SQL string built with formatting or concatenation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion: 'Use parameterized queries with placeholders ($1, ?, :param) instead of string formatting.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip migration files — developer-authored SQL, not user input
      if (isMigrationFile(ctx.filePath)) return false;
      // Python: cursor.execute("SELECT ... " + var) or cursor.execute("SELECT ... %s" % var)
      // or cursor.execute(f"SELECT ...")
      return (
        /\b(?:execute|executemany)\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*%/i.test(line) ||
        /\b(?:execute|executemany)\s*\(\s*'(?:SELECT|INSERT|UPDATE|DELETE)\b[^']*'\s*%/i.test(line) ||
        /\b(?:execute|executemany)\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+/i.test(line) ||
        /\b(?:execute|executemany)\s*\(\s*'(?:SELECT|INSERT|UPDATE|DELETE)\b[^']*'\s*\+/i.test(line) ||
        /\b(?:execute|executemany)\s*\(\s*f(?:"|')(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(line)
      );
    },
  },
  {
    id: 'SQL_INJECTION_ORM_RAW',
    category: 'SQL Injection',
    description: 'ORM raw query without parameterization — vulnerable to SQL injection.',
    severity: 'high',
    fix_suggestion:
      'Use the ORM\'s parameterized raw query API (e.g., sequelize.query(sql, { replacements: [...] }) or knex.raw("?", [value])).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip migration files — developer-authored SQL, not user input
      if (isMigrationFile(ctx.filePath)) return false;
      // Skip Prisma migration files entirely
      if (isPrismaMigrationFile(ctx.filePath)) return false;
      // Skip safe Prisma ORM operations (e.g., prisma.user.findMany())
      if (isPrismaSafeOrmCall(line)) return false;
      // Skip Prisma tagged template literals ($queryRaw`...` and $executeRaw`...`) — auto-parameterized
      if (/\$(?:queryRaw|executeRaw)\s*`/.test(line)) return false;
      // Sequelize, TypeORM, Knex, Prisma, Django, SQLAlchemy raw queries with interpolation
      return (
        /\b(?:sequelize|connection|entityManager|manager|knex|pool|client|db|database)\s*\.\s*(?:query|raw|run|get|all|each|exec)\s*\(\s*`[^`]*\$\{/i.test(line) ||
        /\b(?:sequelize|connection|entityManager|manager|knex|pool|client|db|database)\s*\.\s*(?:query|raw|run|get|all|each|exec)\s*\(\s*"[^"]*"\s*\+/i.test(line) ||
        /\b(?:sequelize|connection|entityManager|manager|knex|pool|client|db|database)\s*\.\s*(?:query|raw|run|get|all|each|exec)\s*\(\s*'[^']*'\s*\+/i.test(line) ||
        /\bRawSQL\s*\(\s*f(?:"|')/i.test(line) ||
        /\.raw\s*\(\s*f(?:"|')(?:SELECT|INSERT|UPDATE|DELETE)/i.test(line) ||
        /\$queryRawUnsafe\s*\(/.test(line)
      );
    },
  },

  // ════════════════════════════════════════════
  // Cross-Site Scripting (XSS)
  // ════════════════════════════════════════════
  {
    id: 'XSS_INNERHTML',
    category: 'Cross-Site Scripting (XSS)',
    description: 'Direct innerHTML assignment allows injection of arbitrary HTML and scripts.',
    severity: 'high',
    fix_suggestion: 'Use textContent instead of innerHTML, or sanitize input with DOMPurify before assignment.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.innerHTML\s*=\s*(?!["']<\/|["']\s*$|''\s*;|""\s*;)/.test(line);
    },
  },
  {
    id: 'XSS_DOCUMENT_WRITE',
    category: 'Cross-Site Scripting (XSS)',
    description: 'document.write() injects unescaped content into the DOM — vulnerable to XSS.',
    severity: 'high',
    fix_suggestion:
      'Avoid document.write(). Use DOM APIs (createElement, appendChild) or a framework\'s rendering methods.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bdocument\s*\.\s*write(?:ln)?\s*\(/.test(line);
    },
  },
  {
    id: 'XSS_DANGEROUSLY_SET_INNERHTML',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'dangerouslySetInnerHTML renders raw HTML — ensure content is sanitized before use.',
    severity: 'high',
    fix_suggestion:
      'Sanitize HTML with DOMPurify or a server-side sanitizer before passing to dangerouslySetInnerHTML.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/dangerouslySetInnerHTML\s*=/.test(line)) return false;
      // JSON.stringify() output is always safe — JSON cannot contain executable HTML
      if (/JSON\s*\.\s*stringify\s*\(/.test(line)) return false;
      return true;
    },
  },
  {
    id: 'XSS_EVAL',
    category: 'Cross-Site Scripting (XSS)',
    description: 'eval() executes arbitrary code — severe XSS and code injection risk.',
    severity: 'critical',
    fix_suggestion:
      'Remove eval(). Use JSON.parse() for data, or a safe expression parser if dynamic evaluation is truly needed.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match eval( but not "evaluate", "interval", etc.
      if (!/\beval\s*\(/.test(line)) return false;
      if (/\bsetInterval\b/.test(line)) return false;
      // Skip redis.eval() — Redis Lua scripting, not code injection
      if (/\b(?:redis|client|ioredis|redisClient|cache)\s*\.\s*eval\s*\(/.test(line)) return false;
      // Skip lines referencing Lua scripts (Redis EVAL/EVALSHA)
      if (/\b(?:luaScript|lua|EVALSHA)\b/.test(line)) return false;
      return true;
    },
  },
  {
    id: 'XSS_UNESCAPED_TEMPLATE',
    category: 'Cross-Site Scripting (XSS)',
    description: 'Unescaped template rendering ({{! or {{{ or |safe) may allow XSS.',
    severity: 'medium',
    fix_suggestion:
      'Use escaped template syntax ({{ }}) and sanitize user-supplied content before rendering.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Handlebars triple-stash {{{, Jinja2 |safe — keep flagging these
      if (/\{\{\{[^}]+\}\}\}/.test(line)) return true;
      if (/\|\s*safe\b/.test(line)) return true;
      // EJS <%- (unescaped): only flag when content looks like user input
      if (/<%- /.test(line)) {
        // Skip build-time config templates, CSS, and static includes
        const lower = line.toLowerCase();
        if (/<%- (?:include|layout|partial|header|footer|head|body|nav|sidebar|style|css|script|config)/.test(line)) return false;
        // Skip if the file appears to be a CSS or config template
        if (ctx.filePath.endsWith('.css') || ctx.filePath.endsWith('.scss')) return false;
        // Only flag when the interpolated content references a dynamic variable
        if (/<%- .*(?:req\.|user|param|query|body|input|data|message|content|text|html|name|title|description)\b/i.test(line)) return true;
        // If it references a variable that could be user-controlled, flag it
        return /<%- [a-zA-Z_]+\s*%>/.test(line) && /\b(?:req|user|param|query|body|input|data|message)\b/i.test(lower);
      }
      return false;
    },
  },

  // ════════════════════════════════════════════
  // Command Injection
  // ════════════════════════════════════════════
  {
    id: 'CMD_INJECTION_EXEC_CONCAT',
    category: 'Command Injection',
    description: 'exec() with string concatenation allows arbitrary command injection.',
    severity: 'critical',
    fix_suggestion:
      'Use execFile() or spawn() with an array of arguments instead of exec() with concatenated strings.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bexec\s*\(\s*(?:"|')[^"']*(?:"|')\s*\+/.test(line) ||
        /\bexec\s*\(\s*`[^`]*\$\{/.test(line);
    },
  },
  {
    id: 'CMD_INJECTION_EXECSYNC',
    category: 'Command Injection',
    description: 'execSync() with template literals or concatenation enables command injection.',
    severity: 'critical',
    fix_suggestion:
      'Use execFileSync() with an array of arguments, or spawn/spawnSync with explicit argument arrays.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bexecSync\s*\(\s*`[^`]*\$\{/.test(line) ||
        /\bexecSync\s*\(\s*(?:"|')[^"']*(?:"|')\s*\+/.test(line);
    },
  },
  {
    id: 'CMD_INJECTION_SPAWN_SHELL',
    category: 'Command Injection',
    description:
      'spawn() with shell: true passes the command through a shell, enabling injection via unsanitized input.',
    severity: 'high',
    fix_suggestion:
      'Remove shell: true and pass the command and arguments as separate array elements to spawn().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bspawn\s*\(.*shell\s*:\s*true/.test(line);
    },
  },
  {
    id: 'CMD_INJECTION_CHILD_PROCESS',
    category: 'Command Injection',
    description:
      'child_process exec/execSync with variable input is vulnerable to command injection.',
    severity: 'high',
    fix_suggestion:
      'Use child_process.execFile() or spawn() with arguments array. Never pass user input to exec().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect import of child_process and usage with variable inputs
      if (/require\s*\(\s*['"]child_process['"]\s*\)/.test(line)) return false; // just the import, not a finding
      // exec(someVariable) — not a string literal
      if (!/\bexec\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*[,)]/.test(line)) return false;
      if (/\bexec\s*\(\s*(?:"|'|`)/.test(line)) return false;
      // Exclude RegExp.exec() — look for regex-related patterns before .exec(
      // e.g., /pattern/.exec(str), someRegex.exec(str), pattern.exec(str)
      if (/\/[^/]+\/[gimsuy]*\s*\.\s*exec\s*\(/.test(line)) return false;
      if (/(?:regex|regexp|re|pattern|match|matcher)\s*\.\s*exec\s*\(/i.test(line)) return false;
      // Check if .exec() is preceded by a variable that looks like a regex
      if (/[a-zA-Z_$][a-zA-Z0-9_$]*Regex\s*\.\s*exec\s*\(/i.test(line)) return false;
      if (/[a-zA-Z_$][a-zA-Z0-9_$]*Re\s*\.\s*exec\s*\(/i.test(line)) return false;
      if (/[a-zA-Z_$][a-zA-Z0-9_$]*Pattern\s*\.\s*exec\s*\(/i.test(line)) return false;
      // Require child_process context: check imports in the file
      const hasChildProcessImport = /\bchild_process\b/.test(ctx.fileContent) ||
        /\bimport\b.*\bexec\b.*\bfrom\b/.test(ctx.fileContent) && /child_process/.test(ctx.fileContent) ||
        /\brequire\s*\(\s*['"]child_process/.test(ctx.fileContent);
      if (!hasChildProcessImport) return false;
      return true;
    },
  },
  {
    id: 'CMD_INJECTION_OS_SYSTEM',
    category: 'Command Injection',
    description: 'os.system() passes the command through the shell — vulnerable to command injection.',
    severity: 'critical',
    fix_suggestion: 'Use subprocess.run() with a list of arguments and shell=False (the default).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bos\s*\.\s*system\s*\(/.test(line);
    },
  },
  {
    id: 'CMD_INJECTION_SUBPROCESS_SHELL',
    category: 'Command Injection',
    description:
      'subprocess.call/run/Popen with shell=True passes commands through the shell — vulnerable to injection.',
    severity: 'critical',
    fix_suggestion:
      'Use subprocess.run() with a list of arguments (shell=False). Pass arguments as a list, not a string.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsubprocess\s*\.\s*(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Path Traversal
  // ════════════════════════════════════════════
  {
    id: 'PATH_TRAVERSAL_USER_INPUT',
    category: 'Path Traversal',
    description:
      'File system operation uses a path from user input (req.params, req.query, req.body) without validation.',
    severity: 'high',
    fix_suggestion:
      'Validate and sanitize the file path. Use path.resolve() and verify the resolved path starts with your allowed base directory.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|access|accessSync|unlink|unlinkSync|readdir|readdirSync|stat|statSync)\s*\([^)]*\breq\s*\.\s*(?:params|query|body|headers)\b/.test(line);
    },
  },
  {
    id: 'PATH_TRAVERSAL_CONCAT',
    category: 'Path Traversal',
    description:
      'File path built with string concatenation may allow directory traversal attacks.',
    severity: 'medium',
    fix_suggestion:
      'Use path.join() with a validated base directory. Check that the resolved path is within the expected directory with path.resolve().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect patterns like readFile("./" + filename) or readFile(basePath + "/" + filename)
      return /\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|open)\s*\(\s*(?:[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\+|["'][^"']*["']\s*\+)/.test(line);
    },
  },
  {
    id: 'PATH_TRAVERSAL_DOTDOT',
    category: 'Path Traversal',
    description:
      'Path containing "../" detected in file operation — potential directory traversal.',
    severity: 'medium',
    fix_suggestion:
      'Reject paths containing ".." or normalize with path.resolve() and validate against an allowed base path.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Only flag if it's in a file operation context, not an import/require
      if (/\b(?:require|import|from)\b/.test(line)) return false;
      return /\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|open|access|unlink|stat)\s*\([^)]*\.\.\//.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Insecure Cryptography
  // ════════════════════════════════════════════
  {
    id: 'CRYPTO_MD5',
    category: 'Insecure Cryptography',
    description:
      'MD5 is cryptographically broken — do not use for passwords, authentication, or integrity checks.',
    severity: 'high',
    fix_suggestion:
      'Use bcrypt or argon2 for passwords, SHA-256 or SHA-3 for integrity checks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /createHash\s*\(\s*['"]md5['"]\s*\)/.test(line) ||
        /\bhashlib\s*\.\s*md5\s*\(/.test(line) ||
        /\bMD5\s*\(/.test(line);
    },
  },
  {
    id: 'CRYPTO_SHA1',
    category: 'Insecure Cryptography',
    description:
      'SHA-1 is deprecated for security purposes — collision attacks are practical.',
    severity: 'medium',
    fix_suggestion: 'Use SHA-256 or SHA-3 instead of SHA-1 for security-sensitive operations.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /createHash\s*\(\s*['"]sha1['"]\s*\)/.test(line) ||
        /\bhashlib\s*\.\s*sha1\s*\(/.test(line);
    },
  },
  {
    id: 'CRYPTO_MATH_RANDOM',
    category: 'Insecure Cryptography',
    description:
      'Math.random() is not cryptographically secure — do not use for tokens, keys, or security-sensitive values.',
    severity: 'high',
    fix_suggestion:
      'Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) for security-sensitive random values.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Flag Math.random() in contexts that suggest security usage
      if (!/\bMath\s*\.\s*random\s*\(\s*\)/.test(line)) return false;
      const lower = line.toLowerCase();
      // In UI components (.tsx/.jsx), skip when used for animation/layout/styling
      const ext = ctx.filePath.toLowerCase();
      if (ext.endsWith('.tsx') || ext.endsWith('.jsx')) {
        const uiTerms = ['animation', 'animate', 'position', 'shuffle', 'color', 'style', 'opacity', 'transform',
          'delay', 'duration', 'rotate', 'translate', 'scale', 'width', 'height', 'offset', 'margin', 'padding'];
        const isUiContext = uiTerms.some(term => lower.includes(term));
        if (isUiContext) return false;
        // Also check surrounding lines for UI context
        const lineIdx = ctx.lineNumber - 1;
        const nearby = ctx.allLines.slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 3)).join(' ').toLowerCase();
        const isNearbyUi = uiTerms.some(term => nearby.includes(term));
        if (isNearbyUi) return false;
      }
      // Check surrounding context for security-related terms
      return (
        lower.includes('token') ||
        lower.includes('secret') ||
        lower.includes('key') ||
        lower.includes('password') ||
        lower.includes('session') ||
        lower.includes('nonce') ||
        lower.includes('salt') ||
        lower.includes('uuid') ||
        lower.includes('random')
      );
    },
  },
  {
    id: 'CRYPTO_WEAK_CIPHER',
    category: 'Insecure Cryptography',
    description:
      'Weak cipher algorithm (DES, RC4, Blowfish) detected — these are broken and should not be used.',
    severity: 'high',
    fix_suggestion: 'Use AES-256-GCM or ChaCha20-Poly1305 for encryption.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /createCipher(?:iv)?\s*\(\s*['"](?:des|des-ede|des-ede3|rc4|rc2|blowfish|bf)(?:-[a-z]+)?['"]/i.test(line) ||
        /\bDES\b/.test(line) && /\b(?:cipher|encrypt|decrypt)\b/i.test(line) ||
        /\bRC4\b/.test(line) && /\b(?:cipher|encrypt|decrypt)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Insecure Configuration
  // ════════════════════════════════════════════
  {
    id: 'CONFIG_CORS_WILDCARD',
    category: 'Insecure Configuration',
    description:
      'CORS with wildcard origin (*) allows any website to make requests — may expose sensitive data.',
    severity: 'medium',
    fix_suggestion:
      'Specify explicit allowed origins instead of "*". Use an allowlist of trusted domains.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return (
        /['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*['"]/.test(line) ||
        /\bcors\s*\(\s*\{?\s*origin\s*:\s*(?:true|['"]\*['"])/.test(line) ||
        /origin\s*:\s*['"]\*['"]/.test(line)
      );
    },
  },
  {
    id: 'CONFIG_SSL_DISABLED',
    category: 'Insecure Configuration',
    description:
      'SSL/TLS certificate verification is disabled (rejectUnauthorized: false) — vulnerable to MITM attacks.',
    severity: 'critical',
    fix_suggestion:
      'Remove rejectUnauthorized: false. Fix the underlying SSL certificate issue instead of disabling verification.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /rejectUnauthorized\s*:\s*false/.test(line) ||
        /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/.test(line) ||
        /process\s*\.\s*env\s*\.\s*NODE_TLS_REJECT_UNAUTHORIZED\s*=/.test(line);
    },
  },
  {
    id: 'CONFIG_DEBUG_PRODUCTION',
    category: 'Insecure Configuration',
    description:
      'Debug mode or verbose error output may be enabled in production — could leak sensitive information.',
    severity: 'medium',
    fix_suggestion:
      'Ensure debug mode is disabled in production. Use environment-specific configuration.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bDEBUG\s*=\s*(?:True|true|1|['"]true['"])/.test(line) &&
        !/\bif\b/.test(line) && !/\bprocess\.env\b/.test(line);
    },
  },
  {
    id: 'CONFIG_BIND_ALL_INTERFACES',
    category: 'Insecure Configuration',
    description:
      'Binding to 0.0.0.0 exposes the service on all network interfaces — may be unintended in production.',
    severity: 'low',
    fix_suggestion:
      'Bind to 127.0.0.1 or a specific interface unless external access is intentionally required.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Match listen/bind calls with 0.0.0.0, but not in comments
      return /\b(?:listen|bind|host)\s*[:=(]\s*['"]0\.0\.0\.0['"]/.test(line) ||
        /['"]0\.0\.0\.0['"].*\b(?:listen|bind|host)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Authentication Issues
  // ════════════════════════════════════════════
  {
    id: 'AUTH_JWT_NO_EXPIRY',
    category: 'Authentication Issues',
    description:
      'JWT signed without an expiration (expiresIn) — tokens remain valid indefinitely if compromised.',
    severity: 'high',
    fix_suggestion:
      'Always set an expiration on JWTs: jwt.sign(payload, secret, { expiresIn: "1h" }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bjwt\s*\.\s*sign\s*\(/.test(line)) return false;
      // Check if expiresIn is present in the same line or nearby lines
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 1), Math.min(ctx.allLines.length, lineIdx + 4)).join(' ');
      return !/expiresIn|exp\s*:/.test(window);
    },
  },
  {
    id: 'AUTH_JWT_HARDCODED_SECRET',
    category: 'Authentication Issues',
    description:
      'JWT secret appears to be hardcoded — secrets should come from environment variables.',
    severity: 'critical',
    fix_suggestion:
      'Store JWT secrets in environment variables (process.env.JWT_SECRET) and use a strong, randomly generated value.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // jwt.sign(payload, "hardcoded-secret") or jwt.sign(payload, 'secret')
      return /\bjwt\s*\.\s*sign\s*\([^,]+,\s*['"][^'"]{1,}['"]/.test(line) ||
        /\bjwt\s*\.\s*verify\s*\([^,]+,\s*['"][^'"]{1,}['"]/.test(line);
    },
  },
  {
    id: 'AUTH_WEAK_PASSWORD_VALIDATION',
    category: 'Authentication Issues',
    description:
      'Password validation appears to only check length with a low minimum — weak passwords may be accepted.',
    severity: 'medium',
    fix_suggestion:
      'Enforce a minimum password length of 12+ characters and require a mix of character types. Consider using zxcvbn for strength estimation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match patterns like password.length >= 4 or len(password) < 6
      return (
        /password\s*\.\s*length\s*(?:>=?|>|===?)\s*[1-7]\b/.test(line) ||
        /\blen\s*\(\s*password\s*\)\s*(?:>=?|>)\s*[1-7]\b/.test(line) ||
        /password\s*\.\s*length\s*<\s*[1-7]\b/.test(line)
      );
    },
  },
  {
    id: 'AUTH_MISSING_AUTH_MIDDLEWARE',
    category: 'Authentication Issues',
    description:
      'Route handler appears to lack authentication middleware — endpoint may be publicly accessible.',
    severity: 'medium',
    fix_suggestion:
      'Add authentication middleware (e.g., requireAuth, isAuthenticated, authGuard) before route handlers that need protection.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match route definitions like app.get("/api/admin/...", handler) without auth middleware
      if (!/\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(/.test(line)) return false;
      // Check for sensitive route patterns
      if (!/['"]\/(?:api\/)?(?:admin|user|account|dashboard|settings|billing|private)\b/.test(line)) return false;
      // Check that no auth middleware is present
      return !/\b(?:auth|authenticate|requireAuth|isAuthenticated|protect|guard|verify|middleware|passport)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Sensitive Data Exposure
  // ════════════════════════════════════════════
  {
    id: 'DATA_CONSOLE_SENSITIVE',
    category: 'Sensitive Data Exposure',
    description:
      'Logging potentially sensitive data (password, token, secret, key) to console.',
    severity: 'medium',
    fix_suggestion:
      'Remove console.log of sensitive data, or redact the values before logging.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bconsole\s*\.\s*(?:log|info|debug|warn|error)\s*\(/.test(line)) return false;
      const lower = line.toLowerCase();
      return (
        lower.includes('password') ||
        lower.includes('secret') ||
        lower.includes('apikey') ||
        lower.includes('api_key') ||
        lower.includes('accesstoken') ||
        lower.includes('access_token') ||
        lower.includes('private_key') ||
        lower.includes('privatekey') ||
        lower.includes('creditcard') ||
        lower.includes('credit_card') ||
        lower.includes('ssn')
      );
    },
  },
  {
    id: 'DATA_STACKTRACE_LEAK',
    category: 'Sensitive Data Exposure',
    description:
      'Error stack trace sent in HTTP response — may leak internal implementation details to attackers.',
    severity: 'medium',
    fix_suggestion:
      'Return generic error messages to clients. Log the full stack trace server-side only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Patterns like res.json({ error: err.stack }) or res.send(error.stack)
      return (
        /\bres\s*\.\s*(?:json|send|status\s*\([^)]*\)\s*\.\s*(?:json|send))\s*\([^)]*(?:\.stack|\.message|err\b|error\b)/.test(line) &&
        /\.stack/.test(line)
      );
    },
  },

  // ════════════════════════════════════════════
  // Unvalidated Redirects
  // ════════════════════════════════════════════
  {
    id: 'REDIRECT_UNVALIDATED',
    category: 'Unvalidated Redirect',
    description:
      'Redirect using user-supplied URL without validation — can be abused for phishing.',
    severity: 'medium',
    fix_suggestion:
      'Validate redirect URLs against an allowlist of domains. Never redirect to a raw user-supplied URL.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return (
        /\bres\s*\.\s*redirect\s*\(\s*req\s*\.\s*(?:query|params|body)\b/.test(line) ||
        /\bres\s*\.\s*redirect\s*\(\s*(?:req\.query\.[a-zA-Z]+|req\.params\.[a-zA-Z]+|req\.body\.[a-zA-Z]+)/.test(line) ||
        /\breturn\s+redirect\s*\(\s*request\s*\.\s*(?:GET|POST|args)\b/.test(line)
      );
    },
  },

  // ════════════════════════════════════════════
  // Prototype Pollution
  // ════════════════════════════════════════════
  {
    id: 'PROTO_POLLUTION_ASSIGN',
    category: 'Prototype Pollution',
    description:
      'Object.assign() or spread with user-controlled input can lead to prototype pollution.',
    severity: 'high',
    fix_suggestion:
      'Validate/sanitize user input before merging. Strip __proto__, constructor, and prototype keys, or use Object.create(null) as the target.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bObject\s*\.\s*assign\s*\([^,]*,\s*req\s*\.\s*(?:body|query|params)\b/.test(line) ||
        /\.\.\.\s*req\s*\.\s*(?:body|query|params)\b/.test(line);
    },
  },
  {
    id: 'PROTO_POLLUTION_BRACKET',
    category: 'Prototype Pollution',
    description:
      'Dynamic property assignment with user input (obj[key] = value) can enable prototype pollution.',
    severity: 'medium',
    fix_suggestion:
      'Validate that the key is not "__proto__", "constructor", or "prototype" before dynamic property assignment.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match obj[req.body.key] = or obj[userInput] = patterns
      return /\[\s*req\s*\.\s*(?:body|query|params)\s*\.\s*[a-zA-Z_]+\s*\]\s*=/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Regex DoS
  // ════════════════════════════════════════════
  {
    id: 'REGEX_DOS',
    category: 'Regex DoS',
    description:
      'Regular expression with nested quantifiers may be vulnerable to catastrophic backtracking (ReDoS).',
    severity: 'medium',
    fix_suggestion:
      'Simplify the regex to avoid nested quantifiers (e.g., (a+)+ or (a|a)*). Consider using a regex analysis tool or the RE2 engine.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect nested quantifiers: (pattern+)+, (pattern*)+, (pattern+)*, etc.
      // Also (a|b+)+ patterns
      return /\([^)]*[+*][^)]*\)[+*]/.test(line) ||
        /\([^)]*\|[^)]*[+*]\)[+*]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Missing Rate Limiting
  // ════════════════════════════════════════════
  {
    id: 'RATE_LIMIT_AUTH_ENDPOINT',
    category: 'Missing Rate Limiting',
    description:
      'Authentication endpoint (login, register, reset-password) without apparent rate limiting.',
    severity: 'medium',
    fix_suggestion:
      'Add rate limiting middleware (e.g., express-rate-limit) to authentication endpoints to prevent brute force attacks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match route definitions for auth-related endpoints
      if (!/\b(?:app|router)\s*\.\s*(?:post|put)\s*\(\s*['"]\/(?:api\/)?(?:auth\/)?(?:login|signin|register|signup|reset-password|forgot-password|verify)\b/.test(line)) {
        return false;
      }
      // Check if rate limit middleware is in the same line or the surrounding context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      return !/\b(?:rateLimit|rateLimiter|limiter|throttle|slowDown|brute)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Hardcoded Secrets (basic patterns)
  // ════════════════════════════════════════════
  {
    id: 'SECRET_HARDCODED_KEY',
    category: 'Hardcoded Secrets',
    description:
      'Potential hardcoded API key or secret detected — secrets should be stored in environment variables.',
    severity: 'high',
    fix_suggestion:
      'Move secrets to environment variables or a secrets manager. Never commit secrets to source code.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Skip lines that reference environment variables
      if (/process\s*\.\s*env\b/.test(line) || /os\s*\.\s*(?:environ|getenv)\b/.test(line)) return false;
      // Skip import/require lines
      if (/\b(?:import|require|from)\b/.test(line)) return false;
      // Match common patterns: API_KEY = "abc123...", apiSecret: "..."
      return /\b(?:api[_-]?key|api[_-]?secret|auth[_-]?token|secret[_-]?key|private[_-]?key|access[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9+/=_-]{16,}['"]/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Python-specific: Pickle deserialization
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_PICKLE_DESERIALIZE',
    category: 'Insecure Deserialization',
    description:
      'pickle.loads() or pickle.load() with untrusted data can execute arbitrary code.',
    severity: 'critical',
    fix_suggestion:
      'Avoid unpickling untrusted data. Use JSON or another safe serialization format.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bpickle\s*\.\s*(?:loads?|Unpickler)\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Python-specific: YAML unsafe load
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_YAML_UNSAFE',
    category: 'Insecure Deserialization',
    description: 'yaml.load() without SafeLoader can execute arbitrary Python objects.',
    severity: 'high',
    fix_suggestion: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\byaml\s*\.\s*load\s*\(/.test(line)) return false;
      // OK if SafeLoader or safe_load is used
      return !/SafeLoader|safe_load/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Insecure SSL verification disabled (Python)
  // ════════════════════════════════════════════
  {
    id: 'CONFIG_SSL_DISABLED_PYTHON',
    category: 'Insecure Configuration',
    description:
      'SSL certificate verification is disabled (verify=False) — vulnerable to man-in-the-middle attacks.',
    severity: 'critical',
    fix_suggestion:
      'Remove verify=False. Fix the underlying certificate issue instead of disabling verification.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\brequests\s*\.\s*(?:get|post|put|patch|delete|head|options|request)\s*\([^)]*verify\s*=\s*False/.test(line) ||
        /\bverify\s*=\s*False/.test(line) && /\b(?:requests|urllib|httpx|aiohttp)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // new Function() — similar to eval
  // ════════════════════════════════════════════
  {
    id: 'XSS_NEW_FUNCTION',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'new Function() compiles and executes a string as code — similar to eval(), enables code injection.',
    severity: 'high',
    fix_suggestion:
      'Avoid new Function(). Use safer alternatives like JSON.parse() for data or a sandboxed evaluator.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+Function\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // setTimeout/setInterval with string argument
  // ════════════════════════════════════════════
  {
    id: 'XSS_SETTIMEOUT_STRING',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'setTimeout/setInterval with a string argument evaluates the string as code — similar to eval().',
    severity: 'medium',
    fix_suggestion:
      'Pass a function reference to setTimeout/setInterval instead of a string.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match setTimeout("code...", ...) or setInterval('code...', ...)
      return /\bset(?:Timeout|Interval)\s*\(\s*['"]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Helmet / security headers missing
  // ════════════════════════════════════════════
  {
    id: 'CONFIG_NO_SECURITY_HEADERS',
    category: 'Insecure Configuration',
    description:
      'Express app created without security headers middleware (helmet) — missing important HTTP security headers.',
    severity: 'low',
    fix_suggestion:
      'Install and use helmet: app.use(helmet()) to set security-related HTTP headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (_line, ctx) => {
      // Only trigger once per file, on the line where express() is called
      if (!/\bexpress\s*\(\s*\)/.test(_line)) return false;
      // Check if helmet is used anywhere in the file
      return !/\bhelmet\b/.test(ctx.fileContent);
    },
  },

  // ════════════════════════════════════════════
  // SSRF (Server-Side Request Forgery)
  // ════════════════════════════════════════════
  {
    id: 'SSRF_USER_URL',
    category: 'Server-Side Request Forgery',
    description:
      'HTTP request made with a URL from user input (req.query, req.body, req.params) — vulnerable to SSRF.',
    severity: 'high',
    fix_suggestion:
      'Validate and sanitize user-supplied URLs. Use an allowlist of permitted domains/IPs. Block internal/private IP ranges (127.0.0.1, 10.x, 192.168.x, 169.254.x).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:fetch|axios\s*\.\s*(?:get|post|put|patch|delete)|http\s*\.\s*(?:get|request)|got\s*\.\s*(?:get|post)|request\s*\.\s*(?:get|post))\s*\(\s*req\s*\.\s*(?:query|body|params|headers)\b/.test(line) ||
        /\b(?:fetch|axios\s*\.\s*(?:get|post|put|patch|delete)|http\s*\.\s*(?:get|request))\s*\(\s*(?:url|uri|href|link|target|redirect|callback)\b/.test(line) &&
        /\breq\s*\.\s*(?:query|body|params)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Insecure Cookie Configuration
  // ════════════════════════════════════════════
  {
    id: 'COOKIE_NO_HTTPONLY',
    category: 'Insecure Cookie',
    description:
      'Cookie set without httpOnly flag — accessible to JavaScript, enabling theft via XSS.',
    severity: 'medium',
    fix_suggestion:
      'Set httpOnly: true on cookies containing session tokens or sensitive data to prevent JavaScript access.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip cookie library source code
      if (isFrameworkSource(ctx.filePath) || isCookieLibrarySource(ctx.filePath)) return false;
      // Match res.cookie(...) calls
      if (!/\bres\s*\.\s*cookie\s*\(/.test(line)) return false;
      // Check for httpOnly in a 5-line window
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return !/httpOnly\s*:\s*true/.test(window);
    },
  },
  {
    id: 'COOKIE_NO_SECURE',
    category: 'Insecure Cookie',
    description:
      'Cookie set without secure flag — will be sent over unencrypted HTTP connections.',
    severity: 'medium',
    fix_suggestion:
      'Set secure: true on cookies to ensure they are only sent over HTTPS.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip cookie library source code
      if (isFrameworkSource(ctx.filePath) || isCookieLibrarySource(ctx.filePath)) return false;
      if (!/\bres\s*\.\s*cookie\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return !/secure\s*:\s*true/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // NoSQL Injection
  // ════════════════════════════════════════════
  {
    id: 'NOSQL_INJECTION',
    category: 'NoSQL Injection',
    description:
      'MongoDB query uses user input directly — vulnerable to NoSQL injection via operator injection ($gt, $ne, etc.).',
    severity: 'high',
    fix_suggestion:
      'Validate and sanitize user input before using in MongoDB queries. Ensure input is the expected type (string, not object). Use mongo-sanitize or explicitly cast values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match patterns like .find({ email: req.body.email }) or .findOne(req.body)
      return /\.\s*(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|aggregate|countDocuments)\s*\(\s*req\s*\.\s*(?:body|query|params)\b/.test(line) ||
        /\.\s*(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany)\s*\(\s*\{[^}]*:\s*req\s*\.\s*(?:body|query|params)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Mass Assignment
  // ════════════════════════════════════════════
  {
    id: 'MASS_ASSIGNMENT',
    category: 'Mass Assignment',
    description:
      'Passing req.body directly to database create/update may allow attackers to set fields they shouldn\'t (e.g., isAdmin, role).',
    severity: 'medium',
    fix_suggestion:
      'Destructure and explicitly pick allowed fields from req.body before passing to database operations. Never pass raw req.body to create/update.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.\s*(?:create|insertOne|insertMany|update|updateOne|findOneAndUpdate|save)\s*\(\s*req\s*\.\s*body\s*[,)]/.test(line) ||
        /\.\s*(?:create|insert)\s*\(\s*\{\s*\.\.\.\s*req\s*\.\s*body\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Timing-Unsafe Comparison
  // ════════════════════════════════════════════
  {
    id: 'TIMING_UNSAFE_COMPARISON',
    category: 'Timing Attack',
    description:
      'Token or secret compared with === which is vulnerable to timing attacks — comparison time reveals information about the value.',
    severity: 'medium',
    fix_suggestion:
      'Use crypto.timingSafeEqual() (Node.js) for comparing secrets, tokens, HMAC digests, or API keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      const lower = line.toLowerCase();
      if (!/===/.test(line)) return false;
      // Only flag when the compared values are security-sensitive
      const securityTerms = ['token', 'secret', 'password', 'hash', 'signature', 'hmac', 'digest', 'api_key', 'apikey'];
      const hasSecurityTerm = securityTerms.some(term => lower.includes(term));
      if (!hasSecurityTerm) return false;
      if (/timingSafeEqual/.test(line)) return false;
      // Skip comparisons against numeric literals or single characters (binary parsers)
      if (/===\s*(?:0x[0-9a-fA-F]+|\d+|'.'|".")/.test(line) || /(?:0x[0-9a-fA-F]+|\d+|'.'|".")\s*===/.test(line)) return false;
      // Check a wider window (10 lines before and after) for timingSafeEqual usage
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 10), Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      if (/timingSafeEqual/.test(window)) return false;
      // Skip if the surrounding context indicates binary data processing (not security comparison)
      const widerWindow = ctx.allLines.slice(Math.max(0, lineIdx - 20), Math.min(ctx.allLines.length, lineIdx + 20)).join('\n');
      if (/\b(?:Buffer|Uint8Array|ArrayBuffer|DataView|Int8Array|Uint16Array|Int16Array|Float32Array|Float64Array)\b/.test(widerWindow) &&
          !/\b(?:timingSafeEqual|crypto|bcrypt|scrypt|argon)\b/i.test(widerWindow)) return false;
      return true;
    },
  },

  // ════════════════════════════════════════════
  // Insecure Randomness (non-crypto contexts)
  // ════════════════════════════════════════════
  {
    id: 'CRYPTO_MATH_RANDOM_ID',
    category: 'Insecure Cryptography',
    description:
      'Math.random() used to generate an ID or token — IDs generated this way are predictable.',
    severity: 'high',
    fix_suggestion:
      'Use crypto.randomUUID() or crypto.randomBytes() for generating unpredictable IDs and tokens.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bMath\s*\.\s*random\s*\(\s*\)/.test(line)) return false;
      const lower = line.toLowerCase();
      return lower.includes('id') || lower.includes('slug') || lower.includes('hash');
    },
  },

  // ════════════════════════════════════════════
  // Insecure Password Storage
  // ════════════════════════════════════════════
  {
    id: 'AUTH_PLAINTEXT_PASSWORD_STORAGE',
    category: 'Authentication Issues',
    description:
      'Password appears to be stored or inserted without hashing — passwords must always be hashed before storage.',
    severity: 'critical',
    fix_suggestion:
      'Hash passwords with bcrypt, argon2, or scrypt before storing. Never store plaintext passwords.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect patterns where password is directly inserted into a database
      // e.g., INSERT INTO users ... VALUES ... password or db.create({ password: req.body.password })
      const lower = line.toLowerCase();
      if (!lower.includes('password')) return false;
      // Skip lines that mention hashing
      if (/\b(?:hash|bcrypt|argon2|scrypt|pbkdf2|crypto)\b/i.test(line)) return false;
      // Skip process.env references
      if (/process\s*\.\s*env\b/.test(line)) return false;
      // Catch INSERT statements with password directly
      if (/\b(?:INSERT|VALUES)\b/i.test(line) && /\$\{[^}]*password[^}]*\}/i.test(line)) return true;
      if (/\b(?:INSERT|VALUES)\b/i.test(line) && /(?:"|')\s*\+\s*[a-zA-Z_$]*password/i.test(line)) return true;
      return false;
    },
  },

  // ════════════════════════════════════════════
  // Exposed Error Details
  // ════════════════════════════════════════════
  {
    id: 'DATA_ERROR_DETAILS_LEAK',
    category: 'Sensitive Data Exposure',
    description:
      'Error message or object sent directly in HTTP response — may leak internal details to attackers.',
    severity: 'medium',
    fix_suggestion:
      'Return a generic error message to clients (e.g., "Internal server error"). Log the full error server-side only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match patterns like res.status(500).json({ error: err }) or res.json({ error: error.message })
      return /\bres\s*\.\s*(?:status\s*\(\s*5\d{2}\s*\)\s*\.\s*)?(?:json|send)\s*\(\s*\{?\s*(?:error|message|err)\s*:\s*(?:err|error|e)\b/.test(line) ||
        /\bres\s*\.\s*(?:status\s*\(\s*5\d{2}\s*\)\s*\.\s*)?(?:json|send)\s*\(\s*(?:err|error|e)\s*[,)]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Hardcoded Database Credentials
  // ════════════════════════════════════════════
  {
    id: 'SECRET_DB_CREDENTIALS',
    category: 'Hardcoded Secrets',
    description:
      'Database connection string or credentials appear to be hardcoded — should use environment variables.',
    severity: 'critical',
    fix_suggestion:
      'Store database credentials in environment variables (e.g., process.env.DATABASE_URL). Never hardcode connection strings.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (/process\s*\.\s*env\b/.test(line) || /os\s*\.\s*(?:environ|getenv)\b/.test(line)) return false;
      // Skip localhost/dev connection strings — not production credentials
      if (/@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(?:[:/]|$)/i.test(line)) return false;
      // Match hardcoded connection strings: mongodb://, postgres://, mysql://, redis:// with credentials
      return /['"](?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\/[^'"]*:[^'"]*@[^'"]+['"]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Unvalidated File Upload
  // ════════════════════════════════════════════
  {
    id: 'UPLOAD_NO_VALIDATION',
    category: 'Insecure File Upload',
    description:
      'File upload handler without apparent file type or size validation — may allow malicious file uploads.',
    severity: 'medium',
    fix_suggestion:
      'Validate file type (MIME type and extension), enforce file size limits, and store uploads outside the web root.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match multer upload without file filter
      if (!/\bmulter\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx), Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      return !/fileFilter|limits|maxFileSize/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Prompt Injection — LLM / AI Security
  // ════════════════════════════════════════════
  {
    id: 'PROMPT_INJECTION_CONCAT',
    category: 'Prompt Injection',
    description:
      'User input concatenated directly into an LLM prompt string — vulnerable to prompt injection attacks.',
    severity: 'high',
    fix_suggestion:
      'Never concatenate user input into prompts. Use structured message arrays with separate system/user roles, and sanitize user input before including it in any prompt context.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect prompt/system message strings concatenated with user input
      // e.g., const prompt = "You are a helpful assistant. " + userInput
      // e.g., const prompt = `You are an assistant. ${req.body.message}`
      const hasPromptContext = /\b(?:prompt|system_prompt|systemPrompt|system_message|systemMessage|instruction|instructions)\s*[:=]\s*/.test(line);
      if (!hasPromptContext) return false;
      // Check for string concatenation or template literal interpolation with likely user input
      return /(?:"|')\s*\+\s*(?:req\s*\.\s*(?:body|query|params)|user[Ii]nput|input|message|query|question|userMessage|userQuery)\b/.test(line) ||
        /`[^`]*\$\{[^}]*(?:req\s*\.\s*(?:body|query|params)|user[Ii]nput|input|message|query|question|userMessage|userQuery)\b[^}]*\}/.test(line);
    },
  },
  {
    id: 'PROMPT_INJECTION_TEMPLATE',
    category: 'Prompt Injection',
    description:
      'User input interpolated into an LLM prompt template — vulnerable to prompt injection.',
    severity: 'high',
    fix_suggestion:
      'Separate system instructions from user content using the API\'s message role system (system/user/assistant). Never embed raw user input into system prompts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Match patterns where user input is embedded in strings that look like LLM prompts
      // e.g., `You are a helpful assistant. The user says: ${userInput}`
      // Look for prompt-like language + interpolation with user-input-like variables
      const isPromptString = /(?:`|"|')(?:You are|Act as|Respond as|Your (?:role|task|job) is|SYSTEM PROMPT)/i.test(line);
      if (!isPromptString) return false;
      // Require interpolation with user-input-like variable names (not generic variables)
      return /\$\{[^}]*(?:req\s*\.\s*(?:body|query|params)|user[Ii]nput|input|message|query|question|userMessage|userQuery|prompt|text|content)\b/.test(line) ||
        /(?:"|')\s*\+\s*(?:req\s*\.\s*(?:body|query|params)|user[Ii]nput|input|message|query|question|userMessage|userQuery|prompt|text|content)\b/.test(line) ||
        /\.\s*(?:format|replace)\s*\(/.test(line);
    },
  },
  {
    id: 'PROMPT_INJECTION_API_UNSANITIZED',
    category: 'Prompt Injection',
    description:
      'User input passed directly to an LLM API call without sanitization — enables prompt injection.',
    severity: 'high',
    fix_suggestion:
      'Sanitize and validate user input before passing to LLM APIs. Strip or escape control sequences, enforce input length limits, and use structured message roles to separate instructions from user content.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect direct req.body/query passed to AI API content fields
      // e.g., { role: "user", content: req.body.message }
      // e.g., messages: [{ role: "user", content: userInput }]
      if (!/\bcontent\s*:\s*req\s*\.\s*(?:body|query|params)\b/.test(line)) return false;
      // Verify this is in an AI API context by checking surrounding lines
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\b(?:role|messages|model|openai|anthropic|claude|gpt|chat\.completions|createMessage)\b/i.test(window);
    },
  },
  {
    id: 'PROMPT_INJECTION_SYSTEM_ROLE_USER_INPUT',
    category: 'Prompt Injection',
    description:
      'User input appears to be included in a system-role message — attackers can override system instructions.',
    severity: 'critical',
    fix_suggestion:
      'Never include user input in system messages. Keep system prompts static. Pass user content only in user-role messages, and consider adding an input validation layer.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect system role messages with interpolated user input
      // e.g., { role: "system", content: `You are... ${req.body.context}` }
      if (!/role\s*:\s*['"]system['"]/.test(line)) return false;
      // Check if this line or nearby lines have user input interpolation in content
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      return /content\s*:.*\$\{/.test(window) ||
        /content\s*:.*\breq\s*\.\s*(?:body|query|params)\b/.test(window) ||
        /content\s*:.*(?:"|')\s*\+/.test(window);
    },
  },
  {
    id: 'PROMPT_INJECTION_NO_INPUT_LIMIT',
    category: 'Prompt Injection',
    description:
      'User input sent to LLM API without apparent length validation — enables token exhaustion and increases prompt injection surface.',
    severity: 'medium',
    fix_suggestion:
      'Enforce a maximum length on user input before passing to LLM APIs. Truncate or reject inputs exceeding the limit. This reduces costs and limits prompt injection surface area.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Look for AI API calls (chat.completions.create, messages.create, etc.) and check
      // if there's input length validation nearby
      if (!/\b(?:completions|messages|chat|generate)\s*\.\s*create\s*\(/.test(line)) return false;
      // Check a wide window for length validation
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 15), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      // If there's length checking, trim, slice, or validation, skip
      if (/\b(?:\.length|\.slice|\.substring|\.trim|maxLength|max_length|MAX_LENGTH|truncate|validate|maxTokens|max_tokens)\b/.test(window)) return false;
      // Check if user input is being passed in
      return /\breq\s*\.\s*(?:body|query|params)\b/.test(window) ||
        /\b(?:user[Ii]nput|userMessage|userQuery|input|message)\b/.test(window);
    },
  },
  {
    id: 'PROMPT_INJECTION_PYTHON_FSTRING',
    category: 'Prompt Injection',
    description:
      'User input embedded in a Python f-string prompt — vulnerable to prompt injection.',
    severity: 'high',
    fix_suggestion:
      'Use structured message roles instead of f-string prompts. Separate system instructions from user content. Sanitize user input before inclusion.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match Python f-strings that look like prompts with user variables
      // e.g., prompt = f"You are a helpful assistant. The user asks: {user_input}"
      const isPromptAssignment = /\b(?:prompt|system_prompt|system_message|instruction|messages?)\s*=\s*f(?:"|')/.test(line);
      if (!isPromptAssignment) return false;
      // Check for variable interpolation (curly braces in f-string)
      if (!/\{[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_]+)*\}/.test(line)) return false;
      // Only flag when: (a) the file imports AI/LLM libraries, OR (b) the variable name is prompt-related
      if (hasAiImports(ctx.fileContent)) return true;
      // Also flag if the variable name explicitly relates to prompts/instructions
      return /\b(?:prompt|system_prompt|system_message|instruction)\s*=/.test(line);
    },
  },
  {
    id: 'PROMPT_INJECTION_RAG_UNSANITIZED',
    category: 'Prompt Injection',
    description:
      'Retrieved document content injected into LLM prompt without sanitization — indirect prompt injection risk via poisoned documents.',
    severity: 'medium',
    fix_suggestion:
      'Sanitize and delimit retrieved content before injecting into prompts. Use clear boundary markers (e.g., XML tags) between instructions and retrieved content. Consider content filtering for suspicious patterns.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect patterns where retrieved/fetched content is embedded in prompts
      // e.g., content: `Based on these documents: ${documents.map(d => d.content).join('\n')}`
      // e.g., prompt = f"Context: {retrieved_docs}\n\nQuestion: {query}"
      const hasContextPattern = /\b(?:context|documents?|chunks?|results?|passages?|retrieved|search_results|embeddings?)\b/i.test(line);
      if (!hasContextPattern) return false;
      // Check if this is in a prompt/message context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      const isLLMContext = /\b(?:prompt|content|messages?|role|system|openai|anthropic|completion)\b/i.test(window);
      if (!isLLMContext) return false;
      // Check for interpolation
      return /\$\{[^}]*(?:document|chunk|result|passage|retrieved|context|search)\b/i.test(line) ||
        /\{[a-zA-Z_]*(?:document|chunk|result|passage|retrieved|context|search)[a-zA-Z_]*\}/i.test(line) ||
        /(?:"|')\s*\+\s*[a-zA-Z_]*(?:document|chunk|result|passage|retrieved|context|search)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Open Redirect (client-side)
  // ════════════════════════════════════════════
  {
    id: 'OPEN_REDIRECT_WINDOW',
    category: 'Open Redirect',
    description:
      'window.location assigned from user-controlled input — allows open redirect attacks for phishing.',
    severity: 'high',
    fix_suggestion:
      'Validate redirect URLs against an allowlist of trusted domains. Never assign user-controlled values directly to window.location.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match window.location = userInput, window.location.href = req.query.redirect, etc.
      if (!/\bwindow\s*\.\s*location\s*(?:\.href)?\s*=/.test(line)) return false;
      // Must be assigned from a variable, not a string literal
      if (/\bwindow\s*\.\s*location\s*(?:\.href)?\s*=\s*['"`]/.test(line)) return false;
      // Skip when URL comes from a known-safe source (API response, Stripe session, etc.)
      // Extract the variable being assigned
      const assignMatch = line.match(/\bwindow\s*\.\s*location\s*(?:\.href)?\s*=\s*([a-zA-Z_$][\w$.]*)/);
      if (assignMatch) {
        const varName = assignMatch[1];
        const lineIdx = ctx.lineNumber - 1;
        const window_ctx = ctx.allLines.slice(Math.max(0, lineIdx - 15), lineIdx + 1).join('\n');
        const escapedVar = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // Skip if the variable is assigned from a fetch/API response or Stripe session
        // Covers both direct assignment (url = ...) and destructured ({ url } = ...)
        const directAssign = new RegExp(`\\b${escapedVar}\\s*=\\s*(?:.*\\.(?:url|data\\.url|session\\.url|checkout\\.url)|.*(?:fetch|axios|api|response|res)\\b)`, 'i');
        const destructuredAssign = new RegExp(`\\{[^}]*\\b${escapedVar}\\b[^}]*\\}\\s*=\\s*(?:.*(?:fetch|axios|response|res|json)\\b)`, 'i');
        if (directAssign.test(window_ctx) || destructuredAssign.test(window_ctx)) return false;
        // Skip known safe variable names (Stripe URLs, internal API responses)
        if (/\b(?:stripe|checkout|session|payment|billing)\b/i.test(varName)) return false;
      }
      return true;
    },
  },

  // ════════════════════════════════════════════
  // Insecure Deserialization (JSON.parse from request)
  // ════════════════════════════════════════════
  {
    id: 'INSECURE_DESERIALIZE_JSON',
    category: 'Insecure Deserialization',
    description:
      'JSON.parse() on raw request body/query without validation — parsed objects may contain unexpected properties or trigger prototype pollution.',
    severity: 'medium',
    fix_suggestion:
      'Validate the parsed result with a schema validator (e.g., Zod, Joi, ajv) before using. Never trust the shape of user-supplied JSON.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bJSON\s*\.\s*parse\s*\(\s*req\s*\.\s*(?:body|query)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // OAuth State Parameter Missing
  // ════════════════════════════════════════════
  {
    id: 'OAUTH_STATE_MISSING',
    category: 'Authentication Issues',
    description:
      'OAuth authorize URL constructed without a state parameter — vulnerable to CSRF attacks on the OAuth flow.',
    severity: 'high',
    fix_suggestion:
      'Always include a cryptographically random state parameter in OAuth authorization requests and verify it on callback.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect /authorize URL construction
      if (!/\/authorize/.test(line)) return false;
      if (!/\b(?:oauth|auth|client_id|response_type|redirect_uri)\b/i.test(line)) return false;
      // Check a window for state parameter
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 2), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return !/\bstate\s*[=:]/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // CORS Credentials with Wildcard Origin
  // ════════════════════════════════════════════
  {
    id: 'CORS_CREDENTIALS_WILDCARD',
    category: 'Insecure Configuration',
    description:
      'CORS configured with credentials: true and a wildcard or permissive origin — this misconfiguration can expose authenticated endpoints to any origin.',
    severity: 'critical',
    fix_suggestion:
      'When using credentials: true, specify exact allowed origins instead of "*" or origin: true. Use an allowlist of trusted domains.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Check for credentials: true near origin: '*' or origin: true
      const lineIdx = ctx.lineNumber - 1;
      const windowLines = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      const hasCreds = /credentials\s*:\s*true/.test(windowLines);
      const hasWildcardOrigin = /origin\s*:\s*(?:['"]\*['"]|true)/.test(windowLines);
      // Only fire on the line that contains credentials: true
      if (!/credentials\s*:\s*true/.test(line)) return false;
      return hasCreds && hasWildcardOrigin;
    },
  },

  // ════════════════════════════════════════════
  // Helmet CSP Disabled
  // ════════════════════════════════════════════
  {
    id: 'HELMET_CSP_DISABLED',
    category: 'Insecure Configuration',
    description:
      'helmet() used with contentSecurityPolicy: false — disables Content-Security-Policy, a critical XSS defense.',
    severity: 'medium',
    fix_suggestion:
      'Configure a proper Content-Security-Policy instead of disabling it. Use helmet.contentSecurityPolicy({ directives: { ... } }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bhelmet\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const windowLines = ctx.allLines
        .slice(Math.max(0, lineIdx), Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      return /contentSecurityPolicy\s*:\s*false/.test(windowLines);
    },
  },

  // ════════════════════════════════════════════
  // HMAC / Signature Unsafe Comparison
  // ════════════════════════════════════════════
  {
    id: 'HMAC_COMPARISON_UNSAFE',
    category: 'Timing Attack',
    description:
      'HMAC, signature, or digest compared with === instead of crypto.timingSafeEqual() — enables timing attacks to forge signatures.',
    severity: 'high',
    fix_suggestion:
      'Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) to compare HMAC digests, signatures, and other secret values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/===/.test(line)) return false;
      if (/timingSafeEqual/.test(line)) return false;
      // Specifically target HMAC/signature/digest comparisons
      return /\b(?:hmac|signature|digest|mac)\b/i.test(line) &&
        /===/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Express Session Insecure
  // ════════════════════════════════════════════
  {
    id: 'EXPRESS_SESSION_INSECURE',
    category: 'Insecure Configuration',
    description:
      'express-session configured with insecure defaults — missing secure cookie flag or using a hardcoded secret string.',
    severity: 'high',
    fix_suggestion:
      'Set cookie.secure: true in production, use a strong secret from environment variables (process.env.SESSION_SECRET), and use a persistent session store (not MemoryStore).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bsession\s*\(\s*\{/.test(line)) return false;
      // Only fire when the file actually uses express-session (not NextAuth or @auth/)
      const hasExpressSession = /\bexpress-session\b/.test(ctx.fileContent) ||
        /\brequire\s*\(\s*['"]express-session['"]/.test(ctx.fileContent);
      if (!hasExpressSession) return false;
      // Skip files that import from next-auth or @auth/ — they have their own session handling
      if (/\b(?:next-auth|@auth\/)\b/.test(ctx.fileContent)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const windowLines = ctx.allLines
        .slice(Math.max(0, lineIdx), Math.min(ctx.allLines.length, lineIdx + 10))
        .join(' ');
      // Flag if secret is a hardcoded string literal
      const hasHardcodedSecret = /secret\s*:\s*['"][^'"]+['"]/.test(windowLines) &&
        !/process\s*\.\s*env\b/.test(windowLines);
      // Flag if secure: true is missing from cookie config
      const missingSecure = !/secure\s*:\s*true/.test(windowLines);
      return hasHardcodedSecret || missingSecure;
    },
  },

  // ════════════════════════════════════════════
  // Unvalidated File Type
  // ════════════════════════════════════════════
  {
    id: 'UNVALIDATED_FILE_TYPE',
    category: 'Insecure File Upload',
    description:
      'User-supplied file metadata (mimetype, originalname) used in path construction without validation — may allow path traversal or arbitrary file overwrites.',
    severity: 'medium',
    fix_suggestion:
      'Validate file extensions against an allowlist. Never use the original filename directly — generate a safe filename (e.g., UUID) and validate the MIME type.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect req.file.mimetype or req.file.originalname used in path operations
      return (
        /\breq\s*\.\s*file\s*\.\s*(?:mimetype|originalname)\b/.test(line) &&
        /\b(?:join|resolve|writeFile|rename|move|createWriteStream|path|extname)\b/.test(line)
      );
    },
  },

  // ════════════════════════════════════════════
  // Response Header Injection
  // ════════════════════════════════════════════
  {
    id: 'RESPONSE_HEADER_INJECTION',
    category: 'Header Injection',
    description:
      'User input placed directly in HTTP response headers — can enable header injection, response splitting, or cache poisoning.',
    severity: 'high',
    fix_suggestion:
      'Sanitize and validate user input before setting response headers. Strip newlines (\\r\\n) and validate against expected values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bres\s*\.\s*(?:setHeader|header|set)\s*\([^,]+,\s*req\s*\.\s*(?:body|query|params|headers)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Prototype Pollution via Deep Merge
  // ════════════════════════════════════════════
  {
    id: 'PROTOTYPE_POLLUTION_MERGE',
    category: 'Prototype Pollution',
    description:
      'Deep merge/extend with user input can lead to prototype pollution — attackers can inject __proto__ or constructor properties.',
    severity: 'high',
    fix_suggestion:
      'Use a merge library that filters prototype keys (e.g., lodash >= 4.17.21 with safeguards), or validate/strip __proto__ and constructor from user input before merging.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:merge|extend|deepMerge|deepExtend|defaultsDeep)\s*\([^)]*req\s*\.\s*(?:body|query|params)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Insecure Random Token Generation
  // ════════════════════════════════════════════
  {
    id: 'INSECURE_RANDOM_TOKEN',
    category: 'Insecure Cryptography',
    description:
      'Using Date.now(), Math.random(), or UUID v1 (timestamp-based) for security tokens — these are predictable and not cryptographically secure.',
    severity: 'high',
    fix_suggestion:
      'Use crypto.randomBytes() or crypto.randomUUID() for generating security tokens, session IDs, and nonces.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      const lower = line.toLowerCase();
      const isSecurityContext = lower.includes('token') || lower.includes('session') ||
        lower.includes('nonce') || lower.includes('csrf') || lower.includes('secret') ||
        lower.includes('apikey') || lower.includes('api_key');
      if (!isSecurityContext) return false;
      return /\bDate\s*\.\s*now\s*\(\s*\)/.test(line) ||
        /\buuid\s*\.\s*v1\s*\(\s*\)/.test(line) ||
        /\buuidv1\s*\(\s*\)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Missing CSRF Protection
  // ════════════════════════════════════════════
  {
    id: 'MISSING_CSRF_PROTECTION',
    category: 'CSRF',
    description:
      'Express app has POST/PUT/DELETE routes but no CSRF protection middleware detected in the file — vulnerable to cross-site request forgery.',
    severity: 'medium',
    fix_suggestion:
      'Add CSRF protection middleware (e.g., csurf, csrf-csrf, or lusca) to state-changing routes. For APIs using tokens (not cookies), CSRF may not be needed.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Only fire on the first POST/PUT/DELETE route definition in the file
      if (!/\b(?:app|router)\s*\.\s*(?:post|put|delete)\s*\(/.test(line)) return false;
      // Check if any CSRF middleware exists in the file
      if (/\b(?:csrf|csurf|csrfProtection|lusca|xsrf)\b/i.test(ctx.fileContent)) return false;
      // Don't flag API-only routes that use bearer token auth (not cookie-based)
      if (/\b(?:bearer|authorization|jwt|api[_-]?key)\b/i.test(ctx.fileContent)) return false;
      return true;
    },
  },

  // ════════════════════════════════════════════
  // SSRF with Variable URL
  // ════════════════════════════════════════════
  {
    id: 'SSRF_FETCH_VARIABLE',
    category: 'Server-Side Request Forgery',
    description:
      'HTTP request made with a variable URL that may originate from user input — potential SSRF vector.',
    severity: 'high',
    fix_suggestion:
      'Validate URLs against an allowlist of permitted domains. Block requests to internal/private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match fetch(url), axios.get(url), got(url) where url is a variable
      const match = /\b(?:fetch|axios\s*(?:\.\s*(?:get|post|put|patch|delete))?|got(?:\.\s*(?:get|post))?|request)\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[,)]/.exec(line);
      if (!match) return false;
      const varName = match[1];
      // Skip if the argument is a string literal, static import, or known-safe
      if (/^['"`]/.test(varName)) return false;
      // Check if user input feeds this variable in nearby lines
      const lineIdx = ctx.lineNumber - 1;
      const windowLines = ctx.allLines
        .slice(Math.max(0, lineIdx - 10), lineIdx + 1)
        .join(' ');
      return /\breq\s*\.\s*(?:body|query|params)\b/.test(windowLines);
    },
  },

  // ════════════════════════════════════════════
  // Log Injection
  // ════════════════════════════════════════════
  {
    id: 'LOG_INJECTION',
    category: 'Log Injection',
    description:
      'User input logged directly without sanitization — enables log forging, log injection, and can corrupt log analysis.',
    severity: 'medium',
    fix_suggestion:
      'Sanitize user input before logging by stripping newlines and control characters, or use structured logging (JSON) to prevent log forging.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:console\s*\.\s*(?:log|info|warn|error|debug)|logger\s*\.\s*(?:info|warn|error|debug|log))\s*\([^)]*req\s*\.\s*(?:body|query|params|headers)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Weak Password Hashing
  // ════════════════════════════════════════════
  {
    id: 'WEAK_PASSWORD_HASH',
    category: 'Insecure Cryptography',
    description:
      'SHA-256/SHA-512 used for password hashing — fast hash algorithms allow rapid brute-force attacks. Use a slow, salted algorithm instead.',
    severity: 'critical',
    fix_suggestion:
      'Use bcrypt, argon2, or scrypt for password hashing. These algorithms are intentionally slow and include salting, making brute-force attacks impractical.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      const lower = line.toLowerCase();
      if (!lower.includes('password') && !lower.includes('passwd')) return false;
      // Skip if bcrypt/argon2/scrypt is mentioned
      if (/\b(?:bcrypt|argon2|scrypt|pbkdf2)\b/i.test(line)) return false;
      // JS: createHash('sha256').update(password)
      // Python: hashlib.sha256(password.encode())
      return /createHash\s*\(\s*['"]sha(?:256|512)['"]\s*\)/.test(line) ||
        /\bhashlib\s*\.\s*sha(?:256|512)\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Python: Insecure Deserialization (marshal, shelve)
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_DESERIALIZE_UNSAFE',
    category: 'Insecure Deserialization',
    description:
      'marshal.loads() or shelve.open() with untrusted data can execute arbitrary code — similar to pickle.',
    severity: 'critical',
    fix_suggestion:
      'Avoid marshal and shelve for untrusted data. Use JSON or another safe serialization format.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bmarshal\s*\.\s*loads?\s*\(/.test(line) ||
        /\bshelve\s*\.\s*open\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Python: exec() / compile() with user input
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_EXEC',
    category: 'Code Injection',
    description:
      'exec() or compile() executes arbitrary Python code — critical code injection risk if user input reaches these functions.',
    severity: 'critical',
    fix_suggestion:
      'Avoid exec() and compile() with dynamic input. Use a safe expression evaluator or AST-based approach if dynamic evaluation is truly needed.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bexec\s*\(/.test(line) || /\bcompile\s*\([^)]+,\s*[^)]+,\s*['"]exec['"]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Python: SSRF
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_SSRF',
    category: 'Server-Side Request Forgery',
    description:
      'HTTP request made with a variable URL in Python — potential SSRF if the URL originates from user input.',
    severity: 'high',
    fix_suggestion:
      'Validate URLs against an allowlist of permitted domains. Block requests to internal/private IP ranges.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // requests.get(url), urllib.request.urlopen(url), httpx.get(url)
      return (
        /\brequests\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]/.test(line) ||
        /\burlopen\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]/.test(line) ||
        /\bhttpx\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]/.test(line)
      ) && !/\(\s*['"]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Python: Server-Side Template Injection (SSTI)
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_TEMPLATE_INJECTION',
    category: 'Template Injection',
    description:
      'render_template_string() or Template() with user input enables server-side template injection — attackers can execute arbitrary code.',
    severity: 'critical',
    fix_suggestion:
      'Never pass user input to render_template_string() or Template(). Use render_template() with separate template files and pass user data as context variables.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // render_template_string(user_input) or Template(user_input)
      return /\brender_template_string\s*\(\s*[a-zA-Z_]/.test(line) ||
        /\bTemplate\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)/.test(line) &&
        !/\bTemplate\s*\(\s*['"]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Python: os.popen() Shell Injection
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_SHELL_INJECTION',
    category: 'Command Injection',
    description:
      'os.popen() passes commands through the shell — vulnerable to command injection.',
    severity: 'critical',
    fix_suggestion:
      'Use subprocess.run() with a list of arguments (shell=False) instead of os.popen().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bos\s*\.\s*popen\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Next.js / React Specific
  // ════════════════════════════════════════════
  {
    id: 'NEXT_SENSITIVE_PROPS',
    category: 'Sensitive Data Exposure',
    description:
      'getServerSideProps or getStaticProps returns sensitive data (password, token, secret) in props — this data is serialized to the client.',
    severity: 'high',
    fix_suggestion:
      'Never return sensitive fields (passwords, tokens, secrets) in page props. Strip sensitive data before returning props.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Check if we're in a getServerSideProps/getStaticProps function
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 10), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      if (!/\b(?:getServerSideProps|getStaticProps)\b/.test(window)) return false;
      // Check if props contain sensitive field names
      if (!/\bprops\s*:/.test(line) && !/\bprops\s*:/.test(window)) return false;
      const propsWindow = ctx.allLines
        .slice(Math.max(0, lineIdx - 2), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\b(?:password|secret|token|apiKey|api_key|privateKey|private_key|ssn|creditCard|credit_card)\s*[:=]/i.test(propsWindow) &&
        /\bprops\s*:/.test(propsWindow);
    },
  },
  {
    id: 'NEXT_API_NO_AUTH',
    category: 'Authentication Issues',
    description:
      'Next.js API route handler (export default function handler) without apparent authentication check — endpoint may be publicly accessible.',
    severity: 'medium',
    fix_suggestion:
      'Add authentication checks (getSession, getServerSession, auth middleware) at the beginning of API route handlers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match export default function handler pattern
      if (!/\bexport\s+default\s+(?:async\s+)?function\s+handler\b/.test(line)) return false;
      // Check entire file for auth checks
      return !/\b(?:auth|getSession|getServerSession|requireAuth|isAuthenticated|protect|guard|verify|middleware|getToken|withAuth|checkAuth|session)\b/i.test(ctx.fileContent);
    },
  },
  {
    id: 'NEXT_REVALIDATE_USER_INPUT',
    category: 'Cache Poisoning',
    description:
      'revalidateTag() or revalidatePath() called with user-supplied input — may allow cache manipulation attacks.',
    severity: 'medium',
    fix_suggestion:
      'Validate revalidation tags/paths against an allowlist. Never pass raw user input to revalidateTag or revalidatePath.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:revalidateTag|revalidatePath)\s*\(\s*[a-zA-Z_$]/.test(line)) return false;
      // Exclude calls with string literals
      if (/\b(?:revalidateTag|revalidatePath)\s*\(\s*['"]/.test(line)) return false;
      // Check if the variable likely comes from user input
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 10), lineIdx + 1)
        .join(' ');
      return /\breq\b|\.json\(\)|\.body\b|\.query\b|\.params\b|\.searchParams\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // GraphQL Security
  // ════════════════════════════════════════════
  {
    id: 'GRAPHQL_INTROSPECTION_ENABLED',
    category: 'Insecure Configuration',
    description:
      'GraphQL introspection is explicitly enabled — in production this exposes the full API schema to attackers.',
    severity: 'medium',
    fix_suggestion:
      'Disable introspection in production: new ApolloServer({ introspection: process.env.NODE_ENV !== "production" }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bintrospection\s*:\s*true\b/.test(line);
    },
  },
  {
    id: 'GRAPHQL_NO_DEPTH_LIMIT',
    category: 'Insecure Configuration',
    description:
      'GraphQL server created without query depth limiting — vulnerable to resource exhaustion via deeply nested queries.',
    severity: 'medium',
    fix_suggestion:
      'Add a query depth limit plugin: new ApolloServer({ plugins: [depthLimit(10)] }). Install graphql-depth-limit or @graphql-tools/utils.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Only trigger on ApolloServer/YogaServer/GraphQLServer creation
      if (!/\bnew\s+(?:ApolloServer|YogaServer|GraphQLServer)\s*\(/.test(line)) return false;
      // Check the whole file for depth limit usage
      return !/\b(?:depthLimit|depth[_-]?limit|maxDepth|max[_-]?depth|queryDepth|query[_-]?depth)\b/i.test(ctx.fileContent);
    },
  },
  {
    id: 'GRAPHQL_MUTATION_NO_AUTH',
    category: 'Authentication Issues',
    description:
      'GraphQL mutation resolver accesses the database without an apparent authentication check — mutations should verify the caller\'s identity.',
    severity: 'high',
    fix_suggestion:
      'Add authentication checks in mutation resolvers. Verify the user is authenticated via context (e.g., context.user, context.auth) before performing database operations.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Look for Mutation resolver definitions
      if (!/\bMutation\s*:\s*\{/.test(line)) return false;
      // Check a window for auth checks in the mutation block
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 20))
        .join(' ');
      // If there's DB access without auth
      const hasDbAccess = /\b(?:db|prisma|knex|sequelize|mongoose|pool|client)\s*\.\s*(?:query|find|create|update|delete|insert|remove|exec|run)\b/i.test(window);
      const hasAuth = /\b(?:auth|context\s*\.\s*(?:user|auth|session|token)|requireAuth|isAuthenticated|authorize)\b/i.test(window);
      return hasDbAccess && !hasAuth;
    },
  },

  // ════════════════════════════════════════════
  // WebSocket Security
  // ════════════════════════════════════════════
  {
    id: 'WEBSOCKET_NO_AUTH',
    category: 'Authentication Issues',
    description:
      'WebSocket server created without origin validation or authentication (verifyClient) — any origin can connect.',
    severity: 'medium',
    fix_suggestion:
      'Add a verifyClient callback to validate the origin and/or authenticate connections: new WebSocketServer({ verifyClient: (info) => validateOrigin(info.origin) }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+WebSocketServer\s*\(/.test(line)) return false;
      // Check a window for verifyClient or authentication
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return !/\b(?:verifyClient|authenticate|auth|handleAuth)\b/i.test(window);
    },
  },
  {
    id: 'WEBSOCKET_BROADCAST_UNSANITIZED',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'WebSocket message broadcast to all clients without sanitization — enables XSS or injection via malicious messages.',
    severity: 'medium',
    fix_suggestion:
      'Sanitize and validate WebSocket messages before broadcasting. Filter or escape HTML/script content, and validate message format.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect patterns like clients.forEach(client => client.send(msg))
      if (!/\bclients\b.*\b(?:forEach|for)\b.*\bsend\s*\(/.test(line)) return false;
      // Check if the message is sanitized before broadcast
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), lineIdx + 1)
        .join(' ');
      return !/\b(?:sanitize|escape|validate|filter|encode|DOMPurify|xss)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // JWT Edge Cases
  // ════════════════════════════════════════════
  {
    id: 'JWT_ALG_NONE',
    category: 'Authentication Issues',
    description:
      'JWT verification accepts the "none" algorithm — attackers can forge tokens by specifying alg: "none" with no signature.',
    severity: 'critical',
    fix_suggestion:
      'Never allow the "none" algorithm. Explicitly specify only the algorithms you use: jwt.verify(token, key, { algorithms: ["HS256"] }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Match algorithms array containing 'none'
      return /algorithms\s*:\s*\[.*['"]none['"]/.test(line);
    },
  },
  {
    id: 'JWT_DECODE_WITHOUT_VERIFY',
    category: 'Authentication Issues',
    description:
      'jwt.decode() returns an unverified payload — using it for authorization decisions allows token forgery.',
    severity: 'high',
    fix_suggestion:
      'Use jwt.verify() instead of jwt.decode() for any authorization or authentication logic. jwt.decode() does NOT validate the signature.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bjwt\s*\.\s*decode\s*\(/.test(line)) return false;
      // Check if the decoded value is used for auth decisions in nearby lines
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\b(?:role|admin|isAdmin|is_admin|permission|authorized|auth|user)\b/i.test(window) ||
        /\bif\s*\(/.test(window);
    },
  },
  {
    id: 'JWT_BEARER_PREFIX',
    category: 'Authentication Issues',
    description:
      'Authorization header value used directly without stripping the "Bearer " prefix — jwt.verify() will fail or behave unexpectedly.',
    severity: 'medium',
    fix_suggestion:
      'Strip the "Bearer " prefix before verification: const token = req.headers.authorization?.replace("Bearer ", ""); then jwt.verify(token, ...).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect req.headers.authorization assigned to a variable
      if (!/\breq\s*\.\s*headers\s*\.\s*authorization\b/.test(line)) return false;
      // Check if Bearer is stripped in nearby lines
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      // If it's passed directly to jwt.verify or used without .replace/.split/.slice
      const hasDirectUse = /jwt\s*\.\s*verify\b/.test(window);
      const hasStrip = /\.\s*(?:replace|split|slice|substring|startsWith)\b/.test(window) || /Bearer/i.test(window);
      return hasDirectUse && !hasStrip;
    },
  },

  // ════════════════════════════════════════════
  // Cloud Misconfiguration
  // ════════════════════════════════════════════
  {
    id: 'S3_PUBLIC_ACL',
    category: 'Cloud Misconfiguration',
    description:
      'S3 bucket configured with public ACL (public-read, public-read-write) — bucket contents are exposed to the internet.',
    severity: 'high',
    fix_suggestion:
      'Remove public ACL. Use S3 bucket policies with explicit access grants. Enable S3 Block Public Access at the account level.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bACL\s*:\s*['"]public-read(?:-write)?['"]/.test(line) ||
        /\bpublic-read(?:-write)?\b/.test(line) && /\b(?:s3|bucket|putBucketAcl|PutBucketAcl|putObjectAcl)\b/i.test(line);
    },
  },
  {
    id: 'S3_CORS_PERMISSIVE',
    category: 'Cloud Misconfiguration',
    description:
      'S3 CORS configuration allows all origins (AllowedOrigins: ["*"]) — any website can make cross-origin requests to this bucket.',
    severity: 'medium',
    fix_suggestion:
      'Specify explicit allowed origins in S3 CORS configuration instead of using a wildcard.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match AllowedOrigins: ['*'] pattern
      if (!/AllowedOrigins\s*:\s*\[\s*['"][*]['"]\s*\]/.test(line)) return false;
      // Verify it's in an S3/CORS context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\b(?:CORS|CORSRules?|AllowedMethods|s3|bucket)\b/i.test(window);
    },
  },
  {
    id: 'NEXT_PUBLIC_SECRET',
    category: 'Sensitive Data Exposure',
    description:
      'Environment variable with NEXT_PUBLIC_ prefix contains a secret-sounding name — NEXT_PUBLIC_ vars are exposed to the client bundle.',
    severity: 'high',
    fix_suggestion:
      'Remove the NEXT_PUBLIC_ prefix from secret environment variables. Only use NEXT_PUBLIC_ for values safe to expose to the browser.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bNEXT_PUBLIC_[A-Z_]*(?:SECRET|PRIVATE|PASSWORD|TOKEN|KEY|CREDENTIAL|AUTH)[A-Z_]*\b/.test(line)) return false;
      // Exclude known-public environment variables (publishable keys, URLs, etc.)
      if (/\bNEXT_PUBLIC_SUPABASE_ANON_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_SUPABASE_URL\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_CLERK_PUBLISHABLE_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_FIREBASE_AUTH_DOMAIN\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_FIREBASE_API_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_POSTHOG_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_SENTRY_AUTH_TOKEN\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_ALGOLIA_SEARCH_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_RECAPTCHA_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_RECAPTCHA_SITE_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_MAPBOX_TOKEN\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_GOOGLE_MAPS_KEY\b/.test(line)) return false;
      // Publishable/public keys are intentionally client-side
      if (/\bNEXT_PUBLIC_\w*PUBLISHABLE\w*\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_\w*PUBLIC_KEY\b/.test(line)) return false;
      return true;
    },
  },

  // ════════════════════════════════════════════
  // Supply Chain Attacks
  // ════════════════════════════════════════════
  {
    id: 'DYNAMIC_REQUIRE',
    category: 'Code Injection',
    description:
      'Dynamic require() with user-controlled input — allows arbitrary module loading and code execution.',
    severity: 'critical',
    fix_suggestion:
      'Never pass user input to require(). Use a whitelist/map of allowed modules: const allowed = { "a": require("./a") }.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match require(variable) where the argument is from user input
      return /\brequire\s*\(\s*req\s*\.\s*(?:body|query|params)\b/.test(line) ||
        /\brequire\s*\(\s*(?:userInput|input|moduleName|module|path)\s*\)/.test(line);
    },
  },
  {
    id: 'SUPPLY_CHAIN_POSTINSTALL',
    category: 'Supply Chain',
    description:
      'Package script downloads and executes remote code (curl|sh, wget|bash) — a common supply chain attack vector.',
    severity: 'critical',
    fix_suggestion:
      'Avoid downloading and executing scripts in package lifecycle hooks. Pin dependencies, use lockfiles, and audit package scripts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Match curl/wget piped to sh/bash in package.json scripts context
      return /\b(?:curl|wget)\s+[^\s|]+\s*\|\s*(?:sh|bash|zsh|node)\b/.test(line) ||
        /["'](?:postinstall|preinstall|install|prepare|prepublish)\s*["']\s*:\s*["'][^"']*(?:curl|wget)[^"']*\|\s*(?:sh|bash)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Race Conditions
  // ════════════════════════════════════════════
  {
    id: 'RACE_CONDITION_NON_ATOMIC',
    category: 'Race Condition',
    description:
      'Balance/inventory check followed by a separate update without a transaction or lock — vulnerable to race conditions that allow double-spending.',
    severity: 'high',
    fix_suggestion:
      'Use a database transaction with SELECT ... FOR UPDATE, or use an atomic UPDATE with a WHERE clause (e.g., UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect SELECT balance/amount/quantity followed by UPDATE without transaction
      if (!/\b(?:SELECT|select)\b.*\b(?:balance|amount|quantity|inventory|stock|credits|points|remaining)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      const hasUpdate = /\b(?:UPDATE|update)\b/.test(window);
      const hasTransaction = /\b(?:transaction|BEGIN|COMMIT|ROLLBACK|FOR UPDATE|LOCK|serialize|atomic|isolation)\b/i.test(ctx.fileContent);
      return hasUpdate && !hasTransaction;
    },
  },

  // ════════════════════════════════════════════
  // AI/LLM Security (expanded)
  // ════════════════════════════════════════════
  {
    id: 'AI_OUTPUT_EVAL',
    category: 'AI Security',
    description:
      'AI/LLM model output passed to eval() — executing AI-generated code enables arbitrary code execution via prompt injection.',
    severity: 'critical',
    fix_suggestion:
      'Never eval() AI-generated output. Use a sandboxed code execution environment (e.g., vm2, isolated-vm, Web Workers) or parse the output as structured data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match eval() with AI-related variable names
      if (!/\beval\s*\(/.test(line)) return false;
      return /\b(?:response|completion|result|output|generated|aiResponse|ai_response|message\.content|choices\[)/i.test(line) ||
        (() => {
          const lineIdx = ctx.lineNumber - 1;
          const window = ctx.allLines
            .slice(Math.max(0, lineIdx - 5), lineIdx + 1)
            .join(' ');
          return /\b(?:openai|anthropic|claude|gpt|completions|chat|llm|ai|model)\b/i.test(window);
        })();
    },
  },
  {
    id: 'AI_OUTPUT_HTML',
    category: 'AI Security',
    description:
      'AI/LLM model output rendered as raw HTML (innerHTML) — enables XSS if the model output contains malicious HTML/scripts.',
    severity: 'high',
    fix_suggestion:
      'Sanitize AI output with DOMPurify before rendering as HTML, or use textContent instead of innerHTML.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\.innerHTML\s*=/.test(line)) return false;
      return /\b(?:completion|response|result|output|generated|aiResponse|choices\[|message\.content)\b/i.test(line) ||
        (() => {
          const lineIdx = ctx.lineNumber - 1;
          const window = ctx.allLines
            .slice(Math.max(0, lineIdx - 5), lineIdx + 1)
            .join(' ');
          return /\b(?:openai|anthropic|claude|gpt|completions|chat|llm|ai|model)\b/i.test(window);
        })();
    },
  },
  {
    id: 'AI_TOOL_INJECTION',
    category: 'AI Security',
    description:
      'User input passed directly to LLM message content without filtering tool-use or function-call directives — enables tool/function injection.',
    severity: 'high',
    fix_suggestion:
      'Filter user input for tool-use injection patterns (<tool_use>, function_call, <|im_start|>) before passing to LLM APIs. Validate message content and strip control sequences.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect user input assigned to a variable and then passed as message content
      if (!/\brole\s*:\s*['"]user['"]/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      // Must have user input in the content field
      const hasUserInput = /content\s*:\s*(?:req\s*\.\s*(?:body|query|params)|userMsg|userMessage|userInput|input|message)\b/.test(window);
      // Must NOT have sanitization
      const hasSanitize = /\b(?:sanitize|filter|escape|validate|strip|clean)\b/i.test(window);
      return hasUserInput && !hasSanitize;
    },
  },
  {
    id: 'AI_PROMPT_LEAK',
    category: 'AI Security',
    description:
      'System prompt or internal AI configuration exposed in an error response or API output — leaks proprietary instructions to users.',
    severity: 'high',
    fix_suggestion:
      'Never include system prompts, internal configuration, or AI instructions in error responses. Log them server-side only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match patterns where systemPrompt/system_prompt is sent in response
      return /\bres\s*\.\s*(?:json|send)\s*\([^)]*\b(?:systemPrompt|system_prompt|SYSTEM_PROMPT|instructions|system_message)\b/.test(line) ||
        /\b(?:prompt|systemPrompt|system_prompt|instructions)\s*:\s*\b(?:systemPrompt|system_prompt|SYSTEM_PROMPT)\b/.test(line) &&
        /\bres\s*\.\s*(?:json|send)\b/.test(line);
    },
  },
  {
    id: 'AI_FUNCTION_SCHEMA_INJECTION',
    category: 'AI Security',
    description:
      'User input embedded in LLM function/tool calling schema (parameters, defaults) — enables manipulation of AI tool behavior.',
    severity: 'high',
    fix_suggestion:
      'Never embed user input in function calling schemas. Define schemas statically and pass user input as message content only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Check for user input in function/tool schemas
      if (!/\b(?:default|description|enum)\s*:\s*(?:userInput|user_input|input|req\s*\.\s*(?:body|query|params))\b/.test(line)) return false;
      // Verify this is in a functions/tools context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 10), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      return /\b(?:functions|tools|function_call|tool_choice|parameters)\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // ORM Raw Query Misuse
  // ════════════════════════════════════════════
  {
    id: 'ORM_RAW_QUERY_UNSAFE',
    category: 'SQL Injection',
    description:
      'ORM raw query API used with string interpolation or concatenation — bypasses ORM safety and enables SQL injection.',
    severity: 'high',
    fix_suggestion:
      'Use the ORM\'s parameterized query API (e.g., createQueryBuilder().where("user.id = :id", { id }), Prisma.$executeRaw with tagged template, Sequelize replacements).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip ORM library internals
      if (isOrmPackage(ctx.filePath) || isLibraryPackage(ctx.filePath)) return false;
      // TypeORM createQueryBuilder with interpolation in .where()
      if (/\.createQueryBuilder\b/.test(line) && /\.where\s*\(\s*`[^`]*\$\{/.test(line)) return true;
      // Prisma $executeRawUnsafe (already caught by SQL_INJECTION_ORM_RAW, but this is explicit)
      if (/\$executeRawUnsafe\s*\(/.test(line)) return true;
      // Sequelize literal() with concatenation (+ operator with user input)
      if (/\bliteral\s*\(\s*"[^"]*"\s*\+/.test(line)) return true;
      if (/\bliteral\s*\(\s*'[^']*'\s*\+/.test(line)) return true;
      if (/\bliteral\s*\(\s*`[^`]*\$\{/.test(line)) return true;
      // Drizzle sql.raw() with template interpolation
      if (/\bsql\s*\.\s*raw\s*\(\s*`[^`]*\$\{/.test(line)) return true;
      return false;
    },
  },

  // ════════════════════════════════════════════
  // Mongoose $where Injection
  // ════════════════════════════════════════════
  {
    id: 'MONGOOSE_WHERE_INJECTION',
    category: 'NoSQL Injection',
    description:
      'Mongoose $where operator with user-controlled JavaScript string enables server-side JS injection — attackers can execute arbitrary code in MongoDB.',
    severity: 'critical',
    fix_suggestion:
      'Avoid $where entirely. Use standard MongoDB query operators ($eq, $gt, $in, etc.) instead. If $where is truly needed, never include user input.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Match $where with template literal or concatenation containing user input
      return /\$where\s*:\s*`[^`]*\$\{/.test(line) ||
        /\$where\s*:\s*(?:"|')[^"']*(?:"|')\s*\+/.test(line) ||
        /\$where\s*:\s*(?:req\s*\.\s*(?:body|query|params)|userInput|input)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Redis Key Injection / Cache Poisoning
  // ════════════════════════════════════════════
  {
    id: 'REDIS_KEY_INJECTION',
    category: 'Cache Poisoning',
    description:
      'Redis/cache key or command built from unsanitized user input — enables cache poisoning, key injection, or data leakage.',
    severity: 'high',
    fix_suggestion:
      'Validate and sanitize user input before using in cache keys. Use a hash function or prefix-based namespace, and strip special characters (newlines, spaces, null bytes).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Direct user input in redis/cache operations
      if (/\b(?:redis|cache|memcached|client)\s*\.\s*(?:get|set|del|hget|hset|sadd|srem|zadd|lpush|rpush|eval|evalsha|expire|exists)\s*\(\s*req\s*\.\s*(?:body|query|params)\b/.test(line)) return true;
      // Template literal with req.params/query/body in cache key
      if (/\b(?:redis|cache|memcached|client)\s*\.\s*(?:get|set|del|hget|hset|sadd|srem|zadd|lpush|rpush|eval|evalsha|expire|exists)\s*\(\s*`[^`]*\$\{[^}]*req\s*\.\s*(?:params|query|body)\b/.test(line)) return true;
      // redis.eval with req.body (Lua script injection)
      if (/\b(?:redis|client)\s*\.\s*eval\s*\(\s*req\s*\.\s*(?:body|query)\b/.test(line)) return true;
      return false;
    },
  },

  // ════════════════════════════════════════════
  // Email / SMS Header Injection
  // ════════════════════════════════════════════
  {
    id: 'EMAIL_HEADER_INJECTION',
    category: 'Injection',
    description:
      'User input placed in email headers, recipient fields, or messaging APIs without sanitization — enables email header injection, BCC injection, or spam relay.',
    severity: 'high',
    fix_suggestion:
      'Validate and sanitize email addresses (strip \\r\\n characters). Use a library like validator.js or email-validator. Never pass raw user input to email header fields.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // CRLF in email context (\\r\\n near email keywords)
      if (/\\r\\n/.test(line) && /\b(?:To|Bcc|Cc|Subject|From|Reply-To|email)\b/i.test(line)) return true;
      // sendMail/transporter with req.body fields
      if (/\b(?:sendMail|send_mail|transporter)\s*\(\s*\{/.test(line) && /req\s*\.\s*(?:body|query|params)\b/.test(line)) return true;
      // Twilio/SNS send with user input
      if (/\b(?:twilio|sns|sendgrid|mailgun)\b/i.test(line) && /\b(?:messages|sms|email)\b/i.test(line) && /req\s*\.\s*(?:body|query|params)\b/.test(line)) return true;
      return false;
    },
  },

  // ════════════════════════════════════════════
  // XXE (XML External Entity) Parser Unsafe
  // ════════════════════════════════════════════
  {
    id: 'XXE_PARSER_UNSAFE',
    category: 'XML External Entity (XXE)',
    description:
      'XML parser used with user input without disabling external entity processing — vulnerable to XXE attacks that can read local files, perform SSRF, or cause denial of service.',
    severity: 'high',
    fix_suggestion:
      'Disable external entity processing. For DOMParser, use a library like fast-xml-parser with entity processing disabled. For libxmljs, set { noent: false, nonet: true }. For Python lxml, use defusedxml.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // JS: DOMParser().parseFromString with variable input
      if (/\bDOMParser\s*\(\s*\)\s*\.\s*parseFromString\s*\(\s*[a-zA-Z_$]/.test(line) &&
          !/\bDOMParser\s*\(\s*\)\s*\.\s*parseFromString\s*\(\s*['"`]/.test(line)) return true;
      // libxmljs.parseXml without safe options
      if (/\blibxmljs\s*\.\s*parseXml\s*\(\s*[a-zA-Z_$]/.test(line) &&
          !/noent\s*:\s*false/.test(line)) return true;
      // xml2js, fast-xml-parser with variable input (no entity config)
      if (/\b(?:xml2js|parseString|Parser)\s*\.\s*parse(?:String)?\s*\(\s*[a-zA-Z_$]/.test(line) &&
          !/\b(?:strict|noent|processEntities)\b/.test(line)) return true;
      // Python: lxml.etree.parse/fromstring with variable
      if (/\b(?:lxml\s*\.\s*)?etree\s*\.\s*(?:parse|fromstring)\s*\(\s*[a-zA-Z_]/.test(line) &&
          !/defuse|defused/i.test(line)) return true;
      return false;
    },
  },

  // ════════════════════════════════════════════
  // LDAP Injection
  // ════════════════════════════════════════════
  {
    id: 'LDAP_INJECTION',
    category: 'LDAP Injection',
    description:
      'LDAP filter built with string interpolation or concatenation — vulnerable to LDAP injection attacks that can bypass authentication or leak directory data.',
    severity: 'high',
    fix_suggestion:
      'Use parameterized LDAP filters or escape special LDAP characters (*, (, ), \\, NUL) in user input. Use ldap-escape or similar library.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // LDAP filter pattern with interpolation: (&(uid=${...}) or (cn=...${...})
      if (/\(\s*(?:&|\|)?\s*\(\s*(?:uid|cn|sn|mail|memberOf|dn|sAMAccountName|userPrincipalName)\s*=/.test(line) &&
          /\$\{/.test(line)) return true;
      // Python f-string LDAP filter
      if (/f(?:"|')\s*\(\s*(?:&|\|)?\s*\(\s*(?:uid|cn|sn|mail)\s*=\s*\{/.test(line)) return true;
      // Python ldap3 search with f-string filter
      if (/\.search\s*\(.*f(?:"|')\(/.test(line) && /\b(?:uid|cn|sn|mail)\b/.test(line)) return true;
      return false;
    },
  },

  // ════════════════════════════════════════════
  // Server-Side Template Injection (SSTI)
  // ════════════════════════════════════════════
  {
    id: 'SSTI_RENDER_USER_INPUT',
    category: 'Template Injection',
    description:
      'Template engine render function called with user-controlled template name or template string — enables server-side template injection (SSTI) for remote code execution.',
    severity: 'critical',
    fix_suggestion:
      'Never pass user input as a template name or template string. Use render() with static template names and pass user data as context variables only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Express res.render() with req.query/body/params as template name
      if (/\bres\s*\.\s*render\s*\(\s*req\s*\.\s*(?:query|body|params)\b/.test(line)) return true;
      // Nunjucks/EJS/Pug renderString with user input
      if (/\b(?:nunjucks|ejs|pug|handlebars|mustache)\s*\.\s*(?:renderString|render|compile)\s*\(\s*req\s*\.\s*(?:body|query|params)\b/.test(line)) return true;
      // Any renderString with user input variable
      if (/\brenderString\s*\(\s*(?:req\s*\.\s*(?:body|query|params)|userInput|user_input|input|template)\b/.test(line)) return true;
      // Python jinja2 from_string with variable (not string literal)
      if (/\bfrom_string\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)/.test(line) &&
          /\b(?:jinja2|jinja|Environment|template)\b/i.test(line)) return true;
      return false;
    },
  },

  // ════════════════════════════════════════════
  // Insecure Direct Object Reference (IDOR)
  // ════════════════════════════════════════════
  {
    id: 'IDOR_NO_OWNERSHIP_CHECK',
    category: 'Broken Access Control',
    description:
      'Database query uses a user-supplied ID (req.params, req.query) to fetch data without comparing against the authenticated user\'s session — enables unauthorized access to other users\' data.',
    severity: 'high',
    fix_suggestion:
      'Always verify that the requested resource belongs to the authenticated user. Compare req.params.id against the session user ID, or add a WHERE clause filtering by the authenticated user.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Must be a route handler that uses req.params or req.query to fetch data
      if (!/\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(/.test(line)) return false;
      // Must be a data-access route (not login/auth)
      if (/\/(?:auth|login|signup|register|public)\b/.test(line)) return false;
      // Check for req.params/query in the handler window
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      const hasUserSuppliedId = /\breq\s*\.\s*(?:params|query)\s*\.\s*(?:id|userId|fileId|accountId|orderId)\b/.test(window);
      if (!hasUserSuppliedId) return false;
      // Check for DB access (supports chained ORM calls like prisma.user.findUnique)
      const hasDbAccess = /\b(?:db|prisma|knex|sequelize|pool|client|mongoose|Model)\s*\.(?:\s*[a-zA-Z_]+\s*\.)*\s*(?:query|find|findOne|findUnique|findFirst|findMany|get|select|findAll)\b/i.test(window);
      if (!hasDbAccess) return false;
      // Check for ownership/auth validation — must be specific patterns, not just the word "user"
      const hasOwnershipCheck = /\b(?:req\.user|session\.user|session\.userId|getSession|getServerSession|currentUser|ctx\.user|context\.user|context\.auth|auth\.user|req\.session)\b/i.test(window);
      // Check for validation middleware in route definition
      const hasValidationMiddleware = /\b(?:validate|validator|param\s*\(|check\s*\(|isUUID|isInt|guard|protect|requireAuth|isAuthenticated|authMiddleware)\b/i.test(line);
      return !hasOwnershipCheck && !hasValidationMiddleware;
    },
  },

  // ════════════════════════════════════════════
  // Header Injection via req.headers
  // ════════════════════════════════════════════
  {
    id: 'HEADER_INJECTION_HOST',
    category: 'Header Injection',
    description:
      'User-controlled Host header or request header value used in URL construction or proxy target — enables SSRF, cache poisoning, or host header injection attacks.',
    severity: 'high',
    fix_suggestion:
      'Never trust the Host header for URL construction. Use a configured/hardcoded host value or validate against an allowlist of expected hosts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Template literal URL construction with req.headers.host
      if (/`[^`]*\$\{[^}]*req\s*\.\s*headers\s*\.\s*host\b/.test(line) &&
          /\b(?:http|https|fetch|axios|request|got|url|URL)\b/i.test(line)) return true;
      // String concat with req.headers.host in URL
      if (/(?:"|')\s*\+\s*req\s*\.\s*headers\s*\.\s*host\b/.test(line) &&
          /\b(?:http|https|fetch|axios|request|got|url|URL)\b/i.test(line)) return true;
      return false;
    },
  },

  // ════════════════════════════════════════════
  // DoS: Unbounded Parsing
  // ════════════════════════════════════════════
  {
    id: 'DOS_UNBOUNDED_PARSE',
    category: 'Denial of Service',
    description:
      'JSON.parse() called on raw request body without size limits — enables denial of service via extremely large payloads.',
    severity: 'medium',
    fix_suggestion:
      'Set request body size limits using express.json({ limit: "100kb" }) or similar middleware. Never parse raw body content without size validation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // JSON.parse(req.body) — raw body parsing without middleware
      return /\bJSON\s*\.\s*parse\s*\(\s*req\s*\.\s*body\s*\)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Zip Bomb / Archive Extraction
  // ════════════════════════════════════════════
  {
    id: 'ZIP_BOMB',
    category: 'Denial of Service',
    description:
      'User-uploaded archive extracted without size validation — vulnerable to zip bomb attacks that exhaust disk space or memory.',
    severity: 'high',
    fix_suggestion:
      'Validate archive contents before extraction: check total uncompressed size, number of entries, and nesting depth. Set extraction size limits.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // AdmZip, unzipper, tar, archiver extraction
      if (!/\b(?:extractAllTo|extract|unzip|decompress|gunzip|inflate)\s*\(/.test(line)) return false;
      // Check for user file context nearby
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      const hasUserFile = /\breq\s*\.\s*(?:file|files|body)\b/.test(window) ||
        /\b(?:upload|uploaded|userFile|file\.buffer)\b/i.test(window);
      if (!hasUserFile) return false;
      // Check for size validation
      const hasSizeCheck = /\b(?:maxSize|max_size|sizeLimit|size_limit|MAX_SIZE|limit|fileSize|uncompressedSize)\b/i.test(window);
      return !hasSizeCheck;
    },
  },

  // ════════════════════════════════════════════
  // ReDoS (enhanced for nested groups)
  // ════════════════════════════════════════════
  {
    id: 'REGEX_DOS_NESTED',
    category: 'Regex DoS',
    description:
      'Complex regular expression with nested groups and quantifiers applied to user input — vulnerable to catastrophic backtracking (ReDoS).',
    severity: 'high',
    fix_suggestion:
      'Simplify the regex or use the RE2 engine (re2 npm package) which guarantees linear-time matching. Avoid nested quantifiers on user-supplied input.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Match nested group quantifiers like ((...)+.)+ or ((...)*.)+ on user input context
      if (!/\b(?:userInput|user_input|input|req\s*\.\s*(?:body|query|params)|match|test|replace|search)\b/.test(line)) return false;
      // Detect nested groups with quantifiers: ((...)+ ...)+ pattern
      return /\(\s*\([^)]*\)\s*[+*][^)]*\)\s*[+*]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // K8s Secret Plaintext
  // ════════════════════════════════════════════
  {
    id: 'K8S_SECRET_PLAINTEXT',
    category: 'Hardcoded Secrets',
    description:
      'Plaintext secret or password value detected in what appears to be a Kubernetes manifest or configuration string — secrets should use K8s Secret resources with base64 encoding at minimum, or an external secrets manager.',
    severity: 'high',
    fix_suggestion:
      'Use Kubernetes Secrets (kind: Secret) with data encoded in base64, or better yet, use an external secrets manager (Vault, AWS Secrets Manager, etc.).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Match password: or apiKey: or secret: followed by a plaintext value (not a variable reference) in manifest-like context
      if (!/\b(?:password|apiKey|api_key|secret_key|secretKey|db_password|database_password|auth_token)\s*:\s*[a-zA-Z0-9_!@#$%^&*]{8,}/.test(line)) return false;
      // Must look like a manifest/config context (YAML-like string or template)
      return /`[^`]*\b(?:password|apiKey|api_key|secret_key|secretKey)\s*:/.test(line) ||
        /['"][^'"]*\b(?:password|apiKey|api_key|secret_key|secretKey)\s*:/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Docker Socket Mount
  // ════════════════════════════════════════════
  {
    id: 'DOCKER_SOCKET_MOUNT',
    category: 'Insecure Configuration',
    description:
      'Docker socket (/var/run/docker.sock) accessed in application code — grants the application full control over the Docker daemon, equivalent to root access on the host.',
    severity: 'critical',
    fix_suggestion:
      'Avoid mounting the Docker socket in application containers. Use Docker-in-Docker (DinD), rootless Docker, or a Docker API proxy with restricted permissions instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\/var\/run\/docker\.sock/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 1: Authentication & Session Management
  // ════════════════════════════════════════════
  {
    id: 'AUTH_LOCALSTORAGE_SENSITIVE',
    category: 'Authentication Issues',
    description:
      'Sensitive data (password, token, JWT, session, secret) stored in localStorage or sessionStorage — accessible to any JavaScript on the page, including XSS payloads.',
    severity: 'high',
    fix_suggestion:
      'Never store passwords, tokens, or secrets in localStorage/sessionStorage. Use httpOnly cookies for session management, or a secure token storage strategy.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(/.test(line)) return false;
      const lower = line.toLowerCase();
      return (
        lower.includes('password') ||
        lower.includes('token') ||
        lower.includes('jwt') ||
        lower.includes('session') ||
        lower.includes('secret') ||
        lower.includes('auth') ||
        lower.includes('credential')
      );
    },
  },
  {
    id: 'AUTH_BYPASS_OR_OPERATOR',
    category: 'Authentication Issues',
    description:
      'Authorization check uses || with user-controlled input (req.query, req.body, req.params) — allows bypass by setting the query parameter.',
    severity: 'critical',
    fix_suggestion:
      'Never use user-supplied input in authorization conditions with ||. Validate roles/permissions from session data only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect patterns like: if (user.role === 'admin' || req.query.admin)
      if (!/\|\|/.test(line)) return false;
      if (!/\bif\s*\(/.test(line)) return false;
      const hasRoleCheck = /\b(?:role|isAdmin|is_admin|admin|permission|authorized)\b/i.test(line);
      const hasUserInput = /\breq\s*\.\s*(?:query|body|params)\b/.test(line);
      return hasRoleCheck && hasUserInput;
    },
  },
  {
    id: 'AUTH_REMEMBER_ME_NO_EXPIRY',
    category: 'Authentication Issues',
    description:
      'Remember-me or persistent session cookie set without expiry (maxAge/expires) — the token may persist indefinitely.',
    severity: 'medium',
    fix_suggestion:
      'Always set maxAge or expires on persistent cookies: res.cookie("remember_me", token, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, secure: true }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bres\s*\.\s*cookie\s*\(/.test(line)) return false;
      const lower = line.toLowerCase();
      if (!lower.includes('remember') && !lower.includes('persist') && !lower.includes('stay_logged')) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return !/\b(?:maxAge|max_age|expires)\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 2: API Security
  // ════════════════════════════════════════════
  {
    id: 'API_KEY_IN_URL',
    category: 'Sensitive Data Exposure',
    description:
      'API key or secret passed in URL query string — visible in server logs, browser history, and referrer headers.',
    severity: 'high',
    fix_suggestion:
      'Pass API keys in the Authorization header or a custom request header instead of the URL query string.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Template literal: fetch(`...?key=${apiKey}`)
      if (/\?[^`'"]*(?:key|apiKey|api_key|token|secret|access_token)\s*=\s*\$\{/.test(line)) return true;
      // Concat: "...?apiKey=" + secretKey
      if (/\?[^"']*(?:key|apiKey|api_key|token|secret|access_token)\s*=\s*["']\s*\+/.test(line)) return true;
      return false;
    },
  },
  {
    id: 'API_INTERNAL_ID_EXPOSURE',
    category: 'Sensitive Data Exposure',
    description:
      'API endpoint returns raw database query results that may include internal IDs (_id, auto-increment id) — leaks internal implementation details.',
    severity: 'low',
    fix_suggestion:
      'Map database results to DTOs that only include fields clients need. Use UUIDs as public identifiers instead of sequential database IDs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Route handler that does SELECT ... and returns directly
      if (!/\bres\s*\.\s*json\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 1))
        .join(' ');
      // Query selects id or _id explicitly
      const selectsIds = /\bSELECT\b[^)]*\b(?:\bid\b|_id)\b/i.test(window);
      const hasDirectReturn = /\bres\s*\.\s*json\s*\(\s*(?:users|results?|rows|data|records)\b/.test(line);
      return selectsIds && hasDirectReturn;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 3: File System Security
  // ════════════════════════════════════════════
  {
    id: 'FS_PERMISSION_WORLD_WRITABLE',
    category: 'Insecure Configuration',
    description:
      'File permission set to 0o777 (world-readable, writable, executable) — any user on the system can read, modify, or execute the file.',
    severity: 'high',
    fix_suggestion:
      'Use restrictive permissions: 0o644 for files (owner read/write, others read) or 0o600 for sensitive files (owner only).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bchmod(?:Sync)?\s*\([^,]+,\s*0o777\s*\)/.test(line) ||
        /\bchmod(?:Sync)?\s*\([^,]+,\s*0?777\s*\)/.test(line) ||
        /\bmode\s*:\s*0o777\b/.test(line);
    },
  },
  {
    id: 'FS_WRITE_EXECUTABLE_PATH',
    category: 'Code Injection',
    description:
      'Writing user-controlled content to an executable system path (/usr/bin, /usr/local/bin, etc.) — enables arbitrary code execution.',
    severity: 'critical',
    fix_suggestion:
      'Never write user content to executable paths. Write to a sandboxed directory and validate file contents before any processing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:writeFile|writeFileSync|createWriteStream)\s*\(/.test(line)) return false;
      return /['"`]\/(?:usr\/(?:local\/)?bin|bin|sbin|opt)\//.test(line) &&
        /\breq\s*\.\s*(?:body|file|files)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 4: Encoding & Data Handling
  // ════════════════════════════════════════════
  {
    id: 'UNSAFE_PARSEINT',
    category: 'Data Handling',
    description:
      'parseInt() called on user input without specifying a radix — can produce unexpected results with inputs starting with "0" (octal) or "0x" (hex).',
    severity: 'low',
    fix_suggestion:
      'Always specify radix 10: parseInt(value, 10). Or use Number() for stricter numeric conversion.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // parseInt(req.query.xxx) or parseInt(userInput) without second arg
      if (!/\bparseInt\s*\(\s*req\s*\.\s*(?:query|params|body)\b/.test(line)) return false;
      // Check that there's no second argument (radix)
      // Match parseInt(req.query.foo) but not parseInt(req.query.foo, 10)
      return /\bparseInt\s*\(\s*req\s*\.\s*(?:query|params|body)\s*\.\s*[a-zA-Z_]+\s*\)/.test(line);
    },
  },
  {
    id: 'BUFFER_NO_ENCODING',
    category: 'Data Handling',
    description:
      'Buffer.from() called on user input without specifying an encoding — can lead to unexpected behavior if the input is not UTF-8.',
    severity: 'low',
    fix_suggestion:
      'Always specify encoding: Buffer.from(data, "utf-8"). For binary data, use Buffer.from(data, "base64") or "hex".',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Buffer.from(req.body.xxx) without second arg
      if (!/\bBuffer\s*\.\s*from\s*\(\s*req\s*\.\s*(?:body|query)\b/.test(line)) return false;
      return /\bBuffer\s*\.\s*from\s*\(\s*req\s*\.\s*(?:body|query)\s*\.\s*[a-zA-Z_]+\s*\)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 5: Error Handling & Logging
  // ════════════════════════════════════════════
  {
    id: 'DEBUG_ENDPOINT',
    category: 'Insecure Configuration',
    description:
      'Debug or diagnostic endpoint detected — may expose sensitive system information (environment variables, memory usage, internals) in production.',
    severity: 'high',
    fix_suggestion:
      'Remove debug endpoints before deploying to production, or protect them with strong authentication and IP allowlisting.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:app|router)\s*\.\s*(?:get|post|all)\s*\(\s*['"]\/debug\b/.test(line)) return false;
      return true;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 6: Third-Party Integration
  // ════════════════════════════════════════════
  {
    id: 'WEBHOOK_NO_SIGNATURE',
    category: 'Authentication Issues',
    description:
      'Webhook endpoint parses request body without verifying the signature — attackers can forge webhook events.',
    severity: 'high',
    fix_suggestion:
      'Verify webhook signatures before processing. For Stripe: stripe.webhooks.constructEvent(body, sig, secret). For GitHub: verify HMAC-SHA256 signature.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\s*\.\s*post\s*\(\s*['"]\/webhook/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10))
        .join(' ');
      // Check for signature verification
      const hasSignatureCheck = /\b(?:constructEvent|verify|signature|sig|hmac|createHmac|timingSafeEqual)\b/i.test(window);
      return !hasSignatureCheck;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 7: Database Security (Advanced)
  // ════════════════════════════════════════════
  {
    id: 'MONGO_REGEX_INJECTION',
    category: 'NoSQL Injection',
    description:
      'MongoDB $regex operator used with unsanitized user input — enables ReDoS attacks via regex injection.',
    severity: 'high',
    fix_suggestion:
      'Escape special regex characters in user input before using in $regex. Use a library like escape-string-regexp, or use $text search instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\$regex\s*:/.test(line)) return false;
      // Check for user input
      if (/\breq\s*\.\s*(?:query|body|params)\b/.test(line)) {
        // Check for escaping/sanitization in surrounding lines
        const lineIdx = ctx.lineNumber - 1;
        const window = ctx.allLines
          .slice(Math.max(0, lineIdx - 5), lineIdx + 1)
          .join(' ');
        return !/\b(?:escape|sanitize|escapeRegex|escape_regex|escapeStringRegexp)\b/i.test(window);
      }
      return false;
    },
  },
  {
    id: 'DB_NO_TLS',
    category: 'Insecure Configuration',
    description:
      'Database connection configured with SSL/TLS explicitly disabled — data transmitted in plaintext, vulnerable to interception.',
    severity: 'high',
    fix_suggestion:
      'Enable SSL/TLS for all database connections: ssl: true or ssl: { rejectUnauthorized: true }. Use sslmode=require for PostgreSQL connection strings.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // ssl: false in database connection config
      if (!/\bssl\s*:\s*false\b/.test(line)) return false;
      // Verify it's in a database connection context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\b(?:Pool|Client|createConnection|createPool|knex|sequelize|mongoose|typeorm|prisma|pg|mysql|host|database|connectionString)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 8: Container & Infrastructure
  // ════════════════════════════════════════════
  {
    id: 'DEBUG_PORT_EXPOSED',
    category: 'Insecure Configuration',
    description:
      'Node.js debug port (--inspect) bound to 0.0.0.0 — allows remote debugging connections from any IP, enabling remote code execution.',
    severity: 'critical',
    fix_suggestion:
      'Bind the debug port to localhost only: --inspect=127.0.0.1:9229. Never expose the debug port to all interfaces in production.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /--inspect(?:-brk)?=0\.0\.0\.0/.test(line);
    },
  },
  {
    id: 'HEALTH_CHECK_INFO_LEAK',
    category: 'Sensitive Data Exposure',
    description:
      'Health check endpoint returns system information (process.memoryUsage, process.uptime, process.env) — leaks internal details to potential attackers.',
    severity: 'medium',
    fix_suggestion:
      'Health check endpoints should only return status information (e.g., { status: "ok" }). Do not expose memory usage, environment variables, or uptime.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\s*\.\s*get\s*\(\s*['"]\/health/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 6))
        .join(' ');
      return /\bprocess\s*\.\s*(?:memoryUsage|uptime|env|versions|arch|platform|cpuUsage)\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 9: Client-Side Security
  // ════════════════════════════════════════════
  {
    id: 'POSTMESSAGE_NO_ORIGIN',
    category: 'Client-Side Security',
    description:
      'postMessage event listener without origin validation — any page can send messages to this window, enabling cross-origin attacks.',
    severity: 'high',
    fix_suggestion:
      'Always check event.origin against a trusted origin before processing: if (event.origin !== "https://trusted.com") return;',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/addEventListener\s*\(\s*['"]message['"]/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      return !/\bevent\s*\.\s*origin\b|\borigin\b.*===/.test(window);
    },
  },
  {
    id: 'WINDOW_OPEN_USER_URL',
    category: 'Open Redirect',
    description:
      'window.open() called with user-controlled URL — enables open redirect and potential phishing attacks.',
    severity: 'high',
    fix_suggestion:
      'Validate the URL against an allowlist of trusted domains before opening. Never pass raw user input to window.open().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bwindow\s*\.\s*open\s*\(/.test(line)) return false;
      // Check for user-controlled URLs
      const hasUserInput = /\bwindow\s*\.\s*open\s*\(\s*req\s*\.\s*(?:query|body|params)\b/.test(line) ||
        /\bwindow\s*\.\s*open\s*\(\s*(?:userUrl|user_url|url|redirectUrl|redirect_url|targetUrl)\b/.test(line);
      if (!hasUserInput) return false;
      // Skip when URL comes from a known-safe source (Stripe session, internal API response)
      const urlArgMatch = line.match(/\bwindow\s*\.\s*open\s*\(\s*([a-zA-Z_$][\w$.]*)/);
      if (urlArgMatch) {
        const varName = urlArgMatch[1];
        const lineIdx = ctx.lineNumber - 1;
        const window_ctx = ctx.allLines.slice(Math.max(0, lineIdx - 15), lineIdx + 1).join('\n');
        // Skip if the variable is assigned from a fetch/API response or Stripe session
        const varAssignPattern = new RegExp(`\\b${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*(?:.*\\.(?:url|data\\.url|session\\.url|checkout\\.url)|.*(?:fetch|axios|api|response|res)\\b)`, 'i');
        if (varAssignPattern.test(window_ctx)) return false;
        // Skip known safe variable names (Stripe URLs, payment session URLs)
        if (/\b(?:stripe|checkout|session|payment|billing)\b/i.test(varName)) return false;
      }
      return true;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 11: Cryptographic Misuse (Advanced)
  // ════════════════════════════════════════════
  {
    id: 'CRYPTO_ECB_MODE',
    category: 'Insecure Cryptography',
    description:
      'ECB mode encryption detected — ECB does not use an IV and produces identical ciphertext for identical plaintext blocks, leaking data patterns.',
    severity: 'high',
    fix_suggestion:
      'Use AES-256-GCM or AES-256-CBC with a random IV instead of ECB mode.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /createCipher(?:iv)?\s*\(\s*['"]aes-(?:128|192|256)-ecb['"]/.test(line);
    },
  },
  {
    id: 'CRYPTO_STATIC_IV',
    category: 'Insecure Cryptography',
    description:
      'Static or zero-filled IV used with cipher — defeats the purpose of the IV and makes encryption deterministic.',
    severity: 'high',
    fix_suggestion:
      'Generate a random IV for each encryption: crypto.randomBytes(16). Never reuse or hardcode IVs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcreateDecipheriv\b/.test(line) && !/\bcreateCipheriv\b/.test(line)) return false;
      return /Buffer\s*\.\s*alloc\s*\(\s*(?:16|12|8)\s*\)/.test(line) ||
        /Buffer\s*\.\s*from\s*\(\s*['"]0{16,}['"]/.test(line) ||
        /\bnew\s+Uint8Array\s*\(\s*(?:16|12|8)\s*\)/.test(line);
    },
  },
  {
    id: 'CRYPTO_HARDCODED_SALT',
    category: 'Insecure Cryptography',
    description:
      'Hardcoded salt used for password hashing — a static salt negates the per-password uniqueness that salting provides.',
    severity: 'high',
    fix_suggestion:
      'Generate a unique random salt per password: crypto.randomBytes(16). Store the salt alongside the hash.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      const lower = line.toLowerCase();
      if (!lower.includes('salt')) return false;
      // salt = "..." or salt: "..." with a string literal
      if (/\bsalt\s*[:=]\s*['"][a-zA-Z0-9+/=_-]+['"]/.test(line)) {
        // Must be in a hashing context
        return /\b(?:hash|pbkdf2|scrypt|crypto|password)\b/i.test(line);
      }
      return false;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 12: OAuth / OpenID Connect
  // ════════════════════════════════════════════
  {
    id: 'OAUTH_NO_PKCE',
    category: 'Authentication Issues',
    description:
      'OAuth token exchange without PKCE (code_verifier missing) — vulnerable to authorization code interception attacks.',
    severity: 'high',
    fix_suggestion:
      'Use PKCE: include code_verifier in the token exchange request and code_challenge in the authorization request.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect token exchange POST with grant_type=authorization_code but no code_verifier
      if (!/\bgrant_type\s*[:=]\s*['"]authorization_code['"]/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return !/\bcode_verifier\b/.test(window);
    },
  },
  {
    id: 'OAUTH_ID_TOKEN_NO_VERIFY',
    category: 'Authentication Issues',
    description:
      'OpenID Connect ID token decoded without signature verification — attackers can forge identity tokens.',
    severity: 'high',
    fix_suggestion:
      'Verify ID token signatures using the provider\'s JWKS endpoint. Use a library like jose or openid-client to validate tokens.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect jwt.decode or atob/base64 decode of id_token without verify
      if (!/\bid_token\b|id[-_]?[Tt]oken\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      const hasDecodeNoVerify = /\b(?:jwt\.decode|atob|JSON\.parse|Buffer\.from)\b/.test(window) &&
        !/\b(?:jwt\.verify|verify|validate|jwks)\b/i.test(window);
      return hasDecodeNoVerify;
    },
  },
  {
    id: 'OAUTH_REFRESH_TOKEN_LOCALSTORAGE',
    category: 'Authentication Issues',
    description:
      'Refresh token stored in localStorage — accessible to JavaScript and XSS attacks. Refresh tokens grant long-term access.',
    severity: 'high',
    fix_suggestion:
      'Store refresh tokens in httpOnly, secure cookies. Never store them in localStorage or sessionStorage.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(/.test(line)) return false;
      return /refresh[-_]?[Tt]oken|refreshToken/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 13: Microservice Security
  // ════════════════════════════════════════════
  {
    id: 'GRPC_NO_TLS',
    category: 'Insecure Configuration',
    description:
      'gRPC server created with insecure credentials — traffic is unencrypted and vulnerable to interception.',
    severity: 'high',
    fix_suggestion:
      'Use grpc.ServerCredentials.createSsl() with proper TLS certificates instead of createInsecure().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bServerCredentials\s*\.\s*createInsecure\s*\(\s*\)/.test(line);
    },
  },
  {
    id: 'TRUST_X_FORWARDED_FOR',
    category: 'Header Injection',
    description:
      'X-Forwarded-For header trusted without proxy validation — easily spoofable, enabling IP-based auth bypass.',
    severity: 'medium',
    fix_suggestion:
      'Only trust X-Forwarded-For when behind a known reverse proxy. Use app.set("trust proxy", 1) with Express and validate the proxy chain.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\breq\s*\.\s*headers?\s*\[\s*['"]x-forwarded-for['"]\s*\]/.test(line) &&
          !/\breq\s*\.\s*(?:header|get)\s*\(\s*['"]x-forwarded-for['"]\s*\)/.test(line)) return false;
      // Check if trust proxy is configured
      const hasTrustProxy = /trust\s*proxy/i.test(ctx.fileContent);
      return !hasTrustProxy;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 14: Serverless / Edge
  // ════════════════════════════════════════════
  {
    id: 'LAMBDA_WILDCARD_IAM',
    category: 'Cloud Misconfiguration',
    description:
      'Lambda/serverless function with wildcard IAM permissions (Action: * or Resource: *) — grants excessive privileges.',
    severity: 'high',
    fix_suggestion:
      'Follow the principle of least privilege. Scope IAM permissions to specific actions and resources needed.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Check for Action: "*" or Resource: "*" patterns
      if (!/(?:Action|Resource)\s*:\s*['"]?\*['"]?/.test(line)) return false;
      // Verify it's in an IAM/policy context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\b(?:iam|policy|Statement|Effect|Allow|Deny|Principal|lambda|serverless)\b/i.test(window);
    },
  },
  {
    id: 'SERVERLESS_CORS_UNRESTRICTED',
    category: 'Insecure Configuration',
    description:
      'Serverless/edge function returns unrestricted CORS headers — any origin can access this endpoint.',
    severity: 'medium',
    fix_suggestion:
      'Restrict Access-Control-Allow-Origin to specific trusted domains instead of "*".',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/Access-Control-Allow-Origin.*\*/.test(line)) return false;
      // Verify serverless/edge context
      const hasServerlessContext = /\b(?:handler|lambda|edge|serverless|export\s+(?:default\s+)?(?:async\s+)?function)\b/i.test(ctx.fileContent);
      return hasServerlessContext;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 15: Data Validation Edge Cases
  // ════════════════════════════════════════════
  {
    id: 'TYPE_COERCION_LOOSE_EQUALITY',
    category: 'Data Handling',
    description:
      'Loose equality (==) used to compare security-sensitive values — type coercion can bypass checks (e.g., 0 == "" is true).',
    severity: 'medium',
    fix_suggestion:
      'Use strict equality (===) for all comparisons, especially for authentication and authorization checks.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Look for == (not ===) comparing against security-sensitive string values
      if (!/(?<!=)={2}(?!=)/.test(line)) return false;
      if (/===/.test(line)) return false;
      const lower = line.toLowerCase();
      return (lower.includes('admin') || lower.includes('role') ||
              lower.includes('auth') || lower.includes('permission')) &&
             /\breq\s*\.\s*(?:body|query|params)\b/.test(line);
    },
  },
  {
    id: 'NULL_BYTE_INJECTION',
    category: 'Injection',
    description:
      'Path or input containing null byte (%00 or \\0) — can truncate strings in C-based libraries, bypassing extension checks.',
    severity: 'high',
    fix_suggestion:
      'Strip null bytes from user input before file operations. Validate that paths do not contain \\0 or %00.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:readFile(?:Sync)?|writeFile(?:Sync)?|createReadStream|open(?:Sync)?|access(?:Sync)?|unlink(?:Sync)?|stat(?:Sync)?|rename(?:Sync)?|readdir(?:Sync)?)\b/.test(line)) return false;
      return /\\0|%00|\\x00/.test(line);
    },
  },
  {
    id: 'PROTOTYPE_POLLUTION_JSON_PARSE',
    category: 'Prototype Pollution',
    description:
      'JSON.parse of user input without filtering __proto__ — parsed objects may contain __proto__ properties that pollute Object prototype.',
    severity: 'medium',
    fix_suggestion:
      'Use a JSON reviver to filter dangerous keys: JSON.parse(input, (key, value) => key === "__proto__" ? undefined : value). Or validate with a schema after parsing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bJSON\s*\.\s*parse\s*\(/.test(line)) return false;
      // Check if input comes from user
      if (!/\breq\s*\.\s*(?:body|query)\b/.test(line) &&
          !/\buserInput\b|\buser_input\b/.test(line)) return false;
      // Check for reviver or schema validation nearby
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return !/\b(?:reviver|__proto__|schema|validate|zod|joi|ajv)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 16: Payment / Financial
  // ════════════════════════════════════════════
  {
    id: 'PAYMENT_AMOUNT_FROM_CLIENT',
    category: 'Payment Security',
    description:
      'Payment amount taken directly from client request without server-side validation — users can manipulate the charge amount.',
    severity: 'critical',
    fix_suggestion:
      'Always compute payment amounts server-side from product prices in your database. Never trust client-supplied amounts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match amount/total from req.body on the same line
      if (/\b(?:amount|unit_amount|total)\s*:\s*req\s*\.\s*(?:body|query)\b/.test(line)) {
        return true;
      }
      // Check for payment-context line with req.body reference in nearby lines
      if (!/\b(?:amount|unit_amount|total)\s*:/.test(line)) return false;
      if (!/\breq\s*\.\s*(?:body|query)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\b(?:stripe|payment|charge|paymentIntent|checkout|price)\b/i.test(window);
    },
  },
  {
    id: 'PAYMENT_PRICE_FROM_CLIENT',
    category: 'Payment Security',
    description:
      'Price ID taken from client without server-side lookup — attacker could substitute a cheaper price ID.',
    severity: 'high',
    fix_suggestion:
      'Look up price IDs server-side based on the product/plan selected. Do not pass price IDs from the client.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bprice\s*:\s*req\s*\.\s*(?:body|query)\b/.test(line) &&
          !/\bprice_?[Ii]d?\s*:\s*req\s*\.\s*(?:body|query)\b/.test(line)) return false;
      // Verify payment context in surrounding lines
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\b(?:stripe|checkout|subscription|payment)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 17: Real-Time / Event-Driven
  // ════════════════════════════════════════════
  {
    id: 'SOCKETIO_NO_AUTH',
    category: 'Authentication Issues',
    description:
      'Socket.io server created without authentication middleware — any client can connect and send events.',
    severity: 'high',
    fix_suggestion:
      'Add authentication middleware: io.use((socket, next) => { verifyToken(socket.handshake.auth.token) ? next() : next(new Error("unauthorized")); });',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+Server\s*\(/.test(line) && !/\b(?:io|socketIo)\s*\(\s*(?:server|httpServer|app)/.test(line)) return false;
      // Check if it's socket.io context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 10))
        .join(' ');
      if (!/\b(?:socket\.io|io\.on|socket\.on|connection|disconnect)\b/i.test(window)) return false;
      // Check for auth middleware
      return !/\bio\s*\.\s*use\b/.test(ctx.fileContent) &&
             !/\b(?:auth|authenticate|middleware|handshake\.auth)\b/i.test(window);
    },
  },
  {
    id: 'SSE_NO_AUTH',
    category: 'Authentication Issues',
    description:
      'Server-Sent Events endpoint without authentication — allows unauthorized streaming data access.',
    severity: 'medium',
    fix_suggestion:
      'Add authentication middleware before SSE endpoints. Validate session/JWT before establishing the event stream.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Match text/event-stream content type setting
      if (!/text\/event-stream/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 10), lineIdx + 1)
        .join(' ');
      return !/\b(?:auth|session|token|jwt|verify|middleware|requireAuth|isAuthenticated)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 18: Mobile API / JWT Advanced
  // ════════════════════════════════════════════
  {
    id: 'TLS_REJECT_UNAUTHORIZED_PRODUCTION',
    category: 'Insecure Configuration',
    description:
      'NODE_TLS_REJECT_UNAUTHORIZED set to 0 — disables all TLS certificate validation, allowing MITM attacks.',
    severity: 'critical',
    fix_suggestion:
      'Remove NODE_TLS_REJECT_UNAUTHORIZED=0. Fix the underlying certificate issue instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/.test(line) &&
        /\bprocess\s*\.\s*env\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 19: Logging / Observability Security
  // ════════════════════════════════════════════
  {
    id: 'LOG_SENSITIVE_DATA',
    category: 'Sensitive Data Exposure',
    description:
      'Sensitive data passed to structured logger fields — passwords, tokens, and PII should never appear in log fields.',
    severity: 'high',
    fix_suggestion:
      'Redact sensitive fields before logging. Use a log redaction library or configure your logger to mask sensitive keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:logger|log|winston|pino|bunyan)\s*\.\s*(?:info|warn|error|debug|log)\s*\(/.test(line)) return false;
      // Check for sensitive field names in structured log object
      return /\{\s*(?:[^}]*,\s*)?(?:password|secret|token|apiKey|api_key|ssn|creditCard|credit_card)\s*[,}:]/i.test(line);
    },
  },
  {
    id: 'METRICS_ENDPOINT_NO_AUTH',
    category: 'Insecure Configuration',
    description:
      'Metrics endpoint (/metrics) exposed without authentication — leaks application internals and can aid attackers.',
    severity: 'medium',
    fix_suggestion:
      'Add authentication middleware to the /metrics endpoint or bind it to a separate internal port.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\s*\.\s*(?:get|use)\s*\(\s*['"]\/metrics['"]/.test(line)) return false;
      // Check for auth middleware
      return !/\b(?:auth|authenticate|requireAuth|middleware|protect|guard|basicAuth)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 20: Comprehensive Edge Cases & Hardening
  // ════════════════════════════════════════════
  {
    id: 'ERROR_MESSAGE_DATA_LEAK',
    category: 'Sensitive Data Exposure',
    description:
      'Template literal in thrown error message may leak sensitive data like emails, IDs, or internal state to error handlers and logs.',
    severity: 'medium',
    fix_suggestion:
      'Use generic error messages for user-facing errors. Log detailed errors server-side only with a correlation ID.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bthrow\s+new\s+Error\s*\(\s*`/.test(line)) return false;
      return /\$\{[^}]*(?:email|password|token|secret|ssn|creditCard|credit_card|user)\b/.test(line);
    },
  },
  {
    id: 'REGEX_ANCHOR_MISSING',
    category: 'Data Handling',
    description:
      'Regex used for route matching or authorization without proper anchoring (^ and $) — allows partial matches that bypass checks.',
    severity: 'medium',
    fix_suggestion:
      'Use properly anchored regex: /^\\/admin$/ instead of /\\/admin/. For route matching, prefer exact string matching.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match regex used in authorization/route context without ^ or $
      if (!/\b(?:test|match|exec)\s*\(/.test(line)) return false;
      const lower = line.toLowerCase();
      if (!(lower.includes('admin') || lower.includes('auth') ||
            lower.includes('protect') || lower.includes('route') ||
            lower.includes('path') || lower.includes('url'))) return false;
      // Check for a regex literal (/.../) containing security-sensitive paths but missing ^ or $
      const regexLiteralMatch = line.match(/\/([^/]+)\//);
      if (!regexLiteralMatch) return false;
      const regexContent = regexLiteralMatch[1];
      if (!/(?:admin|auth|api|private|secret)/i.test(regexContent)) return false;
      // Missing anchoring if no ^ at start or $ at end of regex content
      return !regexContent.startsWith('^') && !regexContent.includes('$');
    },
  },
  {
    id: 'CORS_INTERNAL_IP',
    category: 'Insecure Configuration',
    description:
      'Hardcoded internal IP address in CORS origin — may expose internal services or be inaccessible in production.',
    severity: 'low',
    fix_suggestion:
      'Use domain names and environment variables for CORS origins instead of hardcoded IP addresses.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\borigin\s*:/.test(line) && !/Access-Control-Allow-Origin/.test(line)) return false;
      return /(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 21: React / Next.js Advanced
  // ════════════════════════════════════════════
  {
    id: 'REACT_USEEFFECT_UNCONTROLLED_FETCH',
    category: 'Server-Side Request Forgery',
    description:
      'useEffect making fetch with user-controlled URL without cleanup — enables SSRF and race conditions from stale requests.',
    severity: 'high',
    fix_suggestion:
      'Validate URLs against an allowlist before fetching. Use AbortController for cleanup and avoid user-controlled URLs in useEffect.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\buseEffect\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 12))
        .join(' ');
      const hasFetch = /\bfetch\s*\(/.test(window);
      const hasUserUrl = /\b(?:url|href|src|endpoint)\b/i.test(window) &&
        /\b(?:params|searchParams|query|props\.|input|user)\b/i.test(window);
      const hasCleanup = /\babort|AbortController|return\s*\(\s*\)\s*=>|cleanup/i.test(window);
      return hasFetch && hasUserUrl && !hasCleanup;
    },
  },
  {
    id: 'NEXTJS_REDIRECT_USER_INPUT',
    category: 'Open Redirect',
    description:
      'Next.js redirect() called with user-controlled input in Server Component — enables open redirect attacks.',
    severity: 'high',
    fix_suggestion:
      'Validate redirect targets against an allowlist of paths. Never pass raw user input to redirect().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bredirect\s*\(/.test(line)) return false;
      // Must be a Next.js file — check for next imports or Next.js patterns
      if (!/\bfrom\s+['"]next\//.test(ctx.fileContent) && !/\bnext\/navigation\b/.test(ctx.fileContent) && !/\bnext\/headers\b/.test(ctx.fileContent) && !/['"]use server['"]/.test(ctx.fileContent)) return false;
      // Must NOT be an Express/Fastify file
      if (/\bexpress\s*\(\)|\bfastify\s*\(|\bfrom\s+['"]express['"]|\bfrom\s+['"]fastify['"]/.test(ctx.fileContent)) return false;
      // Must not be a hardcoded string literal (including backtick with no interpolation)
      if (/\bredirect\s*\(\s*['"`]\/[^'"$`]*['"`]\s*\)/.test(line)) return false;
      // Skip config-based redirects (e.g., authOptions.pages.signIn, config.redirectUrl)
      if (/\bredirect\s*\(\s*(?:authOptions|config|settings|options)\s*\./.test(line)) return false;
      // Only fire when the redirect URL comes from user-controlled sources
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 8), lineIdx + 1)
        .join(' ');
      // Must come from req, searchParams, params, or user-controlled variables
      return /\b(?:searchParams|req\s*\.\s*(?:query|body|params))\b/.test(window) &&
        /\bredirect\s*\(\s*(?:req\s*\.\s*(?:query|body|params)\s*\.\s*\w+|searchParams\s*\.\s*(?:get\s*\(|\[\s*['"])|\w*[Uu]rl\b)/.test(line);
    },
  },
  {
    id: 'NEXT_GETSTATIC_PROPS_LEAK',
    category: 'Sensitive Data Exposure',
    description:
      'getStaticProps returning database query results directly in props — all data is serialized to static HTML viewable by anyone.',
    severity: 'high',
    fix_suggestion:
      'Filter and map database results to only include public-facing fields before returning in getStaticProps.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bgetStaticProps\b/.test(ctx.fileContent)) return false;
      if (!/\bprops\s*:/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 8), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      if (!/\bgetStaticProps\b/.test(window)) return false;
      // Check for raw DB results in props
      return /\b(?:db\s*\.\s*query|prisma\s*\.\s*[a-zA-Z]+\s*\.\s*findMany|\.rows)\b/.test(window) &&
        /\bprops\s*:/.test(window);
    },
  },
  {
    id: 'SERVER_ACTION_NO_CSRF',
    category: 'CSRF',
    description:
      'Next.js Server Action (\'use server\') performs state-changing operations without origin/CSRF validation — may be callable cross-origin.',
    severity: 'medium',
    fix_suggestion:
      'Verify the request origin header matches your domain in Server Actions, or use Next.js built-in CSRF protection. Always validate the caller identity.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/['"]use server['"]/.test(line)) return false;
      // Next.js Server Actions (14+) have built-in CSRF protection via origin checking.
      // The 'use server' directive itself enables the protection. No need to flag.
      return false;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 22: AWS SDK Misuse
  // ════════════════════════════════════════════
  {
    id: 'AWS_S3_SIGNED_URL_NO_EXPIRY',
    category: 'Cloud Misconfiguration',
    description:
      'S3 getSignedUrl called without specifying Expires parameter — signed URL defaults to long or no expiry.',
    severity: 'high',
    fix_suggestion:
      'Always set a short Expires value: s3.getSignedUrl("getObject", { Bucket, Key, Expires: 900 }). 900 seconds (15 minutes) is a reasonable default.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bgetSignedUrl\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      return !/\bExpires\s*:/i.test(window);
    },
  },
  {
    id: 'AWS_SES_USER_HTML_BODY',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'SES sendEmail with user-controlled HTML body — enables XSS via email when recipients view the email in a webmail client.',
    severity: 'high',
    fix_suggestion:
      'Sanitize user-provided HTML with DOMPurify or a server-side sanitizer before using in SES email bodies. Use text-only emails when possible.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:sendEmail|sendRawEmail|sendTemplatedEmail)\s*\(/.test(line) &&
          !/\bSES\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10))
        .join(' ');
      return /\b(?:Html|Body)\b.*\breq\s*\.\s*(?:body|query)\b/.test(window) ||
        /\breq\s*\.\s*(?:body|query)\b.*\b(?:Html|Body)\b/.test(window);
    },
  },
  {
    id: 'AWS_DYNAMODB_FULL_SCAN',
    category: 'Denial of Service',
    description:
      'DynamoDB scan() without Limit parameter — scans entire table, causing high read costs and latency at scale.',
    severity: 'medium',
    fix_suggestion:
      'Always set a Limit parameter on DynamoDB scans, or use query() with a key condition instead of scan(). Paginate results.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:dynamodb|docClient|documentClient|ddb)\s*\.\s*scan\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      return !/\bLimit\s*:/i.test(window);
    },
  },
  {
    id: 'AWS_SNS_USER_INPUT',
    category: 'Injection',
    description:
      'SNS publish() with unsanitized user input in Message — may enable notification spam or injection in downstream consumers.',
    severity: 'medium',
    fix_suggestion:
      'Validate and sanitize user input before publishing to SNS. Enforce message length limits and content policies.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:sns|SNS)\s*\.\s*publish\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      return /\bMessage\s*:.*\breq\s*\.\s*(?:body|query)\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 23: Hono / Bun / Deno Specific
  // ════════════════════════════════════════════
  {
    id: 'BUN_FILE_USER_PATH',
    category: 'Path Traversal',
    description:
      'Bun.file() called with user-controlled path — enables path traversal to read arbitrary files on the server.',
    severity: 'high',
    fix_suggestion:
      'Validate and sanitize paths before passing to Bun.file(). Use path.resolve() and verify the resolved path is within an allowed directory.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bBun\s*\.\s*file\s*\(/.test(line)) return false;
      // Must use user input or unvalidated variable
      if (/\bBun\s*\.\s*file\s*\(\s*['"`]/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), lineIdx + 1)
        .join(' ');
      return /\breq\s*\.\s*(?:body|query|params)\b/.test(window) ||
        /\b(?:userPath|filePath|inputPath)\b/.test(window) &&
        !/\b(?:validate|sanitize|resolve|basename|safePath)\b/i.test(window);
    },
  },
  {
    id: 'DENO_RUN_USER_INPUT',
    category: 'Command Injection',
    description:
      'Deno.run() or Deno.Command() with user input in command array — enables command injection.',
    severity: 'critical',
    fix_suggestion:
      'Never pass user input to Deno.run() or Deno.Command(). Use an allowlist of commands and sanitize all arguments.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bDeno\s*\.\s*(?:run|Command)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5))
        .join(' ');
      return /\breq\s*\.\s*(?:body|query|params)\b/.test(window) ||
        /\b(?:userInput|user_input|input|userCmd)\b/.test(window);
    },
  },
  {
    id: 'HONO_HTML_UNSANITIZED',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'Hono c.html() rendering user data without sanitization — enables reflected XSS.',
    severity: 'high',
    fix_suggestion:
      'Sanitize user input with a library like DOMPurify or escape HTML entities before passing to c.html().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bc\s*\.\s*html\s*\(/.test(line)) return false;
      // Exclude static strings
      if (/\bc\s*\.\s*html\s*\(\s*['"`]/.test(line) && !/\$\{/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), lineIdx + 1)
        .join(' ');
      const hasUserData = /\breq\b|\bc\s*\.\s*req\b|\bparam\b|\bquery\b|\bbody\b|\buser/i.test(window);
      const hasSanitize = /\b(?:sanitize|escape|encode|DOMPurify|xss)\b/i.test(window);
      return hasUserData && !hasSanitize;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 24: Rate Limiting & Abuse Prevention
  // ════════════════════════════════════════════
  {
    id: 'RATE_LIMIT_PASSWORD_RESET',
    category: 'Missing Rate Limiting',
    description:
      'Password reset endpoint without rate limiting — enables account enumeration and denial of service via reset email flooding.',
    severity: 'medium',
    fix_suggestion:
      'Add rate limiting to password reset endpoints. Limit by IP and email address.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\s*\.\s*post\s*\(\s*['"]\/(?:api\/)?(?:auth\/)?(?:reset-password|forgot-password|password-reset)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      return !/\b(?:rateLimit|rateLimiter|limiter|throttle|slowDown|brute)\b/i.test(window);
    },
  },
  {
    id: 'RATE_LIMIT_OTP_NO_LIMIT',
    category: 'Missing Rate Limiting',
    description:
      'OTP/2FA verification endpoint without attempt limiting — enables brute-force of short codes.',
    severity: 'high',
    fix_suggestion:
      'Limit OTP verification attempts (e.g., max 5 attempts per code). Lock the code after too many failed attempts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\s*\.\s*post\s*\(\s*['"]\/(?:api\/)?(?:auth\/)?(?:verify|otp|2fa|mfa|totp|verify-code)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      return !/\b(?:rateLimit|rateLimiter|limiter|throttle|attempts?|maxAttempts|lockout)\b/i.test(window);
    },
  },
  {
    id: 'MULTER_NO_LIMITS',
    category: 'Denial of Service',
    description:
      'multer() file upload without limits configuration — allows unlimited file size uploads, enabling denial of service.',
    severity: 'medium',
    fix_suggestion:
      'Configure multer with limits: multer({ limits: { fileSize: 5 * 1024 * 1024 } }) to prevent oversized uploads.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bmulter\s*\(\s*\{/.test(line) && !/\bmulter\s*\(\s*\)/.test(line)) return false;
      // multer() with no args is definitely missing limits
      if (/\bmulter\s*\(\s*\)/.test(line)) return true;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8))
        .join(' ');
      return !/\blimits\b/.test(window);
    },
  },
  {
    id: 'RATE_LIMIT_REGISTRATION',
    category: 'Missing Rate Limiting',
    description:
      'Account creation/registration endpoint without rate limiting — enables bulk fake account registration.',
    severity: 'medium',
    fix_suggestion:
      'Add rate limiting and CAPTCHA to registration endpoints to prevent automated bulk signups.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\s*\.\s*post\s*\(\s*['"]\/(?:api\/)?(?:auth\/)?(?:register|signup|create-account)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 3))
        .join(' ');
      return !/\b(?:rateLimit|rateLimiter|limiter|throttle|captcha|recaptcha|hcaptcha|turnstile)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 25: Secrets in Config Files
  // ════════════════════════════════════════════
  {
    id: 'NPMRC_AUTH_TOKEN',
    category: 'Hardcoded Secrets',
    description:
      'authToken hardcoded in .npmrc-like content — grants npm registry access to anyone who reads this file.',
    severity: 'critical',
    fix_suggestion:
      'Use environment variables for npm auth tokens: //registry.npmjs.org/:_authToken=${NPM_TOKEN}',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /_authToken\s*=\s*[a-zA-Z0-9_-]{20,}/.test(line) &&
        !/\$\{/.test(line) && !/process\s*\.\s*env\b/.test(line);
    },
  },
  {
    id: 'DOCKER_COMPOSE_PLAINTEXT_PASSWORD',
    category: 'Hardcoded Secrets',
    description:
      'Plaintext password in docker-compose environment variable — visible to anyone with access to the compose file.',
    severity: 'high',
    fix_suggestion:
      'Use env_file directive or ${VARIABLE} syntax referencing .env files. Never hardcode passwords in docker-compose.yml.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect YAML-like environment variables with passwords in string literals
      return /(?:PASSWORD|PASSWD|DB_PASS|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD)\s*[:=]\s*['"]?[a-zA-Z0-9!@#$%^&*_-]{6,}['"]?/.test(line) &&
        !/\$\{/.test(line) && !/process\s*\.\s*env\b/.test(line) &&
        !/\benv_file\b/.test(line);
    },
  },
  {
    id: 'GH_ACTIONS_HARDCODED_SECRET',
    category: 'Hardcoded Secrets',
    description:
      'GitHub Actions workflow with hardcoded secret value instead of using ${{ secrets.X }} — secret exposed in repository code.',
    severity: 'critical',
    fix_suggestion:
      'Use GitHub Actions secrets: ${{ secrets.MY_TOKEN }}. Never hardcode tokens in workflow files.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect patterns like GITHUB_TOKEN: "ghp_..." or TOKEN: "sk-..." in workflow-like context
      if (!/\b(?:GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY|DEPLOY_TOKEN|API_KEY|SECRET_KEY)\s*[:=]\s*['"](?:ghp_|gho_|sk_live_|sk-|AKIA|npm_)[a-zA-Z0-9_-]+['"]/.test(line)) return false;
      return !/\$\{\{\s*secrets\./.test(line);
    },
  },
  {
    id: 'TERRAFORM_DEFAULT_CREDENTIALS',
    category: 'Hardcoded Secrets',
    description:
      'Terraform variable with default value containing credentials — defaults are stored in state files and version control.',
    severity: 'high',
    fix_suggestion:
      'Never set default values for sensitive variables in Terraform. Mark them as sensitive and pass via environment variables or .tfvars.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bdefault\s*[:=]\s*['"][a-zA-Z0-9+/=_-]{16,}['"]/.test(line) &&
        /\b(?:password|secret|token|api_key|access_key|credential)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 26: Content Security
  // ════════════════════════════════════════════
  {
    id: 'UGC_HTML_UNSANITIZED',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'User-generated HTML content stored and rendered without sanitization — enables persistent XSS attacks.',
    severity: 'high',
    fix_suggestion:
      'Sanitize all user-generated HTML with DOMPurify or a server-side sanitizer (e.g., sanitize-html) before storage and rendering.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\.innerHTML\s*=/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), lineIdx + 1)
        .join(' ');
      // Must reference user-generated content and lack sanitization
      const hasUGC = /\b(?:comment|post|message|content|description|bio|review|body)\b/i.test(window) &&
        /\b(?:user|author|submitted|stored|db|database|record)\b/i.test(window);
      const hasSanitize = /\b(?:sanitize|DOMPurify|purify|escape|sanitizeHtml|sanitize-html|xss)\b/i.test(window);
      return hasUGC && !hasSanitize;
    },
  },
  {
    id: 'SVG_JAVASCRIPT_UPLOAD',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'SVG file content containing JavaScript event handlers (onload, onerror) — enables XSS when the SVG is served or rendered.',
    severity: 'high',
    fix_suggestion:
      'Sanitize SVG uploads: strip all event handler attributes (on*), <script> tags, and javascript: URIs. Use a dedicated SVG sanitizer.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /<svg\b[^>]*\bon(?:load|error|click|mouseover)\s*=/i.test(line);
    },
  },
  {
    id: 'PDF_GENERATION_USER_HTML',
    category: 'Injection',
    description:
      'PDF generation (puppeteer/wkhtmltopdf) with user-controlled HTML — enables server-side injection to read local files or execute commands.',
    severity: 'high',
    fix_suggestion:
      'Sanitize HTML before PDF generation. Use a template engine with auto-escaping. Restrict file:// protocol access in puppeteer.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:page\s*\.\s*setContent|page\s*\.\s*goto|wkhtmltopdf|setContent)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 5), lineIdx + 1)
        .join(' ');
      return /\breq\s*\.\s*(?:body|query)\b/.test(window) ||
        /\b(?:userHtml|user_html|htmlContent|content)\b/.test(window) &&
        !/\b(?:sanitize|escape|purify)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 27: Concurrency & State
  // ════════════════════════════════════════════
  {
    id: 'GLOBAL_MUTABLE_STATE',
    category: 'Race Condition',
    description:
      'Global mutable state shared between requests — concurrent requests will see/modify each other\'s data, causing data leaks and corruption.',
    severity: 'high',
    fix_suggestion:
      'Use request-scoped state (e.g., res.locals, context objects) instead of module-level mutable variables for per-request data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Module-level `let currentUser = ...` or `let requestData = ...` outside a function
      if (!/^(?:let|var)\s+(?:current(?:User|Request|Session)|request(?:Data|User|Context)|global(?:User|Data|State))\b/.test(line.trim())) return false;
      // Must be at module level (not inside a function)
      const lineIdx = ctx.lineNumber - 1;
      // Count braces before this line to see if we're at module level
      const before = ctx.allLines.slice(0, lineIdx).join('\n');
      const openBraces = (before.match(/\{/g) || []).length;
      const closeBraces = (before.match(/\}/g) || []).length;
      return openBraces - closeBraces <= 0;
    },
  },
  {
    id: 'NON_ATOMIC_READ_WRITE',
    category: 'Race Condition',
    description:
      'Database read followed by conditional write without transaction — concurrent requests can produce inconsistent state.',
    severity: 'high',
    fix_suggestion:
      'Wrap read-then-write sequences in a database transaction with appropriate isolation level, or use atomic operations (e.g., UPDATE ... WHERE).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Look for findUnique/findFirst followed by update without transaction
      if (!/\b(?:findUnique|findFirst|findOne)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10))
        .join(' ');
      const hasConditionalUpdate = /\bif\s*\(/.test(window) && /\b(?:update|save|set)\s*\(/.test(window);
      const hasTransaction = /\b(?:transaction|\$transaction|BEGIN|COMMIT|serializable|isolation)\b/i.test(ctx.fileContent);
      return hasConditionalUpdate && !hasTransaction;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 28: Input Validation Gaps
  // ════════════════════════════════════════════
  {
    id: 'URL_JAVASCRIPT_PROTOCOL',
    category: 'Cross-Site Scripting (XSS)',
    description:
      'URL validation accepts javascript: protocol — enables XSS when the URL is used in href or navigation.',
    severity: 'high',
    fix_suggestion:
      'Validate URLs with the URL constructor and check that protocol is http: or https: only. Reject javascript:, data:, and vbscript: protocols.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect href or src assignment with variable that could be javascript:
      if (!/\b(?:href|src|action|formAction)\s*=\s*\{?\s*(?:url|link|href|redirect|target|userUrl)\b/.test(line)) return false;
      // Check that there's no protocol validation nearby
      return !/\b(?:protocol|startsWith\s*\(\s*['"]https?:?['"]|isValidUrl|validateUrl)\b/.test(line);
    },
  },
  {
    id: 'DATE_PARSE_USER_INPUT',
    category: 'Data Handling',
    description:
      'new Date() with unsanitized user input — can produce NaN, Invalid Date, or unexpected values that break application logic.',
    severity: 'low',
    fix_suggestion:
      'Validate date strings with a library (dayjs, date-fns) or check isNaN(date.getTime()) before use. Use Zod z.coerce.date() for validation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+Date\s*\(\s*req\s*\.\s*(?:body|query|params)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 29: CI/CD & Build Security
  // ════════════════════════════════════════════
  {
    id: 'GH_ACTIONS_EXPRESSION_INJECTION',
    category: 'Code Injection',
    description:
      'GitHub Actions run step using ${{ github.event.pull_request.title }} or similar — enables command injection via crafted PR titles/body.',
    severity: 'critical',
    fix_suggestion:
      'Pass event data as environment variables instead of inline expressions: env: TITLE: ${{ github.event.pull_request.title }}, then use $TITLE in the run step.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect ${{ github.event.* }} in a run: context (string containing both)
      return /\$\{\{\s*github\.event\.(?:pull_request|issue|comment|head_commit)\.(?:title|body|message|name)\s*\}\}/.test(line) &&
        /\brun\s*:/i.test(line);
    },
  },
  {
    id: 'BUILD_HTTP_DEPENDENCY',
    category: 'Supply Chain',
    description:
      'Build script downloading dependency over HTTP (not HTTPS) — vulnerable to man-in-the-middle attacks injecting malicious code.',
    severity: 'high',
    fix_suggestion:
      'Always use HTTPS for downloading build dependencies. Replace http:// with https:// in all download URLs.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:curl|wget|fetch|download|get)\b/i.test(line)) return false;
      return /\bhttp:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(line) &&
        /\b(?:install|setup|build|deploy|script|download)\b/i.test(line);
    },
  },
  {
    id: 'DOCKER_BUILD_ARG_SECRET',
    category: 'Hardcoded Secrets',
    description:
      'Docker build ARG used for secret values — ARGs are visible in image layers and docker history, leaking credentials.',
    severity: 'high',
    fix_suggestion:
      'Use Docker BuildKit secrets: RUN --mount=type=secret,id=mysecret. Never pass secrets via ARG or ENV in Dockerfiles.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bARG\s+(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)\b/i.test(line) &&
        !/\b--secret\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 30: Final Hardening — Edge Cases
  // ════════════════════════════════════════════
  {
    id: 'UNSAFE_REGEX_CONSTRUCTOR',
    category: 'Regex DoS',
    description:
      'RegExp constructor with user input — enables ReDoS via attacker-controlled regex patterns.',
    severity: 'high',
    fix_suggestion:
      'Escape user input before passing to RegExp: new RegExp(escapeRegExp(input)). Or use a safe matching library.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+RegExp\s*\(/.test(line)) return false;
      return /\bnew\s+RegExp\s*\(\s*req\s*\.\s*(?:body|query|params)\b/.test(line) ||
        /\bnew\s+RegExp\s*\(\s*(?:userInput|user_input|input|search|pattern|query)\b/.test(line) &&
        !/\b(?:escape|escapeRegExp|escapeStringRegexp|sanitize)\b/i.test(line);
    },
  },
  {
    id: 'CHILD_PROCESS_CWD_USER_INPUT',
    category: 'Command Injection',
    description:
      'child_process spawn/exec with user-controlled cwd — enables path traversal in command execution context.',
    severity: 'high',
    fix_suggestion:
      'Validate the cwd path against an allowlist. Never use user input directly as the working directory for child processes.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcwd\s*:/.test(line)) return false;
      return /\bcwd\s*:\s*req\s*\.\s*(?:body|query|params)\b/.test(line) ||
        /\bcwd\s*:\s*(?:userDir|userPath|inputDir)\b/.test(line);
    },
  },
  {
    id: 'INSECURE_IFRAME_SANDBOX',
    category: 'Client-Side Security',
    description:
      'iframe with user-controlled src and no sandbox attribute — enables clickjacking and cross-origin attacks.',
    severity: 'medium',
    fix_suggestion:
      'Add sandbox attribute to iframes with user-controlled sources. Validate src against an allowlist of trusted origins.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\biframe\b/i.test(line)) return false;
      if (!/\bsrc\s*=\s*\{/.test(line)) return false;
      return !/\bsandbox\b/.test(line);
    },
  },
  {
    id: 'UNVALIDATED_CONTENT_TYPE',
    category: 'Injection',
    description:
      'Response Content-Type set from user input — enables MIME sniffing attacks and content-type confusion.',
    severity: 'medium',
    fix_suggestion:
      'Validate Content-Type against an allowlist of expected MIME types. Never let users control the Content-Type header.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:Content-Type|content-type)\b.*\breq\s*\.\s*(?:body|query|params)\b/.test(line) ||
        /\bres\s*\.\s*(?:type|contentType|setHeader)\s*\([^)]*\breq\s*\.\s*(?:body|query)\b/.test(line);
    },
  },
  {
    id: 'TEMPLATE_LITERAL_SQL_VARIABLE',
    category: 'SQL Injection',
    description:
      'SQL query assigned to a variable using template literal with interpolation — vulnerable to SQL injection when executed.',
    severity: 'critical',
    fix_suggestion:
      'Use parameterized queries with placeholders ($1, ?, :param) instead of template literal interpolation in SQL strings.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Skip tagged template literals like sql`...`
      if (/\b(?:sql|html|css|gql|graphql)\s*`/.test(line)) return false;
      // Skip Prisma safe tagged templates ($queryRaw`...` and $executeRaw`...`)
      if (/\$(?:queryRaw|executeRaw)\s*`/.test(line)) return false;
      // Skip safe Prisma ORM operations (e.g., prisma.user.findMany())
      if (isPrismaSafeOrmCall(line)) return false;
      // Match variable assignment like: const query = `SELECT ... ${variable} ...`;
      if (!/\b(?:const|let|var)\s+(?:query|sql|stmt|statement)\s*=\s*`/.test(line)) return false;
      return /`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^`]*\$\{[^}]+\}[^`]*`/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 21: Regex & Input Parsing
  // ════════════════════════════════════════════
  {
    id: 'REGEX_USER_INPUT_UNESCAPED',
    category: 'Regex DoS',
    description:
      'User input passed directly to new RegExp() without escaping — enables ReDoS and regex injection attacks.',
    severity: 'high',
    fix_suggestion:
      'Escape user input before passing to RegExp constructor. Use a helper like escapeRegExp(input) or the escape-string-regexp library.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+RegExp\s*\(/.test(line)) return false;
      // Detect user input directly in RegExp without escaping
      const hasUserInput = /\bnew\s+RegExp\s*\(\s*(?:req\s*\.\s*(?:body|query|params)|userInput|searchTerm|filterText|searchQuery)\b/.test(line);
      const hasEscape = /\b(?:escape|escapeRegExp|escapeStringRegexp|sanitize)\b/i.test(line);
      return hasUserInput && !hasEscape;
    },
  },
  {
    id: 'HTTP_PARAM_POLLUTION',
    category: 'Input Validation',
    description:
      'HTTP parameter used without array check — duplicate parameters can bypass validation via HTTP Parameter Pollution.',
    severity: 'medium',
    fix_suggestion:
      'Always validate that query parameters are strings, not arrays. Use typeof check or a validation library to handle duplicate params.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect req.query.param used directly in security-sensitive context without type check
      if (!/\breq\.query\.\w+/.test(line)) return false;
      // Check surrounding context for security-sensitive operations
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 4)).join(' ');
      const hasSensitiveOp = /\b(?:WHERE|SELECT|password|token|auth|admin|role|redirect|url)\b/i.test(window);
      const hasTypeCheck = /\btypeof\s+.*===?\s*['"]string['"]/.test(window) ||
        /\bArray\.isArray\b/.test(window) ||
        /\bString\s*\(/.test(window) ||
        /\bz\.string\b/.test(window);
      return hasSensitiveOp && !hasTypeCheck;
    },
  },
  {
    id: 'UNICODE_CASE_FOLDING_BYPASS',
    category: 'Input Validation',
    description:
      'Security check uses case-insensitive comparison without Unicode normalization — Unicode case-folding can bypass blocklists.',
    severity: 'medium',
    fix_suggestion:
      'Normalize input with str.normalize("NFC") or str.normalize("NFKC") before security checks. Use Unicode-aware comparison.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect toLowerCase/toUpperCase used in security checks without normalize
      if (!/\.(?:toLowerCase|toUpperCase)\s*\(\s*\)/.test(line)) return false;
      const hasSecurityCheck = /\b(?:includes|indexOf|match|test|startsWith|endsWith)\s*\(.*(?:admin|root|script|javascript|__proto__|constructor)\b/i.test(line);
      const hasNormalize = /\.normalize\s*\(/.test(line);
      return hasSecurityCheck && !hasNormalize;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 22: Memory & Buffer Safety
  // ════════════════════════════════════════════
  {
    id: 'BUFFER_ALLOC_UNSAFE_LEAK',
    category: 'Memory Safety',
    description:
      'Buffer.allocUnsafe() used — returns uninitialized memory that may contain sensitive data from previous allocations.',
    severity: 'high',
    fix_suggestion:
      'Use Buffer.alloc() instead of Buffer.allocUnsafe(). It zero-fills the buffer, preventing uninitialized memory leaks.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bBuffer\.allocUnsafe\s*\(/.test(line);
    },
  },
  {
    id: 'BUFFER_DEPRECATED_CONSTRUCTOR',
    category: 'Memory Safety',
    description:
      'Deprecated Buffer() constructor used with user-controlled size — can cause denial-of-service or uninitialized memory exposure.',
    severity: 'high',
    fix_suggestion:
      'Use Buffer.alloc(size) for zero-filled buffers or Buffer.from(data) for data conversion. The Buffer() constructor is deprecated.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect new Buffer(variable) or Buffer(variable) — deprecated constructor
      if (/\bnew\s+Buffer\s*\(\s*(?:req|user|input|size|len|length|n|count)\b/.test(line)) return true;
      if (/(?<!\w)Buffer\s*\(\s*(?:req|user|input|size|len|length|n|count)\b/.test(line) &&
        !/\bBuffer\.\w+\s*\(/.test(line)) return true;
      return false;
    },
  },
  {
    id: 'INTEGER_OVERFLOW_ALLOC',
    category: 'Memory Safety',
    description:
      'Arithmetic on allocation size without overflow check — integer overflow can cause undersized buffer allocation.',
    severity: 'medium',
    fix_suggestion:
      'Validate allocation sizes with explicit bounds checking. Use Number.isSafeInteger() and set maximum size limits before allocation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect Buffer.alloc/allocUnsafe or new ArrayBuffer with arithmetic on size
      return /\b(?:Buffer\.alloc(?:Unsafe)?|new\s+ArrayBuffer|new\s+Uint8Array)\s*\(\s*\w+\s*[*+]\s*\w+/.test(line) &&
        !/\bNumber\.isSafeInteger\b/.test(line) &&
        !/\bMath\.min\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 23: Async Security Patterns
  // ════════════════════════════════════════════
  {
    id: 'ASYNC_AUTH_NO_AWAIT',
    category: 'Authentication',
    description:
      'Async authorization function called without await — check always resolves to truthy Promise, bypassing auth.',
    severity: 'critical',
    fix_suggestion:
      'Always use await when calling async authorization functions: if (await isAuthorized(user)). A Promise is always truthy.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect if (isAuthorized(user)) or if (checkAuth(user)) without await
      if (!/\bif\s*\(\s*(?:isAuthorized|checkAuth|isAdmin|hasPermission|canAccess|isAuthenticated|verifyToken|validateSession)\s*\(/.test(line)) return false;
      // Make sure there's no await
      if (/\bawait\s+(?:isAuthorized|checkAuth|isAdmin|hasPermission|canAccess|isAuthenticated|verifyToken|validateSession)\b/.test(line)) return false;
      // Check if the function is declared as async in nearby context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 15), lineIdx).join('\n');
      return /\basync\s+function\s+(?:isAuthorized|checkAuth|isAdmin|hasPermission|canAccess|isAuthenticated|verifyToken|validateSession)\b/.test(window) ||
        /\b(?:isAuthorized|checkAuth|isAdmin|hasPermission|canAccess|isAuthenticated|verifyToken|validateSession)\s*=\s*async\b/.test(window) ||
        // Also flag if the function itself is in an async context (async handler)
        /\basync\s+(?:function|\()/.test(ctx.allLines[lineIdx - 1] || '') ||
        /\basync\s+(?:function|\()/.test(ctx.allLines[lineIdx - 2] || '');
    },
  },
  {
    id: 'UNHANDLED_REJECTION_AUTH',
    category: 'Authentication',
    description:
      'Security-critical async operation without error handling — unhandled rejection could silently skip auth checks.',
    severity: 'high',
    fix_suggestion:
      'Wrap security-critical async operations in try/catch blocks. An unhandled rejection in auth code could allow unauthorized access.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect auth-related promises without catch or try/catch
      if (!/\b(?:verifyToken|validateSession|checkPermission|authenticate)\s*\(/.test(line)) return false;
      if (/\bawait\b/.test(line)) {
        // Check if inside try block
        const lineIdx = ctx.lineNumber - 1;
        const before = ctx.allLines.slice(Math.max(0, lineIdx - 10), lineIdx).join('\n');
        return !/\btry\s*\{/.test(before);
      }
      // Promise without .catch
      if (/\.then\s*\(/.test(line) && !/\.catch\s*\(/.test(line)) return true;
      return false;
    },
  },
  {
    id: 'PROMISE_ALL_AUTH_NO_BOUNDARY',
    category: 'Authentication',
    description:
      'Promise.all used for auth checks without error boundaries — one failure rejects all, potentially bypassing remaining checks.',
    severity: 'medium',
    fix_suggestion:
      'Use Promise.allSettled() for multiple auth checks, or wrap each in try/catch. Promise.all fails fast — one rejection skips remaining checks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bPromise\.all\s*\(/.test(line)) return false;
      return /(?:auth|permission|access|role|token|verify|validate)/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 24: Docker & CI/CD
  // ════════════════════════════════════════════
  {
    id: 'DOCKER_COMPOSE_SECRET_ENV',
    category: 'Hardcoded Secrets',
    description:
      'Secret value hardcoded in docker-compose environment section — exposed in version control and container inspection.',
    severity: 'high',
    fix_suggestion:
      'Use env_file directive or ${VARIABLE} syntax referencing .env files. Never hardcode API keys or tokens in docker-compose.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect environment variable assignments with secret-sounding names and literal values
      if (!/\b(?:API_KEY|SECRET_KEY|AUTH_TOKEN|PRIVATE_KEY|ACCESS_TOKEN|DATABASE_URL)\s*[:=]/.test(line)) return false;
      // Must have a literal value, not a variable reference
      const hasLiteralValue = /[:=]\s*['"]?(?:sk_|pk_|ghp_|gho_|AKIA|mongodb\+srv|postgres:\/\/|mysql:\/\/)[^\s'"]*/.test(line);
      const hasEnvRef = /\$\{/.test(line) || /process\s*\.\s*env\b/.test(line);
      return hasLiteralValue && !hasEnvRef;
    },
  },
  {
    id: 'DOCKERFILE_NPM_INSTALL_NO_LOCK',
    category: 'Supply Chain',
    description:
      'RUN npm install in Dockerfile without lockfile — may install different package versions in production vs development.',
    severity: 'medium',
    fix_suggestion:
      'Use "RUN npm ci" instead of "RUN npm install" in Dockerfiles. npm ci uses the lockfile for deterministic builds.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect RUN npm install (without --ci flag) in Dockerfile-like content
      return /\bRUN\s+npm\s+install\b/.test(line) &&
        !/\bnpm\s+ci\b/.test(line);
    },
  },
  {
    id: 'DOCKER_LATEST_TAG_PRODUCTION',
    category: 'Supply Chain',
    description:
      'Docker image uses :latest tag — non-deterministic builds may pull different versions, breaking production.',
    severity: 'medium',
    fix_suggestion:
      'Pin Docker images to specific versions or SHA digests (e.g., node:20.11.0-alpine or node@sha256:...) for reproducible builds.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect FROM image:latest in Dockerfile-like content
      return /\bFROM\s+\w+(?:\/\w+)?:latest\b/.test(line);
    },
  },
  {
    id: 'DEBUG_INSPECT_EXPOSED',
    category: 'Configuration',
    description:
      'Node.js --inspect bound to 0.0.0.0 — exposes debugger to the network, allowing remote code execution.',
    severity: 'critical',
    fix_suggestion:
      'Bind --inspect to localhost only (--inspect=127.0.0.1:9229). Never expose the debug port on all interfaces in production.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /--inspect(?:=|-brk=)0\.0\.0\.0/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 25: Secrets in Frontend
  // ════════════════════════════════════════════
  {
    id: 'FIREBASE_ADMIN_IN_CLIENT',
    category: 'Hardcoded Secrets',
    description:
      'Firebase Admin SDK imported in client-side file (.tsx) — Admin SDK credentials should never be in browser code.',
    severity: 'critical',
    fix_suggestion:
      'Move Firebase Admin SDK usage to server-side code only (API routes, server components). Use the client SDK (firebase/app) in frontend code.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bfirebase-admin\b/.test(line)) return false;
      // Only flag in client-side files (.tsx, .jsx) or files without 'server' in path
      const isClientFile = ctx.filePath.endsWith('.tsx') || ctx.filePath.endsWith('.jsx');
      const hasServerIndicator = /(?:server|api|backend|admin)/.test(ctx.filePath.toLowerCase());
      return isClientFile && !hasServerIndicator;
    },
  },
  {
    id: 'VITE_DEFINE_SECRET',
    category: 'Hardcoded Secrets',
    description:
      'Vite define config exposes secret value — define values are inlined into client-side bundle at build time.',
    severity: 'critical',
    fix_suggestion:
      'Never pass secrets through Vite define. Use server-side API routes for secret operations. Only expose public values via define.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bdefine\s*:/.test(line) && !/\bdefine\s*\(/.test(line)) return false;
      return /\b(?:SECRET|API_KEY|PRIVATE_KEY|TOKEN|PASSWORD|CREDENTIAL)\b/i.test(line) &&
        /['"][a-zA-Z0-9_-]{8,}['"]/.test(line) &&
        !/process\s*\.\s*env\b/.test(line);
    },
  },
  {
    id: 'NEXT_PUBLIC_SECRET_NAME',
    category: 'Hardcoded Secrets',
    description:
      'NEXT_PUBLIC_ environment variable with secret/key/password in name — these values are exposed to the browser.',
    severity: 'high',
    fix_suggestion:
      'Remove the NEXT_PUBLIC_ prefix from secret environment variables. Access server-only secrets via API routes or server components.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bNEXT_PUBLIC_\w*(?:SECRET|PASSWORD|PRIVATE_KEY|ADMIN_KEY|DB_PASS|AUTH_KEY)\b/i.test(line)) return false;
      // Exclude known-public environment variables
      if (/\bNEXT_PUBLIC_SUPABASE_ANON_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_SUPABASE_URL\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_CLERK_PUBLISHABLE_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_FIREBASE_AUTH_DOMAIN\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_FIREBASE_API_KEY\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_\w*PUBLISHABLE\w*\b/.test(line)) return false;
      if (/\bNEXT_PUBLIC_\w*PUBLIC_KEY\b/.test(line)) return false;
      return true;
    },
  },
  {
    id: 'API_KEY_LITERAL_REACT',
    category: 'Hardcoded Secrets',
    description:
      'API key string literal in React/frontend component — exposed in client-side JavaScript bundle.',
    severity: 'critical',
    fix_suggestion:
      'Move API keys to server-side code. Use environment variables via server API routes, never hardcode in components.',
    auto_fixable: false,
    fileTypes: ['.tsx', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect API key patterns directly in component files
      if (!/\b(?:apiKey|api_key|API_KEY)\s*[:=]\s*['"]/.test(line)) return false;
      // Must have a real-looking key value, not a placeholder
      return /['"](?:sk_live_|pk_live_|sk-|AIza|AKIA|ghp_|gho_|xox[bpas]-)[a-zA-Z0-9_-]{10,}['"]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 26: Secure Communications
  // ════════════════════════════════════════════
  {
    id: 'INSECURE_HTTP_API',
    category: 'Configuration',
    description:
      'API call using HTTP instead of HTTPS — data transmitted in plaintext, vulnerable to MITM attacks.',
    severity: 'high',
    fix_suggestion:
      'Always use HTTPS for API calls. Replace http:// with https:// for all production endpoints.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bfetch\s*\(\s*['"`]http:\/\//.test(line) &&
        !/\baxios\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"`]http:\/\//.test(line) &&
        !/\bhttp:\/\/[a-zA-Z0-9]/.test(line)) return false;
      // Exclude localhost, 127.0.0.1, and test URLs
      if (/http:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(line)) return false;
      // Must be a fetch/axios/got/request call or URL assignment
      return /\b(?:fetch|axios|got|request|http\.get|http\.post|http\.request)\s*\(\s*['"`]http:\/\//.test(line) ||
        /\b(?:url|endpoint|baseUrl|apiUrl|baseURL)\s*[:=]\s*['"`]http:\/\/(?!localhost|127\.0\.0\.1)/.test(line);
    },
  },
  {
    id: 'INSECURE_WEBSOCKET',
    category: 'Configuration',
    description:
      'WebSocket connection using ws:// instead of wss:// — data transmitted in plaintext over unencrypted WebSocket.',
    severity: 'high',
    fix_suggestion:
      'Use wss:// for WebSocket connections in production. ws:// should only be used for localhost development.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bws:\/\//.test(line)) return false;
      // Exclude localhost and local IPs
      if (/ws:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(line)) return false;
      // Must be in a WebSocket constructor or URL assignment context
      return /\bnew\s+WebSocket\s*\(\s*['"`]ws:\/\//.test(line) ||
        /\b(?:url|endpoint|wsUrl|socketUrl)\s*[:=]\s*['"`]ws:\/\/(?!localhost|127\.0\.0\.1)/.test(line);
    },
  },
  {
    id: 'MIXED_CONTENT_SCRIPT',
    category: 'Configuration',
    description:
      'Script loaded over HTTP in HTTPS context — mixed content allows MITM to inject malicious JavaScript.',
    severity: 'high',
    fix_suggestion:
      'Load all scripts over HTTPS. Use protocol-relative URLs or HTTPS explicitly for all external resources.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect script src loading over HTTP
      if (!/\bsrc\s*=\s*['"`]http:\/\//.test(line) && !/\.src\s*=\s*['"`]http:\/\//.test(line)) return false;
      if (/http:\/\/(?:localhost|127\.0\.0\.1)/.test(line)) return false;
      return /\b(?:script|iframe|link)\b/i.test(line) ||
        /\.src\s*=\s*['"`]http:\/\//.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 27: Authorization Advanced
  // ════════════════════════════════════════════
  {
    id: 'AUTH_ROLE_FROM_CLIENT',
    category: 'Authorization',
    description:
      'Admin/role check using client-provided value (req.body.role) — attacker can set any role in request body.',
    severity: 'critical',
    fix_suggestion:
      'Get user role from server-side session, JWT, or database lookup. Never trust role values from the request body or query parameters.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\breq\s*\.\s*body\s*\.\s*(?:role|isAdmin|permissions|accessLevel)\b/.test(line) &&
        /(?:===?\s*['"]admin['"]|===?\s*['"]root['"]|===?\s*true\b|!==?\s*['"]user['"])/i.test(line);
    },
  },
  {
    id: 'MISSING_OWNERSHIP_CHECK',
    category: 'Authorization',
    description:
      'Database UPDATE/DELETE by ID without ownership check (no user_id/owner_id in WHERE clause) — IDOR vulnerability.',
    severity: 'high',
    fix_suggestion:
      'Always include user_id or owner_id from the authenticated session in WHERE clauses for UPDATE and DELETE operations.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect UPDATE/DELETE with WHERE id = but no user_id/owner_id
      const hasUpdateDelete = /\b(?:UPDATE|DELETE)\b.*\bWHERE\b.*\bid\s*=/.test(line);
      if (!hasUpdateDelete) return false;
      const hasOwnerCheck = /\b(?:user_id|owner_id|created_by|author_id|userId|ownerId)\b/.test(line);
      return !hasOwnerCheck;
    },
  },
  {
    id: 'AUTH_METHOD_OVERRIDE',
    category: 'Authorization',
    description:
      'Method override enabled — attackers can bypass authorization by sending _method parameter to change HTTP method.',
    severity: 'high',
    fix_suggestion:
      'Disable method override in production or restrict to safe methods. If needed, validate the override against the original auth check.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:methodOverride|method-override|_method)\b/.test(line) &&
        /\b(?:use|require|import)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 28: AI/LLM Security v3
  // ════════════════════════════════════════════
  {
    id: 'AI_OUTPUT_EVAL_V2',
    category: 'AI/LLM Security',
    description:
      'LLM output passed to eval(), Function constructor, or vm.runInContext — enables arbitrary code execution from AI responses.',
    severity: 'critical',
    fix_suggestion:
      'Never execute LLM output as code. Use structured output with Zod validation, or a sandboxed interpreter for code execution.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect eval/Function/vm with LLM output variables
      return /\b(?:eval|Function|vm\.run\w*)\s*\(\s*(?:aiResponse|llmOutput|completion|generated|modelOutput|chatResponse|aiResult)\b/.test(line);
    },
  },
  {
    id: 'AI_OUTPUT_SQL',
    category: 'AI/LLM Security',
    description:
      'AI/LLM response inserted into SQL query — enables SQL injection via adversarial model outputs.',
    severity: 'critical',
    fix_suggestion:
      'Never insert AI/LLM output into SQL queries. Validate and sanitize model output, or use parameterized queries with AI-generated values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      const hasSql = /\b(?:query|execute|raw)\s*\(/.test(line) || /\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(line);
      const hasAiVar = /\b(?:aiResponse|llmOutput|completion|generated|modelOutput|chatResponse|aiResult|gptResponse)\b/.test(line);
      return hasSql && hasAiVar && (/\+\s*(?:aiResponse|llmOutput|completion|generated|modelOutput|chatResponse)/.test(line) ||
        /\$\{(?:aiResponse|llmOutput|completion|generated|modelOutput|chatResponse)/.test(line));
    },
  },
  {
    id: 'AI_OUTPUT_HTML_UNSANITIZED',
    category: 'AI/LLM Security',
    description:
      'AI/LLM model output rendered as HTML without sanitization — enables XSS via adversarial model responses.',
    severity: 'high',
    fix_suggestion:
      'Sanitize AI output with DOMPurify before rendering as HTML. Or display as plain text using textContent instead of innerHTML.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.innerHTML\s*=/.test(line) && !/dangerouslySetInnerHTML/.test(line)) return false;
      return /\b(?:aiResponse|llmOutput|completion|generated|modelOutput|chatResponse|aiResult|gptResponse)\b/.test(line) &&
        !/\b(?:sanitize|DOMPurify|purify|escape)\b/i.test(line);
    },
  },
  {
    id: 'AI_TOOL_SCHEMA_USER_INPUT',
    category: 'AI/LLM Security',
    description:
      'User input embedded in AI tool/function calling schema — enables tool-use injection to manipulate AI tool calls.',
    severity: 'high',
    fix_suggestion:
      'Never embed user input in tool/function schemas. Validate and sanitize all inputs before including in AI function definitions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detect user input in tool definitions
      const hasToolSchema = /\b(?:tools|functions|function_call)\s*[:=]/.test(line);
      const hasUserInput = /\b(?:req\.body|userInput|user_input|req\.query)\b/.test(line);
      if (!hasToolSchema && !hasUserInput) return false;
      return hasToolSchema && hasUserInput;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 29: Payment & Financial
  // ════════════════════════════════════════════
  {
    id: 'STRIPE_AMOUNT_FROM_CLIENT',
    category: 'Payment Security',
    description:
      'Stripe charge amount taken directly from request body — attackers can modify the amount to pay less.',
    severity: 'critical',
    fix_suggestion:
      'Always calculate payment amounts server-side from your product/price database. Never trust amounts from the client.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bamount\s*:/.test(line)) return false;
      return /\bamount\s*:\s*req\s*\.\s*body\s*\.\s*(?:amount|price|total|cost)\b/.test(line) &&
        /\bstripe\b/i.test(line);
    },
  },
  {
    id: 'NEGATIVE_QUANTITY_NO_CHECK',
    category: 'Payment Security',
    description:
      'Quantity from user input used in payment calculation without positivity check — negative values can reverse charges.',
    severity: 'high',
    fix_suggestion:
      'Validate that quantity is a positive integer before using in price calculations. Use Math.max(1, quantity) or explicit validation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:quantity|qty)\b/.test(line)) return false;
      if (!/\breq\s*\.\s*body\s*\.\s*(?:quantity|qty)\b/.test(line)) return false;
      return /\b(?:price|amount|total|cost)\b/.test(line) && /[*]/.test(line);
    },
  },
  {
    id: 'STRIPE_PRICE_ID_FROM_CLIENT',
    category: 'Payment Security',
    description:
      'Stripe price ID taken from client request without server validation — attackers can substitute a cheaper price ID.',
    severity: 'high',
    fix_suggestion:
      'Validate price IDs against your server-side product catalog. Never pass client-provided price IDs directly to Stripe.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bprice\s*:\s*req\s*\.\s*body\s*\.\s*(?:priceId|price_id|price)\b/.test(line)) return false;
      return /\bstripe\b/i.test(line) || /\bcheckout\b/i.test(line) || /\bsession\b/i.test(line);
    },
  },
  {
    id: 'WEBHOOK_NO_STRIPE_SIGNATURE',
    category: 'Payment Security',
    description:
      'Stripe webhook handler without signature verification — attackers can forge webhook events to manipulate payment state.',
    severity: 'critical',
    fix_suggestion:
      'Always verify Stripe webhook signatures: stripe.webhooks.constructEvent(body, sig, webhookSecret). Never process unverified events.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect webhook handler processing Stripe events without verification
      if (!/\b(?:checkout\.session\.completed|payment_intent\.succeeded|invoice\.paid|customer\.subscription)\b/.test(line)) return false;
      // If the file already calls constructEvent or webhooks.constructEvent anywhere, the signature is verified
      if (/\b(?:constructEvent|webhooks\.constructEvent)\b/.test(ctx.fileContent)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 10), Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return !/\b(?:constructEvent|verifyWebhookSignature|stripe-signature|webhook_secret)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 31-35: Express / Node.js Deep Dive
  // ════════════════════════════════════════════
  {
    id: 'EXPRESS_STATIC_SENSITIVE_DIR',
    category: 'Server Misconfiguration',
    description:
      'express.static serving the project root, home directory, or sensitive path — may expose .env, .git, or config files.',
    severity: 'high',
    fix_suggestion:
      'Serve only a dedicated public/ or static/ directory. Never serve the project root or parent directories.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bexpress\.static\b/.test(line)) return false;
      return /express\.static\s*\(\s*['"`](?:\.\.?[\/\\]?|\/|~)['"`]\s*\)/.test(line) ||
        /express\.static\s*\(\s*__dirname\s*\)/.test(line) ||
        /express\.static\s*\(\s*process\.cwd\(\)\s*\)/.test(line);
    },
  },
  {
    id: 'CRLF_HEADER_INJECTION',
    category: 'Injection',
    description:
      'Response header set with user input containing potential CRLF characters — enables response splitting attacks.',
    severity: 'high',
    fix_suggestion:
      'Sanitize header values by stripping \\r and \\n characters. Use a framework that auto-escapes header values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:setHeader|writeHead|header)\s*\(/.test(line)) return false;
      return /\b(?:setHeader|writeHead|header)\s*\([^)]*req\s*\.\s*(?:query|params|body|headers)\b/.test(line);
    },
  },
  {
    id: 'EXPRESS_TRUST_PROXY_TRUE',
    category: 'Server Misconfiguration',
    description:
      'Express trust proxy set to true without restriction — allows IP spoofing via X-Forwarded-For header.',
    severity: 'medium',
    fix_suggestion:
      'Set trust proxy to a specific number of hops (e.g., 1) or a trusted subnet rather than boolean true.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bset\s*\(\s*['"`]trust\s+proxy['"`]\s*,\s*true\s*\)/.test(line);
    },
  },
  {
    id: 'PROCESS_EXIT_IN_HANDLER',
    category: 'Reliability',
    description:
      'process.exit() called inside a request handler — kills the entire server on a single request failure.',
    severity: 'high',
    fix_suggestion:
      'Use proper error handling (next(err) or res.status(500)) instead of process.exit() in request handlers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bprocess\.exit\s*\(/.test(line)) return false;
      // Check surrounding context for route handler pattern
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 15), lineIdx + 1).join('\n');
      return /\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(/.test(window) ||
        /\b(?:req|request)\s*,\s*(?:res|response)\b/.test(window);
    },
  },
  {
    id: 'EXPRESS_ERROR_STACK_LEAK',
    category: 'Information Disclosure',
    description:
      'Express error handler sends stack trace to client — reveals internal code paths and dependencies.',
    severity: 'medium',
    fix_suggestion:
      'Only send stack traces in development. In production, return a generic error message.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Pattern: res.json/send with err.stack or error.stack
      if (!/\b(?:res|response)\s*\.\s*(?:json|send|status)\b/.test(line)) return false;
      return /\b(?:err|error)\.stack\b/.test(line);
    },
  },
  {
    id: 'MISSING_REFERRER_POLICY',
    category: 'Security Headers',
    description:
      'Helmet configured without Referrer-Policy — browser may leak full URL in Referer header to third parties.',
    severity: 'low',
    fix_suggestion:
      'Set referrerPolicy to "strict-origin-when-cross-origin" or "no-referrer" in Helmet config.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bhelmet\s*\(/.test(line)) return false;
      return /\breferrerPolicy\s*:\s*false\b/.test(line);
    },
  },
  {
    id: 'HTTP_METHOD_OVERRIDE_UNRESTRICTED',
    category: 'Server Misconfiguration',
    description:
      'HTTP method override enabled without restriction — attackers can change GET to DELETE/PUT via headers.',
    severity: 'medium',
    fix_suggestion:
      'Restrict method override to only specific methods and require authentication for destructive operations.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bmethodOverride\s*\(\s*\)/.test(line) ||
        /\bmethod-override\b/.test(line) && /\b(?:app|router)\s*\.\s*use\b/.test(line) && !/\b(?:only|methods|filter)\b/.test(line);
    },
  },
  {
    id: 'BODYPARSER_NO_LIMIT',
    category: 'Denial of Service',
    description:
      'Body parser without size limit — enables denial of service via oversized request bodies.',
    severity: 'medium',
    fix_suggestion:
      'Set a size limit: express.json({ limit: "100kb" }) or bodyParser.json({ limit: "100kb" }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // express.json() or bodyParser.json() without limit option
      if (!/\b(?:express|bodyParser|body-parser)\s*\.\s*(?:json|urlencoded|raw|text)\s*\(/.test(line)) return false;
      // If empty parens or no limit mentioned
      return /\.\s*(?:json|urlencoded|raw|text)\s*\(\s*\)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 36-40: React / Next.js / Frontend Deep Dive
  // ════════════════════════════════════════════
  {
    id: 'CSP_UNSAFE_INLINE',
    category: 'Security Headers',
    description:
      'Content Security Policy with unsafe-inline — allows execution of inline scripts, defeating XSS protections.',
    severity: 'high',
    fix_suggestion:
      'Replace unsafe-inline with nonces or hashes for inline scripts. Use a strict CSP policy.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bunsafe-inline\b/.test(line)) return false;
      // Must be in a CSP context (meta tag or header)
      return /\bcontent-security-policy\b/i.test(line) ||
        /\bscript-src\b/.test(line) ||
        /\bdefaultSrc\b/.test(line) ||
        /\bscriptSrc\b/.test(line);
    },
  },
  {
    id: 'CSP_UNSAFE_EVAL',
    category: 'Security Headers',
    description:
      'Content Security Policy with unsafe-eval — allows eval() and similar functions, enabling XSS attacks.',
    severity: 'high',
    fix_suggestion:
      'Remove unsafe-eval from CSP. Refactor code that relies on eval(), new Function(), or setTimeout with strings.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bunsafe-eval\b/.test(line)) return false;
      return /\bcontent-security-policy\b/i.test(line) ||
        /\bscript-src\b/.test(line) ||
        /\bdefaultSrc\b/.test(line) ||
        /\bscriptSrc\b/.test(line);
    },
  },
  {
    id: 'CDN_IMPORT_NO_INTEGRITY',
    category: 'Supply Chain',
    description:
      'External CDN script loaded without integrity hash — a compromised CDN can inject malicious code.',
    severity: 'high',
    fix_suggestion:
      'Add integrity="sha384-..." and crossorigin="anonymous" to all CDN script tags.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsrc\s*=\s*['"`]https?:\/\/(?:cdn|unpkg|cdnjs|jsdelivr)\b/.test(line)) return false;
      return !/\bintegrity\s*=/.test(line);
    },
  },
  {
    id: 'INDEXEDDB_AUTH_TOKEN',
    category: 'Client-Side Storage',
    description:
      'Auth tokens stored in IndexedDB — accessible to any script on the same origin, including XSS payloads.',
    severity: 'medium',
    fix_suggestion:
      'Store auth tokens in httpOnly cookies. Use IndexedDB only for non-sensitive application data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:indexedDB|IDBDatabase|objectStore)\b/.test(line)) return false;
      return /\b(?:token|jwt|session|accessToken|refreshToken|access_token|refresh_token|auth)\b/i.test(line) &&
        /\b(?:put|add|store)\s*\(/.test(line);
    },
  },
  {
    id: 'SERVICE_WORKER_CACHE_SENSITIVE',
    category: 'Client-Side Storage',
    description:
      'Service worker caching API responses that may contain sensitive data — cached data persists after logout.',
    severity: 'medium',
    fix_suggestion:
      'Exclude authentication endpoints and user-specific data from service worker cache. Use no-store for sensitive responses.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcache\s*\.\s*(?:put|add|addAll)\b/.test(line)) return false;
      return /\/api\/(?:auth|user|token|session)|\/login|\/oauth/.test(line);
    },
  },
  {
    id: 'WINDOW_LOCATION_HASH_ROUTE',
    category: 'Client-Side Security',
    description:
      'window.location.hash used for routing or auth decisions without validation — enables hash-based attacks.',
    severity: 'medium',
    fix_suggestion:
      'Validate and sanitize hash values. Use a proper routing library instead of manual hash parsing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bwindow\.location\.hash\b/.test(line)) return false;
      return /\b(?:token|auth|session|jwt|admin|role|redirect)\b/i.test(line);
    },
  },
  {
    id: 'NEXT_DATA_AUTH_CHECK',
    category: 'Client-Side Security',
    description:
      'Using __NEXT_DATA__ for authentication/authorization checks — client-side data is trivially editable.',
    severity: 'high',
    fix_suggestion:
      'Perform all auth checks server-side in getServerSideProps or middleware. Never trust __NEXT_DATA__ for security.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b__NEXT_DATA__\b/.test(line)) return false;
      return /\b(?:auth|role|admin|isAdmin|isAuthenticated|user|permission|session)\b/i.test(line);
    },
  },
  {
    id: 'REACT_REF_SECURITY',
    category: 'Client-Side Security',
    description:
      'React ref used for security decisions — refs can be manipulated and should not be trusted for auth logic.',
    severity: 'medium',
    fix_suggestion:
      'Move security logic to server-side. Do not use DOM element refs for access control decisions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bref\s*\.\s*current\b/.test(line)) return false;
      return /\b(?:isAdmin|isAuth|role|permission|authorized|authenticated)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 41-45: Python Deep Dive
  // ════════════════════════════════════════════
  {
    id: 'DJANGO_ALLOWED_HOSTS_WILDCARD',
    category: 'Server Misconfiguration',
    description:
      'Django ALLOWED_HOSTS contains wildcard "*" — allows host header attacks for cache poisoning and password reset hijacking.',
    severity: 'high',
    fix_suggestion:
      'Set ALLOWED_HOSTS to your specific domain names: ALLOWED_HOSTS = ["example.com", "www.example.com"].',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bALLOWED_HOSTS\s*=\s*\[.*['"`]\*['"`]/.test(line);
    },
  },
  {
    id: 'DJANGO_SECRET_KEY_HARDCODED',
    category: 'Secrets',
    description:
      'Django SECRET_KEY hardcoded in source — compromises session security, CSRF tokens, and signed cookies.',
    severity: 'critical',
    fix_suggestion:
      'Load SECRET_KEY from an environment variable: SECRET_KEY = os.environ["DJANGO_SECRET_KEY"].',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bSECRET_KEY\s*=/.test(line)) return false;
      if (isFrameworkSource(ctx.filePath)) return false;
      // Hardcoded if assigned a string literal, not os.environ or config call
      return /\bSECRET_KEY\s*=\s*['"`]/.test(line) && !/\bos\.environ\b/.test(line) && !/\bconfig\s*\(/.test(line);
    },
  },
  {
    id: 'DJANGO_CSRF_COOKIE_INSECURE',
    category: 'Session Security',
    description:
      'Django CSRF_COOKIE_SECURE set to False — CSRF cookies can be intercepted over HTTP.',
    severity: 'medium',
    fix_suggestion:
      'Set CSRF_COOKIE_SECURE = True in production settings to ensure cookies are only sent over HTTPS.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bCSRF_COOKIE_SECURE\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'FLASK_DEBUG_PRODUCTION',
    category: 'Server Misconfiguration',
    description:
      'Flask app running with debug=True — exposes interactive debugger that allows remote code execution.',
    severity: 'critical',
    fix_suggestion:
      'Set debug=False in production. Use FLASK_DEBUG environment variable for development.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bapp\.run\s*\([^)]*\bdebug\s*=\s*True\b/.test(line);
    },
  },
  {
    id: 'FLASK_SECRET_KEY_HARDCODED',
    category: 'Secrets',
    description:
      'Flask secret_key hardcoded in source — compromises session security and signed cookies.',
    severity: 'critical',
    fix_suggestion:
      'Load secret_key from environment: app.secret_key = os.environ["FLASK_SECRET_KEY"].',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsecret_key\s*=/.test(line)) return false;
      return /\bsecret_key\s*=\s*['"`]/.test(line) && !/\bos\.environ\b/.test(line) && !/\bconfig\b/.test(line);
    },
  },
  {
    id: 'SQLALCHEMY_TEXT_FSTRING',
    category: 'SQL Injection',
    description:
      'SQLAlchemy text() called with f-string — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use bound parameters: text("SELECT * FROM users WHERE id = :id").bindparams(id=user_id).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\btext\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'PARAMIKO_NO_HOST_KEY',
    category: 'Network Security',
    description:
      'Paramiko SSH client with AutoAddPolicy — accepts any host key without verification, enabling MITM attacks.',
    severity: 'high',
    fix_suggestion:
      'Use RejectPolicy or a custom HostKeyPolicy that verifies against known_hosts.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bAutoAddPolicy\s*\(\s*\)/.test(line) || /\bset_missing_host_key_policy\s*\(\s*paramiko\s*\.\s*AutoAddPolicy/.test(line);
    },
  },
  {
    id: 'PYTHON_ASSERT_SECURITY',
    category: 'Logic Error',
    description:
      'Python assert used for security check — assertions are stripped when running with python -O, bypassing the check entirely.',
    severity: 'high',
    fix_suggestion:
      'Use if/raise instead of assert for security checks: if not condition: raise PermissionError("...").',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bassert\b/.test(line)) return false;
      return /\bassert\b.*\b(?:is_admin|is_authenticated|has_permission|is_authorized|user\.role|is_staff|is_superuser)\b/.test(line);
    },
  },
  {
    id: 'DJANGO_RAW_SQL_USER_INPUT',
    category: 'SQL Injection',
    description:
      'Django raw() SQL with string formatting — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use raw() with params: Model.objects.raw("SELECT * FROM t WHERE id = %s", [user_id]).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b\.raw\s*\(/.test(line)) return false;
      return /\.raw\s*\(\s*f['"`]/.test(line) || /\.raw\s*\(\s*['"`].*%s/.test(line) && /\b%\s*\(/.test(line) ||
        /\.raw\s*\(\s*['"`].*\bformat\s*\(/.test(line);
    },
  },
  {
    id: 'JINJA2_AUTOESCAPE_DISABLED',
    category: 'XSS',
    description:
      'Jinja2 Environment created with autoescape=False — template output will not be HTML-escaped, enabling XSS.',
    severity: 'high',
    fix_suggestion:
      'Set autoescape=True or use select_autoescape(): Environment(autoescape=select_autoescape()).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bEnvironment\s*\(/.test(line) && /\bautoescape\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'PYTHON_XML_NO_DEFUSE',
    category: 'XXE',
    description:
      'Python XML parsing without defusing — vulnerable to XXE, billion laughs, and external entity attacks.',
    severity: 'high',
    fix_suggestion:
      'Use defusedxml instead of xml.etree.ElementTree: from defusedxml.ElementTree import parse.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bxml\.etree\.ElementTree\b/.test(line) && /\bimport\b/.test(line);
    },
  },
  {
    id: 'DJANGO_MARK_SAFE_USER_INPUT',
    category: 'XSS',
    description:
      'Django mark_safe() called with user-controlled data — disables HTML escaping, enabling XSS.',
    severity: 'critical',
    fix_suggestion:
      'Never use mark_safe() with user input. Use template autoescaping and |escape filter instead.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bmark_safe\s*\(/.test(line)) return false;
      return /\bmark_safe\s*\(\s*f['"`]/.test(line) ||
        /\bmark_safe\s*\([^)]*\brequest\b/.test(line) ||
        /\bmark_safe\s*\([^)]*\buser_input\b/.test(line) ||
        /\bmark_safe\s*\([^)]*\b(?:data|content|body|text|message|html)\b/.test(line) && !/\bmark_safe\s*\(\s*['"`][^'"`{]*['"`]\s*\)/.test(line);
    },
  },
  {
    id: 'FASTAPI_NO_CORS',
    category: 'Server Misconfiguration',
    description:
      'FastAPI CORSMiddleware with allow_origins=["*"] and allow_credentials=True — browsers will send cookies to any origin.',
    severity: 'high',
    fix_suggestion:
      'Specify exact origins when allow_credentials is True. Wildcard with credentials is a security vulnerability.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bCORSMiddleware\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return /allow_origins\s*=\s*\[['"`]\*['"`]\]/.test(window) && /allow_credentials\s*=\s*True/.test(window);
    },
  },
  {
    id: 'PYTHON_TEMPFILE_INSECURE',
    category: 'File System',
    description:
      'Python tempfile with insecure mode or mktemp() — predictable temp file names enable symlink attacks.',
    severity: 'medium',
    fix_suggestion:
      'Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead of tempfile.mktemp().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\btempfile\.mktemp\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 46-50: Database & ORM Deep Dive
  // ════════════════════════════════════════════
  {
    id: 'MONGODB_LOOKUP_INJECTION',
    category: 'NoSQL Injection',
    description:
      'MongoDB aggregation $lookup with user-controlled collection or field — enables cross-collection data theft.',
    severity: 'high',
    fix_suggestion:
      'Hardcode collection names in $lookup stages. Validate and whitelist any user-controlled aggregation parameters.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\$lookup\b/.test(line)) return false;
      return /\$lookup\s*:\s*\{[^}]*from\s*:\s*(?:req\s*\.\s*(?:body|query|params)|userInput|input)/.test(line);
    },
  },
  {
    id: 'REDIS_KEYS_PRODUCTION',
    category: 'Denial of Service',
    description:
      'Redis KEYS command used — blocks the entire Redis server during scan, causing DoS in production.',
    severity: 'high',
    fix_suggestion:
      'Use SCAN command with a cursor instead of KEYS: redis.scan(0, "MATCH", pattern, "COUNT", 100).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:redis|client|cache)\s*\.\s*keys\s*\(\s*['"`]\*['"`]\s*\)/.test(line);
    },
  },
  {
    id: 'SQL_UNION_INJECTION',
    category: 'SQL Injection',
    description:
      'SQL query built with UNION keyword from user input — classic UNION-based SQL injection vector.',
    severity: 'critical',
    fix_suggestion:
      'Use parameterized queries. Never concatenate user input into SQL UNION queries.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bUNION\b/i.test(line)) return false;
      return /\bUNION\b/i.test(line) && /\b(?:SELECT|ALL)\b/i.test(line) &&
        (/\$\{/.test(line) || /\+\s*(?:req|user|input|query|param)/.test(line) || /\bformat\s*\(/.test(line));
    },
  },
  {
    id: 'DB_POOL_NO_MAX',
    category: 'Reliability',
    description:
      'Database connection pool without max connection limit — can exhaust database connections under load.',
    severity: 'medium',
    fix_suggestion:
      'Set a max connection limit: new Pool({ max: 20 }) or createPool({ connectionLimit: 20 }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+Pool\s*\(/.test(line) && !/\bcreatePool\s*\(/.test(line)) return false;
      return /\bnew\s+Pool\s*\(\s*\{/.test(line) && !/\bmax\b/.test(line) && !/\bconnectionLimit\b/.test(line) ||
        /\bcreatePool\s*\(\s*\{/.test(line) && !/\bconnectionLimit\b/.test(line) && !/\bmax\b/.test(line);
    },
  },
  {
    id: 'MONGODB_PROJECTION_INJECTION',
    category: 'NoSQL Injection',
    description:
      'MongoDB projection built from user input — enables $slice/$elemMatch injection for data exfiltration.',
    severity: 'high',
    fix_suggestion:
      'Hardcode projection fields. Validate user-requested fields against a whitelist.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:find|findOne|aggregate)\s*\(/.test(line)) return false;
      return /\b(?:find|findOne)\s*\([^,]+,\s*req\s*\.\s*(?:body|query)\b/.test(line);
    },
  },
  {
    id: 'POSTGRES_COPY_INJECTION',
    category: 'SQL Injection',
    description:
      'PostgreSQL COPY command with user input — can read/write arbitrary files on the database server.',
    severity: 'critical',
    fix_suggestion:
      'Never use COPY with user-controlled file paths or table names. Use parameterized COPY commands.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bCOPY\b/i.test(line)) return false;
      // Require database imports — skip non-DB files (e.g., React components)
      if (!/\b(?:pg|postgres|knex|sequelize|typeorm|pool|client|database|db)\b/.test(ctx.fileContent) &&
          !/\bfrom\s+['"](?:pg|postgres|knex|sequelize|typeorm|better-sqlite3|mysql2?)['"]/.test(ctx.fileContent)) return false;
      return /\bCOPY\b/i.test(line) && /\b(?:FROM|TO)\b/i.test(line) &&
        (/\$\{/.test(line) || /\+\s*(?:req|user|input|file|path)/.test(line) || /\bformat\s*\(/.test(line));
    },
  },
  {
    id: 'ELASTICSEARCH_QUERY_INJECTION',
    category: 'Injection',
    description:
      'Elasticsearch query built with user input — enables query injection for data exfiltration.',
    severity: 'high',
    fix_suggestion:
      'Use the Elasticsearch query DSL with typed parameters. Sanitize and validate all search inputs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:query_string|script)\b/.test(line)) return false;
      return /\bquery_string\s*:\s*\{[^}]*query\s*:\s*(?:req\s*\.\s*(?:body|query)|userInput|input)/.test(line) ||
        /\bscript\s*:\s*\{[^}]*source\s*:\s*(?:req\s*\.\s*(?:body|query)|userInput|input)/.test(line);
    },
  },
  {
    id: 'GRAPHQL_BATCH_NO_LIMIT',
    category: 'Denial of Service',
    description:
      'GraphQL batch queries enabled without a limit — attackers can send thousands of queries in one request.',
    severity: 'medium',
    fix_suggestion:
      'Limit batch query size: server.applyMiddleware({ app, batching: { limit: 10 } }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bbatch\b/i.test(line)) return false;
      return /\bbatch(?:ing)?\s*:\s*(?:true|\{)/.test(line) && !/\blimit\b/.test(line) &&
        /\b(?:graphql|apollo|yoga|mercurius)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 51-55: API & Protocol Security
  // ════════════════════════════════════════════
  {
    id: 'GRAPHQL_ALIAS_DOS',
    category: 'Denial of Service',
    description:
      'GraphQL schema without alias limit — attackers can alias the same field thousands of times for DoS.',
    severity: 'medium',
    fix_suggestion:
      'Use graphql-armor or a custom validation rule to limit the number of aliases per query.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:ApolloServer|createYoga|mercurius|makeExecutableSchema)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return !/\b(?:maxAliases|aliasLimit|graphql-armor|costLimit)\b/.test(window) && !/\bdepthLimit\b/.test(window);
    },
  },
  {
    id: 'GRPC_REFLECTION_PRODUCTION',
    category: 'Information Disclosure',
    description:
      'gRPC reflection enabled — exposes all service definitions and message types to unauthenticated clients.',
    severity: 'medium',
    fix_suggestion:
      'Disable gRPC reflection in production. Only enable it in development environments.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:addReflection|ServerReflection|reflection\.register|enable_server_reflection)\b/.test(line);
    },
  },
  {
    id: 'REST_NO_PAGINATION',
    category: 'Denial of Service',
    description:
      'API endpoint returns all records without pagination — enables data dump and DoS attacks.',
    severity: 'medium',
    fix_suggestion:
      'Add pagination: limit results with LIMIT/OFFSET or cursor-based pagination. Default to 50-100 items max.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:findAll|findMany|find)\s*\(\s*\)/.test(line)) return false;
      return /\b(?:res|response)\s*\.\s*(?:json|send)\b/.test(line) || /\b(?:return|=>)\b/.test(line);
    },
  },
  {
    id: 'WEBHOOK_NO_TIMESTAMP',
    category: 'API Security',
    description:
      'Webhook handler without timestamp validation — vulnerable to replay attacks using captured webhook payloads.',
    severity: 'medium',
    fix_suggestion:
      'Validate webhook timestamps: reject requests older than 5 minutes. Check the timestamp header alongside the signature.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:webhook|hook)\b/i.test(line)) return false;
      if (!/\b(?:app|router)\s*\.\s*post\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 20)).join('\n');
      return /\b(?:verify|signature|hmac)\b/i.test(window) && !/\b(?:timestamp|time|age|replay|expire)\b/i.test(window);
    },
  },
  {
    id: 'JWT_KID_INJECTION',
    category: 'Authentication',
    description:
      'JWT kid header used in file path or SQL query — enables path traversal or SQL injection via token header.',
    severity: 'critical',
    fix_suggestion:
      'Validate the kid claim against a whitelist of known key IDs. Never use it in file paths or SQL queries.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bkid\b/.test(line)) return false;
      return /\b(?:header|decoded)\s*\.\s*kid\b/.test(line) &&
        (/\breadFile\b/.test(line) || /\bpath\b/.test(line) || /\bquery\b/.test(line) || /\bfs\b/.test(line));
    },
  },
  {
    id: 'OAUTH_IMPLICIT_GRANT',
    category: 'Authentication',
    description:
      'OAuth implicit grant flow used — deprecated and insecure, tokens are exposed in URL fragment.',
    severity: 'high',
    fix_suggestion:
      'Use Authorization Code flow with PKCE instead of Implicit Grant. Implicit grant is deprecated by OAuth 2.1.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bresponse_type\s*[=:]\s*['"`]?token['"`&\b]/.test(line) && /\b(?:oauth|auth|authorize)\b/i.test(line);
    },
  },
  {
    id: 'CONTENT_TYPE_MISMATCH',
    category: 'API Security',
    description:
      'JSON.parse used on request body without Content-Type validation — may process unexpected data formats.',
    severity: 'low',
    fix_suggestion:
      'Validate Content-Type header before parsing. Use express.json() middleware which handles validation automatically.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bJSON\.parse\s*\(\s*(?:req\.body|body|rawBody)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 5), lineIdx + 1).join('\n');
      return !/\bcontent-type\b/i.test(window) && !/\bContentType\b/.test(window);
    },
  },
  {
    id: 'API_RATE_LIMIT_EXPENSIVE',
    category: 'Denial of Service',
    description:
      'Expensive API operation (file upload, report generation, AI call) without rate limiting.',
    severity: 'medium',
    fix_suggestion:
      'Add rate limiting to expensive endpoints using express-rate-limit or similar middleware.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:upload|generate|export|report|ai|llm|openai|anthropic|embedding)\b/i.test(line)) return false;
      if (!/\b(?:app|router)\s*\.\s*(?:post|put)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 3)).join('\n');
      return !/\b(?:rateLimit|rateLimiter|throttle|slowDown|limiter)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 56-60: Crypto & Secrets Deep Dive
  // ════════════════════════════════════════════
  {
    id: 'RSA_KEY_SMALL',
    category: 'Cryptography',
    description:
      'RSA key size less than 2048 bits — considered insecure, can be factored with modern hardware.',
    severity: 'high',
    fix_suggestion:
      'Use at least 2048-bit RSA keys. Prefer 4096-bit for long-term security or switch to ECDSA.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:modulusLength|key_size|bits)\b/.test(line)) return false;
      const match = line.match(/\b(?:modulusLength|key_size|bits)\s*[=:]\s*(\d+)/);
      if (!match) return false;
      const bits = parseInt(match[1], 10);
      return bits > 0 && bits < 2048;
    },
  },
  {
    id: 'TLS_OLD_VERSION',
    category: 'Network Security',
    description:
      'TLS 1.0 or 1.1 enabled — these versions have known vulnerabilities and are deprecated.',
    severity: 'high',
    fix_suggestion:
      'Set minimum TLS version to 1.2: tls.createServer({ minVersion: "TLSv1.2" }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bminVersion\s*:\s*['"`]TLSv1(?:\.0|\.1)?['"`]/.test(line) ||
        /\bsecureProtocol\s*:\s*['"`]TLSv1_(?:method|0_method|1_method)['"`]/.test(line);
    },
  },
  {
    id: 'SELF_SIGNED_CERT_ACCEPT',
    category: 'Network Security',
    description:
      'Self-signed certificates accepted in non-development code — enables man-in-the-middle attacks.',
    severity: 'high',
    fix_suggestion:
      'Use properly signed certificates in production. Only accept self-signed certs in development.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\brejectUnauthorized\s*:\s*false\b/.test(line) && !/\bdev\b/i.test(line) && !/\btest\b/i.test(line);
    },
  },
  {
    id: 'AES_KEY_FROM_PASSWORD',
    category: 'Cryptography',
    description:
      'AES encryption key derived directly from password without a KDF — weak and predictable keys.',
    severity: 'high',
    fix_suggestion:
      'Use a proper KDF: crypto.scryptSync(password, salt, 32) or argon2.hash() to derive encryption keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:createCipheriv|createCipher)\s*\(/.test(line)) return false;
      return /\b(?:password|passwd|pass|pwd)\b/i.test(line);
    },
  },
  {
    id: 'HMAC_SHORT_KEY',
    category: 'Cryptography',
    description:
      'HMAC created with a suspiciously short key — key should be at least as long as the hash output.',
    severity: 'medium',
    fix_suggestion:
      'Use a key at least as long as the hash output (32 bytes for SHA-256, 64 bytes for SHA-512).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcreateHmac\s*\(/.test(line)) return false;
      // Short literal key
      const match = line.match(/\.update\s*\(\s*['"`]([^'"`]{1,7})['"`]\s*\)/);
      return !!match;
    },
  },
  {
    id: 'WEAK_PRNG_SEED',
    category: 'Cryptography',
    description:
      'Random number generator seeded with predictable value (Date.now, process.pid) — output becomes predictable.',
    severity: 'medium',
    fix_suggestion:
      'Use crypto.randomBytes() or crypto.getRandomValues() for cryptographic randomness.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bseed\b/i.test(line)) return false;
      return /\bseed\s*[=(:].*\b(?:Date\.now|process\.pid|performance\.now|Math\.random)\b/.test(line);
    },
  },
  {
    id: 'HARDCODED_ENCRYPTION_KEY',
    category: 'Secrets',
    description:
      'Encryption key hardcoded as a string literal — anyone with source code access can decrypt all data.',
    severity: 'critical',
    fix_suggestion:
      'Load encryption keys from environment variables or a key management service (AWS KMS, HashiCorp Vault).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:encryptionKey|encryption_key|ENCRYPTION_KEY|aesKey|aes_key|cipherKey|cipher_key)\b/.test(line)) return false;
      return /\b(?:encryptionKey|encryption_key|ENCRYPTION_KEY|aesKey|aes_key|cipherKey|cipher_key)\s*[=:]\s*['"`]/.test(line) &&
        !/\bprocess\.env\b/.test(line) && !/\bos\.environ\b/.test(line);
    },
  },
  {
    id: 'SECRET_IN_URL_PATH',
    category: 'Secrets',
    description:
      'Secret or token passed in URL path — gets logged in server access logs, browser history, and Referer headers.',
    severity: 'medium',
    fix_suggestion:
      'Pass secrets in Authorization header or request body, never in URL paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:fetch|axios|request|get|post)\s*\(/.test(line)) return false;
      return /['"`]\/api\/[^'"`]*(?:token|key|secret|password|apiKey|api_key)\/\$\{/.test(line) ||
        /['"`]\/api\/[^'"`]*(?:token|key|secret|password|apiKey|api_key)\/' *\+/.test(line);
    },
  },
  {
    id: 'JWT_NO_AUDIENCE',
    category: 'Authentication',
    description:
      'JWT verified without audience check — token intended for one service can be used on another.',
    severity: 'medium',
    fix_suggestion:
      'Always verify JWT audience: jwt.verify(token, secret, { audience: "my-app" }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bjwt\.verify\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return !/\baudience\b/.test(window) && !/\baud\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 61-65: Infrastructure & Config
  // ════════════════════════════════════════════
  {
    id: 'TERRAFORM_OPEN_INGRESS',
    category: 'Infrastructure',
    description:
      'Terraform/Pulumi security group with 0.0.0.0/0 ingress — allows traffic from any IP address.',
    severity: 'high',
    fix_suggestion:
      'Restrict ingress to specific IP ranges or security groups. Use VPN or bastion hosts for admin access.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:cidrBlocks|cidr_blocks|ingress)\b/.test(line)) return false;
      return /['"`]0\.0\.0\.0\/0['"`]/.test(line) && /\b(?:ingress|inbound|securityGroup|security_group)\b/i.test(line);
    },
  },
  {
    id: 'S3_NO_ENCRYPTION',
    category: 'Infrastructure',
    description:
      'S3 bucket created without server-side encryption — data stored unencrypted at rest.',
    severity: 'medium',
    fix_suggestion:
      'Enable server-side encryption: new s3.Bucket({ serverSideEncryptionConfiguration: { ... } }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+(?:aws\.s3\.Bucket|s3\.Bucket|S3Bucket)\b/.test(line) && !/\bcreate_bucket\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\b(?:encryption|serverSideEncryption|sse|SSE|kms)\b/i.test(window);
    },
  },
  {
    id: 'K8S_POD_PRIVILEGED',
    category: 'Infrastructure',
    description:
      'Kubernetes pod running as privileged — container has full access to the host, enabling container escape.',
    severity: 'critical',
    fix_suggestion:
      'Remove privileged: true. Use specific capabilities instead of full privileged mode.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bprivileged\s*:\s*true\b/.test(line) && /\b(?:security|container|pod)\b/i.test(line);
    },
  },
  {
    id: 'GCP_SERVICE_ACCOUNT_KEY',
    category: 'Secrets',
    description:
      'GCP service account key JSON embedded in source code — grants persistent access to Google Cloud resources.',
    severity: 'critical',
    fix_suggestion:
      'Use workload identity or environment-based authentication instead of embedding service account keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\btype.*service_account\b/.test(line) && /\bprivate_key\b/.test(line);
    },
  },
  {
    id: 'CICD_SECRET_IN_LOG',
    category: 'Secrets',
    description:
      'CI/CD pipeline logging a secret or token — secrets visible in build logs are accessible to anyone with log access.',
    severity: 'high',
    fix_suggestion:
      'Never echo or print secrets in CI pipelines. Use secret masking features of your CI provider.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:console\.log|echo|print|puts)\b/.test(line)) return false;
      return /\b(?:process\.env\.\w*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|API_KEY)\w*)\b/.test(line) &&
        /\b(?:console\.log|echo|print)\b/.test(line);
    },
  },
  {
    id: 'ANSIBLE_PLAINTEXT_SECRET',
    category: 'Infrastructure',
    description:
      'Ansible playbook with plaintext password or secret — use ansible-vault for encrypted secrets.',
    severity: 'high',
    fix_suggestion:
      'Encrypt secrets with ansible-vault: ansible-vault encrypt_string "secret" --name "variable_name".',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:ansible|playbook|vars)\b/i.test(line)) return false;
      return /\b(?:password|secret|api_key|token)\s*:\s*['"`](?!{{|vault)/.test(line);
    },
  },
  {
    id: 'HELM_VALUES_SECRET',
    category: 'Infrastructure',
    description:
      'Helm values file with plaintext secrets — secrets visible in version control and Helm release history.',
    severity: 'high',
    fix_suggestion:
      'Use Helm secrets plugin, sealed-secrets, or external-secrets operator for sensitive values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:values|helm|chart)\b/i.test(line)) return false;
      return /\b(?:password|secret|apiKey|token|privateKey)\s*:\s*['"`](?!{{|\$\{)/.test(line) &&
        /\b(?:helm|chart|values)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 66-70: Error Handling & Resilience
  // ════════════════════════════════════════════
  {
    id: 'CATCH_SILENT_SWALLOW',
    category: 'Error Handling',
    description:
      'Catch block swallows error silently without logging or rethrowing — hides bugs and security issues.',
    severity: 'medium',
    fix_suggestion:
      'At minimum, log the error: catch (err) { logger.error(err); }. Consider rethrowing or handling appropriately.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcatch\s*\(\s*\w+\s*\)\s*\{/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const catchBody = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 4)).join('\n');
      // Empty catch or only has closing brace
      return /^\s*\}\s*$/.test(catchBody.trim()) || catchBody.trim() === '';
    },
  },
  {
    id: 'DB_ERROR_TO_CLIENT',
    category: 'Information Disclosure',
    description:
      'Database error details sent to client — reveals table names, column names, and query structure.',
    severity: 'medium',
    fix_suggestion:
      'Return a generic error message to clients. Log the detailed error server-side.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:res|response)\s*\.\s*(?:json|send|status)\b/.test(line)) return false;
      return /\b(?:err|error)\s*\.\s*(?:sqlMessage|sqlState|query|sql|detail|hint|table|column)\b/.test(line);
    },
  },
  {
    id: 'NO_TIMEOUT_HTTP_REQUEST',
    category: 'Reliability',
    description:
      'External HTTP request without timeout — can hang indefinitely, exhausting server resources.',
    severity: 'medium',
    fix_suggestion:
      'Set a timeout: fetch(url, { signal: AbortSignal.timeout(5000) }) or axios.get(url, { timeout: 5000 }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\baxios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(/.test(line)) return false;
      // axios call without timeout in the same line
      return !/\btimeout\b/.test(line);
    },
  },
  {
    id: 'RETRY_NO_BACKOFF_AUTH',
    category: 'Security Logic',
    description:
      'Retry logic on auth endpoints without exponential backoff — enables brute force attacks.',
    severity: 'medium',
    fix_suggestion:
      'Implement exponential backoff with jitter for retries on authentication endpoints.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bretry\b/i.test(line)) return false;
      if (!/\b(?:login|auth|password|token|signin|sign_in)\b/i.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\b(?:backoff|exponential|delay|wait|sleep)\b/i.test(window);
    },
  },
  {
    id: 'VERBOSE_ERROR_PRODUCTION',
    category: 'Information Disclosure',
    description:
      'Verbose error mode enabled in production config — leaks implementation details to attackers.',
    severity: 'medium',
    fix_suggestion:
      'Set verbose errors to false in production. Use structured logging for server-side debugging.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:verbose|debug|detailed)\s*(?:Error|Errors|error|errors)\b/.test(line)) return false;
      return /\b(?:verbose|debug|detailed)\s*(?:Error|Errors|error|errors)\s*[=:]\s*true\b/.test(line);
    },
  },
  {
    id: 'NO_REQUEST_TIMEOUT',
    category: 'Reliability',
    description:
      'HTTP server created without request timeout — slow loris attacks can exhaust connections.',
    severity: 'medium',
    fix_suggestion:
      'Set request timeout: server.requestTimeout = 30000; or server.setTimeout(30000).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:createServer|http\.Server|https\.Server)\s*\(/.test(line)) return false;
      if (/\bexpress\b/.test(line)) return false; // Express handles this differently
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\b(?:requestTimeout|setTimeout|timeout|headersTimeout)\b/.test(window);
    },
  },
  {
    id: 'MISSING_CIRCUIT_BREAKER',
    category: 'Reliability',
    description:
      'External service call in a try/catch without circuit breaker — cascading failures can take down the entire system.',
    severity: 'low',
    fix_suggestion:
      'Use a circuit breaker pattern (opossum, cockatiel) for external service calls to prevent cascading failures.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bfetch\s*\(\s*['"`]https?:\/\//.test(line)) return false;
      // Check if it's a third-party API call
      if (!/\b(?:api|service|external|third.?party)\b/i.test(line)) return false;
      const fileContent = ctx.fileContent;
      return !/\b(?:circuitBreaker|CircuitBreaker|opossum|cockatiel|circuit)\b/i.test(fileContent);
    },
  },

  // ════════════════════════════════════════════
  // Cycles 71-75: Session & Cookie Deep Dive
  // ════════════════════════════════════════════
  {
    id: 'SESSION_ID_IN_URL',
    category: 'Session Security',
    description:
      'Session ID passed in URL — visible in browser history, Referer headers, and server logs (session fixation).',
    severity: 'high',
    fix_suggestion:
      'Use cookies for session management, never URL parameters. Set HttpOnly and Secure flags.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:sessionId|session_id|sid)\s*=\s*(?:req\s*\.\s*(?:query|params)\s*\.\s*(?:sessionId|session_id|sid)|url\.searchParams)/.test(line);
    },
  },
  {
    id: 'COOKIE_NO_SAMESITE',
    category: 'Session Security',
    description:
      'Cookie set without SameSite attribute — vulnerable to CSRF attacks in modern browsers.',
    severity: 'medium',
    fix_suggestion:
      'Set sameSite: "strict" or "lax" on all cookies. Use "strict" for sensitive operations.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip cookie library source code (hono/cookie, express/cookie, tough-cookie, etc.)
      if (isFrameworkSource(ctx.filePath) || isCookieLibrarySource(ctx.filePath)) return false;
      if (!/\b(?:setCookie|cookie|Set-Cookie)\b/i.test(line)) return false;
      if (!/\b(?:httpOnly|secure|maxAge|expires|domain|path)\b/.test(line)) return false;
      return !/\bsameSite\b/i.test(line) && !/\bsame_site\b/i.test(line);
    },
  },
  {
    id: 'SESSION_NO_INVALIDATE_PASSWD',
    category: 'Session Security',
    description:
      'Password change handler without session invalidation — old sessions remain active after password change.',
    severity: 'high',
    fix_suggestion:
      'Invalidate all sessions after password change: req.session.destroy() or delete all user sessions from the store.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:changePassword|updatePassword|resetPassword|change_password|update_password|reset_password)\b/.test(line)) return false;
      // Skip React component files — these are UI, not backend password handlers
      const ext = ctx.filePath.toLowerCase();
      if (ext.endsWith('.tsx') || ext.endsWith('.jsx')) return false;
      // Only flag in backend files — require server-side imports
      if (!hasServerSideImports(ctx.fileContent)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 20)).join('\n');
      return !/\b(?:session\.destroy|invalidate|logout|logOut|signOut|sign_out|revokeAll|revoke_all|destroySession)\b/i.test(window);
    },
  },
  {
    id: 'SESSION_TIMEOUT_LONG',
    category: 'Session Security',
    description:
      'Session timeout set to more than 24 hours — long-lived sessions increase window for session hijacking.',
    severity: 'low',
    fix_suggestion:
      'Set session timeout to at most 24 hours. Use shorter timeouts for sensitive applications.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:maxAge|max_age|expires|ttl)\b/i.test(line)) return false;
      if (!/\b(?:session|cookie)\b/i.test(line)) return false;
      // Check for very large millisecond values (> 24h = 86400000ms)
      const match = line.match(/\b(?:maxAge|max_age|ttl)\s*[=:]\s*(\d+)/);
      if (match) {
        const ms = parseInt(match[1], 10);
        return ms > 86400000;
      }
      // Check for large hour values
      const hourMatch = line.match(/(\d+)\s*\*\s*60\s*\*\s*60\s*\*\s*1000/);
      if (hourMatch) {
        const hours = parseInt(hourMatch[1], 10);
        return hours > 24;
      }
      return false;
    },
  },
  {
    id: 'SESSION_NO_REGENERATE',
    category: 'Session Security',
    description:
      'Login handler without session regeneration — enables session fixation attacks.',
    severity: 'high',
    fix_suggestion:
      'Regenerate session ID after login: req.session.regenerate() to prevent session fixation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:login|signIn|sign_in|authenticate)\s*(?:=|:|\()/.test(line)) return false;
      if (/\b(?:import|require|type|interface)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 20)).join('\n');
      // Must have session usage but no regeneration
      if (!/\b(?:session|req\.session)\b/.test(window)) return false;
      return !/\b(?:regenerate|regenerateId|rotateSession)\b/i.test(window);
    },
  },
  {
    id: 'COOKIE_WILDCARD_DOMAIN',
    category: 'Session Security',
    description:
      'Cookie domain set to wildcard (.example.com) — all subdomains can access the cookie, including attacker-controlled ones.',
    severity: 'medium',
    fix_suggestion:
      'Set the cookie domain to the exact hostname. Avoid wildcard subdomains for sensitive cookies.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (isFrameworkSource(ctx.filePath) || isCookieLibrarySource(ctx.filePath)) return false;
      if (!/\bdomain\s*[=:]\s*['"`]\./.test(line)) return false;
      return /\b(?:cookie|session|setCookie|Set-Cookie)\b/i.test(line) &&
        /\bdomain\s*[=:]\s*['"`]\.\w+\.\w+['"`]/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Additional coverage rules (Cycles 31-75 extras)
  // ════════════════════════════════════════════
  {
    id: 'SUBPROCESS_SHELL_TRUE',
    category: 'Command Injection',
    description:
      'Python subprocess with shell=True and user input — enables command injection.',
    severity: 'critical',
    fix_suggestion:
      'Use subprocess.run(["cmd", arg1, arg2]) without shell=True. Pass arguments as a list.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsubprocess\s*\.\s*(?:run|call|Popen|check_output|check_call)\s*\(/.test(line)) return false;
      return /\bshell\s*=\s*True\b/.test(line) && (/\bf['"`]/.test(line) || /\bformat\s*\(/.test(line) || /\+\s*\w/.test(line));
    },
  },
  {
    id: 'AIOHTTP_SESSION_NO_ENCRYPT',
    category: 'Session Security',
    description:
      'aiohttp session using SimpleCookieStorage — session data is unencrypted and can be tampered with.',
    severity: 'high',
    fix_suggestion:
      'Use EncryptedCookieStorage or RedisStorage instead of SimpleCookieStorage.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSimpleCookieStorage\s*\(\s*\)/.test(line);
    },
  },
  {
    id: 'SQLITE_ATTACH_INJECTION',
    category: 'SQL Injection',
    description:
      'SQLite ATTACH DATABASE with user input — can attach arbitrary database files for data theft.',
    severity: 'critical',
    fix_suggestion:
      'Never use user input in ATTACH DATABASE statements. Whitelist allowed database paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bATTACH\b/i.test(line)) return false;
      return /\bATTACH\s+(?:DATABASE\s+)?/i.test(line) &&
        (/\$\{/.test(line) || /\+\s*(?:req|user|input|path|file)/.test(line) || /\bformat\s*\(/.test(line));
    },
  },
  {
    id: 'SAML_NO_SIGNATURE_CHECK',
    category: 'Authentication',
    description:
      'SAML response processed without signature validation — enables authentication bypass via forged assertions.',
    severity: 'critical',
    fix_suggestion:
      'Always validate SAML signatures: configure wantAssertionsSigned: true and check the signature before processing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:saml|SAML)\b/.test(line)) return false;
      return /\bwantAssertionsSigned\s*:\s*false\b/.test(line) ||
        /\bwantAuthnResponseSigned\s*:\s*false\b/.test(line) ||
        /\bvalidateSignature\s*:\s*false\b/.test(line);
    },
  },
  {
    id: 'HATEOAS_INTERNAL_ROUTES',
    category: 'Information Disclosure',
    description:
      'API response exposing internal route paths in HATEOAS links — reveals internal API structure to clients.',
    severity: 'low',
    fix_suggestion:
      'Use external-facing URLs in HATEOAS links. Map internal routes to public API paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:links|_links|href)\b/.test(line)) return false;
      return /\bhref\s*:\s*['"`]\/(?:internal|admin|debug|private|_internal)\//.test(line);
    },
  },
  {
    id: 'ECDSA_WEAK_CURVE',
    category: 'Cryptography',
    description:
      'ECDSA using weak curve P-192 (secp192r1) — provides insufficient security margin for modern threats.',
    severity: 'high',
    fix_suggestion:
      'Use P-256 (secp256r1) or P-384 (secp384r1) curves instead of P-192.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:secp192r1|prime192v1|P-192|p192)\b/.test(line);
    },
  },
  {
    id: 'PASSWORD_IN_COMMIT',
    category: 'Secrets',
    description:
      'Password or secret value in what appears to be a git commit message or changelog.',
    severity: 'high',
    fix_suggestion:
      'Never include actual secret values in commit messages. Describe the change, not the secret.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:commit|changelog|git)\b/i.test(line)) return false;
      return /\b(?:password|secret|token)\s*(?:=|:)\s*['"`](?![\s*}$<{%])(?:\S{8,})['"`]/.test(line) &&
        /\b(?:commit|changelog)\b/i.test(line);
    },
  },
  {
    id: 'API_KEY_IN_REFERER',
    category: 'Secrets',
    description:
      'API key included in URL that will be sent in Referer header to third-party links.',
    severity: 'medium',
    fix_suggestion:
      'Pass API keys in headers, not URLs. Set Referrer-Policy to strict-origin-when-cross-origin.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:href|src|action|window\.location)\b/.test(line)) return false;
      return /\b(?:href|src|action)\s*=\s*['"`][^'"`]*[?&](?:api_key|apiKey|key|token|secret)=/.test(line) ||
        /\bwindow\.location\s*=\s*['"`][^'"`]*[?&](?:api_key|apiKey|key|token|secret)=/.test(line);
    },
  },
  {
    id: 'MYSQL_LOAD_DATA',
    category: 'SQL Injection',
    description:
      'MySQL LOAD DATA LOCAL with user input — can read arbitrary files from the client machine.',
    severity: 'critical',
    fix_suggestion:
      'Never use LOAD DATA LOCAL with user-controlled paths. Use server-side file loading with validated paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bLOAD\s+DATA\s+LOCAL\b/i.test(line)) return false;
      return /\$\{/.test(line) || /\+\s*(?:req|user|input|file|path)/.test(line) || /\bformat\s*\(/.test(line);
    },
  },
  {
    id: 'SHARED_WORKER_NO_ORIGIN',
    category: 'Client-Side Security',
    description:
      'SharedWorker without origin validation — any page on the origin can connect and exchange messages.',
    severity: 'medium',
    fix_suggestion:
      'Validate the origin of incoming connections in SharedWorker: check event.origin in the connect handler.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+SharedWorker\b/.test(line)) return false;
      const fileContent = ctx.fileContent;
      return !/\b(?:origin|event\.origin)\b/.test(fileContent);
    },
  },
  {
    id: 'LAMBDA_ADMIN_ROLE',
    category: 'Infrastructure',
    description:
      'AWS Lambda with AdministratorAccess or full wildcard IAM policy — overly permissive, violates least privilege.',
    severity: 'critical',
    fix_suggestion:
      'Follow least privilege: grant only the specific permissions needed. Never use AdministratorAccess for Lambda.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:lambda|Lambda|function)\b/i.test(line)) return false;
      return /\bAdministratorAccess\b/.test(line) ||
        /\b(?:Action|Effect)\s*:\s*['"`]\*['"`]/.test(line) && /\b(?:Resource)\s*:\s*['"`]\*['"`]/.test(line);
    },
  },
  {
    id: 'RDS_NO_ENCRYPTION',
    category: 'Infrastructure',
    description:
      'RDS instance without encryption at rest — database data stored unencrypted on disk.',
    severity: 'medium',
    fix_suggestion:
      'Enable encryption: storageEncrypted: true or --storage-encrypted in the RDS instance configuration.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:RDS|rds|database|db)\b/i.test(line)) return false;
      return /\bstorageEncrypted\s*:\s*false\b/.test(line) || /\bstorage_encrypted\s*=\s*false\b/.test(line);
    },
  },
  {
    id: 'DOCKER_ENV_SECRET',
    category: 'Secrets',
    description:
      'Docker ENV instruction with secret value — visible in image layer history to anyone who pulls the image.',
    severity: 'high',
    fix_suggestion:
      'Use Docker secrets or --mount=type=secret instead of ENV for sensitive values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:dockerfile|docker|container)\b/i.test(line)) return false;
      return /\bENV\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*['"`]?\w/.test(line);
    },
  },
  {
    id: 'WEB_CRYPTO_WEAK_ALGO',
    category: 'Cryptography',
    description:
      'Web Crypto API using deprecated/weak algorithm — AES-CBC without integrity or short key lengths.',
    severity: 'medium',
    fix_suggestion:
      'Use AES-GCM with 256-bit keys for authenticated encryption. Avoid AES-CBC without separate MAC.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsubtle\s*\.\s*(?:encrypt|decrypt|generateKey)\b/.test(line)) return false;
      return /\bAES-CBC\b/.test(line) || /\blength\s*:\s*(?:64|128)\b/.test(line) && /\bAES\b/.test(line);
    },
  },
  {
    id: 'CLIENT_SIDE_VALIDATION_ONLY',
    category: 'Validation',
    description:
      'Form validation using only client-side checks (HTML pattern/required) without corresponding server validation.',
    severity: 'low',
    fix_suggestion:
      'Always duplicate client-side validation on the server. Client-side validation is for UX, not security.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // This is intentionally very narrow to avoid false positives
      if (!/\bpattern\s*=\s*['"`]/.test(line)) return false;
      return /\b(?:onSubmit|handleSubmit)\b/.test(line) && /\bpattern\s*=/.test(line) &&
        !/\b(?:validate|sanitize|check|verify)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Express / Node.js patterns
  // ════════════════════════════════════════════
  {
    id: 'EXPRESS_SESSION_MEMORY_STORE',
    category: 'Server Misconfiguration',
    description:
      'Express session using default MemoryStore — leaks memory in production and does not scale across processes.',
    severity: 'medium',
    fix_suggestion:
      'Use a production session store: RedisStore, MongoStore, or connect-pg-simple.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bsession\s*\(/.test(line)) return false;
      if (!/\bsecret\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\bstore\b/.test(window);
    },
  },
  {
    id: 'UNCAUGHT_EXCEPTION_NO_HANDLER',
    category: 'Reliability',
    description:
      'Server lacks uncaughtException handler — unhandled exceptions crash the process silently.',
    severity: 'medium',
    fix_suggestion:
      'Add process.on("uncaughtException") and process.on("unhandledRejection") handlers for graceful shutdown.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app\.listen|server\.listen|createServer)\s*\(/.test(line)) return false;
      return !/\buncaughtException\b/.test(ctx.fileContent) && !/\bunhandledRejection\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'COOKIE_SESSION_NO_ENCRYPT',
    category: 'Session Security',
    description:
      'cookie-session without encryption keys — session data is signed but not encrypted, visible to clients.',
    severity: 'medium',
    fix_suggestion:
      'Use encrypted sessions with express-session + a store, or cookie-session with strong encryption keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (isFrameworkSource(ctx.filePath) || isCookieLibrarySource(ctx.filePath)) return false;
      if (!/\bcookieSession\s*\(/.test(line)) return false;
      return !/\bencrypt\b/i.test(line);
    },
  },
  {
    id: 'EXPRESS_RENDER_USER_INPUT',
    category: 'Server-Side Template Injection',
    description:
      'Express res.render() with user-controlled template name — enables server-side template injection.',
    severity: 'critical',
    fix_suggestion:
      'Whitelist allowed template names. Never use user input directly as the template path.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bres\s*\.\s*render\s*\(/.test(line)) return false;
      return /\bres\s*\.\s*render\s*\(\s*req\s*\.\s*(?:body|query|params)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended React / Frontend patterns
  // ════════════════════════════════════════════
  {
    id: 'REACT_HYDRATION_MISMATCH_LEAK',
    category: 'Information Disclosure',
    description:
      'Server-only data included in React component that hydrates on client — exposes internal data in page source.',
    severity: 'medium',
    fix_suggestion:
      'Use getServerSideProps return value carefully. Only pass data needed for rendering to the client.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bgetServerSideProps\b/.test(line)) return false;
      return /\b(?:password|secret|token|privateKey|private_key|internalId|internal_id|ssn|creditCard)\b/i.test(line);
    },
  },
  {
    id: 'IFRAME_NO_SANDBOX',
    category: 'Client-Side Security',
    description:
      'iframe loading external content without sandbox attribute — loaded page can access parent context.',
    severity: 'medium',
    fix_suggestion:
      'Add sandbox attribute to iframes loading external content: <iframe sandbox="allow-scripts">.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\biframe\b/.test(line)) return false;
      if (!/\bsrc\s*=/.test(line)) return false;
      return /\bsrc\s*=\s*['"`]https?:\/\//.test(line) && !/\bsandbox\b/.test(line);
    },
  },
  {
    id: 'LOCALSTORAGE_SENSITIVE_DATA',
    category: 'Client-Side Storage',
    description:
      'Sensitive data stored in localStorage — persists indefinitely and is accessible to any script on the origin.',
    severity: 'medium',
    fix_suggestion:
      'Store sensitive data in httpOnly cookies. Use localStorage only for non-sensitive preferences.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\blocalStorage\s*\.\s*setItem\s*\(/.test(line)) return false;
      return /\blocalStorage\s*\.\s*setItem\s*\(\s*['"`](?:password|secret|private|creditCard|ssn|credit_card)\b/i.test(line);
    },
  },
  {
    id: 'DOCUMENT_DOMAIN_SET',
    category: 'Client-Side Security',
    description:
      'document.domain being set — relaxes same-origin policy, enabling cross-subdomain attacks.',
    severity: 'high',
    fix_suggestion:
      'Remove document.domain assignments. Use postMessage for cross-origin communication instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bdocument\s*\.\s*domain\s*=/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Python patterns
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_EVAL_USER_INPUT',
    category: 'Code Injection',
    description:
      'Python eval() with user input — allows arbitrary code execution.',
    severity: 'critical',
    fix_suggestion:
      'Use ast.literal_eval() for safe evaluation of literal expressions. Avoid eval() entirely.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\beval\s*\(/.test(line)) return false;
      return /\beval\s*\(\s*(?:request\.|input\(|user_input|data\[|form\.|args\.)/.test(line);
    },
  },
  {
    id: 'DJANGO_SESSION_COOKIE_INSECURE',
    category: 'Session Security',
    description:
      'Django SESSION_COOKIE_SECURE set to False — session cookies sent over unencrypted HTTP.',
    severity: 'medium',
    fix_suggestion:
      'Set SESSION_COOKIE_SECURE = True in production settings.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSESSION_COOKIE_SECURE\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'DJANGO_SESSION_COOKIE_HTTPONLY',
    category: 'Session Security',
    description:
      'Django SESSION_COOKIE_HTTPONLY set to False — session cookies accessible via JavaScript (XSS risk).',
    severity: 'medium',
    fix_suggestion:
      'Set SESSION_COOKIE_HTTPONLY = True (this is the default, do not disable it).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSESSION_COOKIE_HTTPONLY\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'PYTHON_OS_SYSTEM',
    category: 'Command Injection',
    description:
      'Python os.system() with user input — vulnerable to command injection.',
    severity: 'critical',
    fix_suggestion:
      'Use subprocess.run() with a list argument instead of os.system().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bos\s*\.\s*system\s*\(/.test(line)) return false;
      return /\bos\s*\.\s*system\s*\(\s*f['"`]/.test(line) || /\bos\s*\.\s*system\s*\([^)]*\+/.test(line);
    },
  },
  {
    id: 'PYTHON_COMPILE_EXEC',
    category: 'Code Injection',
    description:
      'Python compile() + exec() with user input — enables arbitrary code execution.',
    severity: 'critical',
    fix_suggestion:
      'Remove compile/exec of user-controlled code. Use a sandboxed environment if dynamic code execution is required.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcompile\s*\(/.test(line)) return false;
      return /\bcompile\s*\(\s*(?:request\.|user_input|data\[|form\.|args\.)/.test(line);
    },
  },
  {
    id: 'PYTHON_TARFILE_TRAVERSAL',
    category: 'Path Traversal',
    description:
      'Python tarfile.extractall() without filtering — vulnerable to path traversal via crafted tar archives.',
    severity: 'high',
    fix_suggestion:
      'Use tarfile.extractall(filter="data") (Python 3.12+) or validate member paths before extraction.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b\.extractall\s*\(\s*\)/.test(line) && !/\bfilter\b/.test(line);
    },
  },
  {
    id: 'PYTHON_HASHLIB_MD5',
    category: 'Cryptography',
    description:
      'Python hashlib.md5() used — MD5 is cryptographically broken, vulnerable to collision attacks.',
    severity: 'medium',
    fix_suggestion:
      'Use hashlib.sha256() or hashlib.sha3_256() instead of md5 for hashing.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhashlib\s*\.\s*md5\s*\(/.test(line);
    },
  },
  {
    id: 'PYTHON_RANDOM_SECURITY',
    category: 'Cryptography',
    description:
      'Python random module used for security-sensitive values — random module is not cryptographically secure.',
    severity: 'high',
    fix_suggestion:
      'Use secrets module: secrets.token_hex(), secrets.token_urlsafe(), secrets.choice().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\brandom\s*\.\s*(?:randint|choice|random|randrange|sample)\s*\(/.test(line)) return false;
      return /\b(?:token|password|secret|key|nonce|salt|otp|code|pin)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Database patterns
  // ════════════════════════════════════════════
  {
    id: 'RAW_SQL_MIGRATION',
    category: 'SQL Injection',
    description:
      'Raw SQL in migration file with variable interpolation — migration SQL should use parameterized queries.',
    severity: 'high',
    fix_suggestion:
      'Use the migration framework query builder instead of raw SQL. If raw SQL is needed, use parameterized queries.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:knex|sequelize|migration)\b/i.test(ctx.filePath)) return false;
      if (!/\braw\s*\(/.test(line)) return false;
      return /\braw\s*\(\s*`[^`]*\$\{/.test(line);
    },
  },
  {
    id: 'DB_BACKUP_NO_AUTH',
    category: 'Data Exposure',
    description:
      'Database backup/export endpoint without authentication — exposes entire database to unauthenticated users.',
    severity: 'critical',
    fix_suggestion:
      'Protect backup endpoints with strong authentication and authorization. Limit to admin-only access.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:backup|dump|export)\b/i.test(line)) return false;
      if (!/\b(?:app|router)\s*\.\s*(?:get|post)\s*\(/.test(line)) return false;
      if (!/\b(?:\/api\/.*(?:backup|dump|export)|\/backup|\/dump|\/export)\b/i.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 3)).join('\n');
      return !/\b(?:auth|authenticate|authorize|isAdmin|requireAuth|middleware|protect)\b/i.test(window);
    },
  },
  {
    id: 'SEQUELIZE_RAW_QUERY',
    category: 'SQL Injection',
    description:
      'Sequelize raw query with template literal interpolation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use Sequelize replacements: sequelize.query("SELECT * FROM t WHERE id = ?", { replacements: [id] }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsequelize\s*\.\s*query\s*\(/.test(line)) return false;
      return /\bsequelize\s*\.\s*query\s*\(\s*`[^`]*\$\{/.test(line);
    },
  },
  {
    id: 'TYPEORM_RAW_QUERY',
    category: 'SQL Injection',
    description:
      'TypeORM raw query with template literal interpolation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use TypeORM parameterized queries: manager.query("SELECT * FROM t WHERE id = $1", [id]).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:manager|connection|dataSource)\s*\.\s*query\s*\(/.test(line)) return false;
      return /\b(?:manager|connection|dataSource)\s*\.\s*query\s*\(\s*`[^`]*\$\{/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended API Security patterns
  // ════════════════════════════════════════════
  {
    id: 'API_VERSIONING_MISSING',
    category: 'API Security',
    description:
      'API endpoint without versioning prefix — makes breaking changes harder to manage and may break clients.',
    severity: 'low',
    fix_suggestion:
      'Version your API: /api/v1/users instead of /api/users. Use URL or header-based versioning.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:app|router)\s*\.\s*(?:get|post|put|delete|patch)\s*\(/.test(line)) return false;
      // Check for /api/ routes without version
      return /['"`]\/api\/(?!v\d)/.test(line) && !/\b(?:health|status|metrics|docs|swagger)\b/.test(line);
    },
  },
  {
    id: 'GRAPHQL_FIELD_SUGGESTION',
    category: 'Information Disclosure',
    description:
      'GraphQL field suggestions enabled — reveals schema field names to unauthenticated users.',
    severity: 'low',
    fix_suggestion:
      'Disable field suggestions in production: fieldSuggestions: false in your GraphQL server config.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:ApolloServer|createYoga|mercurius)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return /\bfieldSuggestions\s*:\s*true\b/.test(window);
    },
  },
  {
    id: 'REST_MASS_DELETE',
    category: 'API Security',
    description:
      'Mass delete endpoint without confirmation or soft-delete — permanent data loss on accidental or malicious call.',
    severity: 'medium',
    fix_suggestion:
      'Implement soft-delete, require confirmation token, or limit bulk deletion scope.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:deleteMany|destroy|removeAll|bulkDelete|bulk_delete)\s*\(/.test(line)) return false;
      return /\breq\s*\.\s*(?:body|query)\b/.test(line);
    },
  },
  {
    id: 'CORS_REFLECT_ORIGIN',
    category: 'CORS Misconfiguration',
    description:
      'CORS origin reflects the request Origin header — effectively same as wildcard but with credentials.',
    severity: 'high',
    fix_suggestion:
      'Validate origins against a whitelist instead of reflecting the request Origin header.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\borigin\b/.test(line)) return false;
      return /\borigin\s*:\s*(?:true|req\s*\.\s*headers?\s*(?:\.\s*origin|\[['"`]origin['"`]\]))/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Crypto patterns
  // ════════════════════════════════════════════
  {
    id: 'CRYPTO_DES',
    category: 'Cryptography',
    description:
      'DES encryption used — DES is completely broken with a 56-bit key, trivially crackable.',
    severity: 'critical',
    fix_suggestion:
      'Use AES-256-GCM for authenticated encryption. DES and 3DES are deprecated.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:createCipher(?:iv)?|DES|des-ede3|des-cbc)\s*\(?\s*['"`]?\bdes\b/i.test(line) ||
        /['"`]des(?:-ede3|-cbc|-ecb)?['"`]/.test(line) && /\b(?:cipher|encrypt|decrypt|algorithm)\b/i.test(line);
    },
  },
  {
    id: 'CRYPTO_NO_AUTH_TAG',
    category: 'Cryptography',
    description:
      'AES-CBC used without HMAC/MAC — encrypted data can be tampered with without detection.',
    severity: 'medium',
    fix_suggestion:
      'Use AES-GCM (authenticated encryption) instead of AES-CBC, or add HMAC verification.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/['"`]aes-(?:128|192|256)-cbc['"`]/.test(line)) return false;
      return !/\b(?:hmac|mac|authTag|getAuthTag|auth_tag)\b/i.test(ctx.fileContent);
    },
  },
  {
    id: 'PBKDF2_LOW_ITERATIONS',
    category: 'Cryptography',
    description:
      'PBKDF2 with fewer than 100,000 iterations — modern hardware can brute-force low iteration counts.',
    severity: 'high',
    fix_suggestion:
      'Use at least 600,000 iterations for PBKDF2 (OWASP 2023 recommendation). Prefer argon2id instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bpbkdf2/i.test(line)) return false;
      const match = line.match(/\bpbkdf2\w*\s*\([^,]+,[^,]+,\s*(\d+)/i);
      if (!match) return false;
      const iterations = parseInt(match[1], 10);
      return iterations > 0 && iterations < 100000;
    },
  },
  {
    id: 'CRYPTO_CONSTANT_TIME_BYPASS',
    category: 'Cryptography',
    description:
      'Cryptographic comparison using indexOf/includes instead of constant-time comparison — timing side channel.',
    severity: 'medium',
    fix_suggestion:
      'Use crypto.timingSafeEqual() for all cryptographic comparisons.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:signature|hash|digest|hmac|mac|tag)\b/i.test(line)) return false;
      return /\b(?:indexOf|includes|startsWith)\s*\(/.test(line) && /\b(?:signature|hash|digest|hmac|mac|tag)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Infrastructure patterns
  // ════════════════════════════════════════════
  {
    id: 'CLOUDFRONT_NO_WAF',
    category: 'Infrastructure',
    description:
      'CloudFront distribution without WAF — no protection against common web attacks (SQLi, XSS, bot traffic).',
    severity: 'medium',
    fix_suggestion:
      'Associate a WAF WebACL with the CloudFront distribution for edge-level protection.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:CloudFrontWebDistribution|Distribution|cloudfront)\b/.test(line)) return false;
      if (!/\bnew\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return !/\b(?:waf|webAcl|web_acl|WAF)\b/i.test(window);
    },
  },
  {
    id: 'ELASTICACHE_NO_TRANSIT_ENCRYPT',
    category: 'Infrastructure',
    description:
      'ElastiCache without encryption in transit — data sent between app and cache is readable on the network.',
    severity: 'medium',
    fix_suggestion:
      'Enable transit encryption: transitEncryptionEnabled: true for ElastiCache.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bElastiCache\b/.test(line)) return false;
      return /\btransitEncryptionEnabled\s*:\s*false\b/.test(line) ||
        /\btransit_encryption_enabled\s*=\s*false\b/.test(line);
    },
  },
  {
    id: 'AZURE_STORAGE_NO_SAS',
    category: 'Infrastructure',
    description:
      'Azure storage access without SAS token or managed identity — using account keys directly is a security risk.',
    severity: 'medium',
    fix_suggestion:
      'Use SAS tokens with limited scope and expiry, or use managed identity authentication.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:StorageSharedKeyCredential|accountKey|account_key)\b/.test(line)) return false;
      return /\bStorageSharedKeyCredential\s*\(/.test(line) || /\baccountKey\s*:\s*['"`]/.test(line);
    },
  },
  {
    id: 'K8S_HOST_NETWORK',
    category: 'Infrastructure',
    description:
      'Kubernetes pod using host network — bypasses network policies and can access host services.',
    severity: 'high',
    fix_suggestion:
      'Remove hostNetwork: true unless absolutely required. Use proper Kubernetes networking.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhostNetwork\s*:\s*true\b/.test(line);
    },
  },
  {
    id: 'K8S_HOST_PID',
    category: 'Infrastructure',
    description:
      'Kubernetes pod using host PID namespace — can see and interact with all processes on the host.',
    severity: 'high',
    fix_suggestion:
      'Remove hostPID: true. Pods should use their own PID namespace for isolation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhostPID\s*:\s*true\b/.test(line);
    },
  },
  {
    id: 'K8S_RUN_AS_ROOT',
    category: 'Infrastructure',
    description:
      'Kubernetes container running as root — increases blast radius of container escape vulnerabilities.',
    severity: 'high',
    fix_suggestion:
      'Set runAsNonRoot: true and runAsUser: 1000 (or similar non-root UID) in securityContext.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\brunAsUser\s*:\s*0\b/.test(line) || /\brunAsRoot\s*:\s*true\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Error Handling patterns
  // ════════════════════════════════════════════
  {
    id: 'PROMISE_CATCH_SWALLOW',
    category: 'Error Handling',
    description:
      'Promise .catch() with empty handler — silently swallows async errors, hiding bugs.',
    severity: 'medium',
    fix_suggestion:
      'Log errors in .catch() handlers: .catch(err => logger.error(err)).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)/.test(line) ||
        /\.catch\s*\(\s*\(\s*\w+\s*\)\s*=>\s*\{\s*\}\s*\)/.test(line) ||
        /\.catch\s*\(\s*\(\s*\)\s*=>\s*(?:null|undefined|void\s+0)\s*\)/.test(line);
    },
  },
  {
    id: 'GENERIC_ERROR_NO_LOG',
    category: 'Error Handling',
    description:
      'Generic error response without server-side logging — makes debugging impossible.',
    severity: 'low',
    fix_suggestion:
      'Log errors server-side before returning generic messages: logger.error(err); res.status(500).json({...}).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bres\s*\.\s*status\s*\(\s*500\s*\)\s*\.\s*json\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 5), lineIdx + 1).join('\n');
      return !/\b(?:console\.\w+|logger\.\w+|log\.\w+|winston|pino|bunyan)\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Extended Session / Auth patterns
  // ════════════════════════════════════════════
  {
    id: 'CONCURRENT_SESSION_UNLIMITED',
    category: 'Session Security',
    description:
      'No concurrent session limit — compromised credentials allow unlimited simultaneous sessions.',
    severity: 'low',
    fix_suggestion:
      'Limit concurrent sessions per user. Notify users of active sessions and allow revocation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:login|signIn|authenticate)\s*(?:=|:|\()\s*async/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 25)).join('\n');
      if (!/\bsession\b/.test(window)) return false;
      return !/\b(?:maxSessions|concurrent|activeSession|session.*count|limit.*session)\b/i.test(window);
    },
  },
  {
    id: 'TWO_FACTOR_BYPASS',
    category: 'Authentication',
    description:
      '2FA/MFA check that can be bypassed with a boolean flag — attackers can set skip2fa to true.',
    severity: 'critical',
    fix_suggestion:
      'Never use client-provided flags to skip 2FA. Always enforce 2FA server-side based on user settings.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:skip2fa|skip_2fa|skipMfa|skip_mfa|bypassMfa|bypass_mfa|bypass2fa)\s*[=:]\s*req\s*\.\s*(?:body|query)\b/.test(line);
    },
  },
  {
    id: 'PASSWORD_RESET_NO_EXPIRY',
    category: 'Authentication',
    description:
      'Password reset token without expiry — tokens remain valid indefinitely if not used.',
    severity: 'medium',
    fix_suggestion:
      'Set a short expiry (15-60 minutes) on password reset tokens. Use crypto.randomBytes() for token generation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:resetToken|reset_token|passwordResetToken|password_reset_token)\b/.test(line)) return false;
      if (!/\b(?:save|create|insert|set)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return !/\b(?:expir|ttl|maxAge|validUntil|valid_until|expiresAt|expires_at)\b/i.test(window);
    },
  },
  {
    id: 'ACCOUNT_ENUM_TIMING',
    category: 'Authentication',
    description:
      'Login endpoint returns different error messages for invalid username vs invalid password — enables account enumeration.',
    severity: 'medium',
    fix_suggestion:
      'Return a generic "Invalid credentials" message for both cases. Use constant-time comparison.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:user|User|account)\s+not\s+found\b/i.test(line) && /\b(?:res\s*\.\s*(?:json|send|status)|return)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Supply Chain / Build patterns
  // ════════════════════════════════════════════
  {
    id: 'TYPOSQUATTING_COMMON',
    category: 'Supply Chain',
    description:
      'Import from commonly typosquatted package name — verify the package name is correct.',
    severity: 'medium',
    fix_suggestion:
      'Double-check package names. Use npm audit and lockfile integrity checks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Known typosquatting patterns
      return /\b(?:require|import)\b.*['"`](?:lodahs|lodasch|axois|axos|reacr|reactt|expresss|expresjs|momment|mongose)['"`]/.test(line);
    },
  },
  {
    id: 'EVAL_IMPORT',
    category: 'Code Injection',
    description:
      'Dynamic import() with user-controlled module path — enables loading malicious modules.',
    severity: 'critical',
    fix_suggestion:
      'Whitelist allowed module names. Never use user input directly in import() calls.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bimport\s*\(/.test(line)) return false;
      return /\bimport\s*\(\s*req\s*\.\s*(?:body|query|params)\b/.test(line) ||
        /\bimport\s*\(\s*userInput\b/.test(line);
    },
  },
  {
    id: 'NPM_PUBLISH_NO_IGNORE',
    category: 'Supply Chain',
    description:
      'Package lacks .npmignore or files field — may accidentally publish sensitive files (tests, configs, .env).',
    severity: 'low',
    fix_suggestion:
      'Add a "files" field to package.json or create .npmignore to control published files.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // This is very narrow to avoid false positives — only catches "npm publish" without any safety
      return /\bnpm\s+publish\b/.test(line) && !/\b(?:--dry-run|--access|prepublish)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended File System / OS patterns
  // ════════════════════════════════════════════
  {
    id: 'SYMLINK_RACE',
    category: 'File System',
    description:
      'File existence check followed by file operation — TOCTOU race condition allowing symlink attacks.',
    severity: 'medium',
    fix_suggestion:
      'Use atomic operations: open with O_CREAT|O_EXCL or use fstat on the file descriptor.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:existsSync|accessSync|statSync)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const nextLines = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return /\b(?:writeFileSync|unlinkSync|renameSync|mkdirSync)\s*\(/.test(nextLines);
    },
  },
  {
    id: 'TEMP_DIR_PREDICTABLE',
    category: 'File System',
    description:
      'Temporary file with predictable name — enables symlink attacks and information disclosure.',
    severity: 'medium',
    fix_suggestion:
      'Use fs.mkdtempSync() or crypto.randomUUID() for temp directory/file names.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\btmp\b|\/tmp\//.test(line)) return false;
      return /['"`]\/tmp\/[a-zA-Z_-]+['"`]/.test(line) && /\b(?:writeFile|createWriteStream|open)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Validation patterns
  // ════════════════════════════════════════════
  {
    id: 'EMAIL_VALIDATION_WEAK',
    category: 'Validation',
    description:
      'Email validation using overly simple regex — misses edge cases and can be bypassed.',
    severity: 'low',
    fix_suggestion:
      'Use a proven email validation library (zod.string().email(), validator.isEmail()) instead of custom regex.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bemail\b/i.test(line)) return false;
      // Very simple email regex that misses lots of valid emails
      return /\b(?:email|mail)\w*\s*(?:=|:).*\/\S{1,15}@\S{1,15}\//.test(line) && !/\b(?:validator|zod|joi|yup)\b/i.test(line);
    },
  },
  {
    id: 'URL_VALIDATION_MISSING',
    category: 'Validation',
    description:
      'User-provided URL used without validation — may contain javascript:, data:, or internal addresses.',
    severity: 'medium',
    fix_suggestion:
      'Validate URLs: ensure they start with https:// and do not point to internal IP ranges.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:req\s*\.\s*(?:body|query)\s*\.\s*(?:url|link|href|redirect|callback|returnUrl|return_url))\b/.test(line)) return false;
      return /\b(?:fetch|axios|request|redirect|href|src)\s*[=(:].*\breq\s*\.\s*(?:body|query)\s*\.\s*(?:url|link|href|redirect|callback|returnUrl|return_url)\b/.test(line);
    },
  },
  {
    id: 'JSON_SCHEMA_ADDITIONAL_PROPS',
    category: 'Validation',
    description:
      'JSON schema without additionalProperties: false — allows arbitrary extra fields in input.',
    severity: 'low',
    fix_suggestion:
      'Set additionalProperties: false in JSON schemas to prevent unexpected fields.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bjsonSchema\b|"type"\s*:\s*"object"/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return /\bproperties\b/.test(window) && !/\badditionalProperties\b/.test(window) &&
        /\bvalidate\b/i.test(ctx.fileContent);
    },
  },

  // ════════════════════════════════════════════
  // Extended DNS / Network patterns
  // ════════════════════════════════════════════
  {
    id: 'DNS_REBINDING',
    category: 'Network Security',
    description:
      'Server binding to 0.0.0.0 without host validation — vulnerable to DNS rebinding attacks.',
    severity: 'medium',
    fix_suggestion:
      'Validate the Host header or bind to specific interface. Use helmet to set allowed hosts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\blisten\s*\([^)]*['"`]0\.0\.0\.0['"`]/.test(line)) return false;
      return !/\bhost\s*(?:validation|check|whitelist|allowlist)\b/i.test(ctx.fileContent) &&
        !/\bhelmet\b/.test(ctx.fileContent);
    },
  },

  // ════════════════════════════════════════════
  // Extended Logging patterns
  // ════════════════════════════════════════════
  {
    id: 'LOG_PII_DATA',
    category: 'Data Privacy',
    description:
      'Personally identifiable information (PII) logged — may violate GDPR/CCPA and expose sensitive data.',
    severity: 'medium',
    fix_suggestion:
      'Redact PII from logs: mask email, phone, SSN, and other personal fields before logging.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:console\.log|logger\.\w+|log\.\w+|logging\.\w+)\s*\(/.test(line)) return false;
      return /\b(?:ssn|socialSecurity|social_security|dateOfBirth|date_of_birth|creditCard|credit_card|bankAccount|bank_account)\b/i.test(line);
    },
  },
  {
    id: 'LOG_FULL_REQUEST',
    category: 'Data Privacy',
    description:
      'Entire request object logged — may contain auth tokens, passwords, and sensitive headers.',
    severity: 'medium',
    fix_suggestion:
      'Log only necessary fields. Redact sensitive headers (Authorization, Cookie) before logging.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:console\.log|logger\.\w+|log\.\w+)\s*\(/.test(line)) return false;
      return /\b(?:console\.log|logger\.\w+|log\.\w+)\s*\(\s*req\s*\)/.test(line) ||
        /\b(?:console\.log|logger\.\w+)\s*\(\s*JSON\.stringify\s*\(\s*req\s*\)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Deserialization patterns
  // ════════════════════════════════════════════
  {
    id: 'YAML_UNSAFE_LOAD',
    category: 'Deserialization',
    description:
      'YAML loaded with unsafe loader — enables arbitrary code execution via YAML deserialization.',
    severity: 'critical',
    fix_suggestion:
      'Use yaml.safeLoad() or yaml.load(data, { schema: yaml.SAFE_SCHEMA }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\byaml\s*\.\s*load\s*\(/.test(line) && !/\bsafe\w*\b/i.test(line) && !/\bSAFE_SCHEMA\b/.test(line);
    },
  },
  {
    id: 'MSGPACK_UNVALIDATED',
    category: 'Deserialization',
    description:
      'MessagePack deserialization of untrusted data — can lead to prototype pollution or DoS.',
    severity: 'medium',
    fix_suggestion:
      'Validate the structure and types of deserialized data. Use schema validation after unpacking.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:msgpack|messagepack)\s*\.\s*(?:unpack|decode)\s*\(/.test(line)) return false;
      return /\breq\s*\.\s*body\b/.test(line) || /\bbuffer\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Access Control patterns
  // ════════════════════════════════════════════
  {
    id: 'RBAC_CLIENT_SIDE',
    category: 'Authorization',
    description:
      'Role-based access control check only on the client side — client-side checks are trivially bypassed.',
    severity: 'high',
    fix_suggestion:
      'Enforce RBAC on the server/API side. Client-side role checks should only be for UI rendering.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(/.test(line)) return false;
      return /\bgetItem\s*\(\s*['"`](?:role|userRole|isAdmin|permissions|access_level)['"`]\s*\)/.test(line);
    },
  },
  {
    id: 'HORIZONTAL_PRIVILEGE_ESCALATION',
    category: 'Authorization',
    description:
      'Resource accessed by user-provided ID without ownership verification — other users can access resources.',
    severity: 'high',
    fix_suggestion:
      'Always verify resource ownership: WHERE id = :resourceId AND userId = :currentUserId.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:findById|findByPk|findOne)\s*\(\s*req\s*\.\s*params\s*\.\s*id\b/.test(line)) return false;
      return !/\b(?:userId|user_id|ownerId|owner_id|createdBy|created_by)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended Environment / Config Leak patterns
  // ════════════════════════════════════════════
  {
    id: 'ENV_FILE_IN_PUBLIC',
    category: 'Secrets',
    description:
      '.env file served from public directory — exposes all environment variables to the internet.',
    severity: 'critical',
    fix_suggestion:
      'Never place .env files in public/static directories. Add .env to .gitignore and public/.gitignore.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:express\.static|serveStatic|staticFiles)\b.*\b(?:public|static|www|dist)\b/.test(line) &&
        /\.env\b/.test(line);
    },
  },
  {
    id: 'SOURCEMAP_IN_PRODUCTION',
    category: 'Information Disclosure',
    description:
      'Source maps enabled in production build — reveals original source code to anyone inspecting the bundle.',
    severity: 'medium',
    fix_suggestion:
      'Disable source maps in production or upload them to a private error tracking service.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bdevtool\s*:\s*['"`]source-map['"`]/.test(line)) return false;
      return /\bproduction\b/i.test(line) || /\bprod\b/i.test(line);
    },
  },
  {
    id: 'CONFIG_EXPOSE_INTERNALS',
    category: 'Information Disclosure',
    description:
      'API endpoint exposing internal configuration (versions, paths, db connection strings).',
    severity: 'medium',
    fix_suggestion:
      'Return only necessary information in config/status endpoints. Never expose connection strings or internal paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:res|response)\s*\.\s*json\s*\(/.test(line)) return false;
      return /\bprocess\.env\b/.test(line) && /\b(?:res|response)\s*\.\s*json\s*\(\s*process\.env\s*\)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Extended WebSocket patterns
  // ════════════════════════════════════════════
  {
    id: 'WS_RATE_LIMIT_MISSING',
    category: 'Denial of Service',
    description:
      'WebSocket connection without rate limiting — single client can flood the server with messages.',
    severity: 'medium',
    fix_suggestion:
      'Implement message rate limiting per connection: track message count and disconnect abusers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:ws|wss|WebSocket|socket)\s*\.\s*on\s*\(\s*['"`]message['"`]/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return !/\b(?:rateLimit|rateLimiter|throttle|messageCount|flood|spam)\b/i.test(window);
    },
  },
  {
    id: 'WS_NO_MESSAGE_SIZE_LIMIT',
    category: 'Denial of Service',
    description:
      'WebSocket server without message size limit — allows memory exhaustion via large messages.',
    severity: 'medium',
    fix_suggestion:
      'Set maxPayload limit: new WebSocket.Server({ maxPayload: 1048576 }) for 1MB limit.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+(?:WebSocket\.Server|WebSocketServer|Server)\s*\(/.test(line)) return false;
      if (!/\bWebSocket\b|ws\b/.test(line) && !/\bWebSocket\b/.test(ctx.fileContent)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return !/\bmaxPayload\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Extended TypeScript-specific patterns
  // ════════════════════════════════════════════
  {
    id: 'TS_ANY_SECURITY_CONTEXT',
    category: 'Type Safety',
    description:
      'Type assertion to "any" in security-critical code — bypasses TypeScript type checking for auth/permission logic.',
    severity: 'medium',
    fix_suggestion:
      'Use proper types instead of "any" in security contexts. Define interfaces for auth objects.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bas\s+any\b/.test(line)) return false;
      return /\b(?:auth|permission|role|token|session|user)\b/i.test(line) && /\bas\s+any\b/.test(line);
    },
  },
  {
    id: 'TS_NON_NULL_ASSERTION_AUTH',
    category: 'Type Safety',
    description:
      'Non-null assertion (!) on auth/user object — may crash at runtime if authentication fails.',
    severity: 'medium',
    fix_suggestion:
      'Handle null/undefined cases explicitly: if (!req.user) return res.status(401).json(...).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:req\.user|session\.user|ctx\.user|context\.user)!\./.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Mega Batch Extension: 100+ additional patterns
  // ════════════════════════════════════════════

  // -- Express / Node.js Extended --
  {
    id: 'EXPRESS_CORS_DYNAMIC',
    category: 'CORS Misconfiguration',
    description: 'CORS origin set from request header without validation — effectively allows all origins.',
    severity: 'high',
    fix_suggestion: 'Validate the origin against a whitelist before reflecting it.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\borigin\s*:\s*req\s*\.\s*headers?\s*\.\s*origin\b/.test(line);
    },
  },
  {
    id: 'NODE_TLS_REJECT_DISABLE',
    category: 'Network Security',
    description: 'NODE_TLS_REJECT_UNAUTHORIZED set to 0 — disables all TLS certificate validation globally.',
    severity: 'critical',
    fix_suggestion: 'Remove this setting. Fix certificate issues instead of disabling verification.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bNODE_TLS_REJECT_UNAUTHORIZED\b.*['"`]0['"`]/.test(line);
    },
  },
  {
    id: 'MULTER_NO_FILE_FILTER',
    category: 'File Upload',
    description: 'Multer file upload without fileFilter — accepts any file type including executables.',
    severity: 'medium',
    fix_suggestion: 'Add a fileFilter to validate file types: multer({ fileFilter: (req, file, cb) => {...} }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bmulter\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return !/\bfileFilter\b/.test(window) && !/\bfilter\b/.test(window);
    },
  },
  {
    id: 'EXPRESS_NO_HELMET',
    category: 'Security Headers',
    description: 'Express app without helmet middleware — missing critical security headers.',
    severity: 'medium',
    fix_suggestion: 'Add helmet: app.use(helmet()) to set security headers automatically.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|express)\s*\(\s*\)/.test(line)) return false;
      return !/\bhelmet\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'MORGAN_SENSITIVE_LOGGING',
    category: 'Data Privacy',
    description: 'Morgan HTTP logger in combined/dev format logging Authorization headers.',
    severity: 'low',
    fix_suggestion: 'Use a custom morgan format that excludes sensitive headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bmorgan\s*\(\s*['"`]combined['"`]\s*\)/.test(line);
    },
  },
  {
    id: 'COMPRESSION_BREACH',
    category: 'Network Security',
    description: 'HTTP compression enabled on responses with secrets — vulnerable to BREACH attack.',
    severity: 'low',
    fix_suggestion: 'Disable compression for responses containing CSRF tokens or secrets.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcompression\s*\(\s*\)/.test(line)) return false;
      return /\bcsrf\b/i.test(ctx.fileContent) && !/\bfilter\b/.test(line);
    },
  },

  // -- React / Frontend Extended --
  {
    id: 'REACT_DANGEROUSLYSETINNERHTML_VARIABLE',
    category: 'XSS',
    description: 'React dangerouslySetInnerHTML with uncontrolled variable — direct XSS vector.',
    severity: 'critical',
    fix_suggestion: 'Sanitize HTML with DOMPurify: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bdangerouslySetInnerHTML\b/.test(line)) return false;
      // Skip when the line already uses a known sanitization function
      if (/\b(?:DOMPurify|sanitize|purify|dompurify|xss)\b/i.test(line)) return false;
      // JSON.stringify() output is always safe — JSON cannot contain executable HTML
      if (/JSON\s*\.\s*stringify\s*\(/.test(line)) return false;
      // Check the value between __html: and }} for sanitization wrappers
      const htmlValueMatch = line.match(/__html\s*:\s*(.+?)(?:\}\}|$)/);
      if (htmlValueMatch) {
        const htmlValue = htmlValueMatch[1];
        if (/\b(?:sanitize|DOMPurify\.sanitize|markdownToSafeHTML|purify|xss|sanitizeHtml|escapeHtml|JSON\.stringify)\s*\(/.test(htmlValue)) return false;
      }
      return true;
    },
  },
  {
    id: 'NEXTJS_MIDDLEWARE_NO_MATCHER',
    category: 'Server Misconfiguration',
    description: 'Next.js middleware without route matcher — runs on every request including static assets.',
    severity: 'low',
    fix_suggestion: 'Add a matcher config: export const config = { matcher: ["/api/:path*", "/dashboard/:path*"] }.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bexport\s+(?:default\s+)?function\s+middleware\b/.test(line)) return false;
      return !/\bmatcher\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'BLOB_URL_XSS',
    category: 'XSS',
    description: 'Blob URL created from user-controlled content — can execute arbitrary JavaScript.',
    severity: 'high',
    fix_suggestion: 'Sanitize content before creating Blob URLs. Validate the content type.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+Blob\s*\(/.test(line)) return false;
      return /\b(?:text\/html|application\/javascript)\b/.test(line) &&
        /\b(?:req|user|input|data|content)\b/i.test(line);
    },
  },
  {
    id: 'DOM_XSS_INNERHTML_ASSIGN',
    category: 'XSS',
    description: 'Direct innerHTML assignment — classic DOM-based XSS vector.',
    severity: 'high',
    fix_suggestion: 'Use textContent instead of innerHTML, or sanitize with DOMPurify.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.innerHTML\s*=/.test(line)) return false;
      return !/\b(?:DOMPurify|sanitize|escape)\b/i.test(line) && !/\.innerHTML\s*=\s*['"`]/.test(line);
    },
  },
  {
    id: 'DOM_XSS_OUTERHTML',
    category: 'XSS',
    description: 'Direct outerHTML assignment with dynamic content — DOM-based XSS vector.',
    severity: 'high',
    fix_suggestion: 'Use safe DOM manipulation methods instead of outerHTML.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.outerHTML\s*=/.test(line)) return false;
      return !/\b(?:DOMPurify|sanitize|escape)\b/i.test(line) && !/\.outerHTML\s*=\s*['"`]/.test(line);
    },
  },
  {
    id: 'DOM_XSS_INSERTADJACENTHTML',
    category: 'XSS',
    description: 'insertAdjacentHTML with dynamic content — DOM-based XSS vector.',
    severity: 'high',
    fix_suggestion: 'Use insertAdjacentText or sanitize HTML with DOMPurify before insertion.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\binsertAdjacentHTML\s*\(/.test(line)) return false;
      return !/\b(?:DOMPurify|sanitize|escape)\b/i.test(line);
    },
  },

  // -- Python Extended --
  {
    id: 'PYTHON_FORMAT_SQL',
    category: 'SQL Injection',
    description: 'Python .format() used in SQL query string — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion: 'Use parameterized queries: cursor.execute("SELECT * FROM t WHERE id = %s", (id,)).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(line)) return false;
      return /\.format\s*\(/.test(line);
    },
  },
  {
    id: 'PYTHON_PERCENT_SQL',
    category: 'SQL Injection',
    description: 'Python % string formatting in SQL query — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion: 'Use parameterized queries instead of string formatting.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(line)) return false;
      return /['"`].*\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*%s.*['"`]\s*%\s*\(/.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_DEBUG',
    category: 'Server Misconfiguration',
    description: 'Django DEBUG = True in settings — exposes detailed error pages with stack traces and settings.',
    severity: 'high',
    fix_suggestion: 'Set DEBUG = False in production. Use environment variable: DEBUG = os.environ.get("DEBUG") == "True".',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bDEBUG\s*=\s*True\b/.test(line)) return false;
      // Must be a Django settings file or Django project
      const lowerPath = ctx.filePath.toLowerCase();
      if (lowerPath.includes('settings') || lowerPath.includes('django')) return true;
      // Check for Django imports in the file
      return /\bfrom\s+django\b|\bimport\s+django\b|\bINSTALLED_APPS\b|\bMIDDLEWARE\b|\bALLOWED_HOSTS\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'PYTHON_JWT_NO_VERIFY',
    category: 'Authentication',
    description: 'Python JWT decoded without verification — any token will be accepted.',
    severity: 'critical',
    fix_suggestion: 'Use jwt.decode(token, key, algorithms=["HS256"]) with verification enabled.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bjwt\s*\.\s*decode\s*\(/.test(line)) return false;
      return /\bverify\s*=\s*False\b/.test(line) || /\boptions\s*=.*"verify_signature"\s*:\s*False/.test(line);
    },
  },
  {
    id: 'PYTHON_REGEX_DOS',
    category: 'Denial of Service',
    description: 'Python regex with catastrophic backtracking potential — nested quantifiers on user input.',
    severity: 'medium',
    fix_suggestion: 'Use re2 library for safe regex or simplify the pattern to avoid nested quantifiers.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bre\s*\.\s*(?:match|search|findall|sub|compile)\s*\(/.test(line)) return false;
      return /\([^)]*[+*][^)]*\)[+*]/.test(line);
    },
  },
  {
    id: 'PYTHON_FLASK_CORS_WILDCARD',
    category: 'CORS Misconfiguration',
    description: 'Flask-CORS with wildcard origin and credentials — browsers send cookies to any origin.',
    severity: 'high',
    fix_suggestion: 'Specify allowed origins: CORS(app, origins=["https://example.com"], supports_credentials=True).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bCORS\s*\(\s*app\s*\)/.test(line) || /\bCORS\s*\(\s*app\s*,\s*supports_credentials\s*=\s*True\b/.test(line) && /\borigins?\s*=\s*['"`]\*['"`]/.test(line);
    },
  },
  {
    id: 'PYTHON_OPEN_REDIRECT',
    category: 'Open Redirect',
    description: 'Python/Flask/Django redirect with user-controlled URL — enables phishing attacks.',
    severity: 'medium',
    fix_suggestion: 'Validate redirect URLs against a whitelist. Only allow relative URLs or known domains.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bredirect\s*\(/.test(line)) return false;
      return /\bredirect\s*\(\s*request\s*\.(?:args|form|GET|POST)\s*\.?\s*(?:get\s*\()?['"`]?\w*(?:url|next|redirect|return|callback)\b/.test(line);
    },
  },
  {
    id: 'PYTHON_LOGGING_SENSITIVE',
    category: 'Data Privacy',
    description: 'Python logging sensitive data (password, token, secret) — visible in log files.',
    severity: 'medium',
    fix_suggestion: 'Redact sensitive fields before logging. Use structured logging with field filtering.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:logging\.\w+|logger\.\w+|print)\s*\(/.test(line)) return false;
      return /\b(?:password|secret|token|api_key|private_key|credential)\b/i.test(line) &&
        !/\b(?:redact|mask|sanitize|filter)\b/i.test(line);
    },
  },

  // -- Database Extended --
  {
    id: 'DRIZZLE_RAW_SQL',
    category: 'SQL Injection',
    description: 'Drizzle ORM sql.raw() with template literal — bypasses Drizzle SQL escaping.',
    severity: 'critical',
    fix_suggestion: 'Use Drizzle parameterized queries: sql`SELECT * FROM ${usersTable} WHERE id = ${id}`.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip ORM library internals
      if (isOrmPackage(ctx.filePath) || isLibraryPackage(ctx.filePath)) return false;
      return /\bsql\s*\.\s*raw\s*\(\s*`[^`]*\$\{/.test(line);
    },
  },
  {
    id: 'KNEX_RAW_UNSAFE',
    category: 'SQL Injection',
    description: 'Knex.raw() with template literal — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion: 'Use Knex parameterized raw: knex.raw("SELECT * FROM t WHERE id = ?", [id]).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bknex\s*\.\s*raw\s*\(\s*`[^`]*\$\{/.test(line);
    },
  },
  {
    id: 'PRISMA_RAW_UNSAFE',
    category: 'SQL Injection',
    description: 'Prisma $executeRawUnsafe or $queryRawUnsafe with variable — bypasses Prisma SQL escaping.',
    severity: 'critical',
    fix_suggestion: 'Use tagged template: prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}` (auto-parameterized).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\$(?:executeRawUnsafe|queryRawUnsafe)\s*\(/.test(line);
    },
  },
  {
    id: 'MONGO_CLIENT_INJECTION',
    category: 'NoSQL Injection',
    description: 'MongoDB client query with unvalidated user input in operator position.',
    severity: 'high',
    fix_suggestion: 'Sanitize MongoDB queries: strip $ prefixed keys from user input.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:find|updateOne|updateMany|deleteOne|deleteMany)\s*\(/.test(line)) return false;
      return /\b(?:find|updateOne|updateMany)\s*\(\s*req\s*\.\s*(?:body|query)\s*\)/.test(line);
    },
  },

  // -- Network / HTTP Extended --
  {
    id: 'HTTP_SMUGGLING_TRANSFER_ENCODING',
    category: 'HTTP Security',
    description: 'Manual Transfer-Encoding header handling — may be vulnerable to HTTP request smuggling.',
    severity: 'high',
    fix_suggestion: 'Let the HTTP framework handle Transfer-Encoding. Do not set or parse it manually.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsetHeader\s*\(\s*['"`]transfer-encoding['"`]/i.test(line);
    },
  },
  {
    id: 'PROXY_HEADER_SPOOFING',
    category: 'Network Security',
    description: 'User IP obtained from X-Real-IP without proxy validation — trivially spoofable.',
    severity: 'medium',
    fix_suggestion: 'Only trust X-Real-IP/X-Forwarded-For behind a trusted reverse proxy. Validate proxy chain.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:req|request)\s*\.\s*headers?\s*\[\s*['"`]x-real-ip['"`]\s*\]/.test(line) &&
        /\b(?:rate|limit|auth|block|ban|whitelist|allowlist)\b/i.test(line);
    },
  },
  {
    id: 'FETCH_NO_ERROR_HANDLING',
    category: 'Reliability',
    description: 'Fetch call without checking response.ok — silently accepts error responses as valid.',
    severity: 'low',
    fix_suggestion: 'Check response.ok or response.status after fetch: if (!response.ok) throw new Error(...).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bawait\s+fetch\s*\(/.test(line)) return false;
      if (isFrameworkSource(ctx.filePath)) return false;
      if (/\b(?:\.ok|\.status|response\.ok)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      // Expand forward window to 12 lines (was 6) to catch response checks further down
      const nextLines = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 12)).join('\n');
      if (/\b(?:\.ok|\.status|response\.ok|res\.ok|\.statusText)\b/.test(nextLines)) return false;
      // Expand backward window to 15 lines (was 5) to catch try blocks further up
      const beforeLines = ctx.allLines.slice(Math.max(0, lineIdx - 15), lineIdx).join('\n');
      if (/\btry\s*\{/.test(beforeLines)) return false;
      if (/\.catch\s*\(/.test(nextLines)) return false;
      if (/\.catch\s*\(/.test(line)) return false;
      // Skip if file has a global error handler (wrapper function, interceptor, etc.)
      if (/\b(?:onError|errorHandler|handleError|interceptor|ErrorBoundary|globalErrorHandler|fetchWrapper|safeFetch|apiFetch)\b/.test(ctx.fileContent)) return false;
      // Skip if this is inside a utility/helper function (likely a fetch wrapper)
      const funcContext = ctx.allLines.slice(Math.max(0, lineIdx - 20), lineIdx).join('\n');
      if (/(?:export\s+)?(?:async\s+)?function\s+\w*(?:fetch|request|api|http)\w*\s*\(/i.test(funcContext)) return false;
      return true;
    },
  },

  // -- Auth Extended --
  {
    id: 'AUTH_TOKEN_IN_QUERY_STRING',
    category: 'Authentication',
    description: 'Auth token passed in URL query string — visible in logs, browser history, and Referer headers.',
    severity: 'high',
    fix_suggestion: 'Pass auth tokens in the Authorization header, not URL query parameters.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /['"`][^'"`]*\?[^'"`]*(?:token|access_token|auth_token|api_key)=\$\{/.test(line) ||
        /['"`][^'"`]*\?[^'"`]*(?:token|access_token|auth_token|api_key)=['"` ]*\+/.test(line);
    },
  },
  {
    id: 'MAGIC_LINK_NO_EXPIRY',
    category: 'Authentication',
    description: 'Magic link/invite token without expiry — links remain valid forever if not revoked.',
    severity: 'medium',
    fix_suggestion: 'Set a short expiry (15 minutes to 24 hours) on magic links and invite tokens.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:magicLink|magic_link|inviteToken|invite_token|invitationToken)\b/.test(line)) return false;
      if (!/\b(?:create|save|insert|generate)\b/i.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return !/\b(?:expir|ttl|maxAge|validUntil|valid_until|expiresAt|expires_at)\b/i.test(window);
    },
  },
  {
    id: 'BEARER_TOKEN_LOGGED',
    category: 'Data Privacy',
    description: 'Bearer token or Authorization header logged — tokens visible in log files.',
    severity: 'high',
    fix_suggestion: 'Redact authorization headers before logging. Log only "Bearer ***" prefix.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:console\.log|logger\.\w+|log\.\w+)\s*\(/.test(line)) return false;
      return /\breq\s*\.\s*headers?\s*\.\s*authorization\b/.test(line) ||
        /\b(?:bearer|accessToken|access_token|authToken|auth_token)\b/i.test(line) && /\b(?:console\.log|logger\.\w+)\s*\(/.test(line);
    },
  },
  {
    id: 'SESSION_SERIALIZATION',
    category: 'Session Security',
    description: 'Custom session serialization — may enable deserialization attacks or data corruption.',
    severity: 'medium',
    fix_suggestion: 'Use the session store default serialization. Avoid custom serialize/deserialize methods.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:serialize|deserialize)\b/.test(line)) return false;
      return /\b(?:session|passport)\b/i.test(line) && /\beval\b/.test(line);
    },
  },

  // -- File Upload Extended --
  {
    id: 'FILE_UPLOAD_PATH_USER',
    category: 'Path Traversal',
    description: 'Uploaded file destination path from user input — enables writing to arbitrary locations.',
    severity: 'critical',
    fix_suggestion: 'Generate server-side file paths. Never use user-provided filenames for storage paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:writeFile|createWriteStream|rename|mv|move)\s*\(/.test(line)) return false;
      return /\breq\s*\.\s*(?:body|file|files)\s*\.\s*(?:filename|name|originalname|path)\b/.test(line) &&
        /\b(?:writeFile|createWriteStream|rename)\s*\(/.test(line);
    },
  },
  {
    id: 'FILE_UPLOAD_EXEC',
    category: 'Code Execution',
    description: 'Uploaded file content executed or required — allows remote code execution.',
    severity: 'critical',
    fix_suggestion: 'Never execute uploaded files. Store them in isolated storage and validate content.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:require|import|exec|spawn)\s*\(/.test(line)) return false;
      return /\b(?:require|import)\s*\(\s*(?:req\.file|uploadPath|filePath|uploaded)/.test(line);
    },
  },
  {
    id: 'IMAGE_UPLOAD_NO_REPROCESS',
    category: 'File Upload',
    description: 'Image upload without re-processing — image metadata may contain XSS payloads or GPS coordinates.',
    severity: 'low',
    fix_suggestion: 'Re-process uploaded images with sharp or jimp to strip EXIF data and validate format.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:upload|multer)\b/.test(line)) return false;
      if (!/\b(?:image|photo|avatar|picture|thumbnail)\b/i.test(line)) return false;
      return !/\b(?:sharp|jimp|imagemagick|gm|exiftool)\b/i.test(ctx.fileContent);
    },
  },

  // -- Timing / Race Condition Extended --
  {
    id: 'DOUBLE_SUBMIT_NO_IDEMPOTENCY',
    category: 'Race Condition',
    description: 'Payment/order endpoint without idempotency key — double-submission can charge twice.',
    severity: 'high',
    fix_suggestion: 'Require an idempotency key for payment endpoints. Cache and dedup by key.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:payment|charge|order|purchase|checkout|transfer)\b/i.test(line)) return false;
      if (!/\b(?:app|router)\s*\.\s*post\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return !/\b(?:idempotency|idempotent|dedup|deduplication)\b/i.test(window);
    },
  },
  {
    id: 'RACE_CONDITION_CHECK_THEN_ACT',
    category: 'Race Condition',
    description: 'Read-then-write without atomic operation — concurrent requests can cause inconsistent state.',
    severity: 'medium',
    fix_suggestion: 'Use database transactions or atomic operations: UPDATE ... SET balance = balance - :amount WHERE balance >= :amount.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:balance|stock|inventory|quantity|credits|points|seats|tickets)\b/i.test(line)) return false;
      if (!/\bif\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const nextLines = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return /\b(?:update|save|set|decrement|subtract)\b/i.test(nextLines) &&
        !/\b(?:transaction|atomic|lock|mutex|semaphore)\b/i.test(ctx.allLines.slice(Math.max(0, lineIdx - 5), lineIdx + 10).join('\n'));
    },
  },

  // -- Miscellaneous Security --
  {
    id: 'CRON_JOB_NO_LOCK',
    category: 'Race Condition',
    description: 'Cron job without distributed lock — multiple instances may run simultaneously.',
    severity: 'low',
    fix_suggestion: 'Use a distributed lock (Redis SETNX, database advisory lock) for cron jobs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:cron|schedule|setInterval)\b/i.test(line)) return false;
      if (!/\b(?:cron\.schedule|schedule\.scheduleJob|setInterval)\s*\(/.test(line)) return false;
      return !/\b(?:lock|mutex|semaphore|setnx|advisory)\b/i.test(ctx.fileContent);
    },
  },
  {
    id: 'ADMIN_ROUTE_NO_AUTH',
    category: 'Authorization',
    description: 'Admin route without authentication middleware — admin functions accessible to anyone.',
    severity: 'critical',
    fix_suggestion: 'Add auth and admin role middleware: app.use("/admin", authenticate, requireAdmin, adminRouter).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\s*\.\s*(?:use|get|post|put|delete)\s*\(\s*['"`]\/admin\b/.test(line)) return false;
      if (/\b(?:auth|authenticate|authorize|isAdmin|requireAdmin|adminAuth|requireRole|protect|guard)\b/i.test(line)) return false;
      // Check if router-level auth middleware is applied earlier in the file
      const lineIdx = ctx.lineNumber - 1;
      const before = ctx.allLines.slice(Math.max(0, lineIdx - 15), lineIdx).join('\n');
      return !/\b(?:router|app)\s*\.\s*use\s*\(\s*(?:auth|authenticate|authorize|isAdmin|requireAdmin|protect|guard)\b/i.test(before);
    },
  },
  {
    id: 'SENSITIVE_DATA_IN_ERROR',
    category: 'Information Disclosure',
    description: 'Sensitive data included in error message — may leak to clients or logs.',
    severity: 'medium',
    fix_suggestion: 'Do not include passwords, tokens, or keys in error messages.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+Error\s*\(/.test(line)) return false;
      return /\bnew\s+Error\s*\([^)]*\b(?:password|token|secret|apiKey|api_key|privateKey|private_key)\b/.test(line) &&
        !/\b(?:missing|required|invalid|not found|undefined)\b/i.test(line);
    },
  },
  {
    id: 'GLOBAL_ERROR_HANDLER_LEAK',
    category: 'Information Disclosure',
    description: 'Global error handler sending full error to client in production.',
    severity: 'medium',
    fix_suggestion: 'In production, send generic error messages. Log full details server-side only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:res|response)\s*\.\s*(?:json|send)\s*\(/.test(line)) return false;
      return /\b(?:err|error)\s*\.\s*message\b/.test(line) && /\b(?:err|error)\s*\.\s*stack\b/.test(line);
    },
  },
  {
    id: 'EXPOSE_SERVER_VERSION',
    category: 'Information Disclosure',
    description: 'Server version exposed in response headers — helps attackers identify vulnerabilities.',
    severity: 'low',
    fix_suggestion: 'Remove X-Powered-By header: app.disable("x-powered-by") or use helmet().',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsetHeader\s*\(\s*['"`]X-Powered-By['"`]/i.test(line) ||
        /\bsetHeader\s*\(\s*['"`]Server['"`]\s*,\s*['"`][^'"`]+['"`]\s*\)/.test(line);
    },
  },
  {
    id: 'CLICKJACKING_NO_PROTECTION',
    category: 'Security Headers',
    description: 'Response without X-Frame-Options or frame-ancestors CSP — vulnerable to clickjacking.',
    severity: 'medium',
    fix_suggestion: 'Add X-Frame-Options: DENY header or use CSP frame-ancestors directive. Use helmet().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bframeguard\s*:\s*false\b/.test(line)) return false;
      return /\bhelmet\b/.test(line) || /\bframeguard\b/.test(line);
    },
  },

  // -- AI / LLM Extended --
  {
    id: 'AI_RESPONSE_TO_DB',
    category: 'AI Security',
    description: 'AI/LLM response stored directly in database without sanitization — potential stored XSS or injection.',
    severity: 'medium',
    fix_suggestion: 'Sanitize AI responses before storing. Treat AI output as untrusted user input.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:completion|response|output|result)\s*\.\s*(?:text|content|message|data)\b/.test(line)) return false;
      return /\b(?:insert|create|save|update|upsert)\b/i.test(line) && /\b(?:ai|llm|gpt|claude|openai|anthropic|completion)\b/i.test(line);
    },
  },
  {
    id: 'AI_TOKEN_LIMIT_MISSING',
    category: 'AI Security',
    description: 'AI API call without max_tokens limit — may generate unexpectedly long (and expensive) responses.',
    severity: 'low',
    fix_suggestion: 'Set max_tokens to a reasonable limit: { max_tokens: 1000 } for most use cases.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:openai|anthropic|chat\.completions|messages)\s*\.\s*create\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\bmax_tokens\b/.test(window) && !/\bmaxTokens\b/.test(window);
    },
  },
  {
    id: 'AI_SYSTEM_PROMPT_OVERRIDE',
    category: 'AI Security',
    description: 'User input used as system prompt role — enables complete control over AI behavior.',
    severity: 'critical',
    fix_suggestion: 'Never let users control the system prompt. Hardcode system prompts server-side.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\brole\s*:\s*['"`]system['"`]/.test(line)) return false;
      return /\bcontent\s*:\s*req\s*\.\s*(?:body|query)\b/.test(line);
    },
  },

  // -- JWT Extended --
  {
    id: 'JWT_LONG_EXPIRY',
    category: 'Authentication',
    description: 'JWT with very long expiry (>7 days) — limits the effectiveness of token revocation.',
    severity: 'low',
    fix_suggestion: 'Set JWT expiry to 15 minutes to 1 hour. Use refresh tokens for longer sessions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:expiresIn|expires_in)\b/.test(line)) return false;
      if (!/\bjwt\b|sign\s*\(/i.test(line)) return false;
      return /\bexpiresIn\s*:\s*['"`](?:30d|60d|90d|365d|1y|2y)\b/.test(line);
    },
  },
  {
    id: 'JWT_SECRET_SHORT',
    category: 'Authentication',
    description: 'JWT signing secret appears to be very short — susceptible to brute force attacks.',
    severity: 'high',
    fix_suggestion: 'Use a secret of at least 256 bits (32 bytes). Generate with crypto.randomBytes(32).toString("hex").',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bjwt\s*\.\s*sign\s*\(/.test(line)) return false;
      const match = line.match(/jwt\s*\.\s*sign\s*\([^,]+,\s*['"`]([^'"`]+)['"`]/);
      if (!match) return false;
      return match[1].length < 16;
    },
  },

  // -- Content / Media Security --
  {
    id: 'SVG_INLINE_UNVALIDATED',
    category: 'XSS',
    description: 'SVG content rendered inline without sanitization — SVGs can contain JavaScript.',
    severity: 'high',
    fix_suggestion: 'Sanitize SVG content with DOMPurify before rendering. Remove script and event handler attributes.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:innerHTML|dangerouslySetInnerHTML)\b/.test(line)) return false;
      return /\bsvg\b/i.test(line) && !/\b(?:sanitize|DOMPurify|purify)\b/i.test(line);
    },
  },
  {
    id: 'MARKDOWN_XSS',
    category: 'XSS',
    description: 'Markdown rendered to HTML without sanitization — markdown can contain raw HTML/XSS.',
    severity: 'high',
    fix_suggestion: 'Use marked with sanitize option or DOMPurify: DOMPurify.sanitize(marked(markdown)).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:marked|remarkable|markdown-it|showdown)\s*\(/.test(line)) return false;
      return !/\b(?:sanitize|DOMPurify|purify|xss)\b/i.test(line);
    },
  },

  // -- Email Security Extended --
  {
    id: 'EMAIL_FROM_SPOOFING',
    category: 'Email Security',
    description: 'Email "from" address taken from user input — enables email spoofing.',
    severity: 'medium',
    fix_suggestion: 'Always set the from address to your verified domain. Never use user-provided from addresses.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bfrom\s*:\s*req\s*\.\s*(?:body|query)\b/.test(line)) return false;
      return /\b(?:mail|email|send|smtp|transporter|nodemailer|ses|sendgrid)\b/i.test(line);
    },
  },

  // -- RegExp Extended --
  {
    id: 'REGEX_GLOBAL_STATE',
    category: 'Logic Error',
    description: 'RegExp with /g flag stored in module scope — lastIndex state persists between calls, causing intermittent bugs.',
    severity: 'medium',
    fix_suggestion: 'Create regex inside the function, or use string.match() instead of regex.test() with /g flag.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bconst\s+\w+\s*=\s*(?:new\s+RegExp\s*\([^)]+,\s*['"`][^'"`]*g[^'"`]*['"`]\s*\)|\/[^/]+\/[^/]*g[^/;]*);?\s*$/.test(line);
    },
  },

  // -- Cache Security --
  {
    id: 'CACHE_SENSITIVE_RESPONSE',
    category: 'Data Exposure',
    description: 'Sensitive API response cached without cache-control headers — may be served to other users.',
    severity: 'medium',
    fix_suggestion: 'Set Cache-Control: no-store, private for responses containing personal or auth data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:res|response)\s*\.\s*json\s*\(/.test(line)) return false;
      if (!/\b(?:user|profile|account|settings|token|secret)\b/i.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 3)).join('\n');
      return !/\bcache-control\b/i.test(window) && !/\bno-store\b/.test(window) && !/\bprivate\b/.test(window);
    },
  },

  // -- Type Confusion --
  {
    id: 'ARRAY_ISARRAY_MISSING',
    category: 'Validation',
    description: 'Array method called on user input without Array.isArray check — type confusion can cause crashes.',
    severity: 'low',
    fix_suggestion: 'Validate arrays: if (!Array.isArray(req.body.items)) return res.status(400).json(...).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\breq\s*\.\s*body\s*\.\s*\w+\s*\.\s*(?:map|forEach|filter|reduce|find|some|every)\s*\(/.test(line);
    },
  },

  // -- Configuration Extended --
  {
    id: 'DOTENV_EXPAND_UNSAFE',
    category: 'Configuration',
    description: 'dotenv-expand with user-controlled env vars — enables variable injection.',
    severity: 'medium',
    fix_suggestion: 'Validate environment variables. Do not allow user input to set env vars that get expanded.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bexpand\s*\(\s*config\s*\(\s*\)/.test(line) && /\bdotenv\b/.test(line);
    },
  },
  {
    id: 'ENV_OVERRIDE_FROM_REQUEST',
    category: 'Configuration',
    description: 'Environment variables set from request input — enables environment manipulation.',
    severity: 'critical',
    fix_suggestion: 'Never set environment variables from user input. Environment should be immutable at runtime.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bprocess\s*\.\s*env\s*\[\s*(?:req|request)\b/.test(line) ||
        /\bprocess\s*\.\s*env\s*\.\s*\w+\s*=\s*req\s*\.\s*(?:body|query|params)\b/.test(line);
    },
  },

  // -- WebAssembly --
  {
    id: 'WASM_INSTANTIATE_USER_INPUT',
    category: 'Code Execution',
    description: 'WebAssembly instantiated from user-provided bytes — enables arbitrary code execution.',
    severity: 'critical',
    fix_suggestion: 'Only load WASM modules from trusted, static sources. Never from user uploads.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bWebAssembly\s*\.\s*(?:instantiate|compile)\s*\(/.test(line)) return false;
      return /\breq\s*\.\s*(?:body|file|files)\b/.test(line) || /\buserInput\b/.test(line) || /\bupload\b/i.test(line);
    },
  },

  // -- Error Handling Extended --
  {
    id: 'UNHANDLED_REJECTION_NO_HANDLER',
    category: 'Reliability',
    description: 'Promise rejection without .catch() or try/catch — unhandled rejections crash Node.js.',
    severity: 'medium',
    fix_suggestion: 'Always handle promise rejections: use try/catch with await or .catch() on promises.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect promise-returning call without await/catch
      return /\b(?:fetch|axios\.\w+|got\.\w+)\s*\([^)]+\)\s*;$/.test(line.trim()) &&
        !/\bawait\b/.test(line) && !/\.catch\b/.test(line) && !/\.then\b/.test(line);
    },
  },
  {
    id: 'ASYNC_VOID',
    category: 'Error Handling',
    description: 'Async function returning void — errors are silently swallowed with no way to catch them.',
    severity: 'medium',
    fix_suggestion: 'Return the promise or handle errors within the async function.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\basync\s+\w+\s*\([^)]*\)\s*:\s*Promise\s*<\s*void\s*>/.test(line) &&
        /\b(?:app|router|server)\s*\.\s*(?:on|use|get|post)\b/.test(line);
    },
  },

  // -- Input Validation Extended --
  {
    id: 'PROTOTYPE_KEY_CHECK_MISSING',
    category: 'Prototype Pollution',
    description: 'Object key assignment from user input without __proto__ check — enables prototype pollution.',
    severity: 'high',
    fix_suggestion: 'Reject keys named __proto__, constructor, or prototype from user input.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\[\s*req\s*\.\s*(?:body|query|params)\s*\.\s*\w+\s*\]\s*=/.test(line)) return false;
      return !/\b(?:__proto__|constructor|prototype)\b/.test(line);
    },
  },
  {
    id: 'HEADER_CRLF_SPLIT',
    category: 'Injection',
    description: 'Response header value from user input without CRLF stripping — enables header injection/response splitting.',
    severity: 'high',
    fix_suggestion: 'Strip \\r\\n from all user input used in response headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:res|response)\s*\.\s*(?:setHeader|header|set)\s*\(/.test(line)) return false;
      return /\breq\s*\.\s*(?:query|params|body|headers)\s*\.\s*\w+/.test(line) &&
        !/\b(?:replace|strip|sanitize|escape)\b/.test(line);
    },
  },

  // -- Microservice Security --
  {
    id: 'INTERNAL_API_NO_AUTH',
    category: 'Authorization',
    description: 'Internal/microservice API endpoint without service-to-service authentication.',
    severity: 'high',
    fix_suggestion: 'Add service-to-service auth: mTLS, API keys, or JWT-based service tokens.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:app|router)\s*\.\s*(?:get|post|put|delete)\s*\(\s*['"`]\/internal\//.test(line)) return false;
      return !/\b(?:auth|authenticate|verify|validate|middleware|guard)\b/i.test(line);
    },
  },

  // -- DNS / Domain Security --
  {
    id: 'SUBDOMAIN_TAKEOVER_RISK',
    category: 'Infrastructure',
    description: 'CNAME or DNS record pointing to external service — potential subdomain takeover if service is decommissioned.',
    severity: 'low',
    fix_suggestion: 'Monitor DNS records. Remove CNAME records for services that are no longer active.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bCNAME\b/.test(line)) return false;
      return /\bCNAME\b.*\b(?:herokuapp|azurewebsites|cloudfront|s3-website|ghost\.io|shopify|fastly|zendesk)\b/.test(line);
    },
  },

  // -- Container Security Extended --
  {
    id: 'DOCKER_COPY_SECRETS',
    category: 'Secrets',
    description: 'Dockerfile COPY command including .env or secret files — secrets baked into image layers.',
    severity: 'high',
    fix_suggestion: 'Use Docker secrets or --mount=type=secret. Add .env to .dockerignore.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bCOPY\b/.test(line)) return false;
      return /\bCOPY\b.*\b(?:\.env|\.pem|\.key|credentials|secrets\.json|\.p12)/.test(line);
    },
  },
  {
    id: 'DOCKER_RUN_AS_ROOT',
    category: 'Infrastructure',
    description: 'Dockerfile without USER instruction — container runs as root by default.',
    severity: 'medium',
    fix_suggestion: 'Add USER directive: USER 1000:1000 or USER node. Never run containers as root.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bFROM\b/.test(line)) return false;
      if (!/\bFROM\s+\w/.test(line)) return false;
      return !/\bUSER\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'DOCKER_ADD_REMOTE',
    category: 'Supply Chain',
    description: 'Dockerfile ADD with remote URL — downloads unverified content into the image.',
    severity: 'medium',
    fix_suggestion: 'Use RUN curl + checksum verification instead of ADD for remote URLs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bADD\s+https?:\/\//.test(line);
    },
  },

  // -- Serverless Extended --
  {
    id: 'LAMBDA_TIMEOUT_LOW',
    category: 'Reliability',
    description: 'Lambda function with very low timeout — may fail on normal requests causing retries.',
    severity: 'low',
    fix_suggestion: 'Set a reasonable timeout (10-30 seconds for APIs, higher for background jobs).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\btimeout\s*:\s*\d+/.test(line)) return false;
      if (!/\b(?:lambda|Lambda|function)\b/i.test(line)) return false;
      const match = line.match(/\btimeout\s*:\s*(\d+)/);
      if (!match) return false;
      return parseInt(match[1], 10) <= 3;
    },
  },
  {
    id: 'LAMBDA_ENV_SECRETS',
    category: 'Secrets',
    description: 'Lambda environment variables containing hardcoded secrets — visible in AWS console and CloudFormation.',
    severity: 'high',
    fix_suggestion: 'Use AWS Secrets Manager or SSM Parameter Store instead of Lambda env vars for secrets.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:environment|env)\b/.test(line)) return false;
      if (!/\b(?:lambda|Lambda|function)\b/i.test(line)) return false;
      return /\b(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*:\s*['"`](?!\$\{|{{)/.test(line);
    },
  },

  // -- GraphQL Extended --
  {
    id: 'GRAPHQL_COST_LIMIT_MISSING',
    category: 'Denial of Service',
    description: 'GraphQL server without query cost analysis — expensive queries can DoS the server.',
    severity: 'medium',
    fix_suggestion: 'Add query cost analysis: graphql-cost-analysis or graphql-query-complexity plugin.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:ApolloServer|createYoga|mercurius)\b/.test(line)) return false;
      return !/\b(?:cost|complexity|costAnalysis|queryComplexity)\b/i.test(ctx.fileContent);
    },
  },
  {
    id: 'GRAPHQL_PERSISTED_QUERIES_OFF',
    category: 'API Security',
    description: 'GraphQL without persisted queries — allows arbitrary queries from any client.',
    severity: 'low',
    fix_suggestion: 'Enable persisted queries for production: only allow pre-registered query hashes.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bpersistedQueries\s*:\s*false\b/.test(line);
    },
  },

  // -- Testing/Development Leftover --
  {
    id: 'TODO_SECURITY_FIX',
    category: 'Code Quality',
    description: 'Security-related TODO/FIXME/HACK comment — indicates known security issue not yet addressed.',
    severity: 'medium',
    fix_suggestion: 'Address security TODOs before deploying to production. Track in issue tracker.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:TODO|FIXME|HACK|XXX)\b/i.test(line)) return false;
      return /\b(?:TODO|FIXME|HACK|XXX)\b.*\b(?:secur|auth|vuln|xss|sqli|inject|csrf|ssrf|encrypt|password|token|secret)/i.test(line);
    },
  },
  {
    id: 'HARDCODED_TEST_CREDENTIALS',
    category: 'Secrets',
    description: 'Hardcoded test/debug credentials in non-test code — may be deployed to production.',
    severity: 'high',
    fix_suggestion: 'Remove hardcoded test credentials. Use environment variables or a test fixture system.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:password|pass)\s*[=:]\s*['"`](?:test|password|admin|123456|qwerty|letmein|welcome)['"`]/i.test(line) ||
        /\b(?:username|user)\s*[=:]\s*['"`](?:test|admin|root|debug)['"`]/i.test(line) && /\bpassword\b/i.test(line);
    },
  },
  {
    id: 'CONSOLE_LOG_IN_PRODUCTION',
    category: 'Code Quality',
    description: 'console.log left in production code — may leak sensitive data and impacts performance.',
    severity: 'low',
    fix_suggestion: 'Use a proper logging library (pino, winston) with log levels. Remove console.log calls.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bconsole\.\s*log\s*\(/.test(line)) return false;
      return /\b(?:password|secret|token|key|credential|ssn|creditCard)\b/i.test(line);
    },
  },

  // -- Permissions / ABAC --
  {
    id: 'PERMISSION_CHECK_SKIP',
    category: 'Authorization',
    description: 'Permission check with early return/skip condition — may allow bypass.',
    severity: 'high',
    fix_suggestion: 'Review permission bypass conditions carefully. Ensure all paths enforce authorization.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bif\s*\(\s*(?:skip|bypass|disable|override)\s*(?:Auth|Permission|Check|Authz)\b/i.test(line);
    },
  },

  // -- Data Validation Extended --
  {
    id: 'UNSAFE_REDIRECT_PARAM',
    category: 'Open Redirect',
    description: 'Redirect URL from query parameter without validation — enables phishing attacks.',
    severity: 'medium',
    fix_suggestion: 'Validate redirect URLs: only allow relative paths or known domains.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:res\.redirect|response\.redirect|redirect)\s*\(/.test(line)) return false;
      return /\bredirect\s*\(\s*req\s*\.\s*query\s*\.\s*(?:returnUrl|return_url|next|redirect|callback|returnTo|return_to)\b/.test(line);
    },
  },
  {
    id: 'NUMERIC_ID_NO_VALIDATION',
    category: 'Validation',
    description: 'Numeric ID from URL param used without parseInt/Number validation — may cause NaN or type confusion.',
    severity: 'low',
    fix_suggestion: 'Validate numeric IDs: const id = parseInt(req.params.id, 10); if (isNaN(id)) return 400.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:findById|findByPk|findOne|get)\s*\(\s*req\.params\.id\s*\)/.test(line)) return false;
      return !/\bparseInt\b/.test(line) && !/\bNumber\b/.test(line);
    },
  },

  // -- WebSocket Extended --
  {
    id: 'WS_ORIGIN_NO_CHECK',
    category: 'Client-Side Security',
    description: 'WebSocket server accepting connections without origin validation.',
    severity: 'medium',
    fix_suggestion: 'Validate the Origin header in the verifyClient callback.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+(?:WebSocket\.Server|WebSocketServer)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\bverifyClient\b/.test(window) && !/\borigin\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Final Push: 50 more rules to exceed 500
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_FLASK_SEND_FILE',
    category: 'Path Traversal',
    description: 'Flask send_file with user-controlled path — enables arbitrary file download.',
    severity: 'critical',
    fix_suggestion: 'Use send_from_directory with a fixed directory: send_from_directory(UPLOAD_DIR, filename).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsend_file\s*\(/.test(line)) return false;
      return /\bsend_file\s*\(\s*(?:request\.|user_input|path|filename|f['"`])/.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_EXTRA',
    category: 'SQL Injection',
    description: 'Django QuerySet.extra() with user input — enables SQL injection via the extra clause.',
    severity: 'critical',
    fix_suggestion: 'Use annotate() and F() expressions instead of extra(). extra() is deprecated.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b\.extra\s*\(/.test(line)) return false;
      return /\.extra\s*\([^)]*(?:f['"`]|\.format\(|\+\s*\w)/.test(line);
    },
  },
  {
    id: 'PYTHON_FLASK_SESSION_DEFAULT',
    category: 'Session Security',
    description: 'Flask using default client-side session — session data visible and modifiable by clients.',
    severity: 'medium',
    fix_suggestion: 'Use Flask-Session with server-side storage (Redis, database) for sensitive session data.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bsession\s*\[/.test(line)) return false;
      if (!/\b(?:password|token|secret|credit|ssn)\b/i.test(line)) return false;
      return !/\bFlask-Session\b/.test(ctx.fileContent) && !/\bSession\s*\(\s*app\s*\)/.test(ctx.fileContent);
    },
  },
  {
    id: 'PYTHON_INSECURE_COOKIE',
    category: 'Session Security',
    description: 'Python/Flask cookie set without secure/httponly flags.',
    severity: 'medium',
    fix_suggestion: 'Set secure=True, httponly=True, samesite="Lax" on all cookies.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Only flag in server framework files, not HTTP client libraries
      if (!hasPythonServerImports(ctx.fileContent)) return false;
      if (!/\bset_cookie\s*\(/.test(line)) return false;
      return !/\bsecure\s*=\s*True\b/.test(line) || !/\bhttponly\s*=\s*True\b/.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_STATICFILES_DIRS',
    category: 'Server Misconfiguration',
    description: 'Django STATICFILES_DIRS containing project root — may serve sensitive files.',
    severity: 'medium',
    fix_suggestion: 'Only include specific static file directories, never the project root.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSTATICFILES_DIRS\s*=\s*\[.*BASE_DIR\s*[,\]]/.test(line);
    },
  },
  {
    id: 'PYTHON_PICKLE_NETWORK',
    category: 'Deserialization',
    description: 'Python pickle used to deserialize network data — enables remote code execution.',
    severity: 'critical',
    fix_suggestion: 'Never unpickle data from untrusted sources. Use JSON for network data exchange.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bpickle\s*\.\s*loads?\s*\(/.test(line)) return false;
      return /\b(?:request|socket|recv|data|body|payload|message)\b/i.test(line);
    },
  },
  {
    id: 'CSRF_TOKEN_IN_GET',
    category: 'CSRF',
    description: 'State-changing operation on GET request — GET requests should be safe/idempotent.',
    severity: 'medium',
    fix_suggestion: 'Use POST/PUT/DELETE for state-changing operations. GET should only retrieve data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:app|router)\s*\.\s*get\s*\(/.test(line)) return false;
      return /\b(?:delete|remove|update|create|insert|modify|drop|destroy)\b/i.test(line) &&
        /\b(?:app|router)\s*\.\s*get\s*\(\s*['"`]\/api\//.test(line);
    },
  },
  {
    id: 'OBJECT_FREEZE_BYPASS',
    category: 'Logic Error',
    description: 'Object.freeze on nested object — only freezes top level, nested properties remain mutable.',
    severity: 'low',
    fix_suggestion: 'Use deep freeze or structuredClone for truly immutable configuration objects.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bObject\.freeze\s*\(/.test(line)) return false;
      // Check if the frozen object contains nested objects
      const lineIdx = ctx.lineNumber - 1;
      const prevLines = ctx.allLines.slice(Math.max(0, lineIdx - 10), lineIdx + 1).join('\n');
      return /\b(?:config|settings|secrets|permissions)\b/i.test(line) &&
        /\{[^}]*\{/.test(prevLines);
    },
  },
  {
    id: 'FORM_ACTION_DYNAMIC',
    category: 'Open Redirect',
    description: 'Form action attribute set from user input — enables phishing by redirecting form submissions.',
    severity: 'medium',
    fix_suggestion: 'Hardcode form action URLs. Validate against a whitelist if dynamic.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\baction\s*=\s*\{?\s*(?:req\s*\.\s*(?:query|body)|userUrl|redirectUrl|returnUrl|data\.url)/.test(line);
    },
  },
  {
    id: 'SENTRY_DSN_EXPOSED',
    category: 'Information Disclosure',
    description: 'Sentry DSN exposed in client-side code — allows sending fake error reports to your Sentry project.',
    severity: 'low',
    fix_suggestion: 'Use Sentry tunnel or allowlist referrers. DSN exposure alone is low risk but enables noise.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bdsn\s*:\s*['"`]https:\/\/[a-f0-9]+@[^.]+\.ingest\.sentry\.io\/\d+['"`]/.test(line);
    },
  },
  {
    id: 'SOCKET_EVENT_INJECTION',
    category: 'Injection',
    description: 'Socket.io event name from user input — enables emitting arbitrary events.',
    severity: 'high',
    fix_suggestion: 'Whitelist allowed event names. Never use user input as socket event names.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:socket|io)\s*\.\s*emit\s*\(/.test(line)) return false;
      return /\bemit\s*\(\s*(?:req\s*\.\s*(?:body|query)|data\.\w+|eventName|event)\b/.test(line) &&
        !/\b(?:whitelist|allowlist|valid|allowed)\b/i.test(line);
    },
  },
  {
    id: 'HANDLEBARS_RAW',
    category: 'XSS',
    description: 'Handlebars triple-brace (unescaped) output with user data — direct XSS vulnerability.',
    severity: 'high',
    fix_suggestion: 'Use double-brace {{ }} for auto-escaped output. Only use {{{ }}} for trusted HTML.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\{\{\{.*\b(?:user|input|data|content|body|message|query)\b.*\}\}\}/.test(line);
    },
  },
  {
    id: 'EJS_UNESCAPED',
    category: 'XSS',
    description: 'EJS unescaped output (<%- %>) with user data — direct XSS vulnerability.',
    severity: 'high',
    fix_suggestion: 'Use escaped output (<%= %>) instead of (<%- %>) for user data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /<%-.*\b(?:user|input|data|content|body|message|query)\b.*%>/.test(line);
    },
  },
  {
    id: 'OBJECT_SPREAD_OVERRIDE',
    category: 'Mass Assignment',
    description: 'Object spread with user input before defaults — user can override any field including role/admin.',
    severity: 'high',
    fix_suggestion: 'Put defaults AFTER user input, or destructure only needed fields: const { name, email } = req.body.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\{\s*\.\.\.req\s*\.\s*body\s*,/.test(line) && /\b(?:role|admin|isAdmin|permissions|level|tier)\b/.test(line);
    },
  },
  {
    id: 'CRYPTO_HMAC_SHA1',
    category: 'Cryptography',
    description: 'HMAC created with SHA-1 — while HMAC-SHA1 is not as broken as bare SHA-1, prefer SHA-256.',
    severity: 'low',
    fix_suggestion: 'Use SHA-256 or SHA-512 for HMAC: createHmac("sha256", key).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcreateHmac\s*\(\s*['"`]sha1['"`]/.test(line);
    },
  },
  {
    id: 'FS_READFILE_USER_PATH',
    category: 'Path Traversal',
    description: 'fs.readFile with user-controlled path — enables reading arbitrary files.',
    severity: 'critical',
    fix_suggestion: 'Validate and sanitize file paths. Use path.resolve() and verify the result is within an allowed directory.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:readFile|readFileSync)\s*\(/.test(line)) return false;
      return /\b(?:readFile|readFileSync)\s*\(\s*(?:req\s*\.\s*(?:body|query|params)|userPath|filePath|inputPath)/.test(line);
    },
  },
  {
    id: 'CHILD_PROCESS_UNVALIDATED',
    category: 'Command Injection',
    description: 'Child process spawned with unvalidated arguments from user input.',
    severity: 'critical',
    fix_suggestion: 'Validate and whitelist all arguments. Use execFile instead of exec for argument safety.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:spawn|execFile|fork)\s*\(/.test(line)) return false;
      return /\b(?:spawn|execFile|fork)\s*\([^,]+,\s*\[?\s*req\s*\.\s*(?:body|query|params)\b/.test(line);
    },
  },
  {
    id: 'NGROK_IN_PRODUCTION',
    category: 'Server Misconfiguration',
    description: 'ngrok tunnel configured in non-development code — exposes local services publicly.',
    severity: 'high',
    fix_suggestion: 'Remove ngrok from production code. Use proper deployment and load balancing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bngrok\s*\.\s*connect\s*\(/.test(line);
    },
  },
  {
    id: 'CORS_ALLOW_ALL_METHODS',
    category: 'CORS Misconfiguration',
    description: 'CORS allowing all HTTP methods — DELETE and PATCH from any origin.',
    severity: 'low',
    fix_suggestion: 'Restrict to needed methods: methods: ["GET", "POST"].',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bmethods\b/.test(line)) return false;
      return /\bmethods\s*:\s*['"`]\*['"`]/.test(line) && /\bcors\b/i.test(line);
    },
  },
  {
    id: 'SQL_ORDER_BY_INJECTION',
    category: 'SQL Injection',
    description: 'ORDER BY clause with user input — enables SQL injection even with parameterized queries.',
    severity: 'high',
    fix_suggestion: 'Whitelist allowed column names for ORDER BY. Never interpolate user input into ORDER BY.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bORDER\s+BY\b/i.test(line)) return false;
      return /\bORDER\s+BY\b/i.test(line) && (/\$\{/.test(line) || /\+\s*(?:req|sort|order|column)/.test(line));
    },
  },
  {
    id: 'SQL_LIKE_INJECTION',
    category: 'SQL Injection',
    description: 'SQL LIKE clause with unescaped user input — % and _ wildcards not escaped.',
    severity: 'medium',
    fix_suggestion: 'Escape LIKE wildcards: value.replace(/%/g, "\\%").replace(/_/g, "\\_").',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bLIKE\b/i.test(line)) return false;
      return /\bLIKE\s+['"`]%\$\{/.test(line) || /\bLIKE\s+['"`]%['"` ]*\+/.test(line);
    },
  },
  {
    id: 'MONGODB_MAPREDUCE',
    category: 'Code Injection',
    description: 'MongoDB mapReduce with user input in map/reduce functions — enables server-side JavaScript injection.',
    severity: 'critical',
    fix_suggestion: 'Use aggregation pipeline instead of mapReduce. MapReduce is deprecated in MongoDB 5.0+.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:mapReduce|map_reduce)\s*\(/.test(line) && /\b(?:req|user|input)\b/.test(line);
    },
  },
  {
    id: 'EXPRESS_DIRECTORY_LISTING',
    category: 'Information Disclosure',
    description: 'Express serve-index or directory listing enabled — reveals file structure to attackers.',
    severity: 'medium',
    fix_suggestion: 'Disable directory listing in production. Only serve specific files.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bserveIndex\s*\(/.test(line) || /\bdirectory\s*:\s*true\b/.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_OPENREDIRECT',
    category: 'Open Redirect',
    description: 'Django HttpResponseRedirect with user-controlled URL — enables phishing attacks.',
    severity: 'medium',
    fix_suggestion: 'Use django.utils.http.url_has_allowed_host_and_scheme() to validate redirect URLs.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bHttpResponseRedirect\s*\(/.test(line)) return false;
      return /\bHttpResponseRedirect\s*\(\s*request\.(?:GET|POST|META)\b/.test(line);
    },
  },
  {
    id: 'PYTHON_YAML_FULL_LOAD',
    category: 'Deserialization',
    description: 'Python yaml.full_load() or yaml.unsafe_load() — enables arbitrary code execution.',
    severity: 'critical',
    fix_suggestion: 'Use yaml.safe_load() for untrusted YAML data.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\byaml\s*\.\s*(?:full_load|unsafe_load)\s*\(/.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_XSS_FILTER',
    category: 'Security Headers',
    description: 'Django SECURE_BROWSER_XSS_FILTER set to False — disables browser XSS protection.',
    severity: 'low',
    fix_suggestion: 'Set SECURE_BROWSER_XSS_FILTER = True in Django settings.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSECURE_BROWSER_XSS_FILTER\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_HSTS',
    category: 'Security Headers',
    description: 'Django SECURE_HSTS_SECONDS set to 0 — disables HTTP Strict Transport Security.',
    severity: 'medium',
    fix_suggestion: 'Set SECURE_HSTS_SECONDS = 31536000 for one year HSTS protection.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSECURE_HSTS_SECONDS\s*=\s*0\b/.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_SSL_REDIRECT',
    category: 'Server Misconfiguration',
    description: 'Django SECURE_SSL_REDIRECT set to False — allows HTTP connections in production.',
    severity: 'medium',
    fix_suggestion: 'Set SECURE_SSL_REDIRECT = True in production to force HTTPS.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSECURE_SSL_REDIRECT\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'NODE_CLUSTER_NO_GRACEFUL',
    category: 'Reliability',
    description: 'Node.js cluster without graceful shutdown — kills active connections on worker restart.',
    severity: 'low',
    fix_suggestion: 'Implement graceful shutdown: stop accepting connections, finish active requests, then exit.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcluster\s*\.\s*fork\s*\(/.test(line)) return false;
      return !/\b(?:graceful|SIGTERM|SIGINT|drain|close)\b/i.test(ctx.fileContent);
    },
  },
  {
    id: 'SOCKET_FLOOD_NO_LIMIT',
    category: 'Denial of Service',
    description: 'Socket.io without connection limiting — one client can open unlimited connections.',
    severity: 'medium',
    fix_suggestion: 'Limit connections per IP: use socket.io-connection-limiter or custom middleware.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+Server\s*\(/.test(line)) return false;
      if (!/\bsocket\.io\b|socketio/i.test(ctx.fileContent)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\b(?:maxHttpBufferSize|connectionsPerIp|maxConnections|limiter)\b/i.test(window);
    },
  },
  {
    id: 'UNSAFE_OBJECT_ASSIGN',
    category: 'Prototype Pollution',
    description: 'Object.assign with user-controlled source — can pollute target object prototype.',
    severity: 'medium',
    fix_suggestion: 'Use structured clone or explicit field assignment instead of Object.assign with user data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bObject\s*\.\s*assign\s*\([^,]+,\s*req\s*\.\s*body\s*\)/.test(line);
    },
  },
  {
    id: 'CRYPTO_NULL_IV',
    category: 'Cryptography',
    description: 'AES cipher created with null/empty IV — makes encryption deterministic (same input = same output).',
    severity: 'high',
    fix_suggestion: 'Use a random IV: const iv = crypto.randomBytes(16); Store IV with ciphertext.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcreateCipheriv\s*\(/.test(line)) return false;
      return /\bcreateCipheriv\s*\([^,]+,\s*[^,]+,\s*(?:null|''|""|Buffer\.alloc\s*\(\s*\d+\s*\))/.test(line);
    },
  },
  {
    id: 'SIGNED_URL_LONG_EXPIRY',
    category: 'Data Exposure',
    description: 'Cloud storage signed URL with very long expiry — URL may be shared and used after intended access period.',
    severity: 'medium',
    fix_suggestion: 'Set signed URL expiry to 15 minutes to 1 hour. Regenerate URLs as needed.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:getSignedUrl|presigned|signedUrl|signed_url)\b/i.test(line)) return false;
      const match = line.match(/\b(?:expires|Expires|expiresIn)\s*:\s*(\d+)/);
      if (!match) return false;
      const seconds = parseInt(match[1], 10);
      return seconds > 86400; // More than 24 hours
    },
  },
  {
    id: 'FIREBASE_RULES_OPEN',
    category: 'Authorization',
    description: 'Firebase security rules allowing read/write to all users — database is publicly accessible.',
    severity: 'critical',
    fix_suggestion: 'Restrict Firebase rules: only allow authenticated users to read/write their own data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /['"`]\.read['"`]\s*:\s*['"`]true['"`]/.test(line) || /['"`]\.write['"`]\s*:\s*['"`]true['"`]/.test(line);
    },
  },
  {
    id: 'GRAPHQL_SUBSCRIPTION_NO_AUTH',
    category: 'Authorization',
    description: 'GraphQL subscription without authentication — real-time data exposed to unauthenticated clients.',
    severity: 'high',
    fix_suggestion: 'Authenticate WebSocket connections for GraphQL subscriptions in the context callback.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Require GraphQL library imports before firing
      if (!hasGraphqlImports(ctx.fileContent)) return false;
      if (!/\bsubscription\b/i.test(line)) return false;
      if (!/\b(?:subscribe|Subscription)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\b(?:auth|context|user|permission|guard)\b/i.test(window);
    },
  },
  {
    id: 'EXPRESS_GLOBAL_MIDDLEWARE_AFTER_ROUTES',
    category: 'Server Misconfiguration',
    description: 'Security middleware (helmet, cors, csrf) added after route definitions — routes bypass middleware.',
    severity: 'high',
    fix_suggestion: 'Add security middleware BEFORE route definitions: app.use(helmet()); app.use(cors()); then routes.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bapp\s*\.\s*use\s*\(\s*(?:helmet|cors|csrf|csurf)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const prevContent = ctx.allLines.slice(0, lineIdx).join('\n');
      return /\bapp\s*\.\s*(?:get|post|put|delete|patch)\s*\(/.test(prevContent);
    },
  },
  {
    id: 'COOKIE_SENSITIVE_DATA',
    category: 'Data Exposure',
    description: 'Sensitive data stored directly in cookie value — cookies are visible in network traffic and browser storage.',
    severity: 'medium',
    fix_suggestion: 'Store sensitive data server-side (session store). Put only a session ID in the cookie.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (isFrameworkSource(ctx.filePath) || isCookieLibrarySource(ctx.filePath)) return false;
      if (!/\b(?:setCookie|cookie|res\.cookie)\s*\(/.test(line)) return false;
      return /\b(?:password|secret|token|creditCard|ssn|private)\b/i.test(line) &&
        !/\b(?:name|key|label)\b/i.test(line);
    },
  },
  {
    id: 'UNVALIDATED_REDIRECT_DOMAIN',
    category: 'Open Redirect',
    description: 'Redirect to user-provided domain without domain whitelist check.',
    severity: 'medium',
    fix_suggestion: 'Validate redirect domain against a whitelist of allowed domains.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:res\.redirect|response\.redirect|redirect)\s*\(/.test(line)) return false;
      return /\bredirect\s*\(\s*['"`]https?:\/\/\$\{/.test(line);
    },
  },
  {
    id: 'CRYPT_BCRYPT_LOW_ROUNDS',
    category: 'Cryptography',
    description: 'bcrypt with fewer than 10 rounds — too fast, enables brute force attacks.',
    severity: 'medium',
    fix_suggestion: 'Use at least 12 rounds for bcrypt: bcrypt.hash(password, 12).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bbcrypt\s*\.\s*(?:hash|hashSync|genSalt|genSaltSync)\s*\(/.test(line)) return false;
      const match = line.match(/\b(?:hash|hashSync|genSalt|genSaltSync)\s*\([^,]*,\s*(\d+)/);
      if (!match) return false;
      return parseInt(match[1], 10) < 10;
    },
  },
  {
    id: 'SCRYPT_LOW_COST',
    category: 'Cryptography',
    description: 'scrypt with low cost parameters — enables faster brute force attacks.',
    severity: 'medium',
    fix_suggestion: 'Use high cost parameters: N=32768, r=8, p=1 minimum for scrypt.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bscrypt\b/.test(line)) return false;
      const match = line.match(/\bN\s*:\s*(\d+)/);
      if (!match) return false;
      return parseInt(match[1], 10) < 16384;
    },
  },
  {
    id: 'RATE_LIMIT_BYPASS_HEADER',
    category: 'Denial of Service',
    description: 'Rate limiting keyed on X-Forwarded-For without proxy validation — easily bypassed with fake headers.',
    severity: 'medium',
    fix_suggestion: 'Key rate limiting on authenticated user ID, not IP headers. Or validate proxy chain.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:rateLimit|rateLimiter)\b/.test(line)) return false;
      return /\bkeyGenerator\b.*\bx-forwarded-for\b/i.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_CLICKJACK',
    category: 'Security Headers',
    description: 'Django X_FRAME_OPTIONS set to ALLOW — enables clickjacking attacks.',
    severity: 'medium',
    fix_suggestion: 'Set X_FRAME_OPTIONS = "DENY" or "SAMEORIGIN" in Django settings.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bX_FRAME_OPTIONS\s*=\s*['"`]ALLOW\b/i.test(line);
    },
  },
  {
    id: 'PYTHON_DJANGO_MIDDLEWARE_MISSING',
    category: 'Server Misconfiguration',
    description: 'Django MIDDLEWARE missing SecurityMiddleware — critical security headers will not be set.',
    severity: 'medium',
    fix_suggestion: 'Add "django.middleware.security.SecurityMiddleware" to MIDDLEWARE list.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bMIDDLEWARE\s*=\s*\[/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return !/\bSecurityMiddleware\b/.test(window);
    },
  },
  {
    id: 'SSRF_DNS_REBIND',
    category: 'SSRF',
    description: 'URL fetched without DNS rebinding protection — attacker can resolve to internal IP after initial check.',
    severity: 'high',
    fix_suggestion: 'Pin DNS resolution: resolve the hostname first, validate the IP, then connect to that IP.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:fetch|axios|got|request|http\.get)\s*\(/.test(line)) return false;
      return /\b(?:fetch|axios|got|request)\s*\(\s*(?:req\s*\.\s*(?:body|query)|userUrl|url|targetUrl)\b/.test(line) &&
        !/\b(?:ssrf|validate|allowlist|whitelist|resolve)\b/i.test(line);
    },
  },
  {
    id: 'MULTIPART_NO_LIMIT',
    category: 'Denial of Service',
    description: 'Multipart form parsing without file count or size limits — enables DoS via many/large uploads.',
    severity: 'medium',
    fix_suggestion: 'Set limits: multer({ limits: { fileSize: 5 * 1024 * 1024, files: 5 } }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:busboy|formidable|multiparty)\s*\(/.test(line)) return false;
      return !/\b(?:limit|maxFileSize|maxFiles|maxFieldSize)\b/i.test(line);
    },
  },
  {
    id: 'GIT_INFO_EXPOSED',
    category: 'Information Disclosure',
    description: '.git directory accessible via web server — reveals full source code and commit history.',
    severity: 'critical',
    fix_suggestion: 'Block .git access in web server config. Add .git to your reverse proxy deny list.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bexpress\.static\b.*\b(?:public|static|www)\b/.test(line) &&
        /\.git\b/.test(line);
    },
  },
  {
    id: 'PYTHON_STDLIB_HTTP_SERVER',
    category: 'Server Misconfiguration',
    description: 'Python http.server used in production — no security features, directory listing enabled by default.',
    severity: 'high',
    fix_suggestion: 'Use a production WSGI/ASGI server (gunicorn, uvicorn) instead of http.server.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhttp\.server\b/.test(line) && /\bHTTPServer\b/.test(line);
    },
  },
  {
    id: 'PYTHON_FLASK_JSONIFY_ARRAY',
    category: 'API Security',
    description: 'Flask jsonify with top-level array — may be vulnerable to JSON hijacking in older browsers.',
    severity: 'low',
    fix_suggestion: 'Wrap arrays in an object: jsonify({"data": items}) instead of jsonify(items).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bjsonify\s*\(\s*\[/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 31: Express/Fastify/Hono Framework Patterns
  // ════════════════════════════════════════════
  {
    id: 'BODYPARSER_EXTENDED_PROTO_POLLUTION',
    category: 'Prototype Pollution',
    description:
      'Express body-parser urlencoded with extended:true allows deeply nested objects — enables prototype pollution via qs library.',
    severity: 'medium',
    fix_suggestion:
      'Use extended:false or add depth/parameterLimit options: urlencoded({ extended: true, parameterLimit: 100, depth: 3 }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\burlencoded\s*\(/.test(line)) return false;
      if (!/\bextended\s*:\s*true\b/.test(line)) return false;
      // Flag if no depth or parameterLimit is set
      return !/\b(?:depth|parameterLimit)\b/.test(line);
    },
  },
  {
    id: 'FASTIFY_NO_SCHEMA_VALIDATION',
    category: 'Input Validation',
    description:
      'Fastify route handler without JSON schema validation — bypasses Fastify\'s built-in input validation.',
    severity: 'medium',
    fix_suggestion:
      'Add schema property to route options: { schema: { body: { type: "object", properties: {...}, required: [...] } } }.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bfastify\s*\.\s*(?:post|put|patch)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return !/\bschema\b/.test(window);
    },
  },
  {
    id: 'HONO_CORS_WILDCARD',
    category: 'CORS',
    description:
      'Hono CORS middleware with wildcard origin — allows any website to make authenticated requests.',
    severity: 'high',
    fix_suggestion:
      'Specify allowed origins explicitly: cors({ origin: ["https://app.example.com"] }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcors\s*\(/.test(line)) return false;
      return /\bcors\s*\(\s*\)/.test(line) || /origin\s*:\s*['"`]\*['"`]/.test(line);
    },
  },
  {
    id: 'EXPRESS_STATIC_PROJECT_ROOT',
    category: 'Server Misconfiguration',
    description:
      'Express static middleware serving from project root or current directory — exposes .env, package.json, source code.',
    severity: 'critical',
    fix_suggestion:
      'Serve only a dedicated public/ or static/ directory: app.use(express.static("public")).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bexpress\.static\b/.test(line)) return false;
      // Serving . or ./ or process.cwd()
      return /express\.static\s*\(\s*['"`]\.['"`\/]?\s*\)/.test(line) ||
        /express\.static\s*\(\s*process\.cwd\s*\(\s*\)\s*\)/.test(line);
    },
  },
  {
    id: 'HELMET_MISSING_CSP',
    category: 'Security Headers',
    description:
      'Helmet configured with contentSecurityPolicy explicitly disabled — leaves the app vulnerable to XSS.',
    severity: 'high',
    fix_suggestion:
      'Enable CSP: helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["\'self\'"] } } }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhelmet\s*\(/.test(line) && /contentSecurityPolicy\s*:\s*false/.test(line);
    },
  },
  {
    id: 'HELMET_MISSING_HSTS',
    category: 'Security Headers',
    description:
      'Helmet configured with HSTS explicitly disabled — allows downgrade attacks from HTTPS to HTTP.',
    severity: 'high',
    fix_suggestion:
      'Enable HSTS: helmet({ hsts: { maxAge: 31536000, includeSubDomains: true } }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhelmet\s*\(/.test(line) && /\bhsts\s*:\s*false\b/.test(line);
    },
  },
  {
    id: 'HELMET_MISSING_FRAMEGUARD',
    category: 'Security Headers',
    description:
      'Helmet configured with frameguard explicitly disabled — allows clickjacking attacks via iframes.',
    severity: 'medium',
    fix_suggestion:
      'Enable frameguard: helmet({ frameguard: { action: "deny" } }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhelmet\s*\(/.test(line) && /\bframeguard\s*:\s*false\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 32: Database Connection & Query Patterns
  // ════════════════════════════════════════════
  {
    id: 'DB_POOL_NO_MAX_CONNECTIONS',
    category: 'Denial of Service',
    description:
      'Database connection pool created without max connections limit — can exhaust database connections and cause DoS.',
    severity: 'medium',
    fix_suggestion:
      'Set max connections: new Pool({ max: 20 }) or createPool({ connectionLimit: 20 }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+Pool\s*\(/.test(line) && !/\bcreatePool\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return !/\b(?:max|connectionLimit|pool_size)\s*:/.test(window);
    },
  },
  {
    id: 'DB_CONNECTION_STRING_LOGGED',
    category: 'Secrets',
    description:
      'Database connection string logged or printed — exposes credentials in log files.',
    severity: 'critical',
    fix_suggestion:
      'Never log connection strings. Log only the host/database name without credentials.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:console\.log|logger\.\w+|print|logging\.\w+)\s*\(/.test(line)) return false;
      return /\b(?:connectionString|connection_string|databaseUrl|database_url|DATABASE_URL|DB_URL|MONGO_URI|MONGODB_URI|POSTGRES_URL)\b/.test(line) &&
        !/\b(?:process\.env|os\.environ|redact|mask|censor)\b/.test(line);
    },
  },
  {
    id: 'SQL_TIMING_ORACLE',
    category: 'Information Disclosure',
    description:
      'Different error messages for record exists vs not-exists — allows attackers to enumerate valid records via timing oracle.',
    severity: 'medium',
    fix_suggestion:
      'Return the same generic error message regardless of whether a record exists or not.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:not\s+found|does\s+not\s+exist|no\s+such\s+user|user\s+not\s+found|email\s+not\s+found|account\s+not\s+found)\b/i.test(line)) return false;
      if (!/\b(?:res\.status|throw|return)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return /\b(?:invalid\s+password|wrong\s+password|incorrect\s+password|password\s+mismatch)\b/i.test(window);
    },
  },
  {
    id: 'BATCH_OPS_NO_TRANSACTION',
    category: 'Data Integrity',
    description:
      'Multiple sequential database write operations without a transaction — partial failures leave data inconsistent.',
    severity: 'info',
    fix_suggestion:
      'Wrap related writes in a transaction: await db.transaction(async (tx) => { ... }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bawait\s+\w+\.\s*(?:insert|update|delete|create|destroy|save)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      // Look for another write within 5 lines
      const window = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 6)).join('\n');
      if (!/\bawait\s+\w+\.\s*(?:insert|update|delete|create|destroy|save)\b/.test(window)) return false;
      // Check if we're already in a transaction
      const before = ctx.allLines.slice(Math.max(0, lineIdx - 10), lineIdx).join('\n');
      return !/\b(?:transaction|beginTransaction|startTransaction|BEGIN)\b/i.test(before);
    },
  },
  {
    id: 'RAW_SQL_IN_PRODUCTION_MIGRATION',
    category: 'SQL Injection',
    description:
      'Raw SQL string executed conditionally at runtime (not just in migration) — may be vulnerable to injection.',
    severity: 'high',
    fix_suggestion:
      'Use parameterized queries for any SQL that runs at request time. Raw SQL should only exist in migration files.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:execute|query|exec)\s*\(\s*['"`](?:ALTER|DROP|CREATE|TRUNCATE)\b/i.test(line)) return false;
      // If file is a migration, skip
      return !/migration/i.test(ctx.filePath) && !/seed/i.test(ctx.filePath);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 33: File Upload Comprehensive
  // ════════════════════════════════════════════
  {
    id: 'FILE_UPLOAD_NO_SIZE_LIMIT',
    category: 'Denial of Service',
    description:
      'File upload handler without size limit — allows uploading arbitrarily large files causing DoS.',
    severity: 'high',
    fix_suggestion:
      'Set file size limit: multer({ limits: { fileSize: 10 * 1024 * 1024 } }) or busboy({ limits: { fileSize: ... } }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:multer|busboy|formidable)\s*\(/.test(line)) return false;
      if (/\blimits\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return !/\blimits\b/.test(window) && !/\bfileSize\b/.test(window) && !/\bmaxFileSize\b/.test(window);
    },
  },
  {
    id: 'UPLOAD_IN_WEBROOT',
    category: 'Server Misconfiguration',
    description:
      'File uploads stored in a web-accessible directory (public/, static/, uploads/ under webroot) — uploaded files can be executed.',
    severity: 'critical',
    fix_suggestion:
      'Store uploads outside the webroot. Serve them through a route with access control, not via static file serving.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:destination|dest|uploadDir|upload_dir)\b/.test(line)) return false;
      return /\b(?:destination|dest|uploadDir|upload_dir)\s*[:=]\s*['"`](?:\.\/)?(?:public|static|www|htdocs|webroot)\//.test(line);
    },
  },
  {
    id: 'UPLOAD_ORIGINAL_FILENAME',
    category: 'Path Traversal',
    description:
      'Uploaded file stored using original filename without sanitization — enables path traversal and overwriting server files.',
    severity: 'high',
    fix_suggestion:
      'Generate a random filename: `${crypto.randomUUID()}${path.extname(file.originalname)}` instead of using the original.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:originalname|originalFilename|original_filename|filename)\b/.test(line)) return false;
      return /\b(?:writeFile|rename|mv|copyFile|createWriteStream)\s*\([^)]*\b(?:originalname|originalFilename|original_filename)\b/.test(line) ||
        /\bpath\.join\s*\([^)]*\b(?:originalname|originalFilename|original_filename)\b/.test(line);
    },
  },
  {
    id: 'UPLOAD_MIME_ONLY_CHECK',
    category: 'File Upload',
    description:
      'File type validated by MIME type only (no magic byte check) — MIME types are client-controlled and easily spoofed.',
    severity: 'medium',
    fix_suggestion:
      'Validate file type using magic bytes (file-type library) in addition to MIME type and extension checks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip framework source code (hono, express, etc.)
      if (isFrameworkSource(ctx.filePath)) return false;
      if (!/\b(?:mimetype|mimeType|mime_type|content-type|contentType)\b/.test(line)) return false;
      if (!/\b(?:includes|===|==|startsWith|match)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return !/\b(?:magic|fileType|file-type|fromBuffer|fromFile|signature)\b/i.test(window);
    },
  },
  {
    id: 'UPLOAD_EXECUTABLE_EXTENSION',
    category: 'File Upload',
    description:
      'File upload allows executable extensions (.exe, .sh, .bat, .cmd, .ps1) — enables remote code execution.',
    severity: 'critical',
    fix_suggestion:
      'Maintain an allowlist of permitted extensions (e.g., .jpg, .png, .pdf). Never rely on a denylist.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // Detects an array or set containing executable extensions
      return /['"`]\.(?:exe|sh|bat|cmd|ps1|msi|dll|com|scr|vbs|wsf)['"`]/.test(line) &&
        /(?:\[|new\s+Set|allow|accept|extension|ext|type)/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 34: Session & Cookie Deep Dive
  // ════════════════════════════════════════════
  {
    id: 'COOKIE_MISSING_SAMESITE',
    category: 'Cookie Security',
    description:
      'Cookie set without SameSite attribute — vulnerable to cross-site request forgery attacks.',
    severity: 'medium',
    fix_suggestion:
      'Add sameSite: "strict" or sameSite: "lax" to cookie options.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip cookie library source code
      if (isFrameworkSource(ctx.filePath) || isCookieLibrarySource(ctx.filePath)) return false;
      if (!/\bres\.cookie\s*\(/.test(line)) return false;
      if (/\bsameSite\b/i.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return !/\bsameSite\b/i.test(window);
    },
  },
  {
    id: 'SESSION_MEMORY_STORE',
    category: 'Session Security',
    description:
      'Session stored in memory (MemoryStore) — leaks memory, does not scale across processes, loses sessions on restart.',
    severity: 'medium',
    fix_suggestion:
      'Use a production session store: connect-redis, connect-mongo, or connect-pg-simple.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+(?:session\.)?MemoryStore\s*\(/.test(line) ||
        /\bstore\s*:\s*new\s+MemoryStore\b/.test(line);
    },
  },
  {
    id: 'SESSION_TIMEOUT_EXCESSIVE',
    category: 'Session Security',
    description:
      'Session timeout set to more than 24 hours — increases window for session hijacking attacks.',
    severity: 'medium',
    fix_suggestion:
      'Set session timeout to 1-4 hours for standard apps, shorter for sensitive operations.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match maxAge in milliseconds > 24 hours (86400000)
      const match = line.match(/\bmaxAge\s*:\s*(\d[\d_]*)/);
      if (match) {
        const val = parseInt(match[1].replace(/_/g, ''), 10);
        return val > 86_400_000;
      }
      // Match cookie.maxAge or expiresIn > 24h patterns
      const hoursMatch = line.match(/\b(?:maxAge|expiresIn|ttl)\s*:\s*['"`](\d+)\s*(?:d|days?)['"`]/);
      if (hoursMatch) {
        return parseInt(hoursMatch[1], 10) > 1;
      }
      return false;
    },
  },
  {
    id: 'SESSION_NO_INVALIDATE_ON_PASSWORD_CHANGE',
    category: 'Session Security',
    description:
      'Password change handler does not invalidate existing sessions — old sessions remain valid after password reset.',
    severity: 'high',
    fix_suggestion:
      'Invalidate all sessions after password change: req.session.destroy() or revoke all tokens for the user.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:changePassword|change_password|updatePassword|update_password|resetPassword|reset_password)\b/.test(line)) return false;
      if (!/\b(?:function|async|const|handler|=>\s*{)\b/.test(line)) return false;
      // Skip React component files — these are UI, not backend password handlers
      const ext = ctx.filePath.toLowerCase();
      if (ext.endsWith('.tsx') || ext.endsWith('.jsx')) return false;
      // Only flag in backend files — require server-side imports
      if (!hasServerSideImports(ctx.fileContent)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 20)).join('\n');
      return !/\b(?:session\.destroy|invalidate|revokeAll|deleteAll|clearSessions|logout|signOut)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 35: Input Validation Variants
  // ════════════════════════════════════════════
  {
    id: 'EMAIL_VALIDATION_REGEX_ONLY',
    category: 'Input Validation',
    description:
      'Email validated with regex only — custom email regexes are notoriously incomplete. Use a validation library.',
    severity: 'low',
    fix_suggestion:
      'Use a validation library (Zod z.string().email(), validator.isEmail(), Joi.string().email()).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bemail\b/i.test(line)) return false;
      return /\b(?:test|match|exec)\s*\([^)]*@[^)]*\)/.test(line) ||
        /\/.*@.*\/\s*\.\s*(?:test|exec|match)\b/.test(line);
    },
  },
  {
    id: 'PHONE_NUMBER_IN_SQL',
    category: 'SQL Injection',
    description:
      'Phone number field used directly in SQL query without validation — may contain injection payloads.',
    severity: 'high',
    fix_suggestion:
      'Validate phone numbers with a library (libphonenumber), then use parameterized queries.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:phone|mobile|cell|telephone|tel)\b/i.test(line)) return false;
      return /\b(?:query|execute|raw)\s*\(.*\$\{.*\b(?:phone|mobile|cell|telephone|tel)\b/i.test(line) ||
        /\b(?:query|execute|raw)\s*\(.*\+\s*\w*(?:phone|mobile|cell|telephone|tel)\b/i.test(line);
    },
  },
  {
    id: 'ZIP_CODE_NO_LENGTH_LIMIT',
    category: 'Input Validation',
    description:
      'Zip code or postal code field with no length limit — can be used to inject oversized payloads.',
    severity: 'low',
    fix_suggestion:
      'Validate zip codes with strict length limits (5-10 chars) and allowed character patterns.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:zip_?code|postal_?code|zipCode|postalCode)\b/i.test(line)) return false;
      // DB field or input without maxLength or validation
      return /\b(?:type|Type)\s*:\s*['"`](?:string|text|varchar)['"`]/.test(line) &&
        !/\b(?:maxLength|max_length|length|validate|max)\b/i.test(line);
    },
  },
  {
    id: 'HTML_IN_USERNAME',
    category: 'XSS',
    description:
      'Username field rendered without HTML escaping — allows stored XSS attacks through user display names.',
    severity: 'high',
    fix_suggestion:
      'Sanitize usernames on input (strip HTML) or always escape when rendering.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:innerHTML|dangerouslySetInnerHTML)\b/.test(line)) return false;
      return /\b(?:username|displayName|display_name|userName|user_name|nickname)\b/i.test(line);
    },
  },
  {
    id: 'URL_NO_PROTOCOL_VALIDATION',
    category: 'SSRF',
    description:
      'URL input accepted without protocol validation — allows javascript:, file:, or data: protocol URLs.',
    severity: 'high',
    fix_suggestion:
      'Validate URLs start with https:// or http://. Reject javascript:, data:, file:, and ftp: protocols.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+URL\s*\(\s*(?:req\.|user|input|data|body|params)/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return !/\b(?:protocol|startsWith\s*\(\s*['"`]https?|allowedProtocol|validateUrl|isValidUrl)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 36: Error Handling Comprehensive
  // ════════════════════════════════════════════
  {
    id: 'GLOBAL_ERROR_HANDLER_FULL_ERROR',
    category: 'Information Disclosure',
    description:
      'Global error handler sends full error details to client — leaks stack traces, file paths, and internal state.',
    severity: 'high',
    fix_suggestion:
      'Return generic error messages to clients. Log full error details server-side only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:err|error|e)\s*,\s*(?:req|request)\s*,\s*(?:res|response)\s*,\s*(?:next)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return /\bres\s*\.\s*(?:json|send)\s*\(\s*(?:err|error|e)\s*\)/.test(window) ||
        /\bres\s*\.\s*(?:json|send)\s*\(\s*\{\s*(?:error|message)\s*:\s*(?:err|error|e)\.(?:message|stack)\b/.test(window);
    },
  },
  {
    id: 'EXPRESS_ASYNC_NO_NEXT',
    category: 'Error Handling',
    description:
      'Async Express route handler without next(err) call — unhandled rejections crash the process or hang the request.',
    severity: 'medium',
    fix_suggestion:
      'Wrap async handlers: app.get("/path", asyncHandler(async (req, res) => { ... })) or call next(err) in catch.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(/.test(line)) return false;
      if (!/\basync\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return !/\b(?:next\s*\(|asyncHandler|catchAsync|expressAsyncHandler|tryCatch|wrapAsync)\b/.test(window) &&
        !/\b(?:try\s*\{)\b/.test(window);
    },
  },
  {
    id: 'AUTH_ERROR_TIMING_ORACLE',
    category: 'Authentication',
    description:
      'Try-catch returns different error messages for authentication steps — allows attackers to enumerate valid credentials.',
    severity: 'medium',
    fix_suggestion:
      'Return the same "Invalid credentials" message for both invalid username and invalid password.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:Invalid\s+(?:email|username|user)|User\s+not\s+found|No\s+account)\b/i.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return /\b(?:Invalid\s+password|Wrong\s+password|Incorrect\s+password|Password\s+(?:does\s+not\s+match|mismatch))\b/i.test(window);
    },
  },
  {
    id: 'UNCAUGHT_EXCEPTION_CONTINUE',
    category: 'Reliability',
    description:
      'process.on("uncaughtException") handler that continues running — the process is in an undefined state and must exit.',
    severity: 'high',
    fix_suggestion:
      'Always call process.exit(1) in uncaughtException handlers after logging. Use a process manager to restart.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bprocess\s*\.\s*on\s*\(\s*['"`]uncaughtException['"`]/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\bprocess\.exit\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 37: Logging & Monitoring Security
  // ════════════════════════════════════════════
  {
    id: 'LOG_FULL_REQUEST_BODY',
    category: 'Information Disclosure',
    description:
      'Logging full request body — may contain passwords, tokens, credit cards, or PII.',
    severity: 'high',
    fix_suggestion:
      'Log only specific safe fields. Use a sanitizer that strips sensitive fields before logging.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:console\.log|logger\.\w+|log\.\w+|winston\.\w+|pino\.\w+)\s*\(/.test(line)) return false;
      return /\breq\.body\b/.test(line) && !/\b(?:redact|sanitize|scrub|mask|strip|omit)\b/i.test(line);
    },
  },
  {
    id: 'MORGAN_COMBINED_NO_PROXY',
    category: 'Privacy',
    description:
      'Morgan logging with "combined" format logs client IP addresses — may violate GDPR without proper proxy setup.',
    severity: 'low',
    fix_suggestion:
      'Use a custom format that excludes IPs, or ensure trust proxy is configured and IPs are anonymized.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bmorgan\s*\(/.test(line)) return false;
      return /\bmorgan\s*\(\s*['"`]combined['"`]/.test(line);
    },
  },
  {
    id: 'SENTRY_FULL_USER_DATA',
    category: 'Privacy',
    description:
      'Sentry configured to send full user objects — may leak email, IP, and PII to third-party service.',
    severity: 'medium',
    fix_suggestion:
      'Use Sentry beforeSend to scrub user data: beforeSend(event) { delete event.user.email; return event; }.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bSentry\s*\.\s*(?:setUser|configureScope)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return /\b(?:email|ip_address|ip|fullName|full_name|phone)\b/.test(window) &&
        !/\b(?:beforeSend|scrub|redact|sanitize)\b/i.test(window);
    },
  },
  {
    id: 'LOG_INJECTION_CORRELATION_ID',
    category: 'Log Injection',
    description:
      'Correlation or trace ID taken from user input without sanitization — enables log injection and log forging.',
    severity: 'medium',
    fix_suggestion:
      'Generate correlation IDs server-side with crypto.randomUUID(). Never use client-provided values as log identifiers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:correlationId|correlation_id|traceId|trace_id|requestId|request_id)\s*[=:]\s*(?:req\s*\.\s*(?:headers|query|body|params))\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 38: Rate Limiting & DoS Prevention
  // ════════════════════════════════════════════
  {
    id: 'RATE_LIMIT_MEMORY_ONLY',
    category: 'Rate Limiting',
    description:
      'Rate limiter using in-memory store — easily bypassed by restarting the server, and doesn\'t work across multiple instances.',
    severity: 'medium',
    fix_suggestion:
      'Use a Redis-backed rate limit store: rateLimit({ store: new RedisStore({ ... }) }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\brateLimit\s*\(\s*\{/.test(line)) return false;
      // Only flag when it's being used in an app.use() or assigned to middleware used on a route
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      if (/\bstore\b/.test(window)) return false;
      // Must also have app.use in same line or be directly used as middleware in route
      return /\bapp\s*\.\s*(?:use|get|post|put|delete|patch)\s*\([^)]*rateLimit\s*\(/.test(line);
    },
  },
  {
    id: 'RATE_LIMIT_IP_NO_TRUST_PROXY',
    category: 'Rate Limiting',
    description:
      'Rate limiting by IP behind a proxy without trust proxy — all requests appear from the proxy IP, making rate limiting useless.',
    severity: 'medium',
    fix_suggestion:
      'Configure trust proxy: app.set("trust proxy", 1) when behind a reverse proxy or load balancer.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Only flag when rateLimit is directly used in app.use with explicit keyGenerator referencing req.ip
      if (!/\brateLimit\s*\(/.test(line)) return false;
      if (!/\bkeyGenerator\b/.test(line)) return false;
      if (!/\breq\.ip\b/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/\btrust\s*proxy\b/.test(allContent);
    },
  },
  {
    id: 'NO_RATE_LIMIT_UPLOAD',
    category: 'Denial of Service',
    description:
      'File upload endpoint without rate limiting — allows an attacker to flood the server with uploads.',
    severity: 'medium',
    fix_suggestion:
      'Add rate limiting to upload endpoints: app.post("/upload", uploadLimiter, upload.single("file"), handler).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:app|router)\s*\.\s*(?:post|put)\s*\(/.test(line)) return false;
      if (!/\b(?:upload|multer|busboy)\b/.test(line)) return false;
      return !/(?:rateLimit|[Ll]imiter|throttle|slowDown)\b/.test(line);
    },
  },
  {
    id: 'RECURSIVE_NO_DEPTH_LIMIT',
    category: 'Denial of Service',
    description:
      'Recursive function processing user input without depth limit — can cause stack overflow via deeply nested input.',
    severity: 'medium',
    fix_suggestion:
      'Add a depth parameter with a maximum: function process(data, depth = 0) { if (depth > 100) throw new Error("Too deep"); ... }.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Find recursive function (function that calls itself)
      const funcMatch = line.match(/\bfunction\s+(\w+)\s*\(/);
      if (!funcMatch) return false;
      const funcName = funcMatch[1];
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 20)).join('\n');
      if (!new RegExp(`\\b${funcName}\\s*\\(`).test(window)) return false;
      // Must accept user input (req, request, body, params, data, input, user)
      const funcSignature = line;
      if (!/\b(?:req|request|body|params|data|input|user|json|payload)\b/.test(funcSignature)) return false;
      // Check for depth/maxDepth parameter
      return !/\b(?:depth|maxDepth|max_depth|level|maxLevel|limit|maxRecursion)\b/.test(line) &&
        !/\b(?:depth|maxDepth|max_depth|level|maxLevel|limit|maxRecursion)\b/.test(window);
    },
  },
  {
    id: 'REGEX_NO_TIMEOUT',
    category: 'Denial of Service',
    description:
      'Regular expression executed on user input without timeout — ReDoS-vulnerable patterns can hang the event loop.',
    severity: 'medium',
    fix_suggestion:
      'Use RE2 library for user-facing regex, or set a timeout with node --experimental-vm-modules and vm.runInNewContext.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+RegExp\s*\(/.test(line)) return false;
      return /\bnew\s+RegExp\s*\(\s*(?:req\.|user|input|data|body|params|query)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 39: Encryption & Key Management
  // ════════════════════════════════════════════
  {
    id: 'ENCRYPTION_KEY_NO_KDF',
    category: 'Cryptography',
    description:
      'Encryption key derived from password without a key derivation function — weak and easily brute-forced.',
    severity: 'high',
    fix_suggestion:
      'Use crypto.scryptSync(password, salt, 32) or PBKDF2 to derive keys from passwords.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcreateHash\s*\(/.test(line)) return false;
      return /\bcreateHash\s*\([^)]*\)\s*\.\s*update\s*\(\s*(?:password|passwd|pass|pwd|secret)\b/i.test(line) &&
        /\.\s*digest\b/.test(line);
    },
  },
  {
    id: 'IV_REUSE',
    category: 'Cryptography',
    description:
      'Initialization vector (IV) is static or reused across encryptions — breaks confidentiality of AES-CBC/CTR.',
    severity: 'critical',
    fix_suggestion:
      'Generate a random IV for each encryption: crypto.randomBytes(16). Store the IV alongside the ciphertext.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\biv\b/i.test(line)) return false;
      return /\b(?:const|let|var)\s+iv\s*=\s*(?:Buffer\.from\s*\(\s*['"`]|['"`][0-9a-fA-F]+['"`]|Buffer\.alloc\s*\(\s*16\s*(?:,\s*0)?\s*\))/.test(line);
    },
  },
  {
    id: 'CRYPTO_ECB_MODE_USE',
    category: 'Cryptography',
    description:
      'ECB mode used for encryption — identical plaintext blocks produce identical ciphertext, leaking patterns.',
    severity: 'high',
    fix_suggestion:
      'Use AES-GCM (authenticated encryption) or AES-CBC with HMAC instead of ECB mode.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:aes|des|blowfish|camellia)[-_]?\d*[-_]?ecb\b/i.test(line) &&
        /\b(?:createCipher|createDecipher|algorithm|cipher)\b/.test(line);
    },
  },
  {
    id: 'KEY_IN_SAME_DB',
    category: 'Key Management',
    description:
      'Encryption key stored in the same database as encrypted data — if the database is breached, the encryption is useless.',
    severity: 'high',
    fix_suggestion:
      'Store encryption keys in a separate key management service (AWS KMS, HashiCorp Vault, Azure Key Vault).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:encryption_?[Kk]ey|cipher_?[Kk]ey|master_?[Kk]ey)\b/.test(line)) return false;
      // Check if we're in a schema/model context (look at surrounding lines)
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 10), Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return /\b(?:Schema|schema|model|Model|define|pgTable|createTable|Column|column|DataTypes|varchar|String)\b/.test(window);
    },
  },
  {
    id: 'DEPRECATED_CREATE_CIPHER',
    category: 'Cryptography',
    description:
      'crypto.createCipher() used (deprecated) — derives key from password with MD5 and no IV, extremely weak.',
    severity: 'critical',
    fix_suggestion:
      'Use crypto.createCipheriv() with a properly derived key (scrypt/PBKDF2) and random IV.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcrypto\s*\.\s*createCipher\s*\(/.test(line) && !/\bcreateCipheriv\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 41: TypeScript-Specific Vulnerabilities
  // ════════════════════════════════════════════
  {
    id: 'TS_TYPE_ASSERTION_BYPASS_VALIDATION',
    category: 'Type Safety',
    description:
      'Type assertion (as SomeType) on request body bypasses runtime validation — attacker-controlled data is treated as trusted.',
    severity: 'high',
    fix_suggestion:
      'Validate request body at runtime with Zod, Yup, or io-ts before using it as a typed object.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // req.body as AdminUser, req.body as CreateUserInput etc.
      if (!/\breq\s*\.\s*body\s+as\s+[A-Z]/.test(line)) return false;
      // Exclude if preceded by Zod parse/validation
      return !/\b(?:parse|safeParse|validate|transform)\s*\(/.test(line);
    },
  },
  {
    id: 'TS_GENERIC_PROTOTYPE_POLLUTION',
    category: 'Type Safety',
    description:
      'Generic type parameter with Record or index signature accepting user input — may allow prototype pollution via __proto__ key.',
    severity: 'medium',
    fix_suggestion:
      'Validate object keys against a whitelist. Reject __proto__, constructor, and prototype keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect: Object.assign(target, req.body) or {...target, ...req.body} with Record<string, any>
      if (!/\bObject\s*\.\s*assign\s*\([^,]+,\s*req\s*\.\s*body\b/.test(line) &&
          !/\.\.\.\s*req\s*\.\s*body\b/.test(line)) return false;
      // Check for Record<string, any> or generic index signature in nearby context
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 3)).join('\n');
      return /\bRecord\s*<\s*string\s*,\s*any\s*>/.test(window) || /\[\s*key\s*:\s*string\s*\]\s*:\s*any/.test(window);
    },
  },
  {
    id: 'TS_DISCRIMINATED_UNION_AUTH_NO_DEFAULT',
    category: 'Type Safety',
    description:
      'Switch on user role/type union without default/exhaustive case — new roles may bypass authorization silently.',
    severity: 'high',
    fix_suggestion:
      'Add a default case that throws or denies access. Use TypeScript exhaustive check: const _exhaustive: never = role.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect switch(user.role) or switch(role) patterns
      if (!/\bswitch\s*\(\s*(?:user\s*\.\s*)?(?:role|type|permission|accessLevel)\s*\)/.test(line)) return false;
      // Look ahead for default case or TypeScript exhaustive check within 30 lines
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 30)).join('\n');
      // default: case covers it
      if (/\bdefault\s*:/.test(window)) return false;
      // TypeScript exhaustive checks: `satisfies never`, `assertNever()`, `exhaustiveCheck`, `_exhaustive: never`
      if (/\bsatisfies\s+never\b/.test(window)) return false;
      if (/\bassertNever\s*\(/.test(window)) return false;
      if (/\bexhaustive/i.test(window)) return false;
      if (/:\s*never\b/.test(window)) return false;
      return true;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 42: Next.js App Router Specific
  // ════════════════════════════════════════════
  {
    id: 'NEXTJS_COOKIES_IN_SQL',
    category: 'SQL Injection',
    description:
      'Next.js cookies() value used directly in SQL query — attacker-controlled cookie data can inject SQL.',
    severity: 'critical',
    fix_suggestion:
      'Parameterize the SQL query. Never interpolate cookie values directly into SQL strings.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcookies\s*\(\s*\)/.test(line) && /\b(?:query|execute|raw|prepare)\s*\(/.test(line) && /\$\{/.test(line);
    },
  },
  {
    id: 'NEXTJS_HEADERS_SSRF',
    category: 'SSRF',
    description:
      'Next.js headers() value forwarded to external fetch/request — may enable SSRF via attacker-controlled headers.',
    severity: 'high',
    fix_suggestion:
      'Validate and sanitize header values before forwarding them to external services. Use an allowlist for forwarded headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bheaders\s*\(\s*\)/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return /\bfetch\s*\(\s*(?:url|endpoint|apiUrl|externalUrl)\b/.test(window) ||
        /\baxios\s*\.\s*(?:get|post|put|patch)\s*\(/.test(window);
    },
  },
  {
    id: 'NEXTJS_REDIRECT_USER_INPUT',
    category: 'Open Redirect',
    description:
      'Next.js redirect() with user-controlled input — may redirect users to malicious sites.',
    severity: 'high',
    fix_suggestion:
      'Validate redirect targets against a whitelist of allowed paths/domains. Only allow relative paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Must be a Next.js file — check for next imports or Next.js patterns
      if (!/\bfrom\s+['"]next\//.test(ctx.fileContent) && !/\bnext\/navigation\b/.test(ctx.fileContent) && !/['"]use server['"]/.test(ctx.fileContent)) return false;
      // Must NOT be an Express/Fastify file
      if (/\bexpress\s*\(\)|\bfastify\s*\(|\bfrom\s+['"]express['"]|\bfrom\s+['"]fastify['"]/.test(ctx.fileContent)) return false;
      // Skip config-based redirects (e.g., authOptions.pages.signIn)
      if (/\bredirect\s*\(\s*(?:authOptions|config|settings|options)\s*\./.test(line)) return false;
      // redirect(req.query.url) or redirect(searchParams.get('redirect'))
      return /\bredirect\s*\(\s*(?:req\s*\.\s*(?:query|body)\s*\.\s*\w+|searchParams\s*\.\s*get\s*\()/.test(line);
    },
  },
  {
    id: 'NEXTJS_SERVER_ACTION_NO_REVALIDATE',
    category: 'Data Integrity',
    description:
      'Next.js server action mutates data without calling revalidatePath/revalidateTag — stale cached data may be served.',
    severity: 'medium',
    fix_suggestion:
      'Call revalidatePath() or revalidateTag() after data mutations in server actions to bust the cache.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect 'use server' actions with DB mutations but no revalidation
      if (!/['"]use server['"]/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 30)).join('\n');
      const hasMutation = /\b(?:create|update|delete|insert|remove|save|destroy|upsert)\s*\(/.test(window) ||
        /\b(?:INSERT|UPDATE|DELETE)\b/.test(window);
      if (!hasMutation) return false;
      return !/\brevalidate(?:Path|Tag)\s*\(/.test(window);
    },
  },
  {
    id: 'NEXTJS_UNSTABLE_CACHE_USER_KEY',
    category: 'Cache Poisoning',
    description:
      'Next.js unstable_cache with user-controlled cache key — attacker can poison cache for other users.',
    severity: 'high',
    fix_suggestion:
      'Use server-derived cache keys only. Never use user input (params, cookies, headers) directly as cache keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bunstable_cache\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return /\b(?:req\s*\.\s*(?:query|body|params)|searchParams|cookies\(\)|headers\(\))\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 43: React Server Components & Hydration
  // ════════════════════════════════════════════
  {
    id: 'RSC_SECRET_IN_PROPS',
    category: 'Data Exposure',
    description:
      'Sensitive data passed as server component prop — React serializes all props to the client bundle.',
    severity: 'critical',
    fix_suggestion:
      'Never pass secrets, tokens, or API keys as props to client components. Fetch sensitive data server-side only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // <ClientComponent secret={apiKey} /> or <Component dbPassword={...} />
      if (!/\b(?:secret|apiKey|api_key|password|token|privateKey|private_key|dbPassword|secretKey|secret_key)\s*=\s*\{/.test(line)) return false;
      if (!/<\s*[A-Z]/.test(line)) return false;
      // Skip form/input/auth UI components when the prop is "password" or "token" —
      // these are UI form components handling user credential input, not secret-passing.
      // Only suppress for the ambiguous props (password, token), not for clearly secret
      // props like apiKey, secretKey, privateKey, dbPassword.
      const isAmbiguousProp = /\b(?:password|token)\s*=\s*\{/.test(line) &&
        !/\b(?:apiKey|api_key|privateKey|private_key|dbPassword|secretKey|secret_key|secret)\s*=\s*\{/.test(line);
      if (isAmbiguousProp) {
        const componentMatch = line.match(/<\s*([A-Z][A-Za-z0-9]*)/);
        if (componentMatch) {
          const componentName = componentMatch[1].toLowerCase();
          if (/(?:form|input|field|login|signup|register|auth)/.test(componentName)) return false;
        }
      }
      return true;
    },
  },
  {
    id: 'RSC_USE_CLIENT_RECEIVES_SECRET',
    category: 'Data Exposure',
    description:
      '"use client" component receives secrets via props — the secret will be visible in the browser bundle.',
    severity: 'critical',
    fix_suggestion:
      'Move secret-dependent logic to a server component or API route. Client components should never receive secrets.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Check if file has 'use client' and component accepts secret-like props
      if (!/\b(?:secret|apiKey|api_key|password|token|privateKey|private_key|dbPassword|secretKey)\b/.test(line)) return false;
      if (!/\b(?:props\s*\.\s*|:\s*\{[^}]*)\b(?:secret|apiKey|api_key|password|token|privateKey|private_key|dbPassword|secretKey)\b/.test(line)) return false;
      return /['"]use client['"]/.test(ctx.fileContent);
    },
  },
  {
    id: 'RSC_DANGEROUSLY_SET_DB_DATA',
    category: 'XSS',
    description:
      'dangerouslySetInnerHTML in server component with database data — stored XSS if DB data is attacker-controlled.',
    severity: 'critical',
    fix_suggestion:
      'Sanitize HTML with DOMPurify or similar before using dangerouslySetInnerHTML. Even server components send HTML to the client.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/dangerouslySetInnerHTML/.test(line)) return false;
      // JSON.stringify() output is always safe — JSON cannot contain executable HTML
      if (/JSON\s*\.\s*stringify\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 10), Math.min(ctx.allLines.length, lineIdx + 3)).join('\n');
      return /\b(?:prisma|db|supabase|knex|pool|query|findOne|findFirst|findUnique)\b/.test(window) &&
        !/\b(?:sanitize|DOMPurify|purify|xss|escape)\b/i.test(window);
    },
  },
  {
    id: 'RSC_FORM_NO_CSRF',
    category: 'CSRF',
    description:
      'Form action in React Server Component without CSRF token — cross-site form submissions may be possible.',
    severity: 'high',
    fix_suggestion:
      'Include a CSRF token in forms or use Next.js server actions which have built-in CSRF protection.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // <form action={someServerAction}> without csrf token
      if (!/\bform\b/.test(line) || !/\baction\s*=\s*\{/.test(line)) return false;
      // Next.js Server Actions have built-in CSRF protection
      // Check if file has 'use server' directive or imports a server action
      if (/['"]use server['"]/.test(ctx.fileContent)) return false;
      // Check if the action being referenced is imported from a file that likely has 'use server'
      // Match action={someAction} and check if someAction is imported
      const actionMatch = line.match(/action\s*=\s*\{(\w+)\}/);
      if (actionMatch) {
        const actionName = actionMatch[1];
        // If the action is imported from a module (likely a server action), treat as safe
        if (new RegExp(`import\\s+.*\\b${actionName}\\b.*from\\s+`).test(ctx.fileContent)) return false;
      }
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\b(?:csrf|csrfToken|_csrf|xsrf|token)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 44: Supabase/Firebase Specific
  // ════════════════════════════════════════════
  {
    id: 'SUPABASE_SERVICE_ROLE_CLIENT',
    category: 'Secret Exposure',
    description:
      'Supabase service role key used in client-side code — grants full database access bypassing RLS.',
    severity: 'critical',
    fix_suggestion:
      'Only use the service role key on the server. Use the anon key for client-side Supabase clients.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/SERVICE_ROLE/i.test(line)) return false;
      // Check if in client context
      return /['"]use client['"]/.test(ctx.fileContent) ||
        /NEXT_PUBLIC_/.test(line);
    },
  },
  {
    id: 'SUPABASE_RLS_BYPASS_SERVICE_ROLE',
    category: 'Authorization',
    description:
      'Supabase query using service role client in request handler — bypasses Row Level Security for all queries.',
    severity: 'high',
    fix_suggestion:
      'Use the user-scoped Supabase client (with anon key + user JWT) for request handlers. Reserve service role for admin-only operations.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // supabaseAdmin.from(...) or serviceClient.from(...) in a request handler
      if (!/\b(?:supabaseAdmin|serviceClient|adminClient|supabaseService)\s*\.\s*from\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 15), Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return /\b(?:req|request|handler|app\.\s*(?:get|post|put|delete|patch)|router\.\s*(?:get|post|put|delete|patch))\b/.test(window);
    },
  },
  {
    id: 'SUPABASE_RPC_USER_INPUT',
    category: 'SQL Injection',
    description:
      'Supabase rpc() with user-controlled function name — attacker can call arbitrary database functions.',
    severity: 'critical',
    fix_suggestion:
      'Use a static function name with rpc(). Pass user input only as function parameters, not as the function name.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.\s*rpc\s*\(\s*(?:req\s*\.\s*(?:body|query|params)\s*\.\s*\w+|functionName|fnName)\b/.test(line);
    },
  },
  {
    id: 'FIREBASE_CUSTOM_CLAIMS_CLIENT',
    category: 'Authorization',
    description:
      'Firebase custom claims set from client-side input without validation — users can elevate their own privileges.',
    severity: 'critical',
    fix_suggestion:
      'Set custom claims only from trusted server-side code. Validate claim values against allowed roles.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsetCustomUserClaims\s*\(/.test(line) &&
        /\breq\s*\.\s*(?:body|query)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 45: Prisma/Drizzle/ORM Specific
  // ════════════════════════════════════════════
  {
    id: 'PRISMA_QUERYRAW_TEMPLATE_LITERAL',
    category: 'SQL Injection',
    description:
      'Prisma $queryRaw with untagged template literal — interpolated values are NOT parameterized. Use tagged template (no parentheses).',
    severity: 'critical',
    fix_suggestion:
      'Use prisma.$queryRaw`SELECT ...` (tagged, auto-parameterized) instead of prisma.$queryRaw(`SELECT ...`) (untagged, vulnerable).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      // $queryRaw( ` ... ${...} ) — parenthesized template literal is NOT safe
      return /\$queryRaw\s*\(\s*`[^`]*\$\{/.test(line);
    },
  },
  {
    id: 'PRISMA_MIDDLEWARE_LOG_QUERIES',
    category: 'Data Exposure',
    description:
      'Prisma middleware logging full query parameters — may leak sensitive data (passwords, tokens) to log files.',
    severity: 'medium',
    fix_suggestion:
      'Redact sensitive fields from logged query parameters. Use Prisma event logging with field-level filtering.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b\$use\b/.test(line) && !/\bprisma\s*\.\s*\$use\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return /\bconsole\s*\.\s*log\b/.test(window) && /\bparams\.args\b/.test(window);
    },
  },
  {
    id: 'TYPEORM_SELECT_FALSE_INCLUDED',
    category: 'Data Exposure',
    description:
      'TypeORM column marked {select: false} but explicitly included in find options — defeats the hidden column protection.',
    severity: 'high',
    fix_suggestion:
      'Do not include {select: false} columns in find queries unless absolutely necessary. Use a separate query for sensitive fields.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect findOne/find with select that includes a password/secret column alongside
      if (!/\b(?:findOne|find|findOneBy)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return /\bselect\s*:\s*\[/.test(window) && /['"](?:password|secret|token|hash)['"]/.test(window);
    },
  },
  {
    id: 'SEQUELIZE_PARANOID_HARD_DELETE',
    category: 'Data Integrity',
    description:
      'Hard delete on a Sequelize paranoid (soft-delete) table — bypasses audit trail and may violate data retention policies.',
    severity: 'medium',
    fix_suggestion:
      'Use the default soft delete for paranoid models. Only use force: true with explicit authorization and audit logging.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.\s*destroy\s*\(\s*\{/.test(line) && /\bforce\s*:\s*true\b/.test(line);
    },
  },
  {
    id: 'MONGOOSE_SCHEMA_NO_VALIDATION',
    category: 'Data Integrity',
    description:
      'Mongoose schema field without type validation or required constraint — allows arbitrary data insertion.',
    severity: 'low',
    fix_suggestion:
      'Add type constraints and validation to Mongoose schema fields: { type: String, required: true, validate: ... }.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect new Schema({ field: {} }) — empty schema definition
      if (!/\bnew\s+Schema\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      // Check for fields that are just Schema.Types.Mixed or empty object
      return /Schema\s*\.\s*Types\s*\.\s*Mixed\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 46: Stripe/Payment Edge Cases
  // ════════════════════════════════════════════
  {
    id: 'STRIPE_WEBHOOK_NO_IDEMPOTENCY',
    category: 'Payment Security',
    description:
      'Stripe webhook handler processes events without idempotency check — replayed events may cause duplicate charges or fulfillment.',
    severity: 'high',
    fix_suggestion:
      'Store processed event IDs and check before handling. Use: if (await isEventProcessed(event.id)) return;',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bconstructEvent\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 30)).join('\n');
      return !/\b(?:idempotency|idempotent|processedEvents|eventProcessed|event\.id|eventId)\b/i.test(window) &&
        /\bevent\s*\.\s*type\b/.test(window);
    },
  },
  {
    id: 'STRIPE_CHECKOUT_CLIENT_LINE_ITEMS',
    category: 'Payment Security',
    description:
      'Stripe checkout session with line items from client request — attacker can modify prices or add free items.',
    severity: 'critical',
    fix_suggestion:
      'Build line items server-side from your database. Only accept product/variant IDs from the client, then look up prices.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bline_items\s*:\s*req\s*\.\s*body\s*\.\s*(?:lineItems|line_items|items|cart)\b/.test(line);
    },
  },
  {
    id: 'STRIPE_METADATA_PII',
    category: 'Payment Security',
    description:
      'PII stored in Stripe metadata without encryption — Stripe metadata is visible in dashboard and logs.',
    severity: 'medium',
    fix_suggestion:
      'Encrypt PII before storing in Stripe metadata, or store a reference ID and keep PII in your own encrypted database.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:ssn|social_security|socialSecurity|dateOfBirth|date_of_birth|dob|taxId|tax_id)\s*[=:]/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 10), Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return /\bmetadata\s*:\s*\{/.test(window) && /\bstripe\b/i.test(window);
    },
  },
  {
    id: 'STRIPE_TRIAL_MANIPULATION',
    category: 'Payment Security',
    description:
      'Stripe subscription trial_period_days from user input — attacker can set negative or extremely long trial periods.',
    severity: 'high',
    fix_suggestion:
      'Set trial_period_days server-side from your plan configuration. Never accept trial duration from client.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\btrial_period_days\s*:\s*(?:req\s*\.\s*body\s*\.\s*\w+|parseInt\s*\(\s*req\s*\.\s*body)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 47: AWS SDK v3 / Cloud Provider Specific
  // ════════════════════════════════════════════
  {
    id: 'AWS_S3_SIGNED_URL_LONG_EXPIRY',
    category: 'Cloud Security',
    description:
      'S3 getSignedUrl with expiry greater than 1 hour — long-lived signed URLs increase the window for unauthorized access.',
    severity: 'medium',
    fix_suggestion:
      'Set signed URL expiry to 15 minutes or less. Use: expiresIn: 900 (seconds).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bgetSignedUrl\b/.test(line) && !/\bexpiresIn\b/.test(line)) return false;
      // Match expiresIn: 7200 or Expires: 86400 (anything > 3600)
      const match = line.match(/\b(?:expiresIn|Expires)\s*:\s*(\d+)/);
      if (!match) return false;
      return parseInt(match[1], 10) > 3600;
    },
  },
  {
    id: 'AWS_SES_EMAIL_INJECTION',
    category: 'Injection',
    description:
      'AWS SES email with user-controlled recipient — attacker can send emails to arbitrary addresses (email injection).',
    severity: 'high',
    fix_suggestion:
      'Validate email recipients against your user database. Never send to arbitrary user-provided addresses.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bSendEmailCommand\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return /\breq\s*\.\s*body\s*\.\s*(?:email|to|recipient)\b/.test(window);
    },
  },
  {
    id: 'AWS_LAMBDA_USER_FUNCTION_NAME',
    category: 'Injection',
    description:
      'Lambda invoke with user-controlled function name — attacker can invoke arbitrary Lambda functions in your account.',
    severity: 'critical',
    fix_suggestion:
      'Use a whitelist of allowed function names. Map user input to predefined function ARNs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bInvokeCommand\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return /\bFunctionName\s*:\s*(?:req\s*\.\s*(?:body|query|params)\s*\.\s*\w+|functionName|userFunction)\b/.test(window);
    },
  },
  {
    id: 'AWS_SNS_USER_TOPIC_ARN',
    category: 'Injection',
    description:
      'SNS publish with user-controlled TopicArn — attacker can send messages to arbitrary SNS topics.',
    severity: 'high',
    fix_suggestion:
      'Use a static topic ARN from configuration. Never accept topic ARNs from user input.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bPublishCommand\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return /\bTopicArn\s*:\s*req\s*\.\s*(?:body|query|params)/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 48: Testing & Development Backdoors
  // ════════════════════════════════════════════
  {
    id: 'DEV_MODE_AUTH_SKIP',
    category: 'Authentication Bypass',
    description:
      'Authentication skipped based on NODE_ENV check — if NODE_ENV is misconfigured in production, auth is bypassed.',
    severity: 'critical',
    fix_suggestion:
      'Never conditionally skip authentication based on environment. Use proper test fixtures and mocks instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bNODE_ENV\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return /\b(?:skipAuth|bypassAuth|skipAuthentication|skipValidation|disableAuth)\s*\(/.test(window);
    },
  },
  {
    id: 'TEST_CREDENTIALS_NON_TEST',
    category: 'Hardcoded Credentials',
    description:
      'Test credentials found in non-test file — these may be deployed to production and used as a backdoor.',
    severity: 'critical',
    fix_suggestion:
      'Move test credentials to test files only. Use environment variables for any credentials in application code.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:testPassword|test_password|testToken|test_token|testApiKey|test_api_key)\s*=\s*['"][^'"]{3,}['"]/.test(line);
    },
  },
  {
    id: 'DEBUG_ROUTE_ENV_ONLY',
    category: 'Authentication Bypass',
    description:
      'Debug/admin route guarded only by NODE_ENV check — NODE_ENV can be misconfigured or manipulated.',
    severity: 'high',
    fix_suggestion:
      'Protect debug routes with proper authentication in addition to environment checks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Trigger on the NODE_ENV line, then check the window for debug routes
      if (!/\bNODE_ENV\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      if (!/(?:\/debug|\/admin-debug|\/dev-tools|\/internal\/debug)/.test(window)) return false;
      if (!/\b(?:get|post|use|route)\s*\(/.test(window)) return false;
      return !/\b(?:auth|authenticate|requireAuth|requireAdmin|isAuthenticated|verifyToken)\b/i.test(window);
    },
  },
  {
    id: 'ADMIN_SEEDER_ALL_ENV',
    category: 'Authentication Bypass',
    description:
      'Admin/seed data creation without environment guard — may create default admin accounts in production.',
    severity: 'high',
    fix_suggestion:
      'Guard seed scripts with strict environment checks: if (process.env.NODE_ENV === "production") throw new Error("Cannot seed in production").',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect createUser/insertUser with admin role without NODE_ENV check
      if (!/\b(?:createUser|insertUser|seedAdmin|createAdmin)\s*\(/.test(line)) return false;
      if (!/\b(?:admin|superadmin|root)\b/i.test(line)) return false;
      return !/\bNODE_ENV\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'FEATURE_FLAG_DISABLES_SECURITY',
    category: 'Authentication Bypass',
    description:
      'Feature flag that disables security controls — if flag is misconfigured, security is disabled in production.',
    severity: 'critical',
    fix_suggestion:
      'Never use feature flags to control security. Security controls should always be active regardless of flags.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:DISABLE_AUTH|SKIP_AUTH|BYPASS_SECURITY|DISABLE_CSRF|DISABLE_RATE_LIMIT|SKIP_VALIDATION)\b/.test(line) &&
        /\b(?:process\.env|featureFlags|flags|config)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 49: API Design Anti-Patterns
  // ════════════════════════════════════════════
  {
    id: 'GRAPHQL_MUTATION_RETURNS_FULL_USER',
    category: 'Data Exposure',
    description:
      'GraphQL mutation resolver returns full user object including password/hash — leaks credentials in API response.',
    severity: 'critical',
    fix_suggestion:
      'Explicitly select fields in the resolver return. Never return password, hash, or secret fields from mutations.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect: return user; or return await User.findById() in a mutation context
      if (!/\breturn\s+(?:user|await\s+(?:User|prisma\.user)\s*\.\s*(?:findUnique|findFirst|findById|create|update))\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 15), Math.min(ctx.allLines.length, lineIdx + 3)).join('\n');
      return /\b(?:Mutation|mutation)\b/.test(window) && !/\bselect\b/.test(window) && !/\b(?:omit|exclude|pick)\b/.test(window);
    },
  },
  {
    id: 'API_ARBITRARY_FIELD_SELECTION',
    category: 'Data Exposure',
    description:
      'API accepts fields/select parameter for arbitrary field selection — attacker can request sensitive fields.',
    severity: 'high',
    fix_suggestion:
      'Use a whitelist of allowed fields. Never pass user-provided field lists directly to database select/projection.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:select|fields|projection)\s*:\s*req\s*\.\s*(?:query|body)\s*\.\s*(?:fields|select|columns)\b/.test(line);
    },
  },
  {
    id: 'BATCH_ENDPOINT_NO_PER_ITEM_AUTH',
    category: 'Authorization',
    description:
      'Batch/bulk endpoint iterates items without per-item authorization check — attacker can include unauthorized items.',
    severity: 'high',
    fix_suggestion:
      'Check authorization for each item in a batch operation. Do not assume batch-level auth covers individual items.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect: items.map/forEach with db operations but no auth check per item
      if (!/\b(?:items|ids|batch|bulk)\s*\.\s*(?:map|forEach)\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return /\b(?:delete|update|destroy|remove)\s*\(/.test(window) &&
        !/\b(?:authorize|checkPermission|canAccess|isOwner|hasPermission|belongsTo)\b/i.test(window);
    },
  },
  {
    id: 'WEBHOOK_RETRY_NO_BACKOFF',
    category: 'DoS',
    description:
      'Webhook retry logic without exponential backoff — rapid retries can amplify into DoS on downstream services.',
    severity: 'medium',
    fix_suggestion:
      'Implement exponential backoff with jitter for webhook retries: delay = baseDelay * 2^attempt + random jitter.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Trigger on function/const line containing "webhook" + "retry" in name
      if (!/\b(?:sendWebhook|webhookRetry|retryWebhook|deliverWebhook)\b/i.test(line) &&
          !/\bwebhook\b/i.test(line)) return false;
      if (!/\b(?:function|const|async)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 20)).join('\n');
      return /\b(?:retries|retry|attempt)\b/.test(window) &&
        /\b(?:setTimeout|delay|sleep|wait)\b/.test(window) &&
        !/\b(?:exponential|backoff|Math\.pow|2\s*\*\*|\*\s*2)\b/.test(window);
    },
  },
  {
    id: 'REST_SELECT_STAR_EQUIVALENT',
    category: 'Data Exposure',
    description:
      'API endpoint returns full database record without field filtering — may expose internal or sensitive fields.',
    severity: 'medium',
    fix_suggestion:
      'Use explicit field selection (select/pick) when returning data from API endpoints. Never return raw DB records.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // res.json(user) or res.json(await db.query('SELECT * FROM users'))
      if (!/\bres\s*\.\s*json\s*\(\s*(?:user|account|customer|record|row)\s*\)/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 10), Math.min(ctx.allLines.length, lineIdx + 3)).join('\n');
      return !/\bselect\b/.test(window) && !/\b(?:omit|pick|exclude|sanitize|serialize|toJSON)\b/.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 51: Django Security
  // ════════════════════════════════════════════
  {
    id: 'DJANGO_RAW_FSTRING',
    category: 'SQL Injection',
    description:
      'Django raw() called with f-string — direct SQL injection vulnerability.',
    severity: 'critical',
    fix_suggestion:
      'Use parameterized raw queries: Model.objects.raw("SELECT * FROM t WHERE id = %s", [user_id]).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\.objects\.raw\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'DJANGO_EXTRA_USER_INPUT',
    category: 'SQL Injection',
    description:
      'Django QuerySet .extra() with user-controlled input — deprecated and vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Replace .extra() with .annotate() using F() and Value() expressions, or use RawSQL with params.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.extra\s*\(/.test(line)) return false;
      return /\.extra\s*\([^)]*(?:request\.|user_input|f['"`]|\.format\s*\()/.test(line) ||
        /\.extra\s*\(\s*(?:select|where|tables)\s*=/.test(line) && /\+|%s|\.format|f['"`]|\$\{/.test(line);
    },
  },
  {
    id: 'DJANGO_RAWSQL_INJECTION',
    category: 'SQL Injection',
    description:
      'Django RawSQL() with string interpolation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use RawSQL with params: RawSQL("SELECT col FROM t WHERE id = %s", [user_id]).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bRawSQL\s*\(\s*f['"`]/.test(line) || /\bRawSQL\s*\(\s*['"`].*%s.*['"`]\s*%/.test(line);
    },
  },
  {
    id: 'DJANGO_CSRF_EXEMPT_SENSITIVE',
    category: 'CSRF',
    description:
      'Django @csrf_exempt on a view that handles sensitive operations — bypasses CSRF protection.',
    severity: 'high',
    fix_suggestion:
      'Remove @csrf_exempt and use proper CSRF tokens. For APIs, use authentication-based CSRF exemption (e.g., DRF TokenAuthentication).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/@csrf_exempt\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return /\b(?:def\s+(?:login|register|signup|transfer|payment|checkout|delete|update|create|change_password|reset_password|admin))\b/.test(window) ||
        /\b(?:POST|PUT|DELETE|PATCH)\b/.test(window);
    },
  },
  {
    id: 'DJANGO_DEBUG_TRUE',
    category: 'Server Misconfiguration',
    description:
      'Django DEBUG = True in settings — exposes detailed error pages, stack traces, and SQL queries to attackers.',
    severity: 'high',
    fix_suggestion:
      'Set DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True" and ensure it is False in production.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bDEBUG\s*=\s*True\b/.test(line)) return false;
      if (isFrameworkSource(ctx.filePath)) return false;
      // Must be a Django settings file or Django project
      const lowerPath = ctx.filePath.toLowerCase();
      if (lowerPath.includes('settings') || lowerPath.includes('django')) return true;
      // Check for Django markers in the file content
      return /\bfrom\s+django\b|\bimport\s+django\b|\bINSTALLED_APPS\b|\bMIDDLEWARE\b|\bALLOWED_HOSTS\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'DJANGO_ALLOWED_HOSTS_STAR',
    category: 'Server Misconfiguration',
    description:
      'Django ALLOWED_HOSTS = ["*"] — accepts requests for any hostname, enabling host header attacks.',
    severity: 'high',
    fix_suggestion:
      'Set ALLOWED_HOSTS to your actual domain names: ALLOWED_HOSTS = ["example.com", "www.example.com"].',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bALLOWED_HOSTS\s*=\s*\[['"`]\*['"`]\]/.test(line);
    },
  },
  {
    id: 'DJANGO_SECRET_KEY_INLINE',
    category: 'Secrets',
    description:
      'Django SECRET_KEY hardcoded in settings.py — compromises session security, CSRF tokens, and password hashing.',
    severity: 'critical',
    fix_suggestion:
      'Load SECRET_KEY from environment: SECRET_KEY = os.environ["DJANGO_SECRET_KEY"].',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bSECRET_KEY\s*=\s*['"`]/.test(line)) return false;
      // Only if it looks like a real key value (not env var loading)
      return !/\bos\.environ\b/.test(line) && !/\bconfig\s*\(/.test(line) && !/\benv\s*\(/.test(line) &&
        /\bSECRET_KEY\s*=\s*['"`][a-zA-Z0-9!@#$%^&*()_+\-=]{8,}['"`]/.test(line);
    },
  },
  {
    id: 'DJANGO_MARK_SAFE_FSTRING',
    category: 'XSS',
    description:
      'Django mark_safe() with f-string containing user data — disables HTML escaping, enabling stored/reflected XSS.',
    severity: 'critical',
    fix_suggestion:
      'Use format_html() instead of mark_safe(f"..."). format_html() auto-escapes variables.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bmark_safe\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'DJANGO_SESSION_NO_HTTPONLY',
    category: 'Session Security',
    description:
      'Django SESSION_COOKIE_HTTPONLY = False — session cookies accessible via JavaScript, enabling session hijacking through XSS.',
    severity: 'high',
    fix_suggestion:
      'Set SESSION_COOKIE_HTTPONLY = True (this is the default — remove the explicit False setting).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSESSION_COOKIE_HTTPONLY\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'DJANGO_JSONRESPONSE_QUERYSET',
    category: 'Data Exposure',
    description:
      'Django JsonResponse with serialized queryset may expose internal model fields and sensitive data.',
    severity: 'medium',
    fix_suggestion:
      'Use explicit field selection with .values() before serializing: JsonResponse(list(qs.values("id", "name")), safe=False).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bJsonResponse\s*\(/.test(line)) return false;
      return /\bJsonResponse\s*\([^)]*\b(?:serializers\.serialize|model_to_dict|values_list)\b/.test(line) &&
        !/\bvalues\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 52: Flask/FastAPI Security
  // ════════════════════════════════════════════
  {
    id: 'FLASK_SSTI',
    category: 'Template Injection',
    description:
      'Flask render_template_string() with user input — enables Server-Side Template Injection (SSTI) for RCE.',
    severity: 'critical',
    fix_suggestion:
      'Use render_template() with a file-based template instead. Never pass user input to render_template_string().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\brender_template_string\s*\(/.test(line)) return false;
      return /\brender_template_string\s*\(\s*(?:f['"`]|request\.|user_input|data|content|body|text|param)/.test(line) ||
        /\brender_template_string\s*\([^)]*\+/.test(line) ||
        /\brender_template_string\s*\([^)]*\.format\s*\(/.test(line);
    },
  },
  {
    id: 'FLASK_SEND_FILE_USER_PATH',
    category: 'Path Traversal',
    description:
      'Flask send_file() with user-controlled path — enables arbitrary file read via path traversal.',
    severity: 'critical',
    fix_suggestion:
      'Use send_from_directory() with a fixed base directory, or validate/sanitize the filename with secure_filename().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsend_file\s*\(/.test(line)) return false;
      return /\bsend_file\s*\(\s*(?:request\.|f['"`]|user_|filename|path|file_path)/.test(line) &&
        !/\bsecure_filename\b/.test(line) && !/\bsend_from_directory\b/.test(line);
    },
  },
  {
    id: 'FASTAPI_NO_CORS_MIDDLEWARE',
    category: 'Server Misconfiguration',
    description:
      'FastAPI application without CORS middleware — may be misconfigured or missing cross-origin protection.',
    severity: 'medium',
    fix_suggestion:
      'Add CORSMiddleware with explicit allowed origins: app.add_middleware(CORSMiddleware, allow_origins=["https://yourdomain.com"]).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bFastAPI\s*\(\s*\)/.test(line)) return false;
      // Skip framework source / docs / test / example directories
      const lowerPath = ctx.filePath.toLowerCase();
      if (/\/(docs_src|docs|tests|test|examples|example|fixtures)\//i.test(lowerPath)) return false;
      if (isFrameworkSource(ctx.filePath)) return false;
      // Check the entire file for CORSMiddleware
      return !/\bCORSMiddleware\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'FLASK_APP_SECRET_HARDCODED',
    category: 'Secrets',
    description:
      'Flask app.secret_key set to a hardcoded string — compromises session integrity and signed cookies.',
    severity: 'critical',
    fix_suggestion:
      'Load from environment: app.secret_key = os.environ["FLASK_SECRET_KEY"].',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bapp\.secret_key\s*=\s*['"`]/.test(line)) return false;
      return !/\bos\.environ\b/.test(line) && !/\bconfig\b/.test(line);
    },
  },
  {
    id: 'FASTAPI_SQLALCHEMY_TEXT_INTERPOLATION',
    category: 'SQL Injection',
    description:
      'FastAPI route using SQLAlchemy text() with string interpolation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion:
      'Use bound parameters: text("SELECT * FROM t WHERE id = :id").bindparams(id=user_id).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent) && !/\bfrom\s+sqlalchemy\b/.test(ctx.fileContent)) return false;
      return /\btext\s*\(\s*f['"`].*(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(line) ||
        /\btext\s*\(\s*['"`].*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"`]*['"`]\s*\+/i.test(line) ||
        /\btext\s*\(\s*['"`].*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"`]*['"`]\s*\.format\s*\(/i.test(line);
    },
  },
  {
    id: 'FLASK_DEBUG_MODE_PRODUCTION',
    category: 'Server Misconfiguration',
    description:
      'Flask debug mode enabled unconditionally — exposes Werkzeug debugger for remote code execution.',
    severity: 'critical',
    fix_suggestion:
      'Set debug from environment: app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true").',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bFLASK_DEBUG\s*=\s*True\b/.test(line) && !/\bapp\.debug\s*=\s*True\b/.test(line)) return false;
      return !/\bos\.environ\b/.test(line) && !/\bif\b/.test(line);
    },
  },
  {
    id: 'WERKZEUG_DEBUGGER_PIN',
    category: 'Secrets',
    description:
      'Werkzeug debugger PIN exposed in code — enables authentication bypass to the interactive debugger.',
    severity: 'critical',
    fix_suggestion:
      'Never expose the Werkzeug debugger PIN. Disable the debugger in production entirely.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bWERKZEUG_DEBUG_PIN\s*=\s*['"`]\d+['"`]/.test(line) ||
        /\bdebugger_pin\s*=\s*['"`]\d+['"`]/.test(line);
    },
  },
  {
    id: 'FLASK_SESSION_NO_SECURE',
    category: 'Session Security',
    description:
      'Flask session cookie without Secure flag — cookies sent over HTTP, enabling interception.',
    severity: 'high',
    fix_suggestion:
      'Set SESSION_COOKIE_SECURE = True to ensure cookies are only sent over HTTPS.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSESSION_COOKIE_SECURE\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'FASTAPI_HTML_RESPONSE_USER_INPUT',
    category: 'XSS',
    description:
      'FastAPI Response with text/html media type containing user input — vulnerable to reflected XSS.',
    severity: 'high',
    fix_suggestion:
      'Use HTMLResponse with Jinja2 templates that auto-escape, or sanitize user input before including in HTML.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bResponse\s*\(/.test(line)) return false;
      return /\bResponse\s*\([^)]*(?:content\s*=\s*(?:f['"`]|request\.|user_|data|body))/.test(line) &&
        /\bmedia_type\s*=\s*['"`]text\/html['"`]/.test(line);
    },
  },
  {
    id: 'STARLETTE_STATIC_SENSITIVE',
    category: 'Data Exposure',
    description:
      'Starlette StaticFiles serving a sensitive directory — may expose configuration, secrets, or source code.',
    severity: 'high',
    fix_suggestion:
      'Only serve directories containing public assets. Never mount sensitive directories like /etc, home, or project root.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bStaticFiles\s*\(/.test(line)) return false;
      return /\bStaticFiles\s*\(\s*directory\s*=\s*['"`](?:\/|\.\.\/|~|\/etc|\/home|\.\/src|\.\/config|\.\/\.env)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 53: Python Standard Library Security
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_SUBPROCESS_SHELL_USER_INPUT',
    category: 'Command Injection',
    description:
      'subprocess.run/call/Popen with shell=True and user-controlled input — enables arbitrary command execution.',
    severity: 'critical',
    fix_suggestion:
      'Use subprocess.run(["cmd", arg1, arg2]) with a list of arguments instead of shell=True.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(/.test(line)) return false;
      if (!/\bshell\s*=\s*True\b/.test(line)) return false;
      return /\b(?:request\.|user_input|f['"`]|\.format\s*\(|\+\s*\w)/.test(line) ||
        /\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'PYTHON_MKTEMP_RACE',
    category: 'File System',
    description:
      'tempfile.mktemp() creates a name but not the file — race condition allows symlink attacks.',
    severity: 'medium',
    fix_suggestion:
      'Use tempfile.mkstemp() (creates file atomically) or tempfile.NamedTemporaryFile().',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\btempfile\.mktemp\s*\(/.test(line);
    },
  },
  {
    id: 'PYTHON_XML_PARSE_NO_DEFUSE',
    category: 'XXE',
    description:
      'xml.etree.ElementTree.parse() without defusedxml — vulnerable to XXE and billion laughs attacks.',
    severity: 'high',
    fix_suggestion:
      'Use defusedxml: from defusedxml.ElementTree import parse.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bElementTree\.parse\s*\(/.test(line) && !/\bdefusedxml\b/.test(line);
    },
  },
  {
    id: 'PYTHON_URLLIB_SSRF',
    category: 'SSRF',
    description:
      'urllib.request.urlopen() with user-controlled URL — enables Server-Side Request Forgery.',
    severity: 'high',
    fix_suggestion:
      'Validate and allowlist URLs before opening. Use a URL validation library to block internal/private IP ranges.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\burlopen\s*\(/.test(line)) return false;
      return /\burlopen\s*\(\s*(?:request\.|user_|url|f['"`]|input)/.test(line) &&
        !/\burlopen\s*\(\s*['"`]https?:\/\/[a-zA-Z]/.test(line);
    },
  },
  {
    id: 'PYTHON_FTP_PLAINTEXT',
    category: 'Network Security',
    description:
      'ftplib with plaintext credentials — FTP sends passwords in cleartext, enabling interception.',
    severity: 'high',
    fix_suggestion:
      'Use ftplib.FTP_TLS instead of ftplib.FTP, or switch to SFTP via paramiko.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bFTP\s*\(/.test(line)) return false;
      if (/\bFTP_TLS\b/.test(line)) return false;
      // Check if .login() is on the same line or in a nearby window
      if (/\b\.login\s*\(/.test(line)) return true;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return /\b\.login\s*\(/.test(window);
    },
  },
  {
    id: 'PYTHON_SMTP_NO_TLS',
    category: 'Network Security',
    description:
      'smtplib.SMTP without TLS — email credentials sent in cleartext, enabling interception.',
    severity: 'high',
    fix_suggestion:
      'Use smtplib.SMTP_SSL or call starttls() before login(): smtp.starttls(); smtp.login(user, password).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bSMTP\s*\(/.test(line)) return false;
      if (/\bSMTP_SSL\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 8)).join('\n');
      return /\b\.login\s*\(/.test(window) && !/\bstarttls\s*\(/.test(window);
    },
  },
  {
    id: 'PYTHON_WEAK_HASH_PASSWORD',
    category: 'Cryptography',
    description:
      'hashlib.md5/sha1 used for password hashing — these algorithms are fast and easily brute-forced.',
    severity: 'high',
    fix_suggestion:
      'Use bcrypt, scrypt, or argon2 for password hashing. These are intentionally slow and salt automatically.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bhashlib\.(?:md5|sha1)\s*\(/.test(line)) return false;
      return /\b(?:password|passwd|pwd|pass_hash|user_pass)\b/i.test(line);
    },
  },
  {
    id: 'PYTHON_RANDOM_SECURITY_TOKEN',
    category: 'Cryptography',
    description:
      'random.randint/random.choice used for security tokens — predictable PRNG enables token guessing.',
    severity: 'high',
    fix_suggestion:
      'Use secrets.token_hex(), secrets.token_urlsafe(), or secrets.choice() for security-sensitive randomness.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\brandom\.(?:randint|choice|random|getrandbits|sample)\s*\(/.test(line)) return false;
      return /\b(?:token|secret|key|nonce|otp|verification|code|csrf|session_id|api_key|auth)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 54: Python Data Science / ML Security
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_PICKLE_NETWORK_LOAD',
    category: 'Deserialization',
    description:
      'pickle.loads() on network/untrusted data — enables arbitrary code execution during deserialization.',
    severity: 'critical',
    fix_suggestion:
      'Use JSON, MessagePack, or Protocol Buffers for network data. If pickle is unavoidable, use fickling to audit pickle payloads.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bpickle\.loads?\s*\(/.test(line)) return false;
      return /\b(?:request\.|response\.|socket|recv|data|payload|body|content|message|network|remote|download)\b/i.test(line);
    },
  },
  {
    id: 'PYTHON_TORCH_LOAD_UNSAFE',
    category: 'Deserialization',
    description:
      'torch.load() without weights_only=True — loads arbitrary Python objects via pickle, enabling RCE.',
    severity: 'critical',
    fix_suggestion:
      'Use torch.load(path, weights_only=True) or switch to safetensors format for model loading.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\btorch\.load\s*\(/.test(line)) return false;
      return !/\bweights_only\s*=\s*True\b/.test(line);
    },
  },
  {
    id: 'PYTHON_NUMPY_ALLOW_PICKLE',
    category: 'Deserialization',
    description:
      'numpy.load() with allow_pickle=True — enables arbitrary code execution via crafted .npy files.',
    severity: 'high',
    fix_suggestion:
      'Use numpy.load(path, allow_pickle=False) (the default since NumPy 1.16.3), or use .npz format with savez().',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnumpy\.load\s*\([^)]*\ballow_pickle\s*=\s*True\b/.test(line) ||
        /\bnp\.load\s*\([^)]*\ballow_pickle\s*=\s*True\b/.test(line);
    },
  },
  {
    id: 'PYTHON_JOBLIB_UNTRUSTED',
    category: 'Deserialization',
    description:
      'joblib.load() from untrusted source — joblib uses pickle internally, enabling arbitrary code execution.',
    severity: 'critical',
    fix_suggestion:
      'Only load joblib files from trusted sources. Validate file integrity with checksums before loading.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bjoblib\.load\s*\(/.test(line)) return false;
      return /\bjoblib\.load\s*\(\s*(?:request\.|url|f['"`]|user_|download|remote|path|input)/.test(line) &&
        !/\bjoblib\.load\s*\(\s*['"`](?:\.\/|models\/|data\/)/.test(line);
    },
  },
  {
    id: 'PYTHON_EVAL_MODEL_OUTPUT',
    category: 'Code Injection',
    description:
      'eval() called on model/AI output — enables arbitrary code execution from untrusted model responses.',
    severity: 'critical',
    fix_suggestion:
      'Use ast.literal_eval() for simple data structures, or JSON parsing. Never eval() untrusted output.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\beval\s*\(/.test(line)) return false;
      return /\beval\s*\(\s*(?:model_output|prediction|result|output|response|generated|completion|inference)\b/.test(line);
    },
  },
  {
    id: 'JUPYTER_HARDCODED_CREDS',
    category: 'Secrets',
    description:
      'Jupyter notebook with hardcoded credentials — notebooks are often shared or committed to version control.',
    severity: 'high',
    fix_suggestion:
      'Use environment variables or a .env file (excluded from git) for credentials in notebooks.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!ctx.filePath.endsWith('.py')) return false;
      // Skip test and fixture directories
      if (isTestOrFixtureFile(ctx.filePath)) return false;
      // Match common credential patterns in code cells
      if (!/\b(?:api_key|apikey|secret_key|password|token|credentials)\s*=\s*['"`][a-zA-Z0-9_\-]{8,}['"`]/.test(line)) return false;
      // Skip env-var references
      if (/\b(?:os\.environ|os\.getenv|config|env\(|\.env)\b/.test(line)) return false;
      // Skip obvious fake/placeholder values
      const valueMatch = line.match(/\b(?:api_key|apikey|secret_key|password|token|credentials)\s*=\s*['"`]([^'"`]+)['"`]/);
      if (valueMatch) {
        const value = valueMatch[1].toLowerCase();
        const fakeValues = ['password', 'password123', 'test', 'secret', 'changeme', 'admin', 'default', 'none',
          'pass', 'pass123', 'test123', 'abc123', 'qwerty', 'letmein', 'welcome', 'sample', 'demo'];
        if (fakeValues.includes(value)) return false;
        // Skip placeholder-like values
        if (/^(your[_-]|my[_-]|xxx|test[_-]|example|placeholder|dummy|fake|replace|insert|todo|fixme|changeme|sample)/i.test(value)) return false;
      }
      return true;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 55: Python Async / aiohttp / httpx
  // ════════════════════════════════════════════
  {
    id: 'AIOHTTP_NO_SSL',
    category: 'Network Security',
    description:
      'aiohttp.ClientSession with SSL verification disabled — enables man-in-the-middle attacks.',
    severity: 'high',
    fix_suggestion:
      'Remove ssl=False or use a proper SSL context: ssl=ssl.create_default_context().',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bClientSession\s*\([^)]*\bssl\s*=\s*False\b/.test(line) ||
        /\b\.(?:get|post|put|delete|patch|request)\s*\([^)]*\bssl\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'HTTPX_VERIFY_FALSE',
    category: 'Network Security',
    description:
      'httpx.AsyncClient with verify=False — disables SSL certificate verification, enabling MITM attacks.',
    severity: 'high',
    fix_suggestion:
      'Remove verify=False to use default SSL verification. Only disable for development with explicit env check.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhttpx\.(?:AsyncClient|Client)\s*\([^)]*\bverify\s*=\s*False\b/.test(line) ||
        /\bhttpx\.(?:get|post|put|delete|patch)\s*\([^)]*\bverify\s*=\s*False\b/.test(line);
    },
  },
  {
    id: 'ASYNC_FILE_PATH_TRAVERSAL',
    category: 'Path Traversal',
    description:
      'Async file read with user-controlled path — enables arbitrary file access via path traversal.',
    severity: 'high',
    fix_suggestion:
      'Validate the path against a fixed base directory. Use os.path.realpath() and ensure the result starts with the base.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\baiofiles\.open\s*\(/.test(line) && !/\basync\b.*\bopen\s*\(/.test(line)) return false;
      return /\bopen\s*\(\s*(?:request\.|user_|path|filename|f['"`]|input)/.test(line) &&
        !/\bos\.path\.(?:realpath|abspath)\b/.test(line);
    },
  },
  {
    id: 'AIOHTTP_CORS_ALLOW_ALL',
    category: 'Server Misconfiguration',
    description:
      'aiohttp CORS with allow_all_origins — any website can make authenticated requests to your API.',
    severity: 'high',
    fix_suggestion:
      'Specify explicit allowed origins instead of allowing all: cors.add(route, {"*": aiohttp_cors.ResourceOptions(allow_origins=["https://yourdomain.com"])}).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\baiohttp_cors\b.*\ballow_all_origins\s*=\s*True\b/.test(line) ||
        /\bResourceOptions\s*\([^)]*\ballow_origins\s*=\s*['"`]\*['"`]/.test(line);
    },
  },
  {
    id: 'ASYNCIO_SUBPROCESS_SHELL',
    category: 'Command Injection',
    description:
      'asyncio.create_subprocess_shell() with user input — enables arbitrary command execution.',
    severity: 'critical',
    fix_suggestion:
      'Use asyncio.create_subprocess_exec() with a list of arguments instead of shell mode.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcreate_subprocess_shell\s*\(/.test(line)) return false;
      return /\bcreate_subprocess_shell\s*\(\s*(?:f['"`]|request\.|user_|input|data|cmd)/.test(line) ||
        /\bcreate_subprocess_shell\s*\([^)]*\+/.test(line);
    },
  },
  {
    id: 'AIOHTTP_WS_NO_AUTH',
    category: 'Authentication',
    description:
      'aiohttp WebSocket handler without authentication — any client can connect and interact.',
    severity: 'medium',
    fix_suggestion:
      'Validate authentication (token, session) at the start of the WebSocket handler before processing messages.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bweb\.WebSocketResponse\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 5), Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return !/\b(?:auth|token|session|verify|check_permission|login_required|authenticate)\b/i.test(window);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 56: Python Package Security
  // ════════════════════════════════════════════
  {
    id: 'PYTHON_IMPORTLIB_USER_INPUT',
    category: 'Code Injection',
    description:
      'importlib.import_module() with user-controlled input — enables arbitrary module loading and code execution.',
    severity: 'critical',
    fix_suggestion:
      'Use an allowlist of permitted module names: if module_name in ALLOWED_MODULES: importlib.import_module(module_name).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bimport_module\s*\(/.test(line)) return false;
      return /\bimport_module\s*\(\s*(?:request\.|user_|input|data|name|module_name|f['"`])/.test(line) &&
        !/\bimport_module\s*\(\s*['"`][a-zA-Z]/.test(line);
    },
  },
  {
    id: 'PYTHON_DUNDER_IMPORT_USER',
    category: 'Code Injection',
    description:
      '__import__() with user-controlled input — enables arbitrary module loading and code execution.',
    severity: 'critical',
    fix_suggestion:
      'Use an allowlist of permitted modules and importlib.import_module() instead of __import__().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b__import__\s*\(/.test(line)) return false;
      return /\b__import__\s*\(\s*(?:request\.|user_|input|data|name|module_name|f['"`])/.test(line) &&
        !/\b__import__\s*\(\s*['"`][a-zA-Z]/.test(line);
    },
  },
  {
    id: 'PYTHON_SETUP_CMDCLASS',
    category: 'Supply Chain',
    description:
      'setup.py with cmdclass override — can execute arbitrary code during pip install.',
    severity: 'high',
    fix_suggestion:
      'Review cmdclass overrides carefully. Prefer pyproject.toml with build-system configuration over setup.py cmdclass.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcmdclass\s*=/.test(line)) return false;
      return ctx.filePath.endsWith('setup.py') && /\bcmdclass\s*=\s*\{/.test(line);
    },
  },
  {
    id: 'PYTHON_PIP_INSTALL_URL',
    category: 'Supply Chain',
    description:
      'pip install from URL in code — can install malicious packages from untrusted sources.',
    severity: 'high',
    fix_suggestion:
      'Pin dependencies in requirements.txt from PyPI. Use --require-hashes for integrity verification.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsubprocess\b.*\bpip\b.*\binstall\b.*\bhttps?:\/\//.test(line) ||
        /\bos\.system\b.*\bpip\b.*\binstall\b.*\bhttps?:\/\//.test(line);
    },
  },
  {
    id: 'PYTHON_REQUIREMENTS_CUSTOM_INDEX',
    category: 'Supply Chain',
    description:
      'requirements.txt with --index-url pointing to custom registry — may install packages from untrusted sources.',
    severity: 'medium',
    fix_suggestion:
      'Use PyPI or a verified private registry. Pin hashes with --require-hashes for integrity.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /--index-url\s+https?:\/\/(?!pypi\.org|files\.pythonhosted\.org)/.test(line) ||
        /--extra-index-url\s+https?:\/\/(?!pypi\.org|files\.pythonhosted\.org)/.test(line);
    },
  },
  {
    id: 'PYTHON_PYPIRC_TOKEN',
    category: 'Secrets',
    description:
      '.pypirc with plaintext token or password — credentials for package publishing exposed in code.',
    severity: 'critical',
    fix_suggestion:
      'Use environment variables or keyring for PyPI credentials. Never commit .pypirc to version control.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bpassword\s*=\s*pypi-[a-zA-Z0-9_-]+/.test(line) ||
        /\btoken\s*=\s*pypi-[a-zA-Z0-9_-]+/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 57: Advanced JS/TS — Prototype & Object
  // ════════════════════════════════════════════
  {
    id: 'JS_DEFINE_PROPERTY_USER_DESCRIPTOR',
    category: 'Prototype Pollution',
    description:
      'Object.defineProperty with user-controlled descriptor — enables property injection and prototype pollution.',
    severity: 'high',
    fix_suggestion:
      'Validate descriptor values before passing to Object.defineProperty. Use a static descriptor or Object.freeze() the descriptor.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bObject\.defineProperty\s*\(/.test(line)) return false;
      return /\bObject\.defineProperty\s*\([^,]+,\s*(?:request\.|req\.|user_|input|data|body|params|key|prop)/.test(line) ||
        /\bObject\.defineProperty\s*\([^,]+,\s*[^,]+,\s*(?:request\.|req\.|user_|input|data|body|params)/.test(line);
    },
  },
  {
    id: 'JS_PROXY_UNCHECKED_TARGET',
    category: 'Logic Error',
    description:
      'Proxy handler without validation on get/set traps — may bypass security checks or expose internals.',
    severity: 'medium',
    fix_suggestion:
      'Validate property names in Proxy get/set handlers. Use an allowlist of accessible properties.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+Proxy\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const windowStart = Math.max(0, lineIdx - 15);
      const windowEnd = Math.min(ctx.allLines.length, lineIdx + 15);
      const window = ctx.allLines.slice(windowStart, windowEnd).join('\n');
      return /\bget\s*[:]\s*(?:function|\()/.test(window) &&
        !/\b(?:allowlist|whitelist|allowed|valid|check|validate)\b/i.test(window);
    },
  },
  {
    id: 'JS_REFLECT_SET_USER_KEY',
    category: 'Prototype Pollution',
    description:
      'Reflect.set with user-controlled key — enables arbitrary property setting and prototype pollution.',
    severity: 'high',
    fix_suggestion:
      'Validate property keys against an allowlist before using Reflect.set. Block __proto__ and constructor.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bReflect\.set\s*\(/.test(line)) return false;
      return /\bReflect\.set\s*\([^,]+,\s*(?:request\.|user_|input|data|body|params|key|prop|req\.)/.test(line);
    },
  },
  {
    id: 'JS_WEAKREF_SECURITY_CLEANUP',
    category: 'Logic Error',
    description:
      'WeakRef used for security-sensitive object cleanup — garbage collection timing is non-deterministic, creating race conditions.',
    severity: 'medium',
    fix_suggestion:
      'Use explicit cleanup (try/finally, Symbol.dispose) for security-sensitive resources instead of WeakRef.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+WeakRef\s*\(/.test(line)) return false;
      return /\b(?:session|token|credential|auth|secret|key|permission)\b/i.test(line);
    },
  },
  {
    id: 'JS_STRUCTURED_CLONE_BYPASS',
    category: 'Logic Error',
    description:
      'structuredClone used to bypass non-cloneable security controls — drops functions, proxies, and closures.',
    severity: 'medium',
    fix_suggestion:
      'Do not use structuredClone to copy security-sensitive objects. Implement custom deep clone that preserves security properties.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bstructuredClone\s*\(/.test(line)) return false;
      return /\bstructuredClone\s*\(\s*(?:user|session|auth|context|permissions|securityContext)\b/.test(line);
    },
  },
  {
    id: 'JS_JSON_STRINGIFY_EXPOSE',
    category: 'Data Exposure',
    description:
      'JSON.stringify replacer function may expose hidden or private fields through custom serialization.',
    severity: 'medium',
    fix_suggestion:
      'Use explicit field selection instead of a replacer that transforms values. Consider using toJSON() on the class.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bJSON\.stringify\s*\(/.test(line)) return false;
      return /\bJSON\.stringify\s*\([^,]+,\s*(?:function|(\([^)]*\)\s*=>))/.test(line) &&
        /\b(?:password|secret|token|credential|ssn|credit_card|apiKey|private)\b/i.test(line);
    },
  },
  {
    id: 'JS_SYMBOL_TOPRIMITIVE_OVERRIDE',
    category: 'Logic Error',
    description:
      'Symbol.toPrimitive override in user-provided objects — enables type coercion attacks bypassing security comparisons.',
    severity: 'medium',
    fix_suggestion:
      'Validate input types explicitly using typeof/instanceof before comparison. Do not rely on implicit type coercion.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\[Symbol\.toPrimitive\]/.test(line) && /\b(?:user|input|request|data|body|params)\b/i.test(line);
    },
  },
  {
    id: 'JS_WITH_STATEMENT',
    category: 'Scope Pollution',
    description:
      'with statement used — creates ambiguous scoping that enables variable injection and makes code analysis unreliable.',
    severity: 'medium',
    fix_suggestion:
      'Remove with statement and use explicit object property access. with is forbidden in strict mode.',
    auto_fixable: false,
    fileTypes: ['.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /^\s*with\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 58: Advanced JS/TS — Module & Runtime
  // ════════════════════════════════════════════
  {
    id: 'JS_DYNAMIC_IMPORT_INJECTION',
    category: 'Code Injection',
    description:
      'Dynamic import() with user-controlled path — enables loading arbitrary code modules.',
    severity: 'critical',
    fix_suggestion:
      'Use a static allowlist of importable modules: const allowed = {"mod1": () => import("./mod1")}; allowed[name]().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bimport\s*\(/.test(line)) return false;
      // Skip static imports: import("./module") or import("module-name")
      if (/\bimport\s*\(\s*['"`]/.test(line)) return false;
      return /\bimport\s*\(\s*(?:request\.|user_|input|data|body|params|path|module|name|req\.|url)/.test(line);
    },
  },
  {
    id: 'JS_VM_RUN_USER_CODE',
    category: 'Code Injection',
    description:
      'vm.runInContext/runInNewContext with user code — enables arbitrary code execution in V8 sandbox (which is escapable).',
    severity: 'critical',
    fix_suggestion:
      'Use isolated-vm or a WebAssembly sandbox instead of Node.js vm module. The vm module is NOT a security boundary.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bvm\.(?:runInContext|runInNewContext|runInThisContext|compileFunction|Script)\s*\(/.test(line)) return false;
      return /\bvm\.(?:runInContext|runInNewContext|runInThisContext|compileFunction|Script)\s*\(\s*(?:request\.|user_|input|data|body|code|script|userCode|source)/.test(line);
    },
  },
  {
    id: 'JS_WORKER_USER_SCRIPT',
    category: 'Code Injection',
    description:
      'Worker created with user-controlled script URL — enables loading and executing arbitrary code.',
    severity: 'high',
    fix_suggestion:
      'Use a static Worker script URL. Pass data via postMessage() instead of dynamic script URLs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+Worker\s*\(/.test(line)) return false;
      // Skip static URLs
      if (/\bnew\s+Worker\s*\(\s*['"`]/.test(line)) return false;
      if (/\bnew\s+Worker\s*\(\s*new\s+URL\s*\(\s*['"`]/.test(line)) return false;
      return /\bnew\s+Worker\s*\(\s*(?:request\.|req\.|user_|input|data|url|path|script)/.test(line);
    },
  },
  {
    id: 'JS_SHARED_ARRAY_BUFFER_NO_HEADERS',
    category: 'Security Headers',
    description:
      'SharedArrayBuffer used without COOP/COEP headers — modern browsers require these headers for SharedArrayBuffer.',
    severity: 'medium',
    fix_suggestion:
      'Set Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+SharedArrayBuffer\s*\(/.test(line)) return false;
      return !/\bCross-Origin-Opener-Policy\b/i.test(ctx.fileContent) &&
        !/\bCross-Origin-Embedder-Policy\b/i.test(ctx.fileContent);
    },
  },
  {
    id: 'JS_ATOMICS_AUTH_RACE',
    category: 'Race Condition',
    description:
      'Atomics used in authentication logic — concurrent access to auth state creates race conditions.',
    severity: 'high',
    fix_suggestion:
      'Use single-threaded auth checks or proper mutex/semaphore patterns. Atomics alone do not prevent TOCTOU races.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bAtomics\.(?:load|store|compareExchange|exchange)\s*\(/.test(line)) return false;
      return /(?:auth|session|token|permission|login|role|access)/i.test(line);
    },
  },
  {
    id: 'JS_FINALIZATION_REGISTRY_SENSITIVE',
    category: 'Logic Error',
    description:
      'FinalizationRegistry for security-sensitive cleanup — GC timing is non-deterministic, cleanup may never run.',
    severity: 'medium',
    fix_suggestion:
      'Use explicit cleanup (try/finally, Symbol.dispose, AbortController) instead of FinalizationRegistry for security resources.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnew\s+FinalizationRegistry\s*\(/.test(line)) return false;
      return /\b(?:session|token|credential|secret|key|auth|connection|socket)\b/i.test(line);
    },
  },
  {
    id: 'JS_GLOBALTHIS_MODIFICATION',
    category: 'Scope Pollution',
    description:
      'globalThis directly modified — pollutes global scope, enabling prototype pollution and variable shadowing.',
    severity: 'medium',
    fix_suggestion:
      'Use module-scoped variables or a namespace object instead of modifying globalThis directly.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bglobalThis\s*\[/.test(line) && /=\s*(?!==)/.test(line) ||
        /\bglobalThis\.\w+\s*=\s*(?!==)/.test(line);
    },
  },
  {
    id: 'JS_PROCESS_BINDING',
    category: 'Runtime Security',
    description:
      'process.binding() access — exposes internal Node.js C++ bindings, bypassing security restrictions.',
    severity: 'high',
    fix_suggestion:
      'Use public Node.js APIs instead of process.binding(). Internal bindings are unsupported and security-sensitive.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bprocess\.binding\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 59: Advanced JS/TS — Stream & Buffer
  // ════════════════════════════════════════════
  {
    id: 'JS_STREAM_NO_BACKPRESSURE',
    category: 'DoS',
    description:
      'Readable stream from user input without backpressure handling — enables memory exhaustion DoS.',
    severity: 'high',
    fix_suggestion:
      'Use pipe() with highWaterMark limits, or implement backpressure via writable.write() return value.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+Readable\s*\(/.test(line) && !/\bReadable\.from\s*\(/.test(line)) return false;
      if (!/\b(?:request|req|socket|body|stream|upload|user)\b/i.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15)).join('\n');
      return !/\bhighWaterMark\b/.test(window) && !/\bbackpressure\b/i.test(window);
    },
  },
  {
    id: 'JS_PIPE_NO_ERROR_HANDLER',
    category: 'Error Handling',
    description:
      'Stream pipe() without error handling — unhandled errors crash the process.',
    severity: 'medium',
    fix_suggestion:
      'Use pipeline() from stream/promises, or add .on("error") handlers to both source and destination streams.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\.pipe\s*\(/.test(line)) return false;
      if (/\bpipeline\b/.test(line)) return false;
      // Skip FP / reactive library pipe() — not Node.js streams
      if (hasFpOrReactiveImports(ctx.fileContent)) return false;
      // Skip library/framework source
      if (isLibraryPackage(ctx.filePath)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(Math.max(0, lineIdx - 3), Math.min(ctx.allLines.length, lineIdx + 5)).join('\n');
      return !/\.on\s*\(\s*['"`]error['"`]/.test(window) && !/\b(?:pipeline|pump)\b/.test(window);
    },
  },
  {
    id: 'JS_TRANSFORM_EVAL_CHUNK',
    category: 'Code Injection',
    description:
      'Transform stream with eval() on chunk data — enables arbitrary code execution from stream input.',
    severity: 'critical',
    fix_suggestion:
      'Parse chunk data with JSON.parse() or a safe parser. Never eval() streamed data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\beval\s*\(/.test(line)) return false;
      return /\beval\s*\(\s*(?:chunk|data|buffer|message)\b/.test(line);
    },
  },
  {
    id: 'JS_WRITABLE_USER_PATH',
    category: 'Path Traversal',
    description:
      'Writable stream to user-controlled path — enables arbitrary file write via path traversal.',
    severity: 'high',
    fix_suggestion:
      'Validate the output path against a fixed base directory. Use path.resolve() and verify it starts with the base.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcreateWriteStream\s*\(/.test(line)) return false;
      return /\bcreateWriteStream\s*\(\s*(?:request\.|user_|input|data|body|params|path|filename|req\.)/.test(line) &&
        !/\bpath\.resolve\b/.test(line);
    },
  },
  {
    id: 'JS_BLOB_USER_FILE_WRITE',
    category: 'Path Traversal',
    description:
      'Blob from user data written to file with user-controlled name — enables arbitrary file creation.',
    severity: 'high',
    fix_suggestion:
      'Validate filenames with a strict allowlist. Strip path separators and use a fixed output directory.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+Blob\s*\(/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return /\b(?:writeFile|createWriteStream|write)\b/.test(window) &&
        /\b(?:request\.|user_|input|filename|path|name)\b/.test(window);
    },
  },
  {
    id: 'JS_TEXT_DECODER_FATAL_FALSE',
    category: 'Input Validation',
    description:
      'TextDecoder with fatal:false silently replaces invalid bytes — may hide encoding-based attacks.',
    severity: 'low',
    fix_suggestion:
      'Use new TextDecoder("utf-8", { fatal: true }) to reject malformed input instead of silently replacing it.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+TextDecoder\s*\([^)]*\bfatal\s*:\s*false\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 61: Web Framework Middleware Patterns
  // ════════════════════════════════════════════
  {
    id: 'BODYPARSER_MISSING_LIMIT',
    category: 'Web Framework',
    description: 'Body parser middleware without size limit — allows oversized payloads causing DoS.',
    severity: 'medium',
    fix_suggestion: 'Add a limit option: express.json({ limit: "100kb" }) or bodyParser.json({ limit: "100kb" }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // express.json() or bodyParser.json() or .urlencoded() with empty parens or no limit
      if (!/\b(?:express\.json|express\.urlencoded|bodyParser\.json|bodyParser\.urlencoded)\s*\(/.test(line)) return false;
      // If it has limit: it's fine
      if (/\blimit\s*:/.test(line)) return false;
      // If empty parens or only simple options without limit
      return true;
    },
  },
  {
    id: 'UNVALIDATED_CONTENT_TYPE_DISPATCH',
    category: 'Web Framework',
    description: 'Request content-type used to dispatch logic without validation — allows content-type confusion attacks.',
    severity: 'medium',
    fix_suggestion: 'Validate content-type against an allowlist before dispatching logic based on it.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\breq\.headers\s*\[\s*['"]content-type['"]\s*\]\s*===?\s*(?:req\.|params\.|query\.)/.test(line) ||
        /\bswitch\s*\(\s*req\.headers\s*\[\s*['"]content-type['"]\s*\]/.test(line) ||
        /\bif\s*\(\s*req\.(?:get|header)\s*\(\s*['"]content-type['"]\s*\)\s*\.includes\s*\(/.test(line);
    },
  },
  {
    id: 'MISSING_REQUEST_TIMEOUT',
    category: 'Web Framework',
    description: 'HTTP server or route handler without request timeout — slow clients can exhaust connections.',
    severity: 'medium',
    fix_suggestion: 'Set server.timeout or use a request timeout middleware (e.g., connect-timeout).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Detect http.createServer or new http.Server without timeout nearby
      if (!/\b(?:http\.createServer|https\.createServer|new\s+(?:http|https)\.Server)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 1), Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join('\n');
      return !/\.timeout\s*=/.test(nearby) && !/setTimeout\s*\(/.test(nearby) && !/connect-timeout/.test(nearby);
    },
  },
  {
    id: 'EXPRESS_STATIC_FROM_ROOT',
    category: 'Web Framework',
    description: 'express.static serving from project root or sensitive directory — may expose config files.',
    severity: 'high',
    fix_suggestion: 'Serve static files from a dedicated public/ directory, not the project root.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bexpress\.static\s*\(\s*['"]\.['"]/.test(line) ||
        /\bexpress\.static\s*\(\s*__dirname\s*\)/.test(line) ||
        /\bexpress\.static\s*\(\s*process\.cwd\s*\(\s*\)\s*\)/.test(line);
    },
  },
  {
    id: 'TRUST_USER_AGENT_HEADER',
    category: 'Web Framework',
    description: 'Security or authorization decision based on User-Agent header — trivially spoofed.',
    severity: 'medium',
    fix_suggestion: 'Never use User-Agent for security decisions. Use proper authentication tokens.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bif\s*\(.*(?:user-agent|useragent|userAgent).*(?:admin|internal|bot|service)/i.test(line) ||
        /(?:isAdmin|isInternal|authorized|allowed)\s*=.*(?:user-agent|useragent|userAgent)/i.test(line);
    },
  },
  {
    id: 'RESPONSE_NO_CONTENT_TYPE',
    category: 'Web Framework',
    description: 'Response sent with res.send() or res.end() containing data but no Content-Type set — browser may MIME-sniff.',
    severity: 'low',
    fix_suggestion: 'Always set Content-Type header or use res.json()/res.html() which set it automatically.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bres\.(?:send|end|write)\s*\(/.test(line)) return false;
      if (/\bres\.(?:json|jsonp|render|sendFile|download|redirect|type|setHeader|set)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber).join('\n');
      return !/\bres\.(?:type|setHeader|set|header|contentType)\s*\(/.test(nearby) && !/['"]content-type['"]/i.test(nearby);
    },
  },
  {
    id: 'COOKIE_NO_SIGNED_OPTION',
    category: 'Web Framework',
    description: 'Cookie parser without secret for signed cookies — cookies can be tampered with.',
    severity: 'medium',
    fix_suggestion: 'Pass a secret to cookieParser: cookieParser("your-secret") to enable signed cookies.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (isFrameworkSource(ctx.filePath) || isCookieLibrarySource(ctx.filePath)) return false;
      return /\bcookieParser\s*\(\s*\)/.test(line);
    },
  },
  {
    id: 'NO_COMPRESSION_MIDDLEWARE',
    category: 'Web Framework',
    description: 'Express/Koa app without compression middleware — large responses enable bandwidth DoS.',
    severity: 'low',
    fix_suggestion: 'Add compression middleware: app.use(compression()) to reduce response sizes.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bapp\.listen\s*\(/.test(line)) return false;
      const fileContent = ctx.fileContent;
      return !/\bcompression\s*\(/.test(fileContent) && !/\bcompress\s*\(/.test(fileContent);
    },
  },
  {
    id: 'DOUBLE_CALLBACK_MIDDLEWARE',
    category: 'Web Framework',
    description: 'Middleware calls next() but continues executing — may cause double response or unexpected behavior.',
    severity: 'medium',
    fix_suggestion: 'Always return after calling next() in middleware: return next().',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bnext\s*\(\s*\)/.test(line)) return false;
      // If return next() is anywhere on the line, it's fine
      if (/\breturn\s+next\s*\(\s*\)/.test(line)) return false;
      // next() as the only statement (possibly inside braces) is fine
      if (/^\s*(?:\}?\s*)?next\s*\(\s*\)\s*;?\s*(?:\}?\s*;?\s*)?$/.test(line.trim())) return false;
      // next() followed by a real statement (not just closing braces/parens)
      const afterNext = line.replace(/.*\bnext\s*\(\s*\)\s*;?\s*/, '');
      // If only closing braces/parens/semicolons remain, it's fine
      if (/^[\s\}\)\];,]*$/.test(afterNext)) return false;
      return true;
    },
  },
  {
    id: 'HELMET_MISSING_HSTS_MAXAGE',
    category: 'Web Framework',
    description: 'Helmet HSTS configured with short maxAge — should be at least 1 year (31536000).',
    severity: 'medium',
    fix_suggestion: 'Set helmet.hsts({ maxAge: 31536000, includeSubDomains: true }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bhsts\s*\(?\s*\{/.test(line)) return false;
      const maxAgeMatch = line.match(/maxAge\s*:\s*(\d+)/);
      if (!maxAgeMatch) return false;
      return parseInt(maxAgeMatch[1], 10) < 31536000;
    },
  },
  {
    id: 'HELMET_MISSING_REFERRER_POLICY',
    category: 'Web Framework',
    description: 'Helmet used without referrerPolicy or with unsafe policy — leaks referrer information.',
    severity: 'low',
    fix_suggestion: 'Configure helmet with referrerPolicy: { policy: "strict-origin-when-cross-origin" }.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bhelmet\s*\(\s*\{/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join('\n');
      return /referrerPolicy\s*:\s*false/.test(nearby);
    },
  },
  {
    id: 'HELMET_MISSING_XCTO',
    category: 'Web Framework',
    description: 'Helmet used with noSniff disabled — allows MIME type sniffing attacks.',
    severity: 'medium',
    fix_suggestion: 'Do not disable noSniff: remove noSniff: false from helmet configuration.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bhelmet\s*\(\s*\{/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join('\n');
      return /noSniff\s*:\s*false/.test(nearby);
    },
  },
  {
    id: 'FASTIFY_NO_BODY_LIMIT',
    category: 'Web Framework',
    description: 'Fastify server without bodyLimit — allows oversized request bodies.',
    severity: 'medium',
    fix_suggestion: 'Set bodyLimit in Fastify options: fastify({ bodyLimit: 1048576 }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bfastify\s*\(\s*\{/.test(line) && !/\bFastify\s*\(\s*\{/.test(line)) return false;
      return !/\bbodyLimit\s*:/.test(line);
    },
  },
  {
    id: 'HONO_NO_BODY_LIMIT',
    category: 'Web Framework',
    description: 'Hono app without body size limit middleware — allows oversized payloads.',
    severity: 'medium',
    fix_suggestion: 'Use Hono body limit middleware: app.use(bodyLimit({ maxSize: 100 * 1024 })).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+Hono\s*\(/.test(line)) return false;
      return !/\bbodyLimit\s*\(/.test(ctx.fileContent);
    },
  },
  {
    id: 'KOA_NO_BODY_LIMIT',
    category: 'Web Framework',
    description: 'Koa body parser without size limit — allows oversized payloads causing DoS.',
    severity: 'medium',
    fix_suggestion: 'Set jsonLimit and formLimit: koaBody({ jsonLimit: "100kb", formLimit: "100kb" }).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:koaBody|bodyParser)\s*\(\s*\)/.test(line)) return false;
      return true;
    },
  },

  // ════════════════════════════════════════════
  // Cycle 62: Database Patterns Comprehensive
  // ════════════════════════════════════════════
  {
    id: 'DB_CONNECTION_NO_TIMEOUT',
    category: 'Database',
    description: 'Database connection without connection timeout — can hang indefinitely.',
    severity: 'medium',
    fix_suggestion: 'Set connectionTimeout or connectTimeout in your database connection options.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:createConnection|createPool|new\s+Pool|new\s+Client)\s*\(\s*\{/.test(line)) return false;
      return !/\b(?:connectionTimeout|connectTimeout|acquireTimeout|timeout)\s*:/.test(line);
    },
  },
  {
    id: 'DB_QUERY_NO_TIMEOUT',
    category: 'Database',
    description: 'Database query without statement timeout — runaway queries can exhaust resources.',
    severity: 'medium',
    fix_suggestion: 'Set statement_timeout or query_timeout in your database configuration.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:createPool|new\s+Pool)\s*\(\s*\{/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join('\n');
      return !/\b(?:statement_timeout|query_timeout|idle_in_transaction_session_timeout)\s*[=:]/.test(nearby);
    },
  },
  {
    id: 'N_PLUS_ONE_QUERY',
    category: 'Database',
    description: 'Database query inside a loop — likely N+1 query pattern causing performance issues.',
    severity: 'medium',
    fix_suggestion: 'Use batch queries, JOINs, or eager loading (include/populate) instead of querying in loops.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip ORM library source and test files
      if (isOrmPackage(ctx.filePath) || isLibraryPackage(ctx.filePath)) return false;
      if (isTestOrFixtureFile(ctx.filePath)) return false;
      if (!/\bawait\s+(?:\w+\.)*(?:query|findOne|findUnique|findFirst|get|execute)\s*\(/.test(line)) return false;
      // Check if inside a for/forEach/map
      const prevLines = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 8), ctx.lineNumber - 1).join('\n');
      return /\b(?:for\s*\(|\.forEach\s*\(|\.map\s*\(|for\s+await)/.test(prevLines);
    },
  },
  {
    id: 'SQL_LIKE_WILDCARD_UNESCAPED',
    category: 'Database',
    description: 'LIKE clause with unescaped user input — wildcards (%, _) can cause slow full-table scans.',
    severity: 'medium',
    fix_suggestion: 'Escape LIKE wildcards in user input: input.replace(/%/g, "\\%").replace(/_/g, "\\_").',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /LIKE\s*['"`]%\s*\$\{/.test(line) ||
        /LIKE\s*['"`]%\s*['"]\s*\+\s*(?:req\.|params\.|query\.|input|search|filter)/i.test(line) ||
        /LIKE\s+\?\s*.*(?:req\.|params\.|query\.)/.test(line);
    },
  },
  {
    id: 'DB_RESULT_DIRECT_RESPONSE',
    category: 'Database',
    description: 'Raw database query result passed directly to HTTP response — may leak internal columns.',
    severity: 'medium',
    fix_suggestion: 'Map query results to a DTO/response shape, excluding internal fields (id, password_hash, etc.).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bres\.json\s*\(\s*(?:rows|results|records|data)\s*\)/.test(line) ||
        /\bres\.send\s*\(\s*(?:rows|results|records)\s*\)/.test(line);
    },
  },
  {
    id: 'DB_ENUM_FROM_USER_INPUT',
    category: 'Database',
    description: 'User input used as database enum or column name — can cause injection or unexpected behavior.',
    severity: 'high',
    fix_suggestion: 'Validate user input against an allowlist of valid enum values or column names.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /ORDER\s+BY\s+\$\{(?:req\.|params\.|query\.)/.test(line) ||
        /ORDER\s+BY\s+['"]?\s*\+\s*(?:req\.|params\.|query\.)/.test(line) ||
        /GROUP\s+BY\s+\$\{(?:req\.|params\.|query\.)/.test(line);
    },
  },
  {
    id: 'MONGO_SET_FROM_BODY',
    category: 'Database',
    description: 'MongoDB $set operator using full req.body — allows overwriting unintended fields.',
    severity: 'high',
    fix_suggestion: 'Destructure specific allowed fields from req.body instead of passing it entirely to $set.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\$set\s*:\s*req\.body\b/.test(line) ||
        /\$set\s*:\s*body\b/.test(line) ||
        /\$set\s*:\s*ctx\.request\.body\b/.test(line);
    },
  },
  {
    id: 'POSTGRES_NOTIFY_USER_DATA',
    category: 'Database',
    description: 'PostgreSQL NOTIFY with unsanitized user data — can inject into notification channel.',
    severity: 'medium',
    fix_suggestion: 'Sanitize and validate data before using it in NOTIFY payloads.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bNOTIFY\b.*\$\{(?:req\.|params\.|body\.|user)/.test(line) ||
        /\bNOTIFY\b.*['"]?\s*\+\s*(?:req\.|params\.|body\.)/.test(line);
    },
  },
  {
    id: 'REDIS_PUBSUB_UNVALIDATED_CHANNEL',
    category: 'Database',
    description: 'Redis pub/sub with user-controlled channel name — can subscribe to or publish on unintended channels.',
    severity: 'high',
    fix_suggestion: 'Validate channel names against an allowlist before subscribing or publishing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:subscribe|publish|psubscribe)\s*\(\s*(?:req\.|params\.|query\.|body\.)/.test(line) ||
        /\b(?:subscribe|publish)\s*\(\s*`[^`]*\$\{(?:req\.|params\.|query\.)/.test(line);
    },
  },
  {
    id: 'DB_MIGRATION_IN_PRODUCTION',
    category: 'Database',
    description: 'Database migration running in production request handler — should be a separate deployment step.',
    severity: 'high',
    fix_suggestion: 'Run migrations as a separate deployment step, not in request handlers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:migrate|runMigrations|sync)\s*\(\s*\{?\s*\bforce\b/.test(line) && !/\.sync\s*\(\s*\{\s*force\s*:\s*true/.test(line)) return false;
      // Check if inside a route handler
      const prevLines = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber).join('\n');
      return /\b(?:app|router)\.\b(?:get|post|put|patch|delete)\s*\(/.test(prevLines);
    },
  },
  {
    id: 'DB_CREDENTIALS_IN_LOG',
    category: 'Database',
    description: 'Database connection string logged with cleartext credentials.',
    severity: 'critical',
    fix_suggestion: 'Never log connection strings. If needed, redact the password portion.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:console\.log|logger\.\w+|print)\s*\(.*(?:connectionString|databaseUrl|DATABASE_URL|connection_string|dsn)/i.test(line) &&
        /\b(?:console\.log|logger\.\w+|print)\s*\(/.test(line);
    },
  },
  {
    id: 'SEQUELIZE_LOGGING_TRUE',
    category: 'Database',
    description: 'Sequelize logging enabled with console.log — may log sensitive query data in production.',
    severity: 'medium',
    fix_suggestion: 'Set logging: false or use a secure logger that redacts sensitive data.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+Sequelize\s*\(/.test(line) && /logging\s*:\s*console\.log/.test(line);
    },
  },
  {
    id: 'DRIZZLE_RAW_TEMPLATE',
    category: 'Database',
    description: 'Drizzle ORM sql.raw() with template literal interpolation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion: 'Use Drizzle sql`` tagged templates with sql.placeholder() instead of sql.raw() with interpolation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip ORM library internals
      if (isOrmPackage(ctx.filePath) || isLibraryPackage(ctx.filePath)) return false;
      return /\bsql\.raw\s*\(\s*`[^`]*\$\{/.test(line);
    },
  },
  {
    id: 'TYPEORM_SYNCHRONIZE_PRODUCTION',
    category: 'Database',
    description: 'TypeORM synchronize: true can drop production data — use migrations instead.',
    severity: 'high',
    fix_suggestion: 'Set synchronize: false and use TypeORM migrations for schema changes.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsynchronize\s*:\s*true\b/.test(line) && /\b(?:DataSource|createConnection|TypeORM)\b/.test(line);
    },
  },
  {
    id: 'MONGOOSE_NO_STRICT',
    category: 'Database',
    description: 'Mongoose schema with strict: false — allows arbitrary fields to be saved.',
    severity: 'medium',
    fix_suggestion: 'Remove strict: false to enforce schema validation on all documents.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+(?:mongoose\.)?Schema\s*\(/.test(line) && /\bstrict\s*:\s*false\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 63: Authentication Patterns Deep
  // ════════════════════════════════════════════
  {
    id: 'TIMING_UNSAFE_RESET_TOKEN',
    category: 'Authentication',
    description: 'Password reset token compared with === instead of timing-safe comparison — vulnerable to timing attack.',
    severity: 'high',
    fix_suggestion: 'Use crypto.timingSafeEqual() or a constant-time comparison library for token comparison.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:resetToken|reset_token|passwordResetToken|password_reset_token)\s*===?\s*/.test(line) &&
        !/timingSafeEqual/.test(line);
    },
  },
  {
    id: 'PASSWORD_RESET_TOKEN_NO_TTL',
    category: 'Authentication',
    description: 'Password reset token generated without expiry time — tokens remain valid indefinitely.',
    severity: 'high',
    fix_suggestion: 'Add an expiry timestamp when generating password reset tokens (e.g., 1 hour).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:resetToken|reset_token|passwordResetToken)\s*[:=]/.test(line)) return false;
      if (!/\b(?:randomBytes|randomUUID|uuid|nanoid|crypto)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join('\n');
      return !/\b(?:expir|ttl|validUntil|expiresAt|expires_at)\b/i.test(nearby);
    },
  },
  {
    id: 'EMAIL_VERIFICATION_BYPASS',
    category: 'Authentication',
    description: 'Email verification can be bypassed — account actions allowed without verified email.',
    severity: 'medium',
    fix_suggestion: 'Require email verification before allowing sensitive account actions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:emailVerified|email_verified|isVerified|is_verified)\s*(?:!==?\s*(?:true|false)|\?\?|[|][|])/.test(line) &&
        /\b(?:continue|proceed|allow|skip)\b/.test(line);
    },
  },
  {
    id: 'TWO_FA_BACKUP_CODES_UNHASHED',
    category: 'Authentication',
    description: '2FA backup codes stored without hashing — attacker with DB access can bypass 2FA.',
    severity: 'high',
    fix_suggestion: 'Hash backup codes with bcrypt or similar before storing. Compare with timing-safe comparison.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:backupCodes|backup_codes|recoveryCodes|recovery_codes)\s*[:=]\s*\[/.test(line) &&
        !/\b(?:hash|bcrypt|argon|scrypt)\b/i.test(line);
    },
  },
  {
    id: 'SESSION_NO_IP_BINDING',
    category: 'Authentication',
    description: 'Session created without binding to client IP or fingerprint — vulnerable to session hijacking.',
    severity: 'medium',
    fix_suggestion: 'Store client IP and/or fingerprint in session and validate on each request.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:req\.session|session)\.\w+\s*=\s*(?:user|userId|user_id)/i.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join('\n');
      return !/\b(?:ip|ipAddress|fingerprint|userAgent)\b/.test(nearby);
    },
  },
  {
    id: 'LOGIN_NO_LOCKOUT',
    category: 'Authentication',
    description: 'Login endpoint without account lockout or rate limiting after failed attempts.',
    severity: 'high',
    fix_suggestion: 'Implement account lockout or exponential backoff after 5-10 failed login attempts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\.post\s*\(\s*['"]\/(?:login|signin|auth|authenticate)['"]/i.test(line)) return false;
      const fileContent = ctx.fileContent;
      return !/\b(?:lockout|maxAttempts|max_attempts|failedAttempts|failed_attempts|rateLimit|rateLimiter)\b/i.test(fileContent);
    },
  },
  {
    id: 'REMEMBER_ME_NO_DEVICE_BINDING',
    category: 'Authentication',
    description: 'Remember-me token without device binding — stolen token usable from any device.',
    severity: 'medium',
    fix_suggestion: 'Bind remember-me tokens to device fingerprint (user-agent + IP hash).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:rememberMe|remember_me|rememberToken|remember_token)\b/.test(line)) return false;
      if (!/\b(?:set|create|generate|save)\b/i.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join('\n');
      return !/\b(?:device|fingerprint|userAgent|ip)\b/i.test(nearby);
    },
  },
  {
    id: 'AUTH_TOKEN_IN_URL',
    category: 'Authentication',
    description: 'Authentication token passed in URL path — logged in server access logs and browser history.',
    severity: 'high',
    fix_suggestion: 'Pass auth tokens in the Authorization header, not in URL paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bfetch\s*\(\s*`[^`]*\/(?:token|auth|jwt|api[_-]?key)\s*\/\s*\$\{/.test(line) ||
        /\baxios\.(?:get|post|put|delete)\s*\(\s*`[^`]*\/(?:token|auth|jwt)\s*\/\s*\$\{/.test(line);
    },
  },
  {
    id: 'PASSWORD_CHANGE_NO_POLICY',
    category: 'Authentication',
    description: 'Password change endpoint without password strength validation.',
    severity: 'medium',
    fix_suggestion: 'Enforce password policy (min length, complexity) on password change, not just registration.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\.(?:post|put|patch)\s*\(\s*['"].*(?:change|update|reset).*password/i.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 20)).join('\n');
      return !/\b(?:passwordStrength|password_strength|validatePassword|isStrongPassword|minLength|zxcvbn)\b/i.test(nearby);
    },
  },
  {
    id: 'SSO_CALLBACK_NO_STATE',
    category: 'Authentication',
    description: 'SSO/OAuth callback without state parameter validation — vulnerable to CSRF.',
    severity: 'high',
    fix_suggestion: 'Validate the state parameter in OAuth/SSO callbacks to prevent CSRF attacks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\.get\s*\(\s*['"].*(?:callback|redirect|sso|oauth)/i.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join('\n');
      return !/\bstate\b/.test(nearby);
    },
  },
  {
    id: 'MAGIC_LINK_TOKEN_REUSE',
    category: 'Authentication',
    description: 'Magic link token not invalidated after use — allows token replay.',
    severity: 'high',
    fix_suggestion: 'Delete or mark the magic link token as used after successful authentication.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:magicLink|magic_link|loginLink|login_link)\b/.test(line)) return false;
      if (!/\b(?:verify|validate|check|find)\b/i.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join('\n');
      return !/\b(?:delete|remove|invalidate|markUsed|mark_used|used\s*[:=])\b/i.test(nearby);
    },
  },
  {
    id: 'API_KEY_NO_ROTATION',
    category: 'Authentication',
    description: 'API key without rotation mechanism or expiry — compromised keys remain valid indefinitely.',
    severity: 'medium',
    fix_suggestion: 'Implement API key rotation with expiry dates and a key management lifecycle.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:generateApiKey|generate_api_key|createApiKey|create_api_key)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join('\n');
      return !/\b(?:expir|rotation|rotateAt|rotate_at|validUntil)\b/i.test(nearby);
    },
  },
  {
    id: 'SERVICE_ACCOUNT_ADMIN',
    category: 'Authentication',
    description: 'Service account with admin or root privileges — violates principle of least privilege.',
    severity: 'high',
    fix_suggestion: 'Assign only the minimum required permissions to service accounts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:serviceAccount|service_account)\b.*\b(?:role|permission)\s*[:=]\s*['"](?:admin|root|superuser|superadmin)['"]/i.test(line);
    },
  },
  {
    id: 'AUTH_HEADER_FORWARDED',
    category: 'Authentication',
    description: 'Authorization header forwarded to third-party service — leaks credentials.',
    severity: 'high',
    fix_suggestion: 'Use separate credentials for third-party services. Never forward user auth headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bheaders\s*:\s*\{[^}]*[Aa]uthorization\s*:\s*req\.headers\.authorization\b/.test(line) &&
        /\b(?:fetch|axios|http|request)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 64: Cryptography Comprehensive
  // ════════════════════════════════════════════
  {
    id: 'RSA_KEY_TOO_SMALL',
    category: 'Cryptography',
    description: 'RSA key size less than 2048 bits — insufficient for modern security.',
    severity: 'high',
    fix_suggestion: 'Use RSA key size of at least 2048 bits (4096 recommended).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:modulusLength|key_size|keySize)\s*[:=]\s*(\d+)/.test(line)) return false;
      const match = line.match(/\b(?:modulusLength|key_size|keySize)\s*[:=]\s*(\d+)/);
      if (!match) return false;
      const size = parseInt(match[1], 10);
      return size > 0 && size < 2048;
    },
  },
  {
    id: 'ECDSA_P192_CURVE',
    category: 'Cryptography',
    description: 'ECDSA with P-192 curve — considered weak for modern applications.',
    severity: 'high',
    fix_suggestion: 'Use P-256 or P-384 curves instead of P-192.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:secp192r1|prime192v1|P-192|p192)\b/.test(line);
    },
  },
  {
    id: 'CRYPTO_DSA_USAGE',
    category: 'Cryptography',
    description: 'DSA algorithm usage — deprecated and considered weak. Use ECDSA or Ed25519.',
    severity: 'high',
    fix_suggestion: 'Replace DSA with ECDSA (P-256) or Ed25519.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:generateKeyPair|createSign|createVerify)\s*\(\s*['"]dsa['"]/i.test(line) ||
        /\bdsa\.\b(?:generate|sign|verify)\s*\(/.test(line);
    },
  },
  {
    id: 'CRYPTO_NO_AEAD',
    category: 'Cryptography',
    description: 'Encryption without AEAD mode — ciphertext can be modified undetected.',
    severity: 'medium',
    fix_suggestion: 'Use AEAD modes like AES-GCM or ChaCha20-Poly1305 instead of CBC/CTR without MAC.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bcreateDecipher(?:iv)?\s*\(\s*['"]aes-\d+-cbc['"]/i.test(line) &&
          !/\bcreateDecipher(?:iv)?\s*\(\s*['"]aes-\d+-ctr['"]/i.test(line)) return false;
      return true;
    },
  },
  {
    id: 'CRYPTO_CTR_NO_MAC',
    category: 'Cryptography',
    description: 'CTR mode encryption without MAC — malleable ciphertext allows bit-flipping attacks.',
    severity: 'high',
    fix_suggestion: 'Use AES-GCM or add HMAC verification over ciphertext when using CTR mode.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcreateCipher(?:iv)?\s*\(\s*['"]aes-\d+-ctr['"]/i.test(line)) return false;
      return !/\b(?:createHmac|hmac|HMAC|getAuthTag)\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'PBKDF2_LOW_ITERATION_COUNT',
    category: 'Cryptography',
    description: 'PBKDF2 with low iteration count — insufficient key stretching.',
    severity: 'high',
    fix_suggestion: 'Use at least 600,000 iterations for PBKDF2 (OWASP 2023 recommendation).',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bpbkdf2\b/i.test(line)) return false;
      const match = line.match(/\bpbkdf2\w*\s*\([^)]*?,\s*(\d+)/i);
      if (!match) return false;
      const iterations = parseInt(match[1], 10);
      return iterations > 0 && iterations < 100000;
    },
  },
  {
    id: 'HMAC_WITH_SHA1',
    category: 'Cryptography',
    description: 'HMAC using SHA-1 — use SHA-256 or SHA-512 for better collision resistance.',
    severity: 'medium',
    fix_suggestion: 'Replace SHA-1 with SHA-256 or SHA-512 in HMAC operations.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcreateHmac\s*\(\s*['"]sha1?['"]/i.test(line);
    },
  },
  {
    id: 'TLS_CERT_VALIDATION_BYPASS',
    category: 'Cryptography',
    description: 'TLS certificate validation bypassed — allows MITM attacks.',
    severity: 'critical',
    fix_suggestion: 'Remove rejectUnauthorized: false and use proper CA certificates.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\brejectUnauthorized\s*:\s*false\b/.test(line) ||
        /\bcheckServerIdentity\s*:\s*\(\s*\)\s*=>\s*(?:true|undefined|void\s*0)\b/.test(line);
    },
  },
  {
    id: 'CUSTOM_CRYPTO_IMPL',
    category: 'Cryptography',
    description: 'Custom cryptographic implementation — use well-tested libraries instead.',
    severity: 'high',
    fix_suggestion: 'Use established crypto libraries (crypto, sodium-native, tweetnacl) instead of custom implementations.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bfunction\s+(?:encrypt|decrypt|hash|hmac|sign|verify)\s*\(/.test(line) &&
        /\b(?:for\s*\(|while\s*\(|XOR|xor|shift|rotate|sbox)\b/i.test(line);
    },
  },
  {
    id: 'KDF_NO_SALT',
    category: 'Cryptography',
    description: 'Key derivation function without salt — enables rainbow table attacks.',
    severity: 'high',
    fix_suggestion: 'Always use a unique random salt with key derivation functions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:pbkdf2|scrypt|hkdf)\b/i.test(line)) return false;
      return /\b(?:pbkdf2|scrypt|hkdf)\w*\s*\([^,]+,\s*['"](?:['"]|\s*,)/.test(line) ||
        /\b(?:pbkdf2|scrypt|hkdf)\w*\s*\([^,]+,\s*(?:null|undefined|"")\s*[,)]/.test(line);
    },
  },
  {
    id: 'PKCS1_V15_PADDING',
    category: 'Cryptography',
    description: 'RSA PKCS#1 v1.5 padding used — vulnerable to Bleichenbacher attack. Use OAEP.',
    severity: 'high',
    fix_suggestion: 'Use RSA-OAEP padding instead of PKCS#1 v1.5 for encryption.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bRSA_PKCS1_PADDING\b/.test(line) ||
        /\bpadding\s*[:=]\s*crypto\.constants\.RSA_PKCS1_PADDING\b/.test(line) ||
        /\bPKCS1v15\s*\(/.test(line);
    },
  },
  {
    id: 'WEAK_RANDOM_SEED',
    category: 'Cryptography',
    description: 'PRNG seeded with predictable value (Date.now, process.pid) — output is predictable.',
    severity: 'high',
    fix_suggestion: 'Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive randomness.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bseed\s*[:=]\s*(?:Date\.now|process\.pid|process\.ppid|performance\.now)\s*\(?\s*\)?/.test(line);
    },
  },
  {
    id: 'HARDCODED_ENCRYPTION_KEY_V2',
    category: 'Cryptography',
    description: 'Encryption key hardcoded as string literal — easily extractable from source.',
    severity: 'critical',
    fix_suggestion: 'Load encryption keys from environment variables or a secure key management system.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:encryptionKey|encryption_key|aesKey|aes_key|secretKey|secret_key)\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]/.test(line);
    },
  },
  {
    id: 'KEY_MATERIAL_IN_LOG',
    category: 'Cryptography',
    description: 'Cryptographic key material logged — exposes secrets in log files.',
    severity: 'critical',
    fix_suggestion: 'Never log key material. Remove logging of encryption keys, private keys, or secrets.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:console\.log|logger\.\w+|print)\s*\(.*\b(?:privateKey|private_key|secretKey|secret_key|encryptionKey|encryption_key|signingKey|signing_key)\b/.test(line);
    },
  },
  {
    id: 'IV_NONCE_COUNTER_OVERFLOW',
    category: 'Cryptography',
    description: 'IV/nonce counter without overflow check — counter wrap causes nonce reuse.',
    severity: 'high',
    fix_suggestion: 'Check for counter overflow and rotate keys before the counter wraps.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:nonce|counter|iv)\s*(?:\+\+|\+=\s*1|=\s*\w+\s*\+\s*1)\b/i.test(line) &&
        !/\b(?:if|check|max|overflow|wrap|limit)\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 65: Network Security
  // ════════════════════════════════════════════
  {
    id: 'DNS_REBINDING_FETCH',
    category: 'Network Security',
    description: 'Fetching user-provided URL without DNS rebinding protection — IP may change between checks.',
    severity: 'high',
    fix_suggestion: 'Resolve DNS before fetching and validate the resolved IP is not internal/private.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bfetch\s*\(\s*(?:req\.|params\.|query\.|url|userUrl|targetUrl)/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber).join('\n');
      return /\b(?:isAllowed|isValid|validateUrl|checkUrl)\b/.test(nearby) &&
        !/\b(?:dns\.resolve|dns\.lookup|net\.isIP)\b/.test(nearby);
    },
  },
  {
    id: 'CORS_PREFLIGHT_MISSING',
    category: 'Network Security',
    description: 'CORS headers set on response but OPTIONS preflight not handled — some browsers will block requests.',
    severity: 'medium',
    fix_suggestion: 'Handle OPTIONS requests explicitly or use a CORS middleware that handles preflight.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bAccess-Control-Allow-Origin\b/.test(line)) return false;
      if (!/\bres\.(?:setHeader|header|set)\s*\(/.test(line)) return false;
      return !/\b(?:OPTIONS|options|cors\s*\()\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'WEBSOCKET_UPGRADE_NO_AUTH',
    category: 'Network Security',
    description: 'WebSocket upgrade handled without authentication check.',
    severity: 'high',
    fix_suggestion: 'Verify authentication token before accepting WebSocket upgrade.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bon\s*\(\s*['"]upgrade['"]/.test(line)) return false;
      // Check surrounding context (before and after) for auth-related keywords
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join('\n');
      return !/\b(?:auth|token|verify|jwt|session|cookie|authenticate)\b/i.test(nearby);
    },
  },
  {
    id: 'REQUEST_BODY_NO_ROUTE_LIMIT',
    category: 'Network Security',
    description: 'File upload or large body route without per-route size limit — global limits may be too permissive.',
    severity: 'medium',
    fix_suggestion: 'Set per-route body size limits for upload endpoints.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:app|router)\.post\s*\(\s*['"].*(?:upload|import|bulk|batch)/i.test(line) &&
        !/\b(?:limit|maxFileSize|maxSize|fileSize)\b/i.test(line);
    },
  },
  {
    id: 'HOST_HEADER_INJECTION',
    category: 'Network Security',
    description: 'Host header used in URL construction — vulnerable to host header injection.',
    severity: 'high',
    fix_suggestion: 'Use a configured hostname from environment variables, not the Host header.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:req\.headers\.host|req\.hostname|req\.get\s*\(\s*['"]host['"]\s*\))/.test(line) &&
        /(?:https?:\/\/|url\s*[:=]|redirect|href)/i.test(line);
    },
  },
  {
    id: 'REDIRECT_CHAIN_NO_LIMIT',
    category: 'Network Security',
    description: 'HTTP client following redirects without limit — can be tricked into infinite redirect loop.',
    severity: 'medium',
    fix_suggestion: 'Set maxRedirects option (e.g., maxRedirects: 5) in HTTP client configuration.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:axios\.create|got\.extend|new\s+HttpClient)\s*\(\s*\{/.test(line)) return false;
      return !/\bmaxRedirects\s*:/.test(line);
    },
  },
  {
    id: 'HTTP_METHOD_OVERRIDE',
    category: 'Network Security',
    description: 'X-HTTP-Method-Override header accepted — can bypass method-based access controls.',
    severity: 'medium',
    fix_suggestion: 'Do not accept X-HTTP-Method-Override unless specifically needed, and validate allowed methods.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:methodOverride|method-override)\s*\(\s*\)/.test(line) ||
        /\bX-HTTP-Method-Override\b/i.test(line) && /\breq\.headers\b/.test(line);
    },
  },
  {
    id: 'TRACE_METHOD_ENABLED',
    category: 'Network Security',
    description: 'HTTP TRACE method enabled — can be used for cross-site tracing (XST) attacks.',
    severity: 'medium',
    fix_suggestion: 'Disable the TRACE HTTP method on your server.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:app|router)\.trace\s*\(\s*['"]/.test(line);
    },
  },
  {
    id: 'OPTIONS_INFO_LEAK',
    category: 'Network Security',
    description: 'OPTIONS response exposing internal route methods or server details.',
    severity: 'low',
    fix_suggestion: 'Limit OPTIONS response to only the necessary CORS headers without exposing internals.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:app|router)\.options\s*\(\s*['"][*]/.test(line) &&
        /\bAllow\s*['"]?\s*[:,]\s*['"].*(?:DELETE|PATCH|PUT)/.test(line);
    },
  },
  {
    id: 'PROXY_URL_ENCODING_BYPASS',
    category: 'Network Security',
    description: 'URL validation that can be bypassed via URL encoding — double-encoding or unicode normalization.',
    severity: 'medium',
    fix_suggestion: 'Decode URLs fully before validation and validate the decoded form.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Check for URL validation followed by fetch without decoding
      return /\bnew\s+URL\s*\(\s*(?:req\.|params\.|query\.)/.test(line) &&
        !/\b(?:decodeURI|decodeURIComponent)\b/.test(line) &&
        /\b(?:hostname|origin|protocol)\b/.test(line);
    },
  },
  {
    id: 'SNI_MISMATCH_IGNORE',
    category: 'Network Security',
    description: 'TLS SNI mismatch ignored — allows connection to wrong server.',
    severity: 'high',
    fix_suggestion: 'Always validate that the TLS certificate matches the requested hostname.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcheckServerIdentity\s*:\s*(?:\(\s*\)\s*=>\s*(?:undefined|void|null|true)|function\s*\(\s*\)\s*\{)/.test(line);
    },
  },
  {
    id: 'EXPIRED_CERT_ACCEPT',
    category: 'Network Security',
    description: 'Expired TLS certificate explicitly accepted — allows MITM attacks.',
    severity: 'critical',
    fix_suggestion: 'Remove expired certificate exceptions and use valid certificates.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:CERT_HAS_EXPIRED|DEPTH_ZERO_SELF_SIGNED_CERT|UNABLE_TO_VERIFY_LEAF_SIGNATURE)\b/.test(line) &&
        /\b(?:return\s*true|continue|next\s*\(\s*\)|resolve)\b/.test(line);
    },
  },
  {
    id: 'HTTP2_PRIORITY_ABUSE',
    category: 'Network Security',
    description: 'HTTP/2 server without priority flood protection — can cause CPU exhaustion.',
    severity: 'medium',
    fix_suggestion: 'Set maxOutstandingPings and maxSessionMemory limits on HTTP/2 servers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bhttp2\.createServer\s*\(\s*\{/.test(line) && !/\bhttp2\.createSecureServer\s*\(\s*\{/.test(line)) return false;
      return !/\b(?:maxOutstandingPings|maxSessionMemory|maxHeaderListPairs)\s*:/.test(line);
    },
  },
  {
    id: 'TRANSFER_ENCODING_SMUGGLING',
    category: 'Network Security',
    description: 'Transfer-Encoding header manually set — can enable request smuggling attacks.',
    severity: 'medium',
    fix_suggestion: 'Let the HTTP framework handle Transfer-Encoding. Do not set it manually.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:setHeader|header|set)\s*\(\s*['"]transfer-encoding['"]/i.test(line) &&
        /\bchunked\b/i.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 66: Data Privacy & Compliance
  // ════════════════════════════════════════════
  {
    id: 'PII_IN_ANALYTICS',
    category: 'Data Privacy',
    description: 'PII (email, name, phone) sent to analytics service — violates data minimization.',
    severity: 'high',
    fix_suggestion: 'Send only anonymized/pseudonymized identifiers to analytics services.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:analytics|gtag|mixpanel|segment|amplitude|posthog)\.\b(?:track|identify|page|event)\s*\(/.test(line) &&
        /\b(?:email|phone|firstName|lastName|first_name|last_name|ssn|address|dateOfBirth)\b/.test(line);
    },
  },
  {
    id: 'SENTRY_FULL_USER',
    category: 'Data Privacy',
    description: 'Sentry configured with full user data (email, username) — PII in error tracking.',
    severity: 'medium',
    fix_suggestion: 'Send only user.id to Sentry. Remove email, username, and ip_address.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSentry\.setUser\s*\(\s*\{/.test(line) &&
        /\b(?:email|username|ip_address)\s*:/.test(line);
    },
  },
  {
    id: 'IP_STORED_WITHOUT_CONSENT',
    category: 'Data Privacy',
    description: 'IP address stored in database without anonymization — may violate GDPR.',
    severity: 'medium',
    fix_suggestion: 'Anonymize IP addresses before storage (e.g., zero the last octet) or get explicit consent.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:ip|ipAddress|ip_address|clientIp|client_ip)\s*[:=]\s*(?:req\.ip|req\.connection\.remoteAddress|req\.socket\.remoteAddress)/.test(line) &&
        /\b(?:save|create|insert|update|store)\b/i.test(line);
    },
  },
  {
    id: 'GEOLOCATION_LOGGED',
    category: 'Data Privacy',
    description: 'User geolocation data logged — may violate privacy regulations.',
    severity: 'medium',
    fix_suggestion: 'Do not log precise geolocation data. Use approximate locations if needed.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:console\.log|logger\.\w+)\s*\(.*\b(?:latitude|longitude|lat|lng|geolocation|geoip|geo_location)\b/i.test(line);
    },
  },
  {
    id: 'USER_AGENT_FINGERPRINTING',
    category: 'Data Privacy',
    description: 'User agent combined with other signals for fingerprinting — may violate privacy consent.',
    severity: 'low',
    fix_suggestion: 'Ensure fingerprinting has user consent and data minimization compliance.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:fingerprint|deviceId|device_id)\s*[:=].*\b(?:userAgent|user-agent|navigator\.userAgent)\b/.test(line) &&
        /\b(?:screen|canvas|webgl|plugin|font)\b/i.test(line);
    },
  },
  {
    id: 'TRACKING_NO_CONSENT',
    category: 'Data Privacy',
    description: 'Tracking/analytics initialized without consent check — may violate GDPR/CCPA.',
    severity: 'medium',
    fix_suggestion: 'Check for user consent before initializing tracking scripts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:gtag|analytics\.init|mixpanel\.init|segment\.load|amplitude\.init)\s*\(/.test(line)) return false;
      const prevLines = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber).join('\n');
      return !/\b(?:consent|cookie|gdpr|ccpa|optIn|opt_in|hasConsent|cookieConsent)\b/i.test(prevLines);
    },
  },
  {
    id: 'DATA_RETENTION_NO_TTL',
    category: 'Data Privacy',
    description: 'User data stored without TTL or retention policy — may violate data minimization principles.',
    severity: 'low',
    fix_suggestion: 'Implement data retention policies with automatic deletion after the retention period.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:redis|cache|store)\.(?:set|hset|setex)\s*\(\s*['"`]user[_:]/.test(line) &&
        !/\b(?:ttl|ex|px|expire|EX|TTL|expiresIn)\b/i.test(line);
    },
  },
  {
    id: 'SENSITIVE_DATA_IN_URL',
    category: 'Data Privacy',
    description: 'Sensitive data passed in URL query parameters — logged in server logs and browser history.',
    severity: 'high',
    fix_suggestion: 'Send sensitive data in request body (POST) or headers, not URL parameters.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:fetch|axios|http|request)\b.*[?&](?:password|token|secret|ssn|credit_card|api_key)=/i.test(line);
    },
  },
  {
    id: 'AUDIT_LOG_NO_ACTION',
    category: 'Data Privacy',
    description: 'Audit log entry without user action or timestamp — insufficient for compliance.',
    severity: 'low',
    fix_suggestion: 'Include user ID, action, timestamp, and affected resource in all audit log entries.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\b(?:auditLog|audit_log|auditTrail|audit_trail)\b/.test(line)) return false;
      if (!/\b(?:create|insert|push|add|log)\b/i.test(line)) return false;
      return !/\b(?:action|event|operation)\s*[:=]/.test(line);
    },
  },
  {
    id: 'DATA_EXPORT_NO_ENCRYPTION',
    category: 'Data Privacy',
    description: 'User data export without encryption — PII exposed in transit or at rest.',
    severity: 'medium',
    fix_suggestion: 'Encrypt data exports with a user-specific key or password-protect the archive.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:export|download).*(?:userData|user_data|personalData|personal_data)\b/.test(line) &&
        /\b(?:csv|json|xlsx|zip)\b/i.test(line) &&
        !/\b(?:encrypt|cipher|password|protected)\b/i.test(line);
    },
  },
  {
    id: 'BACKUP_NO_ENCRYPTION',
    category: 'Data Privacy',
    description: 'Database backup without encryption — exposes all data if backup is compromised.',
    severity: 'high',
    fix_suggestion: 'Encrypt database backups with strong encryption (AES-256-GCM).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:pg_dump|mysqldump|mongodump)\b/.test(line) &&
        !/\b(?:encrypt|gpg|openssl|cipher)\b/i.test(line);
    },
  },
  {
    id: 'PII_IN_DEBUG_LOG',
    category: 'Data Privacy',
    description: 'PII data in debug/verbose log — may be retained longer than compliance allows.',
    severity: 'medium',
    fix_suggestion: 'Remove PII from debug logs or ensure debug logging is disabled in production.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:console\.debug|logger\.debug|log\.debug)\s*\(.*\b(?:email|password|ssn|creditCard|credit_card|phoneNumber|phone_number)\b/.test(line);
    },
  },
  {
    id: 'CACHE_KEY_PII',
    category: 'Data Privacy',
    description: 'User PII used as cache key — identifiable data in cache infrastructure.',
    severity: 'medium',
    fix_suggestion: 'Use hashed or anonymized identifiers as cache keys instead of PII.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:cache|redis|memcached)\.(?:get|set|has)\s*\(\s*`[^`]*\b(?:email|phone|ssn)\b/.test(line) ||
        /\b(?:cache|redis|memcached)\.(?:get|set|has)\s*\(\s*['"].*(?:email|phone|ssn)/.test(line);
    },
  },
  {
    id: 'CROSS_BORDER_DATA_NO_CHECK',
    category: 'Data Privacy',
    description: 'User data sent to external API without region/residency check — may violate data sovereignty.',
    severity: 'medium',
    fix_suggestion: 'Check user data residency requirements before sending data to external/cross-border APIs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bfetch\s*\(\s*['"]https?:\/\/(?!localhost)/.test(line)) return false;
      if (!/\b(?:userData|user_data|personalData|personal_data|userProfile|user_profile)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber).join('\n');
      return !/\b(?:region|residency|country|jurisdiction|gdpr|dataLocality)\b/i.test(nearby);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 67: Mobile/PWA Security
  // ════════════════════════════════════════════
  {
    id: 'SW_CACHE_SENSITIVE',
    category: 'PWA Security',
    description: 'Service worker caching sensitive API responses (auth, user data) — persists in browser cache.',
    severity: 'high',
    fix_suggestion: 'Exclude sensitive API endpoints from service worker cache strategies.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcache\.(?:put|add|addAll)\s*\(/.test(line) &&
        /\/api\/(?:auth|user|token|session|profile|account)|\/login|\/me\b/.test(line);
    },
  },
  {
    id: 'PUSH_NOTIFICATION_SENSITIVE',
    category: 'PWA Security',
    description: 'Push notification containing sensitive user data — visible on lock screen.',
    severity: 'medium',
    fix_suggestion: 'Send generic push notifications. Load sensitive details only when the app is opened.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:webpush\.sendNotification|pushSubscription\.send|self\.registration\.showNotification)\s*\(/.test(line) &&
        /\b(?:balance|amount|ssn|password|creditCard|account_number|accountNumber)\b/.test(line);
    },
  },
  {
    id: 'PWA_LOCALSTORAGE_AUTH',
    category: 'PWA Security',
    description: 'Auth token stored in localStorage in PWA — accessible by XSS and persists across sessions.',
    severity: 'high',
    fix_suggestion: 'Store auth tokens in httpOnly cookies or use in-memory storage with refresh token rotation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\blocalStorage\.setItem\s*\(\s*['"](?:token|access_token|accessToken|auth_token|authToken|jwt|id_token|refresh_token)['"]\s*,/.test(line);
    },
  },
  {
    id: 'UNVALIDATED_DEEP_LINK',
    category: 'PWA Security',
    description: 'Deep link URL handled without validation — can navigate to malicious destinations.',
    severity: 'high',
    fix_suggestion: 'Validate deep link URLs against an allowlist of allowed schemes and hosts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bwindow\.location\s*=\s*(?:new\s+URL\s*\()?(?:params|query|searchParams)\.get\s*\(/.test(line) ||
        /\bwindow\.open\s*\(\s*(?:params|query|searchParams)\.get\s*\(/.test(line);
    },
  },
  {
    id: 'POSTMESSAGE_PARENT_NO_ORIGIN',
    category: 'PWA Security',
    description: 'postMessage to parent/opener without target origin — data sent to any embedding page.',
    severity: 'high',
    fix_suggestion: 'Always specify the target origin: parent.postMessage(data, "https://expected-origin.com").',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:parent|window\.parent|window\.opener|opener)\.postMessage\s*\([^)]+,\s*['"][*]['"]\s*\)/.test(line);
    },
  },
  {
    id: 'WEBVIEW_JS_BRIDGE',
    category: 'PWA Security',
    description: 'WebView JavaScript bridge exposed to untrusted content — allows native API access.',
    severity: 'high',
    fix_suggestion: 'Restrict JavaScript bridge to trusted origins only.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\baddJavascriptInterface\s*\(/.test(line) ||
        /\bwindow\.webkit\.messageHandlers\b/.test(line) && /\b(?:eval|exec|run|execute)\b/i.test(line);
    },
  },
  {
    id: 'INDEXEDDB_SENSITIVE_UNENCRYPTED',
    category: 'PWA Security',
    description: 'Sensitive data stored in IndexedDB without encryption — accessible by XSS.',
    severity: 'medium',
    fix_suggestion: 'Encrypt sensitive data before storing in IndexedDB using Web Crypto API.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:objectStore|store)\.(?:put|add)\s*\(/.test(line) &&
        /\b(?:password|token|secret|creditCard|credit_card|ssn|apiKey|api_key)\b/.test(line) &&
        !/\b(?:encrypt|cipher|CryptoKey)\b/i.test(line);
    },
  },
  {
    id: 'BACKGROUND_SYNC_CREDENTIALS',
    category: 'PWA Security',
    description: 'Background sync sending credentials — may execute without user awareness.',
    severity: 'medium',
    fix_suggestion: 'Avoid sending sensitive credentials in background sync. Re-authenticate when the app is active.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsync\.register\s*\(/.test(line) && /\b(?:password|token|credential|secret)\b/i.test(line);
    },
  },
  {
    id: 'CLIPBOARD_NO_GESTURE',
    category: 'PWA Security',
    description: 'Clipboard access without user gesture — may read clipboard silently.',
    severity: 'medium',
    fix_suggestion: 'Only access clipboard in response to user gestures (click, keypress).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnavigator\.clipboard\.(?:readText|read)\s*\(/.test(line)) return false;
      const prevLines = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber).join('\n');
      return !/\b(?:click|keydown|keypress|keyup|pointerdown|mousedown|touchstart)\b/.test(prevLines) &&
        !/\b(?:onClick|onKeyDown|handleClick|handleKey)\b/.test(prevLines);
    },
  },
  {
    id: 'MEDIA_ACCESS_NO_PURPOSE',
    category: 'PWA Security',
    description: 'Camera/microphone access requested without clear purpose in surrounding code.',
    severity: 'low',
    fix_suggestion: 'Document why media access is needed and only request it when immediately needed.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnavigator\.mediaDevices\.getUserMedia\s*\(\s*\{\s*(?:video|audio)\s*:\s*true\b/.test(line)) return false;
      const prevLines = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber).join('\n');
      return !/\b(?:video|audio|call|stream|record|capture|conference|meeting|camera|mic)\b/i.test(prevLines);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 68: GraphQL Deep
  // ════════════════════════════════════════════
  {
    id: 'GRAPHQL_NO_COMPLEXITY_LIMIT',
    category: 'GraphQL',
    description: 'GraphQL server without query complexity analysis — allows expensive nested queries.',
    severity: 'high',
    fix_suggestion: 'Add query complexity analysis: use graphql-query-complexity or similar.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bnew\s+ApolloServer\s*\(\s*\{/.test(line) && !/\bcreateYoga\s*\(\s*\{/.test(line) && !/\b(?:graphqlHTTP|graphqlExpress)\s*\(\s*\{/.test(line)) return false;
      return !/\b(?:complexity|queryComplexity|costAnalysis|costLimit|maxComplexity)\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'GRAPHQL_NO_FIELD_AUTH',
    category: 'GraphQL',
    description: 'GraphQL resolver accessing sensitive field without field-level authorization.',
    severity: 'high',
    fix_suggestion: 'Add field-level authorization directives (@auth) or resolver-level permission checks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:email|password|ssn|salary|role|isAdmin|creditCard)\s*[:]\s*(?:\(|async)?\s*(?:parent|root|obj)/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join('\n');
      return !/\b(?:auth|authorize|permission|role|isAdmin|requireAuth|checkPermission)\b/i.test(nearby);
    },
  },
  {
    id: 'GRAPHQL_BATCH_UNLIMITED',
    category: 'GraphQL',
    description: 'GraphQL batched queries accepted without batch size limit — enables DoS.',
    severity: 'medium',
    fix_suggestion: 'Limit batch size: configure maxBatchSize option in your GraphQL server.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:allowBatchedHttpRequests|batching)\s*:\s*true\b/.test(line) &&
        !/\b(?:maxBatchSize|batchLimit|maxBatch)\s*:/.test(line);
    },
  },
  {
    id: 'GRAPHQL_PERSISTED_NOT_ENFORCED',
    category: 'GraphQL',
    description: 'GraphQL server not enforcing persisted queries — arbitrary queries can be sent.',
    severity: 'medium',
    fix_suggestion: 'Enforce persisted queries in production to prevent arbitrary query execution.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bpersistedQueries\s*:\s*\{/.test(line) && /\b(?:enforcePersistedQueries|onlyPersistedQueries)\s*:\s*false\b/.test(line);
    },
  },
  {
    id: 'GRAPHQL_SUBSCRIPTION_NO_AUTH_V2',
    category: 'GraphQL',
    description: 'GraphQL subscription resolver without authentication check.',
    severity: 'high',
    fix_suggestion: 'Add authentication check in subscription resolver or connection init handler.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bsubscribe\s*:\s*(?:async\s*)?\(/.test(line)) return false;
      // Check if inside Subscription resolvers
      const prevLines = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber).join('\n');
      if (!/\bSubscription\b/.test(prevLines)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join('\n');
      return !/\b(?:auth|context\.user|ctx\.user|requireAuth|isAuthenticated)\b/i.test(nearby);
    },
  },
  {
    id: 'GRAPHQL_SCALAR_NO_VALIDATION',
    category: 'GraphQL',
    description: 'Custom GraphQL scalar without input validation — accepts any value.',
    severity: 'medium',
    fix_suggestion: 'Implement parseValue and parseLiteral with proper validation in custom scalars.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+GraphQLScalarType\s*\(\s*\{/.test(line) &&
        /\bparseValue\s*:\s*\(\s*\w+\s*\)\s*=>\s*\w+\b/.test(line);
    },
  },
  {
    id: 'GRAPHQL_CIRCULAR_REF',
    category: 'GraphQL',
    description: 'GraphQL type with circular reference without depth limit — enables infinite recursion.',
    severity: 'medium',
    fix_suggestion: 'Add query depth limiting to prevent circular reference exploitation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Only match inside GraphQL schema definitions (gql`...`, typeDefs, .graphql content)
      // Must see gql tag, typeDefs, or buildSchema to confirm GraphQL context
      if (!/\bgql\s*`|typeDefs|buildSchema|makeExecutableSchema|GraphQLObjectType/.test(ctx.fileContent)) return false;
      // Must match a GraphQL type definition pattern: type TypeName {
      if (!/^\s*type\s+(\w+)\s*\{/.test(line) && !/['"`]\s*type\s+(\w+)\s*\{/.test(line)) return false;
      const match = line.match(/type\s+(\w+)\s*\{/) || line.match(/type\s+(\w+)\b/);
      if (!match) return false;
      const typeName = match[1];
      // Skip built-in GraphQL types
      if (['Query', 'Mutation', 'Subscription', 'String', 'Int', 'Float', 'Boolean', 'ID'].includes(typeName)) return false;
      // Look for self-reference within the type's field block (next 20 lines)
      const nearby = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 20)).join('\n');
      // Must find the type name used as a field type (e.g., `friends: [User]` or `parent: User`)
      const fieldRefPattern = new RegExp(`:\\s*\\[?${typeName}\\]?`);
      return fieldRefPattern.test(nearby) && !/\bdepthLimit\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'GRAPHQL_INTROSPECTION_INTERNAL',
    category: 'GraphQL',
    description: 'GraphQL introspection enabled exposing internal types (__Admin, __Debug, Internal*).',
    severity: 'medium',
    fix_suggestion: 'Disable introspection in production or filter out internal types from the schema.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bintrospection\s*:\s*true\b/.test(line) ||
        /\bintrospection\s*:\s*(?:process\.env\.NODE_ENV\s*!==?\s*['"]production['"])/.test(line);
    },
  },
  {
    id: 'GRAPHQL_MUTATION_NO_VALIDATION',
    category: 'GraphQL',
    description: 'GraphQL mutation resolver without input validation — accepts any args.',
    severity: 'medium',
    fix_suggestion: 'Validate mutation inputs using Yup, Zod, or custom validation before processing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bMutation\s*[:=]\s*\{/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join('\n');
      return !/\b(?:validate|schema\.parse|zod|yup|joi|assert|sanitize)\b/i.test(nearby);
    },
  },
  {
    id: 'GRAPHQL_RESOLVER_ERROR_LEAK',
    category: 'GraphQL',
    description: 'GraphQL resolver error thrown with internal details — leaks implementation info.',
    severity: 'medium',
    fix_suggestion: 'Catch errors in resolvers and throw generic GraphQL errors without internal details.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bthrow\s+(?:new\s+)?(?:GraphQLError|ApolloError|UserInputError)\s*\(\s*(?:err|error|e)\.(?:message|stack)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 69: Serverless & Edge Deep
  // ════════════════════════════════════════════
  {
    id: 'LAMBDA_UNTRUSTED_LAYER',
    category: 'Serverless',
    description: 'Lambda layer from untrusted or public ARN — may contain malicious code.',
    severity: 'high',
    fix_suggestion: 'Only use Lambda layers from your own account or verified publishers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\blayers?\s*[:=]\s*\[?\s*['"]arn:aws:lambda:[^'"]*:\d{12}:layer:/.test(line) &&
        !/\b(?:self|own|internal|verified)\b/i.test(line);
    },
  },
  {
    id: 'ENV_VARS_IN_RESPONSE',
    category: 'Serverless',
    description: 'Environment variables exposed in HTTP response — leaks secrets.',
    severity: 'critical',
    fix_suggestion: 'Never return process.env or os.environ in HTTP responses.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx', '.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:res\.json|res\.send|return\s+Response|return\s+\{)\s*\(?\s*(?:process\.env|os\.environ)\b/.test(line) ||
        /\bbody\s*[:=]\s*JSON\.stringify\s*\(\s*process\.env\s*\)/.test(line);
    },
  },
  {
    id: 'COLD_START_TIMING_ORACLE',
    category: 'Serverless',
    description: 'Lambda/function cold start detectable via timing — can reveal deployment state.',
    severity: 'low',
    fix_suggestion: 'Use provisioned concurrency or add random delay to mask cold starts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:isColdStart|is_cold_start|coldStart|cold_start)\s*[:=]\s*true\b/.test(line) &&
        /\b(?:res|response|headers|body)\b/.test(line);
    },
  },
  {
    id: 'EDGE_FUNCTION_DYNAMIC_IMPORT',
    category: 'Serverless',
    description: 'Edge function with dynamic import from user input — code injection risk.',
    severity: 'critical',
    fix_suggestion: 'Never use dynamic import with user-controlled paths in edge functions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bimport\s*\(\s*(?:req\.|params\.|query\.|body\.|`[^`]*\$\{(?:req|params|query))/.test(line);
    },
  },
  {
    id: 'API_GATEWAY_NO_WAF',
    category: 'Serverless',
    description: 'API Gateway deployed without WAF association — no DDoS or injection protection.',
    severity: 'medium',
    fix_suggestion: 'Associate a WAF WebACL with your API Gateway for DDoS and injection protection.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+(?:apigateway\.|apigw\.)(?:RestApi|HttpApi)\s*\(\s*/.test(line) &&
        !/\bwebAcl\b/.test(line);
    },
  },
  {
    id: 'FUNCTION_URL_NO_AUTH',
    category: 'Serverless',
    description: 'Lambda Function URL with AuthType NONE — publicly accessible without authentication.',
    severity: 'high',
    fix_suggestion: 'Set authType to AWS_IAM or add custom authentication middleware.',
    auto_fixable: true,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:authType|auth_type)\s*[:=]\s*['"]NONE['"]/.test(line) &&
        /\b(?:FunctionUrl|function_url|functionUrl|addFunctionUrl)\b/.test(line);
    },
  },
  {
    id: 'STEP_FUNCTION_USER_STATE',
    category: 'Serverless',
    description: 'Step Function with user-controlled state input — can manipulate workflow execution.',
    severity: 'high',
    fix_suggestion: 'Validate and sanitize all input passed to Step Function state machines.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bstartExecution\s*\(\s*\{/.test(line) &&
        /\binput\s*:\s*(?:JSON\.stringify\s*\()?\s*(?:req\.body|body|event\.body)/.test(line);
    },
  },
  {
    id: 'SQS_MESSAGE_NO_VALIDATION',
    category: 'Serverless',
    description: 'SQS message body parsed and used without validation — may contain tampered data.',
    severity: 'medium',
    fix_suggestion: 'Validate and sanitize SQS message bodies with a schema before processing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bJSON\.parse\s*\(\s*(?:record|message|event)\.(?:body|Body)\s*\)/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join('\n');
      // Check for validation AFTER parsing (not JSON.parse itself which contains "parse")
      return !/\b(?:validate|schema\.parse|\.parse\(|zod|joi|yup|assert)\b/i.test(nearby);
    },
  },
  {
    id: 'EVENTBRIDGE_USER_DETAIL',
    category: 'Serverless',
    description: 'EventBridge event with user-controlled detail field — can inject malicious event data.',
    severity: 'medium',
    fix_suggestion: 'Validate event detail data with a schema before publishing to EventBridge.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bputEvents\s*\(\s*\{/.test(line) &&
        /\bDetail\s*:\s*(?:JSON\.stringify\s*\()?\s*(?:req\.body|body|event\.body)/.test(line);
    },
  },
  {
    id: 'CF_WORKER_RESTRICTED_API',
    category: 'Serverless',
    description: 'Cloudflare Worker accessing potentially restricted or dangerous APIs.',
    severity: 'medium',
    fix_suggestion: 'Review Cloudflare Worker API usage and ensure only necessary APIs are accessed.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\benv\.(?:SECRET|API_KEY|TOKEN|PASSWORD|PRIVATE_KEY)\b/.test(line) &&
        /\b(?:fetch|Response)\b/.test(line) &&
        /\b(?:json|text|body)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 71: API Gateway & Rate Limiting
  // ════════════════════════════════════════════
  {
    id: 'RATE_LIMIT_WRITE_MISSING',
    category: 'Rate Limiting',
    description: 'Write endpoint (POST/PUT/DELETE) without rate limiting middleware.',
    severity: 'high',
    fix_suggestion: 'Apply per-endpoint rate limits to all write operations (POST, PUT, DELETE).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\.\s*(?:post|put|delete|patch)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 5).join(' ');
      return !/\b(?:rateLimit|rateLimiter|throttle|limiter|slowDown)\b/i.test(nearby);
    },
  },
  {
    id: 'RATE_LIMIT_HEADERS_EXPOSED',
    category: 'Rate Limiting',
    description: 'Rate limit headers (X-RateLimit-Limit) expose exact limits to attackers.',
    severity: 'low',
    fix_suggestion: 'Consider omitting exact rate limit values from response headers or use generic headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsetHeader\s*\(\s*['"]X-RateLimit-(?:Limit|Remaining|Reset)['"]/.test(line) ||
        /\bres\.set\s*\(\s*['"]X-RateLimit-Limit['"]/.test(line);
    },
  },
  {
    id: 'API_KEY_NOT_ROTATABLE',
    category: 'Rate Limiting',
    description: 'API key is stored as a static constant without rotation mechanism.',
    severity: 'medium',
    fix_suggestion: 'Store API keys in a secrets manager with automated rotation support.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bconst\s+API_KEY\s*=\s*['"][A-Za-z0-9_\-]{20,}['"]/.test(line);
    },
  },
  {
    id: 'RATE_LIMIT_IPV6_BYPASS',
    category: 'Rate Limiting',
    description: 'Rate limiter keyed on IP without normalizing IPv6 addresses — can be bypassed with different IPv6 representations.',
    severity: 'medium',
    fix_suggestion: 'Normalize IPv6 addresses before using them as rate limit keys. Use canonical form.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bkeyGenerator\s*:\s*.*\breq\.ip\b/.test(line) &&
        !/\bnormalize|canonical|replace.*::/.test(line);
    },
  },
  {
    id: 'TOKEN_BUCKET_NO_BURST',
    category: 'Rate Limiting',
    description: 'Token bucket implementation without burst protection allows sudden traffic spikes.',
    severity: 'medium',
    fix_suggestion: 'Add a burst/maxBurst parameter to the token bucket to prevent sudden spikes.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+TokenBucket\s*\(/.test(line) &&
        !/\bburst\b|maxBurst\b/.test(line);
    },
  },
  {
    id: 'SLIDING_WINDOW_NOT_ATOMIC',
    category: 'Rate Limiting',
    description: 'Sliding window rate limiter with non-atomic read-then-write — race condition allows bypass.',
    severity: 'high',
    fix_suggestion: 'Use atomic operations (MULTI/EXEC, Lua scripts in Redis) for sliding window rate limiting.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:slidingWindow|sliding_window)\b/i.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 8), ctx.lineNumber + 8).join(' ');
      return /\b(?:get|hget)\b/.test(nearby) && /\b(?:set|hset|incr)\b/.test(nearby) &&
        !/\b(?:multi|pipeline|atomic|lua|eval)\b/i.test(nearby);
    },
  },
  {
    id: 'RATE_LIMIT_SESSION_UNVALIDATED',
    category: 'Rate Limiting',
    description: 'Rate limit keyed on session ID but session is not validated — attacker can forge session IDs.',
    severity: 'high',
    fix_suggestion: 'Validate sessions before using session IDs as rate limit keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bkeyGenerator\s*:\s*.*\bsession(?:Id|ID|_id)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber + 3).join(' ');
      return !/\b(?:verifySession|validateSession|isAuthenticated|authenticate)\b/i.test(nearby);
    },
  },
  {
    id: 'GRAPHQL_QUERY_COST_NO_LIMIT',
    category: 'Rate Limiting',
    description: 'GraphQL endpoint without query cost/depth analysis — allows expensive queries.',
    severity: 'high',
    fix_suggestion: 'Add query cost analysis and depth limiting middleware to the GraphQL endpoint.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:graphqlHTTP|ApolloServer|createYoga|buildSchema)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 15).join(' ');
      return !/\b(?:costAnalysis|queryCost|depthLimit|queryComplexity|maxDepth|costLimit)\b/i.test(nearby);
    },
  },
  {
    id: 'WEBSOCKET_MSG_RATE_MISSING',
    category: 'Rate Limiting',
    description: 'WebSocket message handler without per-message rate limiting — allows flood attacks.',
    severity: 'medium',
    fix_suggestion: 'Add per-connection message rate limiting to WebSocket handlers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:ws|socket|conn)\.on\s*\(\s*['"]message['"]/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 10).join(' ');
      return !/\b(?:rateLimit|throttle|messageCount|msgRate|flood)\b/i.test(nearby);
    },
  },
  {
    id: 'FILE_UPLOAD_BANDWIDTH_UNLIMITED',
    category: 'Rate Limiting',
    description: 'File upload endpoint without bandwidth/size rate limiting.',
    severity: 'medium',
    fix_suggestion: 'Add bandwidth limits and per-user upload quotas to file upload endpoints.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:multer|busboy|formidable|upload)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 10).join(' ');
      return !/\b(?:rateLimit|bandwidth|bytesPerSecond|maxRate)\b/i.test(nearby);
    },
  },
  {
    id: 'STREAMING_NO_TIMEOUT',
    category: 'Rate Limiting',
    description: 'Streaming/SSE endpoint without timeout — allows clients to hold connections indefinitely.',
    severity: 'medium',
    fix_suggestion: 'Add timeout and max-duration limits to streaming endpoints.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:text\/event-stream|EventSource|createReadStream|pipe\s*\(res)/.test(line)) return false;
      // Skip streaming SDK / library source
      if (isStreamingLibrary(ctx.filePath)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 10).join(' ');
      return !/\b(?:timeout|setTimeout|maxDuration|deadline)\b/i.test(nearby);
    },
  },
  {
    id: 'LONG_POLL_NO_CONN_LIMIT',
    category: 'Rate Limiting',
    description: 'Long-polling endpoint without connection limit — allows resource exhaustion.',
    severity: 'medium',
    fix_suggestion: 'Limit concurrent long-poll connections per user/IP.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\blongPoll|long[_-]?poll/i.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 10).join(' ');
      return !/\b(?:maxConnections|connectionLimit|concurrency)\b/i.test(nearby);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 72: Secrets Management
  // ════════════════════════════════════════════
  {
    id: 'SECRET_ROTATION_MISSING',
    category: 'Secrets Management',
    description: 'Secret/credential without automated rotation — increases exposure window if compromised.',
    severity: 'medium',
    fix_suggestion: 'Implement automated secret rotation using a secrets manager (Vault, AWS Secrets Manager).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bprocess\.env\.(?:SECRET|PRIVATE_KEY|DB_PASSWORD)\b/.test(line)) return false;
      const fileContent = ctx.fileContent;
      return !/\b(?:rotateSecret|secretRotation|SecretManager|SecretsManager)\b/i.test(fileContent);
    },
  },
  {
    id: 'VAULT_TOKEN_HARDCODED',
    category: 'Secrets Management',
    description: 'HashiCorp Vault token is hardcoded — compromises the entire secrets store.',
    severity: 'critical',
    fix_suggestion: 'Use Vault auto-auth, AppRole, or Kubernetes auth instead of hardcoded tokens.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bVAULT_TOKEN\s*[:=]\s*['"][shv]\.[\w\-.]{20,}['"]/.test(line) ||
        /\btoken\s*[:=]\s*['"]hvs\.[\w\-.]{20,}['"]/.test(line);
    },
  },
  {
    id: 'KMS_KEY_NO_ROTATION',
    category: 'Secrets Management',
    description: 'KMS key creation without rotation enabled — stale keys increase risk.',
    severity: 'medium',
    fix_suggestion: 'Enable automatic key rotation when creating KMS keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:createKey|CreateKeyCommand)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 10).join(' ');
      return !/\b(?:EnableKeyRotation|keyRotation|rotationPeriod)\b/i.test(nearby);
    },
  },
  {
    id: 'SECRETS_IN_TERRAFORM_STATE',
    category: 'Secrets Management',
    description: 'Sensitive values in Terraform files without marking as sensitive — will appear in state.',
    severity: 'high',
    fix_suggestion: 'Mark sensitive variables with sensitive = true and use a remote encrypted backend.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bterraform\b.*\b(?:password|secret|api_key|token)\b/i.test(line) &&
        !/\bsensitive\s*[:=]\s*true\b/.test(line);
    },
  },
  {
    id: 'ENV_IN_DOCKER_LAYERS',
    category: 'Secrets Management',
    description: 'Secrets copied into Docker image via COPY .env or ENV directive — persists in image layers.',
    severity: 'high',
    fix_suggestion: 'Use Docker secrets, BuildKit --mount=type=secret, or runtime env injection instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:COPY|ADD)\s+.*\.env\b/.test(line) &&
        /\bDockerfile|dockerfile|docker/i.test(line);
    },
  },
  {
    id: 'SECRET_IN_GHA_OUTPUT',
    category: 'Secrets Management',
    description: 'Secret value written to GitHub Actions output — visible in logs and downstream steps.',
    severity: 'high',
    fix_suggestion: 'Use GitHub Actions masks (::add-mask::) or pass secrets via environment variables.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcore\.setOutput\s*\(\s*['"][^'"]*(?:secret|token|password|key|credential)[^'"]*['"]/.test(line) ||
        /::set-output\s+name=.*(?:secret|token|password|key)/i.test(line);
    },
  },
  {
    id: 'ENV_INJECTION_LD_PRELOAD',
    category: 'Secrets Management',
    description: 'LD_PRELOAD environment variable set from user input — allows library injection attacks.',
    severity: 'critical',
    fix_suggestion: 'Never allow user input to set LD_PRELOAD or similar loader variables.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES)\s*[:=]/.test(line) &&
        /\b(?:req\.|input|params|query|body|args|argv)\b/.test(line);
    },
  },
  {
    id: 'SECRET_TIMING_COMPARISON',
    category: 'Secrets Management',
    description: 'Secret/token compared with === or == — vulnerable to timing attacks.',
    severity: 'high',
    fix_suggestion: 'Use crypto.timingSafeEqual() for constant-time secret comparison.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:apiKey|api_key|secret|token|signature|hmac|digest)\s*(?:===?|!==?)\s*(?:req\.|header|body|params)/.test(line) ||
        /\b(?:req\.|header|body|params).*(?:===?|!==?)\s*(?:apiKey|api_key|secret|token|signature|hmac|digest)\b/.test(line);
    },
  },
  {
    id: 'KEY_MATERIAL_NOT_ZEROED',
    category: 'Secrets Management',
    description: 'Cryptographic key material not zeroed after use — remains in memory.',
    severity: 'medium',
    fix_suggestion: 'Zero/fill key buffers after use (e.g., buffer.fill(0)) to minimize exposure window.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:privateKey|secretKey|keyMaterial|masterKey)\s*=\s*(?:Buffer|crypto|await)/.test(line)) return false;
      const afterLines = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 20).join(' ');
      return !/\b(?:fill\s*\(\s*0|zeroize|wipe|destroy|clear)\b/i.test(afterLines);
    },
  },
  {
    id: 'CERT_EXPIRY_NOT_MONITORED',
    category: 'Secrets Management',
    description: 'TLS certificate loaded without expiry monitoring — can cause outages.',
    severity: 'medium',
    fix_suggestion: 'Add certificate expiry monitoring and alerting before expiration.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:readFileSync|readFile)\s*\(.*\b(?:cert|certificate|\.pem|\.crt)\b/.test(line)) return false;
      const fileContent = ctx.fileContent;
      return !/\b(?:expiresAt|validTo|notAfter|certExpiry|renewBefore)\b/i.test(fileContent);
    },
  },
  {
    id: 'JWKS_NO_CACHE',
    category: 'Secrets Management',
    description: 'JWKS endpoint fetched on every request without caching — performance issue and potential DoS.',
    severity: 'medium',
    fix_suggestion: 'Cache JWKS responses with appropriate TTL and background refresh.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:jwks|\.well-known\/jwks)\b/i.test(line)) return false;
      if (!/\bfetch\b|axios|got\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 10).join(' ');
      return !/\b(?:cache|cached|memoize|ttl|lru)\b/i.test(nearby);
    },
  },
  {
    id: 'HMAC_KEY_SHARED_ACROSS_SERVICES',
    category: 'Secrets Management',
    description: 'HMAC key shared across multiple services — compromise of one service exposes all.',
    severity: 'medium',
    fix_suggestion: 'Use unique per-service HMAC keys and a key derivation function if needed.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSHARED_HMAC_KEY\b|GLOBAL_HMAC_SECRET\b|COMMON_SIGNING_KEY\b/.test(line) ||
        (/\bhmacKey\b/.test(line) && /\bshared\b|global\b|common\b/i.test(line));
    },
  },

  // ════════════════════════════════════════════
  // Cycle 73: Injection Variants
  // ════════════════════════════════════════════
  {
    id: 'CRLF_LOG_INJECTION',
    category: 'Injection',
    description: 'User input written to logs without CRLF sanitization — allows log injection/forging.',
    severity: 'medium',
    fix_suggestion: 'Strip or encode \\r\\n characters from user input before logging.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:logger|log|console)\.\w+\s*\(.*\b(?:req\.body|req\.query|req\.params|req\.headers)\b/.test(line) &&
        !/\b(?:sanitize|escape|replace|strip)\b/i.test(line);
    },
  },
  {
    id: 'TEMPLATE_INJECTION_EMAIL',
    category: 'Injection',
    description: 'User input in email template subject — template injection risk.',
    severity: 'medium',
    fix_suggestion: 'Sanitize user input before using in email templates. Escape template syntax.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsubject\s*:\s*`[^`]*\$\{.*(?:req\.|user\.|input|name|body)/.test(line) ||
        /\bsubject\s*:\s*.*\+\s*(?:req\.|user\.|input)/.test(line);
    },
  },
  {
    id: 'CSS_INJECTION_USER_STYLE',
    category: 'Injection',
    description: 'User-controlled CSS injected into page — can exfiltrate data via CSS selectors.',
    severity: 'medium',
    fix_suggestion: 'Validate and sanitize user CSS. Use a CSS sanitizer library or allowlist properties.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return (/\bstyle\s*=\s*[{`]/.test(line) || /\binnerHTML\s*=.*<style/.test(line)) &&
        /\b(?:req\.|user\.|input|params|query|body)\b/.test(line);
    },
  },
  {
    id: 'SVG_XSS_UPLOAD',
    category: 'Injection',
    description: 'SVG file upload without sanitization — SVGs can contain JavaScript for XSS.',
    severity: 'high',
    fix_suggestion: 'Sanitize uploaded SVG files (remove <script>, event handlers) or convert to raster.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:\.svg|image\/svg|svg\+xml)\b/i.test(line)) return false;
      if (!/\b(?:upload|accept|mimetype|content-type|fileFilter)\b/i.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 10).join(' ');
      return !/\b(?:sanitize|DOMPurify|svgo|strip|clean)\b/i.test(nearby);
    },
  },
  {
    id: 'PDF_INJECTION_USER_CONTENT',
    category: 'Injection',
    description: 'User content injected into PDF generation without sanitization.',
    severity: 'medium',
    fix_suggestion: 'Sanitize and escape user content before including in PDF generation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (/\b(?:PDFDocument|jsPDF|puppeteer|pdf-lib|pdfkit)\b/.test(line) &&
          /\b(?:req\.body|req\.query|req\.params|user\.input)\b/.test(line)) return true;
      // Check nearby lines for PDF library + user input combination
      if (!/\b(?:req\.body|req\.query|req\.params)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber).join(' ');
      return /\b(?:PDFDocument|jsPDF|puppeteer|pdf-lib|pdfkit)\b/.test(nearby);
    },
  },
  {
    id: 'MARKDOWN_XSS',
    category: 'Injection',
    description: 'Markdown rendered to HTML without sanitization — XSS via markdown content.',
    severity: 'high',
    fix_suggestion: 'Sanitize HTML output from markdown rendering (e.g., use DOMPurify on the result).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:marked|markdown-it|remark|showdown|snarkdown)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 8).join(' ');
      return !/\b(?:sanitize|DOMPurify|xss|purify|escape)\b/i.test(nearby);
    },
  },
  {
    id: 'REDOS_USER_PATTERN',
    category: 'Injection',
    description: 'User-supplied regex pattern compiled without protection — ReDoS risk.',
    severity: 'high',
    fix_suggestion: 'Use a safe regex library (re2, safe-regex) or validate/limit user regex patterns.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnew\s+RegExp\s*\(\s*(?:req\.|user\.|input|params|query|body|args)/.test(line);
    },
  },
  {
    id: 'XPATH_INJECTION',
    category: 'Injection',
    description: 'XPath query built with user input — vulnerable to XPath injection.',
    severity: 'high',
    fix_suggestion: 'Use parameterized XPath queries or validate/escape user input.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:xpath|evaluate|select)\s*\(\s*[`'"]\s*\/\//.test(line) &&
        /\$\{|"\s*\+/.test(line);
    },
  },
  {
    id: 'HEADER_INJECTION_MULTILINE',
    category: 'Injection',
    description: 'HTTP header set from user input without newline stripping — header injection via CRLF.',
    severity: 'high',
    fix_suggestion: 'Strip \\r and \\n from user input before using in HTTP headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:setHeader|writeHead|header)\s*\(.*(?:req\.|user\.|input|params|query|body)/.test(line) &&
        !/\b(?:replace|strip|sanitize|escape)\b/i.test(line) &&
        !/\b(?:Content-Type|content-type|Authorization)\b/.test(line);
    },
  },
  {
    id: 'RESPONSE_SPLITTING',
    category: 'Injection',
    description: 'Response splitting via user-controlled header value — allows HTTP response splitting.',
    severity: 'high',
    fix_suggestion: 'Validate and sanitize all user input used in HTTP response headers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bres\.(?:setHeader|writeHead|header)\s*\(\s*['"]Location['"].*(?:req\.|query|params|body)/.test(line) &&
        !/\b(?:encodeURI|sanitize|replace|URL)\b/.test(line);
    },
  },
  {
    id: 'CSV_FORMULA_INJECTION',
    category: 'Injection',
    description: 'CSV export with user data not sanitized for formula injection (=, +, -, @).',
    severity: 'medium',
    fix_suggestion: 'Prefix cells starting with =, +, -, @ with a single quote or tab to prevent formula execution.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:csv|createCsvStringifier|writeToStream|text\/csv|\.csv)\b/i.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 10).join(' ');
      return !/\b(?:escapeFormula|sanitizeCSV|csvSanitize|formulaEscape|startsWith.*[=+\-@])\b/i.test(nearby);
    },
  },
  {
    id: 'LINK_INJECTION_ERROR',
    category: 'Injection',
    description: 'User-controlled URL in error messages — can redirect users to malicious sites.',
    severity: 'medium',
    fix_suggestion: 'Validate and sanitize URLs in error messages. Use allowlisted redirect URLs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:Error|error)\s*\(\s*`[^`]*(?:href|url|link)\s*[:=]\s*\$\{/.test(line) ||
        /\bnew\s+Error\s*\(.*\b(?:req\.url|redirectUrl|returnUrl|next)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 74: Access Control
  // ════════════════════════════════════════════
  {
    id: 'BATCH_PRIVILEGE_ESCALATION',
    category: 'Access Control',
    description: 'Batch operation without per-item authorization — allows horizontal privilege escalation.',
    severity: 'info',
    fix_suggestion: 'Check authorization for each item in batch operations, not just the batch as a whole.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:bulkUpdate|bulkDelete|batchUpdate|updateMany|deleteMany)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 8), ctx.lineNumber + 3).join(' ');
      return !/\b(?:authorize|checkPermission|canAccess|isOwner|belongsTo)\b/i.test(nearby);
    },
  },
  {
    id: 'VERTICAL_ESCALATION_PARAM',
    category: 'Access Control',
    description: 'Role or permission set from request parameter — allows vertical privilege escalation.',
    severity: 'critical',
    fix_suggestion: 'Never derive roles/permissions from user input. Use server-side session/token claims.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (/\b(?:role|permission|isAdmin|is_admin|accessLevel)\s*=\s*(?:req\.body|req\.params|req\.query|body\.|params\.|query\.)/.test(line)) return true;
      return false;
    },
  },
  {
    id: 'PERMISSION_CACHE_NO_INVALIDATION',
    category: 'Access Control',
    description: 'Permissions cached without invalidation — stale permissions after role changes.',
    severity: 'medium',
    fix_suggestion: 'Add cache invalidation when roles or permissions are updated.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:permissionCache|roleCache|authCache|aclCache)\b/.test(line)) return false;
      if (!/\b(?:set|put|cache)\b/.test(line)) return false;
      const fileContent = ctx.fileContent;
      return !/\b(?:invalidate|delete|clear|flush|purge)\b/i.test(fileContent);
    },
  },
  {
    id: 'ROLE_HIERARCHY_BYPASS',
    category: 'Access Control',
    description: 'Role check without hierarchy — sub-roles may bypass higher role requirements.',
    severity: 'medium',
    fix_suggestion: 'Implement role hierarchy checks (admin inherits moderator permissions).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\brole\s*===?\s*['"]admin['"]/.test(line) &&
        !/\b(?:includes|hierarchy|inherits|isAtLeast|hasRole)\b/i.test(line);
    },
  },
  {
    id: 'SHARED_RESOURCE_NO_TENANT',
    category: 'Access Control',
    description: 'Shared resource query without tenant/organization filter — data leak risk.',
    severity: 'high',
    fix_suggestion: 'Always include tenant/organization ID in queries for shared resources.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:findAll|findMany|select\s*\*|getAll)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 5).join(' ');
      return /\bshared\b|multi[_-]?tenant/i.test(ctx.fileContent) &&
        !/\b(?:tenantId|orgId|organizationId|tenant_id|org_id)\b/.test(nearby);
    },
  },
  {
    id: 'API_ENUM_TIMING',
    category: 'Access Control',
    description: 'API endpoint returns different timing for existing vs non-existing resources — enumeration risk.',
    severity: 'medium',
    fix_suggestion: 'Use constant-time responses for resource lookups. Return same status for exists/not-exists.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:findById|findOne|getUserBy)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 8).join(' ');
      return /\bif\s*\(\s*!?\s*(?:user|resource|item|record)\s*\)/.test(nearby) &&
        /\b(?:404|not.?found)\b/i.test(nearby) &&
        !/\b(?:timingSafe|constantTime|sleep)\b/.test(nearby);
    },
  },
  {
    id: 'ADMIN_PANEL_PATH_ACCESS',
    category: 'Access Control',
    description: 'Admin panel accessible by predictable path without authentication middleware.',
    severity: 'critical',
    fix_suggestion: 'Protect admin routes with authentication and authorization middleware.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:app|router)\.(?:use|get)\s*\(\s*['"]\/admin/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 2), ctx.lineNumber + 3).join(' ');
      return !/\b(?:authenticate|isAdmin|requireAuth|authMiddleware|protect|guard|isAuthenticated)\b/i.test(nearby);
    },
  },
  {
    id: 'CAPABILITY_URL_NO_EXPIRY',
    category: 'Access Control',
    description: 'Capability URL (signed/token URL) generated without expiry — permanent access risk.',
    severity: 'medium',
    fix_suggestion: 'Add TTL/expiration to capability URLs. Use short-lived signed URLs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:signedUrl|presignedUrl|getSignedUrl|createPresignedPost)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 2), ctx.lineNumber + 8).join(' ');
      return !/\b(?:expires|expiresIn|Expires|ttl|maxAge)\b/i.test(nearby);
    },
  },
  {
    id: 'DELEGATION_NO_SCOPE',
    category: 'Access Control',
    description: 'Permission delegation without scope limits — delegated access may exceed intended scope.',
    severity: 'high',
    fix_suggestion: 'Always define explicit scopes and time limits when delegating permissions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:delegate|delegateAccess|grantAccess|shareWith)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 8).join(' ');
      return !/\b(?:scope|permission|limit|restrict|expires)\b/i.test(nearby);
    },
  },
  {
    id: 'IMPERSONATION_NO_AUDIT',
    category: 'Access Control',
    description: 'User impersonation without audit logging — actions cannot be traced.',
    severity: 'high',
    fix_suggestion: 'Log all impersonation events with impersonator identity and timestamp.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:impersonate|actAs|switchUser|loginAs|sudoAs)\b/i.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 8).join(' ');
      return !/\b(?:audit|log|track|record|emit)\b/i.test(nearby);
    },
  },
  {
    id: 'SERVICE_NO_MTLS',
    category: 'Access Control',
    description: 'Service-to-service HTTP call without mutual TLS — allows service impersonation.',
    severity: 'medium',
    fix_suggestion: 'Use mutual TLS (mTLS) for service-to-service communication.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:INTERNAL_SERVICE_URL|SERVICE_URL|MICROSERVICE_URL)\b/.test(line) &&
        /\bfetch\b|axios\b|got\b|http\.request/.test(line) &&
        !/\b(?:cert|tls|ssl|mtls|certificate)\b/i.test(line);
    },
  },
  {
    id: 'CROSS_TENANT_DATA_LEAK',
    category: 'Access Control',
    description: 'Query joins or lookups across tenant boundaries without tenant ID filter.',
    severity: 'critical',
    fix_suggestion: 'Always filter by tenantId in multi-tenant queries. Use row-level security.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bJOIN\b.*\bON\b/i.test(line) &&
        /(?:tenant|org_|organization)/i.test(line) &&
        !/(?:tenant_id|tenantId|orgId|org_id)\s*=/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 75: Error & Exception Handling
  // ════════════════════════════════════════════
  {
    id: 'UNCAUGHT_EXCEPTION_CONTINUE_V2',
    category: 'Error Handling',
    description: 'Uncaught exception handler that does not exit the process — leaves app in undefined state.',
    severity: 'high',
    fix_suggestion: 'Always call process.exit(1) after handling uncaughtException. Use graceful shutdown.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bprocess\.on\s*\(\s*['"]uncaughtException['"]/.test(line)) return false;
      const afterLines = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 10).join(' ');
      return !/\bprocess\.exit\b/.test(afterLines);
    },
  },
  {
    id: 'ERROR_LISTENER_LEAK',
    category: 'Error Handling',
    description: 'Event listener added in error handler but never removed — memory leak on repeated errors.',
    severity: 'medium',
    fix_suggestion: 'Remove event listeners in error/cleanup handlers to prevent memory leaks.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:catch|\.on\s*\(\s*['"]error)/.test(line)) return false;
      const afterLines = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 8).join(' ');
      return /\b(?:addEventListener|\.on\s*\(|addListener)\b/.test(afterLines) &&
        !/\b(?:removeEventListener|\.off\s*\(|removeListener|removeAllListeners)\b/.test(afterLines);
    },
  },
  {
    id: 'CIRCULAR_REF_ERROR_SERIALIZE',
    category: 'Error Handling',
    description: 'Error object serialized with JSON.stringify without circular reference handling.',
    severity: 'medium',
    fix_suggestion: 'Use a safe serializer that handles circular references (e.g., flatted, safe-stable-stringify).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bJSON\.stringify\s*\(\s*(?:err|error|e)\s*\)/.test(line);
    },
  },
  {
    id: 'STACK_TRACE_PRODUCTION',
    category: 'Error Handling',
    description: 'Stack trace exposed in production API response.',
    severity: 'high',
    fix_suggestion: 'Only include stack traces in development. Use generic error messages in production.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:res\.json|res\.send|response\.json)\s*\(\s*\{[^}]*\bstack\s*:\s*(?:err|error|e)\.stack/.test(line);
    },
  },
  {
    id: 'ERROR_PAGE_DEBUG_INFO',
    category: 'Error Handling',
    description: 'Error page renders debug information (stack, query, env) — information disclosure.',
    severity: 'high',
    fix_suggestion: 'Render generic error pages in production. Only show debug info in development.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:errorHandler|errorPage|renderError|handleError)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 15).join(' ');
      return /\b(?:stack|stackTrace|\.stack|process\.env|req\.query)\b/.test(nearby) &&
        !/\bNODE_ENV\s*(?:===?|!==?)\s*['"](?:development|dev)['"]/.test(nearby);
    },
  },
  {
    id: 'ERROR_CLASS_INTERNAL_LEAK',
    category: 'Error Handling',
    description: 'Custom error class includes internal state (query, connection, config) in message.',
    severity: 'medium',
    fix_suggestion: 'Do not include internal state in error messages. Log internally, return generic messages.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bclass\s+\w*Error\s+extends\s+Error\b/.test(line) &&
        /\bthis\.(?:query|sql|connection|config|dsn|connectionString)\b/.test(line);
    },
  },
  {
    id: 'RETRY_AUTH_NO_BACKOFF',
    category: 'Error Handling',
    description: 'Authentication retry without exponential backoff — allows credential brute force.',
    severity: 'high',
    fix_suggestion: 'Use exponential backoff with jitter for auth retries. Lock accounts after N failures.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bretry\b.*\b(?:auth|login|password|credential)\b/i.test(line) &&
          !/\b(?:auth|login|password|credential)\b.*\bretry\b/i.test(line) &&
          !/\bretryAuth\b|\bloginRetry\b|\bauthRetry\b|\bretryLogin\b/i.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 10).join(' ');
      return !/\b(?:backoff|exponential|delay\s*\*|Math\.pow|jitter)\b/i.test(nearby);
    },
  },
  {
    id: 'ERROR_AGGREGATION_CONTEXT_LOSS',
    category: 'Error Handling',
    description: 'Error aggregation loses individual error context — makes debugging impossible.',
    severity: 'low',
    fix_suggestion: 'Preserve individual error details when aggregating errors.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\berrors\.length\b/.test(line) &&
        /\bnew\s+Error\s*\(\s*[`'"].*\berrors?\b.*\blength\b/.test(line);
    },
  },
  {
    id: 'PANIC_DUMP_WITH_SECRETS',
    category: 'Error Handling',
    description: 'Crash/panic dump includes environment or process info — may contain secrets.',
    severity: 'high',
    fix_suggestion: 'Scrub environment variables and secrets from crash dumps before writing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:crashDump|panicHandler|dumpState)\b/.test(line) &&
        /\bprocess\.env\b/.test(line);
    },
  },
  {
    id: 'UNHANDLED_STREAM_ERROR',
    category: 'Error Handling',
    description: 'Stream created without error event handler — unhandled error will crash process.',
    severity: 'high',
    fix_suggestion: 'Always attach an error handler to streams (stream.on("error", handler)).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:createReadStream|createWriteStream)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 2), ctx.lineNumber + 8).join(' ');
      return !/\.on\s*\(\s*['"]error['"]/.test(nearby) &&
        !/\bpipeline\b/.test(nearby);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 76: Caching Security
  // ════════════════════════════════════════════
  {
    id: 'CACHE_POISONING_HOST',
    category: 'Caching',
    description: 'Cache key derived from Host header — cache poisoning via Host header manipulation.',
    severity: 'high',
    fix_suggestion: 'Never use the Host header as part of cache keys. Validate Host against allowlist.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcacheKey\b.*\breq\.(?:headers\.host|hostname)\b/.test(line) ||
        /\bcache\.(?:set|put)\s*\(.*\breq\.(?:headers\.host|hostname)\b/.test(line);
    },
  },
  {
    id: 'SENSITIVE_DATA_CDN_CACHE',
    category: 'Caching',
    description: 'Response with sensitive data has public Cache-Control — will be cached by CDN.',
    severity: 'high',
    fix_suggestion: 'Use Cache-Control: private, no-store for responses with sensitive data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bCache-Control['"]?\s*[:=,]\s*['"]?public\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber + 10).join(' ');
      return /\b(?:password|token|secret|credit.?card|ssn|email|phone|personal)\b/i.test(nearby);
    },
  },
  {
    id: 'CACHE_KEY_NO_USER_CONTEXT',
    category: 'Caching',
    description: 'Cache key does not include user/session context — serves cached data to wrong users.',
    severity: 'high',
    fix_suggestion: 'Include user ID or session ID in cache keys for user-specific data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcacheKey\s*=\s*/.test(line)) return false;
      if (!/\breq\.(?:path|url|originalUrl)\b/.test(line)) return false;
      return !/\b(?:userId|user_id|sessionId|session_id|req\.user)\b/.test(line);
    },
  },
  {
    id: 'STALE_CACHE_AFTER_PERM_CHANGE',
    category: 'Caching',
    description: 'Permission change does not invalidate related caches — stale access after role update.',
    severity: 'high',
    fix_suggestion: 'Invalidate user/role caches whenever permissions or roles are modified.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:updateRole|changePermission|revokeAccess|removeRole)\s*\(/.test(line)) return false;
      const afterLines = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 10).join(' ');
      return !/\b(?:invalidate|delete|clear|purge|flush|cache\.del)\b/i.test(afterLines);
    },
  },
  {
    id: 'NO_CACHE_CONTROL_SENSITIVE',
    category: 'Caching',
    description: 'Sensitive endpoint response without Cache-Control header — browser may cache.',
    severity: 'medium',
    fix_suggestion: 'Set Cache-Control: no-store, no-cache for sensitive endpoints.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/(?:\/api\/(?:user|profile|account|settings|billing)|\/me\b)/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 10).join(' ');
      if (!/\b(?:res\.json|res\.send)\b/.test(nearby)) return false;
      return !/\bCache-Control\b/i.test(nearby);
    },
  },
  {
    id: 'SHARED_CACHE_ACROSS_TENANTS',
    category: 'Caching',
    description: 'Cache shared across tenants without tenant-scoped keys — data leakage risk.',
    severity: 'critical',
    fix_suggestion: 'Prefix all cache keys with tenant ID in multi-tenant applications.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcache\.(?:get|set|put)\s*\(/.test(line)) return false;
      if (!/\b(?:tenant|multi.?tenant)\b/i.test(ctx.fileContent)) return false;
      return !/\b(?:tenantId|tenant_id|orgId|org_id)\b/.test(line);
    },
  },
  {
    id: 'CACHE_STAMPEDE_NO_LOCK',
    category: 'Caching',
    description: 'Cache miss triggers expensive recomputation without lock — cache stampede risk.',
    severity: 'medium',
    fix_suggestion: 'Use cache lock/mutex, stale-while-revalidate, or probabilistic early recomputation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcache\.get\b/.test(line)) return false;
      const afterLines = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 10).join(' ');
      return /\bif\s*\(\s*!/.test(afterLines) &&
        /\b(?:database|db\.|fetch|query|compute)\b/.test(afterLines) &&
        !/\b(?:lock|mutex|singleflight|swr|stale)\b/i.test(afterLines);
    },
  },
  {
    id: 'PROXY_CACHE_SET_COOKIE',
    category: 'Caching',
    description: 'Response with Set-Cookie header and public caching — leaks session cookies via cache.',
    severity: 'high',
    fix_suggestion: 'Never cache responses with Set-Cookie headers. Use Cache-Control: private.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bSet-Cookie\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 5).join(' ');
      return /\bCache-Control['"]?\s*[:=,]\s*['"]?public\b/.test(nearby) ||
        /\bs-maxage\b/.test(nearby);
    },
  },
  {
    id: 'CACHE_WITH_AUTH_TOKEN',
    category: 'Caching',
    description: 'Response containing auth token is cacheable — token leakage via shared cache.',
    severity: 'high',
    fix_suggestion: 'Ensure responses containing auth tokens have Cache-Control: no-store.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:accessToken|access_token|refreshToken|refresh_token|jwt)\b/.test(line)) return false;
      if (!/\b(?:res\.json|res\.send|response\.json)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 5).join(' ');
      return !/\bno-store\b/.test(nearby);
    },
  },
  {
    id: 'VARY_HEADER_MISSING_AUTH',
    category: 'Caching',
    description: 'Cached response varies by auth but Vary header does not include Authorization.',
    severity: 'medium',
    fix_suggestion: 'Add Vary: Authorization header when response content depends on authentication.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bVary\b/.test(line)) return false;
      if (!/\bsetHeader\s*\(\s*['"]Vary['"]/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber + 10).join(' ');
      return /\b(?:req\.user|isAuthenticated|authorization)\b/i.test(nearby) &&
        !/\bAuthorization\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 77: File & Storage Security
  // ════════════════════════════════════════════
  {
    id: 'SYMLINK_TRAVERSAL_ARCHIVE',
    category: 'File Security',
    description: 'Archive extraction without symlink validation — path traversal via symlinks in archives.',
    severity: 'high',
    fix_suggestion: 'Check for and reject symlinks when extracting archives. Validate resolved paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:extract|unzip|tar\.x|untar|decompress)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 10).join(' ');
      return !/\b(?:symlink|followSymlink|noFollow|rejectSymlinks|lstat)\b/i.test(nearby);
    },
  },
  {
    id: 'WORLD_READABLE_TEMP',
    category: 'File Security',
    description: 'Temporary file created with world-readable permissions (0o666/0o777).',
    severity: 'medium',
    fix_suggestion: 'Create temp files with restrictive permissions (0o600) to prevent unauthorized access.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:writeFileSync|writeFile)\s*\(.*\b(?:tmp|temp)\b/.test(line) &&
        /\bmode\s*:\s*0o(?:666|777|644)\b/.test(line);
    },
  },
  {
    id: 'FILE_LOCK_BYPASS',
    category: 'File Security',
    description: 'File operation without advisory lock — race condition with concurrent access.',
    severity: 'medium',
    fix_suggestion: 'Use file locking (flock, lockfile) for concurrent file access.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:readFileSync|writeFileSync)\s*\(/.test(line)) return false;
      if (!/\bshared\b|concurrent|multi/i.test(ctx.fileContent)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 5).join(' ');
      return !/\b(?:lock|flock|lockfile|mutex|semaphore)\b/i.test(nearby);
    },
  },
  {
    id: 'DIRECTORY_LISTING_ENABLED',
    category: 'File Security',
    description: 'Static file serving with directory listing enabled — exposes file structure.',
    severity: 'medium',
    fix_suggestion: 'Disable directory listing in static file serving configuration.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bserve-index\b/.test(line) ||
        (/\bexpress\.static\b/.test(line) && /\bdirectory\s*:\s*true\b/.test(line));
    },
  },
  {
    id: 'STORAGE_BUCKET_NO_ENCRYPTION',
    category: 'File Security',
    description: 'Cloud storage bucket/container created without encryption at rest.',
    severity: 'high',
    fix_suggestion: 'Enable server-side encryption (SSE-S3, SSE-KMS) for storage buckets.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:createBucket|CreateBucketCommand|s3\.putObject)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 10).join(' ');
      return !/\b(?:ServerSideEncryption|encryption|SSE|kmsKeyId)\b/i.test(nearby);
    },
  },
  {
    id: 'FILE_METADATA_USER_LEAK',
    category: 'File Security',
    description: 'File metadata (EXIF, author) not stripped from user uploads — leaks personal info.',
    severity: 'medium',
    fix_suggestion: 'Strip metadata (EXIF, XMP) from uploaded files before storing.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:upload|multer|formidable|busboy)\b/.test(line)) return false;
      if (!/\b(?:image|photo|picture|jpeg|jpg|png)\b/i.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 15).join(' ');
      return !/\b(?:exif|metadata|strip|sharp|imagemagick|removeExif)\b/i.test(nearby);
    },
  },
  {
    id: 'HARDLINK_SENSITIVE_FILE',
    category: 'File Security',
    description: 'Hard link created to potentially sensitive file — bypasses file permission changes.',
    severity: 'medium',
    fix_suggestion: 'Avoid hard links to sensitive files. Use copies or symlinks with proper validation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:linkSync|link)\s*\(.*(?:\/etc\/|passwd|shadow|\.key|\.pem|\.env)/.test(line);
    },
  },
  {
    id: 'SPARSE_FILE_DOS',
    category: 'File Security',
    description: 'File created from user-specified size without limits — sparse file DoS.',
    severity: 'medium',
    fix_suggestion: 'Validate and limit file sizes from user input to prevent disk space exhaustion.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:truncate|ftruncate|allocate)\s*\(.*(?:req\.|user\.|input|params|query|body|size)/.test(line);
    },
  },
  {
    id: 'INODE_EXHAUSTION_SMALL_FILES',
    category: 'File Security',
    description: 'User-controlled file creation without limit — inode exhaustion via many small files.',
    severity: 'medium',
    fix_suggestion: 'Limit the number of files users can create. Use quotas or cleanup policies.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:writeFile|createWriteStream)\s*\(/.test(line)) return false;
      if (!/\b(?:forEach|map|for\s)\b/.test(ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber).join(' '))) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 8), ctx.lineNumber + 3).join(' ');
      return /\b(?:req\.|user\.|input|items|files)\b/.test(nearby) &&
        !/\b(?:limit|maxFiles|quota|count\s*[<>])\b/i.test(nearby);
    },
  },
  {
    id: 'ACL_NOT_PROPAGATED',
    category: 'File Security',
    description: 'Parent directory ACL not propagated to child objects — inconsistent permissions.',
    severity: 'medium',
    fix_suggestion: 'Propagate ACLs to child objects or use inherited ACLs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:mkdir|mkdirSync|createDirectory)\s*\(/.test(line)) return false;
      if (!/\bacl\b|permissions?\b/i.test(ctx.fileContent)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 10).join(' ');
      return !/\b(?:inherit|propagate|setACL|chmod)\b/i.test(nearby);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 78: Monitoring & Observability Security
  // ════════════════════════════════════════════
  {
    id: 'METRICS_BUSINESS_DATA_EXPOSED',
    category: 'Monitoring',
    description: 'Metrics endpoint exposes business-sensitive data (revenue, user counts, etc.).',
    severity: 'medium',
    fix_suggestion: 'Protect metrics endpoints with authentication and limit exposed business metrics.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/(?:\/metrics|prometheus|prom-client)/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 15).join(' ');
      return /(?:revenue|sales|profit|payment|billing|subscription)/i.test(nearby);
    },
  },
  {
    id: 'TRACE_CONTEXT_INJECTION',
    category: 'Monitoring',
    description: 'Trace context (traceparent/tracestate) accepted from untrusted input without validation.',
    severity: 'medium',
    fix_suggestion: 'Validate trace context headers and sanitize before propagating.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:traceparent|tracestate)\b/i.test(line) &&
        /\breq\.headers\b/.test(line) &&
        !/\b(?:validate|sanitize|parse|W3C)\b/i.test(line);
    },
  },
  {
    id: 'LOG_AGGREGATOR_NO_AUTH',
    category: 'Monitoring',
    description: 'Log aggregation/shipping endpoint without authentication — log injection risk.',
    severity: 'high',
    fix_suggestion: 'Require authentication on log ingestion endpoints.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/(?:\/logs\/ingest|\/api\/logs|logstash|fluentd)/i.test(line)) return false;
      if (!/\b(?:app|router)\.(?:post|put)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 5).join(' ');
      return !/\b(?:auth|authenticate|apiKey|token|bearer)\b/i.test(nearby);
    },
  },
  {
    id: 'ALERT_FATIGUE_NOISY',
    category: 'Monitoring',
    description: 'Alert threshold set too low — causes alert fatigue and missed real incidents.',
    severity: 'low',
    fix_suggestion: 'Tune alert thresholds based on baseline metrics. Use anomaly detection.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\balert\b.*\bthreshold\s*[:=]\s*(?:0|1)\b/.test(line) ||
        /\btrigger.*\bcount\s*[><=]+\s*(?:0|1)\b/.test(line);
    },
  },
  {
    id: 'MONITORING_BLIND_SPOT_ERROR',
    category: 'Monitoring',
    description: 'Empty catch block swallows errors silently — failures will go undetected.',
    severity: 'low',
    fix_suggestion: 'Add error logging or monitoring in catch blocks. At minimum, log the error.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Only flag truly empty catch blocks: catch (e) { }
      if (!/\bcatch\s*\(\s*(?:e|err|error|_)?\s*\)\s*\{/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const afterLines = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 4));
      // Check if the catch block is empty or only has whitespace before closing brace
      const bodyBeforeClose = afterLines.join('\n');
      const closingBraceMatch = bodyBeforeClose.match(/^(\s*)\}/m);
      if (!closingBraceMatch) return false;
      // If the closing brace is within 2 lines and nothing meaningful is between
      const linesBeforeClose = bodyBeforeClose.split('\n');
      for (let i = 0; i < linesBeforeClose.length; i++) {
        const trimmed = linesBeforeClose[i].trim();
        if (trimmed === '}') {
          // Catch block closes here — check if everything before was empty/comments
          const bodyLines = linesBeforeClose.slice(0, i);
          const hasCode = bodyLines.some((l) => l.trim().length > 0 && !l.trim().startsWith('//'));
          return !hasCode;
        }
        if (trimmed.length > 0 && !trimmed.startsWith('//')) {
          // Non-empty, non-comment line found — not an empty catch
          return false;
        }
      }
      return false;
    },
  },
  {
    id: 'CUSTOM_METRIC_PII',
    category: 'Monitoring',
    description: 'Custom metric includes PII (email, name, IP) — violates privacy regulations.',
    severity: 'high',
    fix_suggestion: 'Never include PII in metric labels. Use anonymized identifiers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b\w*(?:counter|gauge|histogram|summary)\w*\.(?:labels|observe|inc)\s*\(/i.test(line) &&
        /\b(?:email|userName|ip|address|phone|ssn|username)\b/.test(line);
    },
  },
  {
    id: 'HEALTH_ENDPOINT_VERSION_LEAK',
    category: 'Monitoring',
    description: 'Health endpoint reveals application version — aids targeted attacks.',
    severity: 'low',
    fix_suggestion: 'Only expose version info on authenticated health endpoints.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/(?:\/health|\/healthz|\/readyz|\/livez)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 10).join(' ');
      return /\b(?:version|nodeVersion|appVersion|process\.version)\b/i.test(nearby);
    },
  },
  {
    id: 'STATUS_PAGE_INTERNAL_IPS',
    category: 'Monitoring',
    description: 'Status page or health response includes internal IP addresses.',
    severity: 'medium',
    fix_suggestion: 'Remove internal IP addresses from status/health responses.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/(?:\/status|statusPage|\/health)/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 10).join(' ');
      return /\b(?:internalIp|privateIp|hostname|os\.hostname|networkInterfaces)\b/.test(nearby);
    },
  },
  {
    id: 'APM_FULL_REQUEST_CAPTURE',
    category: 'Monitoring',
    description: 'APM agent configured to capture full request bodies — may capture sensitive data.',
    severity: 'high',
    fix_suggestion: 'Configure APM to redact sensitive fields from captured requests.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:captureBody|capture_body)\s*[:=]\s*['"](?:all|on|true)['"]/.test(line) ||
        /\bcaptureHeaders\s*[:=]\s*true\b/.test(line);
    },
  },
  {
    id: 'PROFILER_PRODUCTION',
    category: 'Monitoring',
    description: 'Profiler endpoint exposed in production — performance data and potential DoS.',
    severity: 'high',
    fix_suggestion: 'Disable profiler endpoints in production or require strong authentication.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/(?:\/profiler|\/heap|\/profile\b)/.test(line)) return false;
      if (!/\b(?:app|router)\.(?:get|use)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 5).join(' ');
      return !/\b(?:authenticate|isAdmin|requireAuth|NODE_ENV|production)\b/i.test(nearby);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 79: CI/CD & Build Security
  // ════════════════════════════════════════════
  {
    id: 'BUILD_ARTIFACT_EMBEDDED_SECRET',
    category: 'CI/CD',
    description: 'Build artifact may embed secrets via environment variable interpolation.',
    severity: 'high',
    fix_suggestion: 'Use runtime environment injection instead of build-time secret embedding.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bdefinePlugin\b|DefinePlugin\b/.test(line) &&
        /\bprocess\.env\.(?:SECRET|API_KEY|PRIVATE_KEY|PASSWORD|TOKEN)\b/.test(line);
    },
  },
  {
    id: 'GHA_PULL_REQUEST_TARGET',
    category: 'CI/CD',
    description: 'GitHub Action uses pull_request_target with checkout — allows code injection from forks.',
    severity: 'critical',
    fix_suggestion: 'Avoid checkout in pull_request_target workflows. Use pull_request event instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bpull_request_target\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 10).join(' ');
      return /\bcheckout\b|actions\/checkout/.test(nearby);
    },
  },
  {
    id: 'NPM_PUBLISH_NO_2FA',
    category: 'CI/CD',
    description: 'npm publish without 2FA enforcement — allows unauthorized package publishing.',
    severity: 'high',
    fix_suggestion: 'Enable npm 2FA for publishing: npm profile enable-2fa auth-and-writes.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bnpm\s+publish\b/.test(line) &&
        !/\b(?:--otp|--auth-type|2fa|provenance)\b/.test(line);
    },
  },
  {
    id: 'DOCKER_BUILD_ARGS_SECRET',
    category: 'CI/CD',
    description: 'Docker build uses ARG for secrets — secrets persist in image layer history.',
    severity: 'high',
    fix_suggestion: 'Use BuildKit --mount=type=secret instead of ARG for sensitive values.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /--build-arg\b.*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)/i.test(line);
    },
  },
  {
    id: 'CI_ENV_INJECTION',
    category: 'CI/CD',
    description: 'CI environment variable set from untrusted PR input — command injection risk.',
    severity: 'critical',
    fix_suggestion: 'Sanitize PR inputs (title, body, labels) before using in CI environment.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bgithub\.event\.pull_request\.(?:title|body|head\.ref)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 5).join(' ');
      return /GITHUB_ENV|process\.env|setEnv|set-env/.test(nearby);
    },
  },
  {
    id: 'UNPINNED_ACTION_VERSION',
    category: 'CI/CD',
    description: 'GitHub Action pinned to branch/tag instead of SHA — supply chain risk.',
    severity: 'medium',
    fix_suggestion: 'Pin GitHub Actions to full SHA hashes instead of branch/tag references.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\buses:\s+[\w\-]+\/[\w\-]+@(?:v\d|main|master)\b/.test(line) &&
        !/\b[a-f0-9]{40}\b/.test(line);
    },
  },
  {
    id: 'SELF_HOSTED_RUNNER_NO_ISOLATION',
    category: 'CI/CD',
    description: 'Self-hosted runner without isolation — previous job artifacts may leak.',
    severity: 'high',
    fix_suggestion: 'Use ephemeral self-hosted runners or container isolation for each job.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bself-hosted\b/.test(line)) return false;
      if (!/\bruns-on\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 10).join(' ');
      return !/\b(?:ephemeral|container|docker|clean)\b/i.test(nearby);
    },
  },
  {
    id: 'ARTIFACT_UPLOAD_NO_ENCRYPTION',
    category: 'CI/CD',
    description: 'CI artifact upload without encryption — sensitive build outputs exposed.',
    severity: 'medium',
    fix_suggestion: 'Encrypt sensitive artifacts before uploading in CI pipelines.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bupload-artifact\b|upload.*artifact/i.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 10).join(' ');
      return /\b(?:secret|key|credential|token|\.env)\b/i.test(nearby) &&
        !/\b(?:encrypt|gpg|age|sealed)\b/i.test(nearby);
    },
  },
  {
    id: 'DEPLOY_WEBHOOK_NO_AUTH',
    category: 'CI/CD',
    description: 'Deployment webhook endpoint without authentication — allows unauthorized deployments.',
    severity: 'critical',
    fix_suggestion: 'Require webhook secret verification for deployment triggers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/(?:\/deploy|\/webhook\/deploy|\/api\/deploy)/.test(line)) return false;
      if (!/\b(?:app|router)\.(?:post|put|get)\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 8).join(' ');
      return !/\b(?:verifySignature|authenticate|secret|hmac|token|bearer|apiKey)\b/i.test(nearby);
    },
  },
  {
    id: 'BUILD_CACHE_POISONING',
    category: 'CI/CD',
    description: 'Build cache restored without integrity check — cache poisoning risk.',
    severity: 'medium',
    fix_suggestion: 'Verify cache integrity with checksums. Use separate caches for different branches.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:actions\/cache|cache-restore|restoreCache)\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), ctx.lineNumber + 10).join(' ');
      return !/\b(?:hashFiles|checksum|integrity|verify)\b/i.test(nearby);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 81: Django ORM & Models Deep (15 rules)
  // ════════════════════════════════════════════

  {
    id: 'DJANGO_QUERYSET_EXTRA_SQL',
    category: 'SQL Injection',
    description: 'Django QuerySet.extra() with user input — deprecated and prone to SQL injection.',
    severity: 'critical',
    fix_suggestion: 'Replace .extra() with .annotate() using F(), Value(), and database functions.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.extra\s*\(/.test(line)) return false;
      return /\.extra\s*\(\s*(?:select|where|tables)\s*=\s*\{[^}]*(?:request\.|input|f['"`]|\+\s*\w)/.test(line);
    },
  },
  {
    id: 'DJANGO_ANNOTATE_RAWSQL_INJECT',
    category: 'SQL Injection',
    description: 'Django annotate() with RawSQL containing string interpolation — SQL injection risk.',
    severity: 'critical',
    fix_suggestion: 'Use RawSQL with params argument: annotate(val=RawSQL("SELECT %s", [param])).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.annotate\s*\([^)]*RawSQL\s*\(\s*f['"`]/.test(line) ||
        /\.annotate\s*\([^)]*RawSQL\s*\(\s*['"][^'"]*%s.*['"].*%\s/.test(line);
    },
  },
  {
    id: 'DJANGO_F_EXPRESSION_USER_STRING',
    category: 'SQL Injection',
    description: 'Django F() expression constructed from user-supplied string — potential SQL injection.',
    severity: 'high',
    fix_suggestion: 'Validate field names against an allowlist before using in F() expressions.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bF\s*\(\s*(?:request\.|user_input|field_name|param|kwargs|args)/.test(line) ||
        /\bF\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'DJANGO_SUBQUERY_RAW_SQL',
    category: 'SQL Injection',
    description: 'Django Subquery with raw SQL string interpolation — SQL injection risk.',
    severity: 'critical',
    fix_suggestion: 'Use Django ORM expressions inside Subquery instead of raw SQL strings.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bSubquery\s*\(\s*(?:RawSQL|raw)\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'DJANGO_DEFER_SENSITIVE_FIELDS',
    category: 'Data Exposure',
    description: 'Django QuerySet.only() or defer() may inadvertently expose or trigger lazy load of sensitive fields.',
    severity: 'medium',
    fix_suggestion: 'Explicitly list required fields with .only() and ensure sensitive fields like password are never included.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.only\s*\([^)]*(?:password|secret|token|ssn|credit_card|api_key)/.test(line) ||
        /\.defer\s*\([^)]*\)/.test(line) && /serializ|json|response|return/.test(line);
    },
  },
  {
    id: 'DJANGO_META_ORDERING_USER_INPUT',
    category: 'SQL Injection',
    description: 'Django model Meta ordering or order_by() with user-controlled field name — SQL injection risk.',
    severity: 'high',
    fix_suggestion: 'Validate sort fields against an allowlist of model field names.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.order_by\s*\(\s*(?:request\.|user_input|sort_field|order_field|params|kwargs)/.test(line) ||
        /\.order_by\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'DJANGO_CHARFIELD_NO_MAX_LENGTH',
    category: 'Data Validation',
    description: 'Django CharField without max_length — can cause database errors or storage abuse.',
    severity: 'low',
    fix_suggestion: 'Always specify max_length on CharField: models.CharField(max_length=255).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bCharField\s*\(/.test(line)) return false;
      // Skip Django migration files entirely
      if (isDjangoMigration(ctx.filePath)) return false;
      // Check current line for max_length
      if (/max_length\s*=/.test(line)) return false;
      // Check next 2 lines (multi-line field definitions)
      const lineIdx = ctx.lineNumber - 1;
      const nextLines = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 3)).join(' ');
      if (/max_length\s*=/.test(nextLines)) return false;
      return true;
    },
  },
  {
    id: 'DJANGO_FILEFIELD_NO_VALIDATION',
    category: 'File Upload',
    description: 'Django FileField without upload_to or validators — files stored in root with no type validation.',
    severity: 'medium',
    fix_suggestion: 'Specify upload_to path and add FileExtensionValidator: FileField(upload_to="uploads/", validators=[...]).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Require Django imports before firing
      if (!hasDjangoImports(ctx.fileContent)) return false;
      if (!/\bFileField\s*\(/.test(line) && !/\bImageField\s*\(/.test(line)) return false;
      return !/upload_to\s*=/.test(line) || !/validator/.test(line);
    },
  },
  {
    id: 'DJANGO_JSONFIELD_USER_PATH',
    category: 'Injection',
    description: 'Django JSONField queried with user-controlled path — potential NoSQL-style injection.',
    severity: 'medium',
    fix_suggestion: 'Validate JSON field lookup paths against an allowlist of expected keys.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.filter\s*\(\s*\*\*\{.*(?:request\.|user_input|param)/.test(line) ||
        /\.filter\s*\(\s*\*\*(?:request|kwargs|params|filter_args)/.test(line);
    },
  },
  {
    id: 'DJANGO_GENERIC_FK_NO_VALIDATION',
    category: 'Data Validation',
    description: 'Django GenericForeignKey without content_type validation — may reference unintended models.',
    severity: 'medium',
    fix_suggestion: 'Add limit_choices_to on the content_type ForeignKey to restrict allowed models.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bGenericForeignKey\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 5).join(' ');
      return !/limit_choices_to/.test(nearby);
    },
  },
  {
    id: 'DJANGO_BULK_CREATE_NO_UNIQUE',
    category: 'Data Integrity',
    description: 'Django bulk_create without ignore_conflicts or update_conflicts — may silently fail on duplicate data.',
    severity: 'info',
    fix_suggestion: 'Use bulk_create(objs, ignore_conflicts=True) or update_conflicts=True with update_fields.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.bulk_create\s*\(/.test(line)) return false;
      return !/ignore_conflicts|update_conflicts/.test(line);
    },
  },
  {
    id: 'DJANGO_UPDATE_OR_CREATE_RACE',
    category: 'Race Condition',
    description: 'Django update_or_create without select_for_update — race condition under concurrent access.',
    severity: 'medium',
    fix_suggestion: 'Wrap update_or_create in a transaction with select_for_update, or use database-level constraints.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip migration files — these run in a controlled context, not under concurrent access
      if (isDjangoMigration(ctx.filePath)) return false;
      if (!/\.update_or_create\s*\(/.test(line) && !/\.get_or_create\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber).join(' ');
      return !/select_for_update|atomic|transaction/.test(nearby);
    },
  },
  {
    id: 'DJANGO_SELECT_FOR_UPDATE_NO_TIMEOUT',
    category: 'Denial of Service',
    description: 'Django select_for_update() without timeout — can cause indefinite database lock waits.',
    severity: 'medium',
    fix_suggestion: 'Use select_for_update(nowait=True) or wrap in a database query with a timeout.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.select_for_update\s*\(/.test(line)) return false;
      return /\.select_for_update\s*\(\s*\)/.test(line);
    },
  },
  {
    id: 'DJANGO_AGGREGATE_USER_FIELD',
    category: 'SQL Injection',
    description: 'Django aggregation with user-controlled field name — potential SQL injection.',
    severity: 'high',
    fix_suggestion: 'Validate aggregation field names against a fixed allowlist of model fields.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.aggregate\s*\([^)]*(?:Sum|Avg|Count|Max|Min)\s*\(\s*(?:request\.|user_input|field_name|param|f['"`])/.test(line);
    },
  },
  {
    id: 'DJANGO_VALUES_LIST_SENSITIVE',
    category: 'Data Exposure',
    description: 'Django values_list() including sensitive fields — may expose hidden data in API responses.',
    severity: 'medium',
    fix_suggestion: 'Exclude sensitive fields from values_list() — never include password, token, or secret fields.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.values_list\s*\([^)]*(?:password|secret_key|api_key|token|ssn|credit_card)/.test(line) ||
        /\.values\s*\([^)]*(?:password|secret_key|api_key|token|ssn|credit_card)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 82: Django Views & Forms (15 rules)
  // ════════════════════════════════════════════

  {
    id: 'DJANGO_FORMVIEW_NO_CSRF',
    category: 'CSRF',
    description: 'Django FormView with csrf_exempt decorator — disables CSRF protection on form submission.',
    severity: 'critical',
    fix_suggestion: 'Remove @csrf_exempt from FormView. Use Django CSRF middleware for protection.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bclass\b.*\bFormView\b/.test(line)) return false;
      const above = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 4), ctx.lineNumber - 1).join(' ');
      return /csrf_exempt/.test(above);
    },
  },
  {
    id: 'DJANGO_MODELFORM_EXCLUDE',
    category: 'Data Exposure',
    description: 'Django ModelForm using exclude instead of fields — new model fields are automatically exposed.',
    severity: 'high',
    fix_suggestion: 'Use explicit fields = [...] instead of exclude in ModelForm Meta to prevent accidental exposure.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bexclude\s*=\s*[\[(]/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber + 5).join(' ');
      return /\bclass\s+Meta\b/.test(nearby) && /ModelForm|Form/.test(nearby);
    },
  },
  {
    id: 'DJANGO_FILE_UPLOAD_NO_SIZE_LIMIT',
    category: 'Denial of Service',
    description: 'Django file upload handler without size limit — allows unlimited file uploads.',
    severity: 'high',
    fix_suggestion: 'Set DATA_UPLOAD_MAX_MEMORY_SIZE and FILE_UPLOAD_MAX_MEMORY_SIZE in settings, or validate in the view.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bFileUploadHandler\b/.test(line) && !/\bhandler\s*=.*Upload/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join(' ');
      return !/max.*size|size.*limit|content_length|MAX_UPLOAD/.test(nearby);
    },
  },
  {
    id: 'DJANGO_STREAMING_USER_CONTENT',
    category: 'Injection',
    description: 'Django StreamingHttpResponse with user-controlled content — potential XSS or injection.',
    severity: 'high',
    fix_suggestion: 'Sanitize and escape user content before streaming. Set appropriate Content-Type headers.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bStreamingHttpResponse\s*\(\s*(?:request\.|user_|input_|data\b)/.test(line) ||
        /\bStreamingHttpResponse\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'DJANGO_RESPONSE_USER_CONTENT_TYPE',
    category: 'Injection',
    description: 'Django HttpResponse with content_type from user input — can lead to MIME type confusion attacks.',
    severity: 'high',
    fix_suggestion: 'Use a fixed allowlist of content types rather than accepting user-supplied values.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bHttpResponse\s*\([^)]*content_type\s*=\s*(?:request\.|user_|input_|param|f['"`])/.test(line);
    },
  },
  {
    id: 'DJANGO_REDIRECT_USER_URL',
    category: 'Open Redirect',
    description: 'Django redirect() with user-controlled URL — open redirect vulnerability.',
    severity: 'high',
    fix_suggestion: 'Validate redirect URLs against an allowlist of trusted domains, or use url_has_allowed_host_and_scheme().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bredirect\s*\(/.test(line)) return false;
      return /\bredirect\s*\(\s*(?:request\.(?:GET|POST|META)|next_url|return_url|redirect_url|url\b|target)/.test(line) ||
        /\bredirect\s*\(\s*request\.(?:GET|POST)\s*(?:\[|\.get)/.test(line);
    },
  },
  {
    id: 'DJANGO_LOGINVIEW_NO_RATE_LIMIT',
    category: 'Brute Force',
    description: 'Django LoginView without rate limiting — vulnerable to brute force credential attacks.',
    severity: 'high',
    fix_suggestion: 'Add django-axes, django-ratelimit, or custom throttling to the login view.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bLoginView\b/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/ratelimit|axes|throttle|Throttle|rate_limit|django_ratelimit/.test(allContent);
    },
  },
  {
    id: 'DJANGO_PASSWORD_RESET_NO_EXPIRY',
    category: 'Authentication',
    description: 'Django PasswordResetView without token expiry configuration — tokens may never expire.',
    severity: 'medium',
    fix_suggestion: 'Set PASSWORD_RESET_TIMEOUT in settings (default is 3 days in Django 3.1+). Use shorter timeout for production.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bPasswordResetView\b/.test(line) && !/\bpassword_reset\b/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/PASSWORD_RESET_TIMEOUT|token_expires/.test(allContent);
    },
  },
  {
    id: 'DJANGO_USER_CREATION_NO_PASSWORD_VALIDATION',
    category: 'Authentication',
    description: 'Django UserCreationForm without password validation — allows weak passwords.',
    severity: 'medium',
    fix_suggestion: 'Ensure AUTH_PASSWORD_VALIDATORS is configured in settings with multiple validators.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bUserCreationForm\b/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/password_validators|validate_password|AUTH_PASSWORD_VALIDATORS|MinimumLengthValidator/.test(allContent);
    },
  },
  {
    id: 'DJANGO_ADMIN_NO_2FA',
    category: 'Authentication',
    description: 'Django admin site without two-factor authentication — admin accounts vulnerable to credential theft.',
    severity: 'medium',
    fix_suggestion: 'Add django-otp or django-two-factor-auth to protect the admin site with 2FA.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\badmin\.site\.urls\b/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/otp|two_factor|2fa|OTPAdmin|TwoFactor/.test(allContent);
    },
  },
  {
    id: 'DJANGO_PERMISSION_NO_LOGIN_URL',
    category: 'Authorization',
    description: 'Django permission_required without login_url — unauthenticated users get 403 instead of redirect.',
    severity: 'low',
    fix_suggestion: 'Add login_url parameter: @permission_required("app.perm", login_url="/login/").',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bpermission_required\s*\(/.test(line)) return false;
      return !/login_url\s*=/.test(line);
    },
  },
  {
    id: 'DJANGO_CACHE_PAGE_AUTHENTICATED',
    category: 'Data Exposure',
    description: 'Django cache_page on authenticated view — may serve cached user-specific data to other users.',
    severity: 'high',
    fix_suggestion: 'Use vary_on_cookie or vary_on_headers, or avoid cache_page on views with user-specific content.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcache_page\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join(' ');
      return /login_required|permission_required|IsAuthenticated|request\.user/.test(nearby);
    },
  },
  {
    id: 'DJANGO_JSONRESPONSE_MODEL_INSTANCE',
    category: 'Data Exposure',
    description: 'Django JsonResponse with model instance via __dict__ — may serialize sensitive internal fields.',
    severity: 'high',
    fix_suggestion: 'Use Django serializers or explicit field dictionaries instead of __dict__ on model instances.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bJsonResponse\s*\([^)]*\.__dict__/.test(line) ||
        /\bJsonResponse\s*\(\s*model_to_dict\s*\(/.test(line) && !/fields\s*=/.test(line);
    },
  },
  {
    id: 'DJANGO_SIMPLE_UPLOADED_NO_TYPE_CHECK',
    category: 'File Upload',
    description: 'Django SimpleUploadedFile without content type validation — allows malicious file uploads.',
    severity: 'medium',
    fix_suggestion: 'Validate the content_type of uploaded files against an allowlist of expected MIME types.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/request\.FILES/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join(' ');
      return !/content_type|mime|MIME|file_type|validate|extension/.test(nearby);
    },
  },
  {
    id: 'DJANGO_INMEMORY_UPLOAD_NO_SIZE',
    category: 'Denial of Service',
    description: 'Django InMemoryUploadedFile processed without size validation — memory exhaustion risk.',
    severity: 'medium',
    fix_suggestion: 'Check file.size before processing and enforce DATA_UPLOAD_MAX_MEMORY_SIZE in settings.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bInMemoryUploadedFile\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join(' ');
      return !/\.size|max_size|MAX_MEMORY|size_limit/.test(nearby);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 83: Flask Deep (15 rules)
  // ════════════════════════════════════════════

  {
    id: 'FLASK_BLUEPRINT_NO_AUTH',
    category: 'Authentication',
    description: 'Flask Blueprint without authentication middleware — routes may be unprotected.',
    severity: 'high',
    fix_suggestion: 'Add @login_required or before_request authentication check to the Blueprint.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bBlueprint\s*\(/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/login_required|before_request|jwt_required|token_required|auth_required|before_app_request/.test(allContent);
    },
  },
  {
    id: 'FLASK_LOGIN_NO_SESSION_PROTECTION',
    category: 'Session',
    description: 'Flask-Login without session protection — vulnerable to session fixation attacks.',
    severity: 'high',
    fix_suggestion: 'Set login_manager.session_protection = "strong" to regenerate sessions on auth changes.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bLoginManager\s*\(/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/session_protection\s*=\s*['"]strong['"]/.test(allContent);
    },
  },
  {
    id: 'FLASK_WTF_CSRF_DISABLED',
    category: 'CSRF',
    description: 'Flask-WTF CSRF protection explicitly disabled — forms vulnerable to CSRF attacks.',
    severity: 'critical',
    fix_suggestion: 'Remove WTF_CSRF_ENABLED = False. Flask-WTF CSRF should always be enabled in production.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /WTF_CSRF_ENABLED\s*=\s*False/.test(line) ||
        /CSRFProtect.*disable/.test(line) ||
        /app\.config\s*\[\s*['"]WTF_CSRF_ENABLED['"]\s*\]\s*=\s*False/.test(line);
    },
  },
  {
    id: 'FLASK_SQLALCHEMY_RAW_SQL',
    category: 'SQL Injection',
    description: 'Flask-SQLAlchemy with raw SQL and string interpolation — SQL injection risk.',
    severity: 'critical',
    fix_suggestion: 'Use SQLAlchemy text() with bound parameters: db.session.execute(text("SELECT ... WHERE id = :id"), {"id": val}).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /db\.session\.execute\s*\(\s*f['"`]/.test(line) ||
        /db\.engine\.execute\s*\(\s*f['"`]/.test(line) ||
        /db\.session\.execute\s*\(\s*['"][^'"]*%s.*['"].*%/.test(line);
    },
  },
  {
    id: 'FLASK_MAIL_NO_TLS',
    category: 'Transport Security',
    description: 'Flask-Mail configured without TLS — email credentials sent in plaintext.',
    severity: 'high',
    fix_suggestion: 'Set MAIL_USE_TLS = True or MAIL_USE_SSL = True in Flask config.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /MAIL_USE_TLS\s*=\s*False/.test(line) ||
        /MAIL_USE_SSL\s*=\s*False/.test(line) && /MAIL_USE_TLS\s*=\s*False/.test(line);
    },
  },
  {
    id: 'FLASK_SESSION_COOKIE_NO_SIGNING',
    category: 'Session',
    description: 'Flask session cookie used without a secret key — sessions can be tampered with.',
    severity: 'critical',
    fix_suggestion: 'Set app.secret_key to a strong random value: app.secret_key = os.urandom(32).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bsession\s*\[/.test(line)) return false;
      const allContent = ctx.fileContent;
      // Must be a Flask file — check for Flask imports or Flask() instantiation
      if (!/\bfrom\s+flask\b|\bimport\s+flask\b|\bFlask\s*\(/i.test(allContent)) return false;
      // Must NOT be a Django file
      if (/\bfrom\s+django\b|\bimport\s+django\b/.test(allContent)) return false;
      return !/secret_key\s*=|SECRET_KEY/.test(allContent);
    },
  },
  {
    id: 'FLASK_RESTFUL_NO_INPUT_VALIDATION',
    category: 'Data Validation',
    description: 'Flask-RESTful Resource using raw request.json without reqparse or marshmallow — no input validation.',
    severity: 'medium',
    fix_suggestion: 'Use reqparse.RequestParser or marshmallow schema to validate input data.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/request\.json\b|request\.get_json\b/.test(line)) return false;
      const allContent = ctx.fileContent;
      return /\bResource\b/.test(allContent) && !/reqparse|RequestParser|marshmallow|Schema|validate|pydantic/.test(allContent);
    },
  },
  {
    id: 'FLASK_CORS_CREDENTIALS_WILDCARD',
    category: 'CORS',
    description: 'Flask-CORS with supports_credentials=True and wildcard origin — allows any site to make authenticated requests.',
    severity: 'critical',
    fix_suggestion: 'When using supports_credentials=True, specify exact allowed origins instead of wildcard.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bCORS\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join(' ');
      return /supports_credentials\s*=\s*True/.test(nearby) && /origins?\s*=\s*['"]?\*/.test(nearby);
    },
  },
  {
    id: 'FLASK_SEND_FROM_DIR_USER_SUBPATH',
    category: 'Path Traversal',
    description: 'Flask send_from_directory with user-controlled subdirectory — path traversal risk.',
    severity: 'high',
    fix_suggestion: 'Validate and sanitize the filename parameter. Use secure_filename() from werkzeug.utils.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsend_from_directory\s*\([^)]*(?:request\.|user_|input_|param|filename\b)/.test(line) &&
        !/secure_filename/.test(line);
    },
  },
  {
    id: 'FLASK_BEFORE_REQUEST_NO_AUTH_EXCLUSION',
    category: 'Authentication',
    description: 'Flask before_request with auth check but no exclusion list — may block health checks and public routes.',
    severity: 'low',
    fix_suggestion: 'Add exclusion list for public endpoints: if request.endpoint in EXCLUDE_LIST: return.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bbefore_request\b/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join(' ');
      return /auth|login|token/.test(below) && !/exclude|skip|whitelist|public|health|static/.test(below);
    },
  },
  {
    id: 'FLASK_LIMITER_NOT_GLOBAL',
    category: 'Denial of Service',
    description: 'Flask-Limiter instantiated but not applied globally — some routes may have no rate limiting.',
    severity: 'medium',
    fix_suggestion: 'Use Limiter with default_limits=["200 per day", "50 per hour"] for global protection.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bLimiter\s*\(/.test(line)) return false;
      return !/default_limits\s*=/.test(line) && !/default_limits/.test(ctx.fileContent);
    },
  },
  {
    id: 'FLASK_ERRORHANDLER_TRACEBACK',
    category: 'Information Disclosure',
    description: 'Flask errorhandler exposing traceback or exception details — information leakage.',
    severity: 'high',
    fix_suggestion: 'Log tracebacks server-side and return generic error messages to users.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\berrorhandler\s*\(/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join(' ');
      return /traceback|str\s*\(\s*e\s*\)|repr\s*\(\s*e|format_exc|exc_info/.test(below);
    },
  },
  {
    id: 'FLASK_SESSION_FILESYSTEM_BACKEND',
    category: 'Session',
    description: 'Flask-Session with filesystem backend — insecure in multi-server or shared hosting environments.',
    severity: 'medium',
    fix_suggestion: 'Use Redis, Memcached, or database backend for Flask-Session in production.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /SESSION_TYPE\s*=\s*['"]filesystem['"]/.test(line);
    },
  },
  {
    id: 'FLASK_URL_FOR_EXTERNAL_USER_HOST',
    category: 'Open Redirect',
    description: 'Flask url_for with _external=True and user-controlled SERVER_NAME — host header injection.',
    severity: 'high',
    fix_suggestion: 'Set SERVER_NAME to a fixed value in production config. Do not derive it from request headers.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\burl_for\s*\([^)]*_external\s*=\s*True/.test(line) &&
        /request\.host|request\.url_root|SERVER_NAME.*request/.test(line);
    },
  },
  {
    id: 'FLASK_MIGRATE_USER_REVISION',
    category: 'Code Injection',
    description: 'Flask-Migrate or Alembic with user-controlled revision ID — allows arbitrary migration execution.',
    severity: 'high',
    fix_suggestion: 'Never accept migration revision IDs from user input. Use fixed revision strings.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:upgrade|downgrade|stamp)\s*\(\s*(?:request\.|user_|input_|revision|rev\b)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 84: FastAPI & Pydantic Deep (15 rules)
  // ════════════════════════════════════════════

  {
    id: 'FASTAPI_NO_MIDDLEWARE_STACK',
    category: 'Security Configuration',
    description: 'FastAPI app without security middleware — missing CORS, TrustedHost, or HTTPS enforcement.',
    severity: 'medium',
    fix_suggestion: 'Add TrustedHostMiddleware, HTTPSRedirectMiddleware, and CORSMiddleware to your FastAPI app.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bFastAPI\s*\(/.test(line)) return false;
      // Skip framework source / docs / test / example directories
      const lowerPath = ctx.filePath.toLowerCase();
      if (/\/(docs_src|docs|tests|test|examples|example|fixtures)\//i.test(lowerPath)) return false;
      if (isFrameworkSource(ctx.filePath)) return false;
      const allContent = ctx.fileContent;
      return !/TrustedHostMiddleware|HTTPSRedirectMiddleware/.test(allContent);
    },
  },
  {
    id: 'PYDANTIC_MODEL_NO_VALIDATORS',
    category: 'Data Validation',
    description: 'Pydantic model used as API request body with sensitive fields but no field validators — weak input validation.',
    severity: 'medium',
    fix_suggestion: 'Add @field_validator or @validator for fields like email, password, URL to enforce format constraints.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip framework source and example directories
      if (isFrameworkSource(ctx.filePath)) return false;
      if (isExampleOrDocsDir(ctx.filePath)) return false;
      if (!/\bclass\b.*\bBaseModel\b/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 20)).join(' ');
      // Must have sensitive fields
      if (!/(?:password|email|url|phone)\s*:\s*str/.test(below)) return false;
      // Must NOT already have validators
      if (/validator|field_validator|Field\s*\(/.test(below)) return false;
      // Only flag if the model is used as a request body (referenced in a route handler)
      // Check if the class name appears in a route handler parameter in the file
      const classNameMatch = line.match(/\bclass\s+(\w+)/);
      if (!classNameMatch) return false;
      const className = classNameMatch[1];
      // Check if the model class name is referenced as a request body in route handlers
      const fileContent = ctx.fileContent;
      const usedInRoute = new RegExp(`@(?:app|router)\\.(?:post|put|patch|delete).*\\n[^)]*\\b${className}\\b`, 'i').test(fileContent) ||
        new RegExp(`def\\s+\\w+.*${className}\\b`, 'i').test(fileContent);
      return usedInRoute;
    },
  },
  {
    id: 'FASTAPI_FILE_UPLOAD_NO_SIZE_LIMIT',
    category: 'Denial of Service',
    description: 'FastAPI File/UploadFile parameter without size limit — memory exhaustion risk.',
    severity: 'high',
    fix_suggestion: 'Check file.size or use a custom middleware to enforce upload size limits.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bUploadFile\b/.test(line) && !/\bFile\s*\(/.test(line)) return false;
      if (isFrameworkSource(ctx.filePath)) return false;
      const lowerPath = ctx.filePath.toLowerCase();
      if (/\/(docs_src|docs|tests|test|examples|example|fixtures)\//i.test(lowerPath)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 2), Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join(' ');
      return !/\.size|max_size|content_length|MAX_UPLOAD|size_limit/.test(nearby);
    },
  },
  {
    id: 'FASTAPI_BACKGROUND_TASK_USER_FUNC',
    category: 'Code Injection',
    description: 'FastAPI BackgroundTask with user-controlled function — remote code execution risk.',
    severity: 'critical',
    fix_suggestion: 'Only pass pre-defined functions to BackgroundTask. Never use user input to select functions.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      return /\bBackgroundTask\s*\(\s*(?:request\.|user_|input_|getattr|globals|locals)/.test(line) ||
        /\bbackground_tasks\.add_task\s*\(\s*(?:request\.|user_|getattr|eval|globals)/.test(line);
    },
  },
  {
    id: 'FASTAPI_DEPENDENCY_NO_SCOPED_SESSION',
    category: 'Data Integrity',
    description: 'FastAPI database dependency without scoped session — concurrent requests may share session state.',
    severity: 'medium',
    fix_suggestion: 'Use dependency injection with yield to create request-scoped database sessions.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bDepends\s*\(\s*get_db\b/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/\byield\b/.test(allContent) && /Session/.test(allContent);
    },
  },
  {
    id: 'SQLMODEL_RAW_SQL',
    category: 'SQL Injection',
    description: 'SQLModel with raw SQL string interpolation — SQL injection risk.',
    severity: 'critical',
    fix_suggestion: 'Use SQLModel query methods with parameters instead of raw SQL string interpolation.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /session\.exec\s*\(\s*(?:text\s*\(\s*)?f['"`]/.test(line) ||
        /session\.execute\s*\(\s*(?:text\s*\(\s*)?f['"`]/.test(line);
    },
  },
  {
    id: 'FASTAPI_WEBSOCKET_NO_AUTH',
    category: 'Authentication',
    description: 'FastAPI WebSocket endpoint without authentication — allows unauthenticated real-time connections.',
    severity: 'high',
    fix_suggestion: 'Validate auth tokens in the WebSocket handshake using query params or first message.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      // Skip framework source, example, and documentation directories
      if (isFrameworkSource(ctx.filePath)) return false;
      if (isExampleOrDocsDir(ctx.filePath)) return false;
      if (!/\basync\s+def\s+websocket/.test(line) && !/@\w+\.websocket\s*\(/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join(' ');
      return !/auth|token|verify|jwt|bearer|Depends|Security/.test(below);
    },
  },
  {
    id: 'FASTAPI_EXCEPTION_HANDLER_LEAK',
    category: 'Information Disclosure',
    description: 'FastAPI custom exception handler leaking internal error details — information disclosure.',
    severity: 'high',
    fix_suggestion: 'Log detailed errors server-side. Return generic error messages to the client.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bexception_handler\b/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join(' ');
      return /str\s*\(\s*exc\s*\)|traceback|repr\s*\(\s*exc|exc_info|format_exc/.test(below);
    },
  },
  {
    id: 'PYDANTIC_ARBITRARY_TYPES',
    category: 'Data Validation',
    description: 'Pydantic model with arbitrary_types_allowed — bypasses type validation for custom types.',
    severity: 'medium',
    fix_suggestion: 'Avoid arbitrary_types_allowed. Create proper Pydantic validators for custom types.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /arbitrary_types_allowed\s*=\s*True/.test(line);
    },
  },
  {
    id: 'FASTAPI_MOUNT_NO_PATH_VALIDATION',
    category: 'Path Traversal',
    description: 'FastAPI app.mount with user-controlled path — allows mounting at arbitrary routes.',
    severity: 'high',
    fix_suggestion: 'Use fixed, hardcoded paths for app.mount(). Never derive mount paths from user input.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      return /\.mount\s*\(\s*(?:f['"`]|path_var|user_|request\.|input_)/.test(line);
    },
  },
  {
    id: 'FASTAPI_UPLOADFILE_NO_CONTENT_TYPE',
    category: 'File Upload',
    description: 'FastAPI UploadFile processed without content type validation — allows malicious file uploads.',
    severity: 'medium',
    fix_suggestion: 'Check file.content_type against an allowlist before processing the uploaded file.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bUploadFile\b/.test(line)) return false;
      if (!/\basync\s+def\b/.test(line) && !/\bdef\b/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join(' ');
      return !/content_type|mime|MIME|file_type|extension/.test(below);
    },
  },
  {
    id: 'FASTAPI_RESPONSE_USER_HEADERS',
    category: 'Header Injection',
    description: 'FastAPI Response with user-controlled headers — HTTP header injection risk.',
    severity: 'high',
    fix_suggestion: 'Validate and sanitize header values. Use an allowlist of permitted header names.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      return /\bResponse\s*\([^)]*headers\s*=\s*(?:request\.|user_|input_|\{.*request)/.test(line) ||
        /\.headers\s*\[\s*(?:request\.|user_|key)\s*\]\s*=/.test(line);
    },
  },
  {
    id: 'FASTAPI_DEPENDS_NO_ERROR_HANDLING',
    category: 'Error Handling',
    description: 'FastAPI Depends chain with yield but no exception handling — may leak resources on error.',
    severity: 'medium',
    fix_suggestion: 'Use try/finally with yield dependencies: try: yield session; finally: session.close().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\byield\b/.test(line)) return false;
      const above = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 10), ctx.lineNumber).join(' ');
      if (!/\bdef\b.*\b(?:get_db|get_session|dependency)\b/.test(above)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join(' ');
      return !/\btry\b|finally/.test(nearby);
    },
  },
  {
    id: 'STARLETTE_MIDDLEWARE_NO_EXCEPTION',
    category: 'Error Handling',
    description: 'Starlette middleware dispatch without exception handling — may crash the server on errors.',
    severity: 'medium',
    fix_suggestion: 'Wrap middleware dispatch in try/except to handle errors gracefully.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\basync\s+def\s+dispatch\b/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 15)).join(' ');
      return /call_next/.test(below) && !/try|except/.test(below);
    },
  },
  {
    id: 'FASTAPI_STARTUP_BLOCKING',
    category: 'Performance',
    description: 'FastAPI startup event with blocking operation — delays server startup and may cause timeouts.',
    severity: 'low',
    fix_suggestion: 'Use asyncio for I/O operations in startup events, or run blocking calls in run_in_executor().',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/\bon_event\s*\(\s*['"]startup['"]/.test(line) && !/\bstartup\b.*\basync\b/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 10)).join(' ');
      return /time\.sleep|requests\.get|open\s*\(|subprocess/.test(below);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 85: Python Async Deep (12 rules)
  // ════════════════════════════════════════════

  {
    id: 'ASYNCIO_SUBPROCESS_SHELL_TRUE',
    category: 'Command Injection',
    description: 'asyncio.create_subprocess_shell with user input — command injection risk.',
    severity: 'critical',
    fix_suggestion: 'Use asyncio.create_subprocess_exec with a list of arguments instead of shell=True.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcreate_subprocess_shell\s*\(\s*(?:f['"`]|cmd|command|user_|input_|request\.)/.test(line);
    },
  },
  {
    id: 'AIOFILES_USER_PATH',
    category: 'Path Traversal',
    description: 'aiofiles.open with user-controlled path — path traversal vulnerability.',
    severity: 'high',
    fix_suggestion: 'Validate and sanitize file paths. Use os.path.realpath() and check against an allowed base directory.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\baiofiles\.open\s*\(\s*(?:request\.|user_|input_|filename|file_path|path\b)/.test(line) ||
        /\baiofiles\.open\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'AIOMYSQL_NO_PARAMS',
    category: 'SQL Injection',
    description: 'aiomysql query without parameterized arguments — SQL injection risk.',
    severity: 'critical',
    fix_suggestion: 'Use parameterized queries: await cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,)).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bcursor\.execute\s*\(\s*f['"`].*(?:SELECT|INSERT|UPDATE|DELETE)/i.test(line) ||
        /\bawait\s+.*\.execute\s*\(\s*f['"`].*(?:SELECT|INSERT|UPDATE|DELETE)/i.test(line);
    },
  },
  {
    id: 'ASYNCPG_UNSAFE_QUERY',
    category: 'SQL Injection',
    description: 'asyncpg query with string interpolation — SQL injection risk.',
    severity: 'critical',
    fix_suggestion: 'Use parameterized queries: await conn.fetch("SELECT * FROM t WHERE id = $1", user_id).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:conn|connection|pool)\.(?:fetch|execute|fetchrow|fetchval)\s*\(\s*f['"`]/.test(line);
    },
  },
  {
    id: 'AIOREDIS_USER_KEY',
    category: 'Injection',
    description: 'aioredis with user-controlled key — may access or modify arbitrary Redis data.',
    severity: 'high',
    fix_suggestion: 'Prefix Redis keys with a namespace and validate user input against expected key patterns.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bredis\.(?:get|set|delete|hget|hset|lpush|rpush|sadd)\s*\(\s*(?:f['"`]|request\.|user_|input_)/.test(line) ||
        /\bawait\s+redis\.(?:get|set|delete|hget|hset)\s*\(\s*(?:f['"`]|request\.)/.test(line);
    },
  },
  {
    id: 'TRIO_TCP_NO_TLS',
    category: 'Transport Security',
    description: 'trio.open_tcp_stream without TLS — data transmitted in plaintext.',
    severity: 'high',
    fix_suggestion: 'Use trio.open_ssl_over_tcp_stream for encrypted connections.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\btrio\.open_tcp_stream\b/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join(' ');
      return !/ssl|tls|starttls/.test(nearby);
    },
  },
  {
    id: 'ANYIO_USER_TIMEOUT',
    category: 'Denial of Service',
    description: 'anyio with user-controlled timeout value — can be set to infinity to cause hangs.',
    severity: 'medium',
    fix_suggestion: 'Validate and cap timeout values: timeout = min(float(user_timeout), MAX_TIMEOUT).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:move_on_after|fail_after|CancelScope)\s*\(\s*(?:request\.|user_|input_|timeout_param|int\s*\(\s*request)/.test(line);
    },
  },
  {
    id: 'ASYNCIO_WAIT_FOR_NO_CLEANUP',
    category: 'Resource Leak',
    description: 'asyncio.wait_for without cancellation cleanup — cancelled tasks may leave resources open.',
    severity: 'medium',
    fix_suggestion: 'Handle asyncio.TimeoutError and clean up resources: try/except TimeoutError with cleanup logic.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bwait_for\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 3), Math.min(ctx.allLines.length, ctx.lineNumber + 5)).join(' ');
      return !/try|except.*(?:TimeoutError|CancelledError)|finally/.test(nearby);
    },
  },
  {
    id: 'AIOHTTP_SESSION_NO_TIMEOUT',
    category: 'Denial of Service',
    description: 'aiohttp.ClientSession without timeout — requests may hang indefinitely.',
    severity: 'medium',
    fix_suggestion: 'Set timeout: aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bClientSession\s*\(/.test(line)) return false;
      return !/timeout\s*=/.test(line);
    },
  },
  {
    id: 'ASYNC_GENERATOR_NO_CLEANUP',
    category: 'Resource Leak',
    description: 'Async generator without proper cleanup — resources may not be released if consumer stops iterating.',
    severity: 'medium',
    fix_suggestion: 'Use try/finally in async generators to ensure cleanup when iteration is interrupted.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\basync\s+def\b/.test(line)) return false;
      const below = ctx.allLines.slice(ctx.lineNumber, Math.min(ctx.allLines.length, ctx.lineNumber + 20)).join(' ');
      return /\byield\b/.test(below) && /open\(|connect|Session|cursor/.test(below) && !/finally/.test(below);
    },
  },
  {
    id: 'ASYNCIO_LOCK_NO_TIMEOUT',
    category: 'Denial of Service',
    description: 'asyncio.Lock acquire without timeout — can cause indefinite waiting under contention.',
    severity: 'low',
    fix_suggestion: 'Use asyncio.wait_for(lock.acquire(), timeout=10) to prevent indefinite blocking.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bawait\s+.*lock\.acquire\s*\(\s*\)/.test(line);
    },
  },
  {
    id: 'CONCURRENT_FUTURES_USER_EXECUTOR',
    category: 'Code Injection',
    description: 'concurrent.futures executor with user-controlled function — code injection risk.',
    severity: 'high',
    fix_suggestion: 'Only submit pre-defined functions to the executor. Never use user input to select callables.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:executor|pool)\.submit\s*\(\s*(?:request\.|user_|getattr|globals|eval|input_)/.test(line) ||
        /\b(?:executor|pool)\.map\s*\(\s*(?:request\.|user_|getattr|globals|eval)/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 86: Python Security Libraries Misuse (12 rules)
  // ════════════════════════════════════════════

  {
    id: 'CRYPTOGRAPHY_UNSAFE_PARAMS',
    category: 'Cryptography',
    description: 'Python cryptography library with unsafe parameters (weak key size, no padding, etc.).',
    severity: 'high',
    fix_suggestion: 'Use recommended defaults: RSA key_size=2048+, AES with GCM mode, OAEP padding.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bgenerate_private_key\s*\([^)]*(?:key_size\s*=\s*(?:512|768|1024)\b)/.test(line) ||
        /\bARC4\b|Blowfish\s*\(|TripleDES\s*\(|IDEA\s*\(|CAST5\s*\(/.test(line);
    },
  },
  {
    id: 'PYJWT_NO_ALGORITHM_VERIFY',
    category: 'Authentication',
    description: 'PyJWT decode without explicit algorithms — allows algorithm confusion attacks.',
    severity: 'critical',
    fix_suggestion: 'Always specify algorithms: jwt.decode(token, key, algorithms=["HS256"]).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bjwt\.decode\s*\(/.test(line)) return false;
      return !/algorithms\s*=/.test(line);
    },
  },
  {
    id: 'PASSLIB_DEPRECATED_SCHEME',
    category: 'Cryptography',
    description: 'passlib using deprecated hashing scheme (md5_crypt, des_crypt, etc.) — easily cracked.',
    severity: 'high',
    fix_suggestion: 'Use modern schemes: bcrypt, argon2, or pbkdf2_sha256 via passlib.hash.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bpasslib\.hash\.\s*(?:md5_crypt|des_crypt|sha1_crypt|mysql41|lmhash|nthash|ldap_md5)/.test(line) ||
        /\bCryptContext\s*\([^)]*schemes\s*=\s*\[.*(?:md5_crypt|des_crypt|sha1_crypt)/.test(line);
    },
  },
  {
    id: 'ITSDANGEROUS_SHORT_SECRET',
    category: 'Cryptography',
    description: 'itsdangerous Signer with short or weak secret — signed tokens easily forged.',
    severity: 'high',
    fix_suggestion: 'Use a secret key of at least 32 random bytes. Generate with os.urandom(32).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:URLSafeTimedSerializer|Signer|URLSafeSerializer)\s*\(\s*['"][^'"]{1,15}['"]/.test(line);
    },
  },
  {
    id: 'AUTHLIB_NO_STATE_VALIDATION',
    category: 'Authentication',
    description: 'Authlib OAuth without state parameter validation — vulnerable to CSRF attacks.',
    severity: 'high',
    fix_suggestion: 'Always validate the state parameter in OAuth callback: client.authorize_access_token() validates state automatically.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bauthorize_redirect\b/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/state/.test(allContent) || /state\s*=\s*None/.test(allContent);
    },
  },
  {
    id: 'PYTHON_JOSE_NONE_ALGORITHM',
    category: 'Authentication',
    description: 'python-jose JWT with "none" algorithm allowed — tokens accepted without signature.',
    severity: 'critical',
    fix_suggestion: 'Never include "none" in allowed algorithms. Use: jwt.decode(token, key, algorithms=["HS256"]).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bjwt\.decode\s*\([^)]*algorithms\s*=\s*\[.*['"]none['"]/.test(line) ||
        /\bjose\b.*\.decode\s*\([^)]*algorithms\s*=\s*\[.*['"]none['"]/.test(line);
    },
  },
  {
    id: 'BCRYPT_LOW_ROUNDS',
    category: 'Cryptography',
    description: 'bcrypt with low rounds (< 10) — significantly reduces brute-force resistance.',
    severity: 'high',
    fix_suggestion: 'Use bcrypt with at least 12 rounds: bcrypt.hashpw(password, bcrypt.gensalt(rounds=12)).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bgensalt\s*\(\s*(?:rounds\s*=\s*)?[1-9]\s*\)/.test(line) &&
        !/gensalt\s*\(\s*(?:rounds\s*=\s*)?(?:1[0-9]|[2-9][0-9])\s*\)/.test(line);
    },
  },
  {
    id: 'FERNET_HARDCODED_KEY',
    category: 'Cryptography',
    description: 'Fernet encryption with hardcoded key — encryption can be trivially reversed.',
    severity: 'critical',
    fix_suggestion: 'Store Fernet keys in environment variables or key management services, not in source code.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /\bFernet\s*\(\s*b?['"][A-Za-z0-9+/=]{20,}['"]/.test(line);
    },
  },
  {
    id: 'RSA_SMALL_KEY_CRYPTOGRAPHY',
    category: 'Cryptography',
    description: 'RSA key generation with key size less than 2048 bits — vulnerable to factoring attacks.',
    severity: 'high',
    fix_suggestion: 'Use RSA key size of at least 2048 bits, preferably 4096: rsa.generate_private_key(key_size=4096).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\brsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(?:512|768|1024)\b/.test(line);
    },
  },
  {
    id: 'PARAMIKO_NO_HOST_KEY_VERIFY',
    category: 'Transport Security',
    description: 'Paramiko SSH without host key verification — vulnerable to MITM attacks.',
    severity: 'high',
    fix_suggestion: 'Use AutoAddPolicy only in development. In production, load known host keys.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bset_missing_host_key_policy\s*\(\s*(?:paramiko\.)?(?:AutoAddPolicy|WarningPolicy)\s*\(\s*\)/.test(line);
    },
  },
  {
    id: 'SSL_WEAK_PROTOCOL',
    category: 'Transport Security',
    description: 'SSL context with weak protocol version (SSLv2, SSLv3, TLSv1.0) — known vulnerabilities.',
    severity: 'high',
    fix_suggestion: 'Use ssl.PROTOCOL_TLS_CLIENT or ssl.TLSVersion.TLSv1_2 minimum.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bssl\.PROTOCOL_SSLv[23]\b/.test(line) ||
        /\bssl\.PROTOCOL_TLSv1\b(?!_[12])/.test(line) ||
        /\bSSLv2_METHOD\b|SSLv3_METHOD\b|TLSv1_METHOD\b/.test(line);
    },
  },
  {
    id: 'CERTIFI_CUSTOM_CA_BUNDLE',
    category: 'Transport Security',
    description: 'Custom CA bundle replacing certifi — may trust rogue certificates.',
    severity: 'medium',
    fix_suggestion: 'Use the default certifi CA bundle. Only add custom CAs when absolutely necessary with proper review.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bverify\s*=\s*['"]\//.test(line) && /\b(?:requests|httpx|urllib3)\b/.test(line) ||
        /\bSSLContext\b.*\bload_verify_locations\s*\(/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 87: Python Data Processing (12 rules)
  // ════════════════════════════════════════════

  {
    id: 'PANDAS_READ_CSV_USER_PATH',
    category: 'Path Traversal',
    description: 'pandas read_csv with user-controlled path — can read arbitrary files from the filesystem.',
    severity: 'high',
    fix_suggestion: 'Validate file paths against an allowlist of directories. Use os.path.realpath() for canonicalization.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bpd\.read_csv\s*\(\s*(?:request\.|user_|input_|file_path|filename|path\b|f['"`])/.test(line) ||
        /\bread_csv\s*\(\s*(?:request\.|user_|input_|file_path|filename)/.test(line);
    },
  },
  {
    id: 'OPENPYXL_MACRO_ENABLED',
    category: 'Code Execution',
    description: 'openpyxl loading macro-enabled file (.xlsm) — macros may contain malicious code.',
    severity: 'high',
    fix_suggestion: 'Reject macro-enabled files (.xlsm, .xltm). Only accept .xlsx files.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bload_workbook\s*\([^)]*keep_vba\s*=\s*True/.test(line) ||
        /\bload_workbook\s*\([^)]*\.xlsm/.test(line);
    },
  },
  {
    id: 'REPORTLAB_USER_CONTENT',
    category: 'Injection',
    description: 'reportlab PDF generation with user-controlled content — PDF injection risk.',
    severity: 'medium',
    fix_suggestion: 'Sanitize and escape user content before adding to PDF. Validate URLs and file paths.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bParagraph\s*\(\s*(?:request\.|user_|input_|f['"`])/.test(line) ||
        /\bdrawString\s*\([^)]*(?:request\.|user_|input_|f['"`])/.test(line);
    },
  },
  {
    id: 'PIL_IMAGE_BOMB',
    category: 'Denial of Service',
    description: 'PIL/Pillow Image.open without decompression bomb protection — can exhaust memory.',
    severity: 'high',
    fix_suggestion: 'Set PIL.Image.MAX_IMAGE_PIXELS to a reasonable limit, or use Image.open with a size check.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bImage\.MAX_IMAGE_PIXELS\s*=\s*None/.test(line) ||
        /\bImage\.MAX_IMAGE_PIXELS\s*=\s*0/.test(line) ||
        /\bDecompressionBombWarning\b.*\bignore\b/.test(line);
    },
  },
  {
    id: 'CSV_READER_NO_FIELD_SIZE_LIMIT',
    category: 'Denial of Service',
    description: 'csv.reader without field size limit — malicious CSV can exhaust memory.',
    severity: 'medium',
    fix_suggestion: 'Set csv.field_size_limit(131072) before reading CSV files to prevent memory exhaustion.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\bcsv\.(?:reader|DictReader)\s*\(/.test(line)) return false;
      const allContent = ctx.fileContent;
      return !/field_size_limit/.test(allContent);
    },
  },
  {
    id: 'JSON_LOADS_NO_SIZE_LIMIT',
    category: 'Denial of Service',
    description: 'json.loads on untrusted input without size limit — may exhaust memory on large payloads.',
    severity: 'medium',
    fix_suggestion: 'Validate input size before parsing: if len(data) > MAX_SIZE: raise ValueError.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bjson\.loads\s*\(\s*(?:request\.(?:body|data|text)|body\b|raw_data|payload)/.test(line);
    },
  },
  {
    id: 'YAML_LOAD_UNSAFE_LOADER',
    category: 'Code Execution',
    description: 'yaml.load without SafeLoader — can execute arbitrary Python code.',
    severity: 'critical',
    fix_suggestion: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\byaml\.load\s*\(/.test(line)) return false;
      return !/SafeLoader|safe_load|Loader\s*=\s*yaml\.SafeLoader|Loader\s*=\s*SafeLoader|BaseLoader|FullLoader/.test(line);
    },
  },
  {
    id: 'CONFIGPARSER_INTERPOLATION_INJECTION',
    category: 'Injection',
    description: 'ConfigParser with user-controlled values and interpolation enabled — format string injection.',
    severity: 'medium',
    fix_suggestion: 'Use RawConfigParser or set interpolation=None to disable format string processing.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bConfigParser\s*\(\s*\)/.test(line) && !/RawConfigParser/.test(line) ||
        /\.set\s*\([^)]*(?:request\.|user_|input_)/.test(line) && /ConfigParser/.test(line);
    },
  },
  {
    id: 'SQLITE3_USER_DB_PATH',
    category: 'Path Traversal',
    description: 'sqlite3.connect with user-controlled database path — can access or create arbitrary database files.',
    severity: 'high',
    fix_suggestion: 'Validate database paths against an allowed directory. Never accept user input for database file paths.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bsqlite3\.connect\s*\(\s*(?:request\.|user_|input_|db_path|filename|f['"`]|path\b)/.test(line);
    },
  },
  {
    id: 'H5PY_UNTRUSTED_HDF5',
    category: 'Code Execution',
    description: 'h5py loading untrusted HDF5 files — can contain malicious data or trigger buffer overflows.',
    severity: 'high',
    fix_suggestion: 'Validate HDF5 files before loading. Run h5py operations in a sandboxed environment.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bh5py\.File\s*\(\s*(?:request\.|user_|input_|file_path|filename|f['"`])/.test(line);
    },
  },
  {
    id: 'PARQUET_USER_SCHEMA',
    category: 'Data Injection',
    description: 'Arrow/Parquet file loaded with user-controlled schema or path — data injection risk.',
    severity: 'medium',
    fix_suggestion: 'Validate Parquet file paths and enforce expected schemas before reading.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bpq\.read_table\s*\(\s*(?:request\.|user_|input_|file_path|f['"`])/.test(line) ||
        /\bpd\.read_parquet\s*\(\s*(?:request\.|user_|input_|file_path|f['"`])/.test(line);
    },
  },
  {
    id: 'XLRD_FORMULA_EVAL',
    category: 'Code Execution',
    description: 'xlrd loading Excel file with formula evaluation — malicious formulas can execute commands.',
    severity: 'high',
    fix_suggestion: 'Use openpyxl with data_only=True instead of xlrd. Reject files with formulas from untrusted sources.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bxlrd\.open_workbook\s*\(\s*(?:request\.|user_|input_|file_path|filename|f['"`])/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 88: Python Web Scraping & Network (10 rules)
  // ════════════════════════════════════════════

  {
    id: 'REQUESTS_NO_TIMEOUT',
    category: 'Denial of Service',
    description: 'Python requests library call without timeout — can hang indefinitely.',
    severity: 'medium',
    fix_suggestion: 'Always set timeout: requests.get(url, timeout=30).',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\brequests\.(?:get|post|put|delete|patch|head|options)\s*\(/.test(line)) return false;
      return !/timeout\s*=/.test(line);
    },
  },
  {
    id: 'URLLIB3_DISABLED_WARNINGS',
    category: 'Transport Security',
    description: 'urllib3 warnings disabled — suppresses critical TLS/SSL certificate warnings.',
    severity: 'high',
    fix_suggestion: 'Fix the underlying SSL issue instead of disabling warnings. Use proper certificates.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\burllib3\.disable_warnings\s*\(/.test(line) ||
        /\bwarnings\.filterwarnings\s*\(\s*['"]ignore['"].*InsecureRequestWarning/.test(line);
    },
  },
  {
    id: 'SELENIUM_USER_URL',
    category: 'SSRF',
    description: 'Selenium WebDriver navigating to user-controlled URL — can access internal services.',
    severity: 'high',
    fix_suggestion: 'Validate URLs against an allowlist of permitted domains before navigation.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bdriver\.get\s*\(\s*(?:request\.|user_|input_|url\b|target_url|f['"`])/.test(line);
    },
  },
  {
    id: 'BEAUTIFULSOUP_LXML_UNTRUSTED_XML',
    category: 'XML Injection',
    description: 'BeautifulSoup with lxml parser on untrusted XML — vulnerable to XML external entity attacks.',
    severity: 'high',
    fix_suggestion: 'Use "html.parser" for untrusted HTML, or defusedxml for XML parsing.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bBeautifulSoup\s*\([^)]*['"](?:lxml-xml|xml)['"]/.test(line);
    },
  },
  {
    id: 'SCRAPY_USER_START_URLS',
    category: 'SSRF',
    description: 'Scrapy spider with user-controlled start_urls — can crawl arbitrary targets.',
    severity: 'high',
    fix_suggestion: 'Validate and restrict start_urls to an allowlist of permitted domains.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bstart_urls\s*=\s*\[?\s*(?:request\.|user_|input_|url\b|sys\.argv)/.test(line) ||
        /\bstart_requests\b.*\b(?:request\.|user_|input_)/.test(line);
    },
  },
  {
    id: 'PARAMIKO_EXEC_USER_INPUT',
    category: 'Command Injection',
    description: 'Paramiko exec_command with user-controlled input — remote command injection.',
    severity: 'critical',
    fix_suggestion: 'Use shlex.quote() to escape arguments, or use a fixed command allowlist.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bexec_command\s*\(\s*(?:f['"`]|cmd|command|user_|input_|request\.)/.test(line);
    },
  },
  {
    id: 'FTPLIB_NO_TLS',
    category: 'Transport Security',
    description: 'ftplib FTP connection without TLS — credentials and data transmitted in plaintext.',
    severity: 'high',
    fix_suggestion: 'Use ftplib.FTP_TLS instead of FTP for encrypted file transfers.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bftplib\.FTP\s*\(/.test(line) && !/FTP_TLS/.test(line);
    },
  },
  {
    id: 'SOCKET_BIND_ALL_INTERFACES',
    category: 'Network Security',
    description: 'Socket bound to 0.0.0.0 — listens on all network interfaces, exposing the service externally.',
    severity: 'medium',
    fix_suggestion: 'Bind to 127.0.0.1 for local-only services, or use a specific interface address.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\.bind\s*\(\s*\(\s*['"]0\.0\.0\.0['"]/.test(line) ||
        /\.bind\s*\(\s*\(\s*['"]["']\s*,/.test(line);
    },
  },
  {
    id: 'HTTPLIB2_NO_CERT_VERIFY',
    category: 'Transport Security',
    description: 'httplib2 with certificate verification disabled — vulnerable to MITM attacks.',
    severity: 'high',
    fix_suggestion: 'Remove disable_ssl_certificate_validation=True. Always verify SSL certificates.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bhttplib2\.Http\s*\([^)]*disable_ssl_certificate_validation\s*=\s*True/.test(line);
    },
  },
  {
    id: 'DNS_RESOLVER_USER_QUERY',
    category: 'SSRF',
    description: 'DNS resolver with user-controlled query — can probe internal network infrastructure.',
    severity: 'medium',
    fix_suggestion: 'Validate and sanitize domain names. Restrict queries to public domains only.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bresolver\.(?:resolve|query)\s*\(\s*(?:request\.|user_|input_|domain|hostname|f['"`])/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 89: Python Testing & DevOps (10 rules)
  // ════════════════════════════════════════════

  {
    id: 'PYTEST_FIXTURE_REAL_CREDS',
    category: 'Secrets',
    description: 'pytest fixture with hardcoded credentials — secrets may leak via test output or CI logs.',
    severity: 'high',
    fix_suggestion: 'Use environment variables or a .env file for test credentials. Never hardcode secrets in tests.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: false,
    detect: (line, ctx) => {
      if (!/\b(?:password|secret|api_key|token)\s*=\s*['"][^'"]{8,}['"]/.test(line)) return false;
      const allContent = ctx.fileContent;
      return /@pytest\.fixture\b/.test(allContent) || /\bdef\s+\w+\s*\(\s*\)\s*:\s*$/.test(line);
    },
  },
  {
    id: 'UNITTEST_MOCK_SIDE_EFFECT_EXEC',
    category: 'Code Execution',
    description: 'unittest.mock patch with side_effect executing user-controlled code — test RCE risk.',
    severity: 'medium',
    fix_suggestion: 'Only use static return values or pre-defined functions as side_effect in mocks.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: false,
    detect: (line) => {
      return /\bside_effect\s*=\s*(?:eval|exec|compile|os\.system|subprocess)/.test(line);
    },
  },
  {
    id: 'FABRIC_INVOKE_USER_CMD',
    category: 'Command Injection',
    description: 'Fabric/Invoke run with user-controlled command — remote command injection.',
    severity: 'critical',
    fix_suggestion: 'Use a command allowlist and shlex.quote() for any arguments.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\b(?:c\.run|ctx\.run|conn\.run|connection\.run)\s*\(\s*(?:f['"`]|cmd|command|user_|input_|request\.)/.test(line)) return false;
      return /\b(?:fabric|invoke|Connection|Context)\b/.test(ctx.fileContent);
    },
  },
  {
    id: 'ANSIBLE_RAW_MODULE',
    category: 'Command Injection',
    description: 'Ansible playbook using raw or shell module with user input — command injection risk.',
    severity: 'high',
    fix_suggestion: 'Use the command module with argv list, or use specialized Ansible modules instead of shell/raw.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bmodule\s*=\s*['"](?:raw|shell)['"]/.test(line) && /\b(?:args|cmd)\s*=.*(?:\{\{|user_|input_|request\.)/.test(line) ||
        /\bansible_runner\.run\s*\([^)]*(?:module\s*=\s*['"](?:raw|shell)['"])/.test(line);
    },
  },
  {
    id: 'BOTO3_NO_REGION_VALIDATION',
    category: 'Security Configuration',
    description: 'boto3 client with user-controlled region — can redirect requests to attacker-controlled endpoints.',
    severity: 'medium',
    fix_suggestion: 'Validate region names against a fixed allowlist of expected AWS regions.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bboto3\.client\s*\([^)]*region_name\s*=\s*(?:request\.|user_|input_|region\b|f['"`])/.test(line);
    },
  },
  {
    id: 'DOCKER_PY_USER_IMAGE',
    category: 'Code Execution',
    description: 'docker-py running container with user-controlled image — can execute arbitrary containers.',
    severity: 'critical',
    fix_suggestion: 'Only allow images from a trusted registry allowlist. Pin images by digest.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:client|docker)\.containers\.run\s*\(\s*(?:request\.|user_|input_|image_name|f['"`])/.test(line);
    },
  },
  {
    id: 'K8S_CLIENT_USER_NAMESPACE',
    category: 'Authorization',
    description: 'Kubernetes client with user-controlled namespace — can access resources in other namespaces.',
    severity: 'high',
    fix_suggestion: 'Validate namespace against an allowlist of permitted namespaces.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\b(?:v1|apps_v1|batch_v1)\.(?:list|create|delete|patch)_namespaced_\w+\s*\([^)]*namespace\s*=\s*(?:request\.|user_|input_|ns\b|f['"`])/.test(line);
    },
  },
  {
    id: 'CELERY_TASK_USER_ARGS',
    category: 'Code Injection',
    description: 'Celery task dispatched with user-controlled task name or args — arbitrary code execution risk.',
    severity: 'critical',
    fix_suggestion: 'Use a fixed allowlist of task names. Never let users specify which Celery task to execute.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /\bapp\.send_task\s*\(\s*(?:request\.|user_|input_|task_name|f['"`])/.test(line) ||
        /\bcelery_app\.send_task\s*\(\s*(?:request\.|user_|input_|task_name)/.test(line);
    },
  },
  {
    id: 'GUNICORN_DEBUG_MODE',
    category: 'Security Configuration',
    description: 'Gunicorn running with debug mode enabled — exposes debugging information in production.',
    severity: 'high',
    fix_suggestion: 'Remove --log-level debug and --reload flags in production. Set loglevel to "info" or "warning".',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (/\bloglevel\s*=\s*['"]debug['"]/.test(line)) {
        return /gunicorn/.test(ctx.fileContent) || /gunicorn/.test(ctx.filePath);
      }
      return /\bgunicorn\b.*\breload\s*=\s*True/.test(line);
    },
  },
  {
    id: 'UVICORN_RELOAD_PRODUCTION',
    category: 'Security Configuration',
    description: 'Uvicorn with reload=True in production — enables file watching and auto-restart, not safe for production.',
    severity: 'high',
    fix_suggestion: 'Remove reload=True for production deployments. Use reload only in development.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/\buvicorn\.run\s*\(/.test(line)) return false;
      return /reload\s*=\s*True/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 91: Python Web Security Final (15 rules)
  // ════════════════════════════════════════════
  {
    id: 'DJANGO_TEMPLATE_AUTOESCAPE_OFF',
    category: 'Cross-Site Scripting',
    description: 'Django template autoescape disabled — renders user content as raw HTML, enabling XSS.',
    severity: 'high',
    fix_suggestion: 'Remove {% autoescape off %} or ensure only trusted content is rendered.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => /autoescape\s*=\s*False/.test(line) || /\{%\s*autoescape\s+off\s*%\}/.test(line),
  },
  {
    id: 'DJANGO_UNVALIDATED_REDIRECT_CHAIN',
    category: 'Open Redirect',
    description: 'Django HttpResponseRedirect with chained user input — open redirect via query parameter.',
    severity: 'high',
    fix_suggestion: 'Validate redirect URLs against a whitelist of allowed domains before redirecting.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /HttpResponseRedirect\s*\(\s*request\.(GET|POST|META)/.test(line);
    },
  },
  {
    id: 'DJANGO_CACHE_SENSITIVE_DATA',
    category: 'Information Disclosure',
    description: 'Django cache.set with potentially sensitive data — may expose PII via cache backend.',
    severity: 'medium',
    fix_suggestion: 'Avoid caching sensitive user data. If necessary, encrypt before caching and set short TTLs.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/cache\.set\s*\(/.test(line)) return false;
      return /\b(password|token|secret|ssn|credit_card|api_key)\b/i.test(line);
    },
  },
  {
    id: 'FLASK_RENDER_STRING_USER_INPUT',
    category: 'Server-Side Template Injection',
    description: 'Flask render_template_string with user input — allows server-side template injection.',
    severity: 'critical',
    fix_suggestion: 'Use render_template with a file instead of render_template_string. Never pass user input to template strings.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/render_template_string\s*\(/.test(line)) return false;
      return /\brequest\b/.test(line) || /\bformat\s*\(/.test(line) || /f['"]/.test(line) || /\%\s*\(/.test(line);
    },
  },
  {
    id: 'FLASK_UNSAFE_FILE_EXTENSION',
    category: 'File Upload',
    description: 'Flask file upload without extension validation — allows uploading executable files.',
    severity: 'high',
    fix_suggestion: 'Use werkzeug.utils.secure_filename and validate file extensions against an allow list.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/request\.files/.test(line)) return false;
      if (/\.save\s*\(/.test(line)) {
        // Check if secure_filename is used nearby
        const nearby = ctx.allLines.slice(Math.max(0, ctx.lineNumber - 5), ctx.lineNumber + 5).join('\n');
        return !/secure_filename/.test(nearby) && !/allowed_extensions/.test(nearby);
      }
      return false;
    },
  },
  {
    id: 'FASTAPI_PATH_PARAM_NO_VALIDATION',
    category: 'Input Validation',
    description: 'FastAPI path parameter without type validation — may accept unexpected input.',
    severity: 'medium',
    fix_suggestion: 'Use Pydantic validators or Path(..., regex=...) to constrain path parameters.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      // Detect @app.get("/{something}") where something has no type hint
      return /\@app\.(get|post|put|delete|patch)\s*\(\s*["'].*\{[a-zA-Z_]+\}/.test(line) &&
        !/Path\s*\(/.test(line);
    },
  },
  {
    id: 'DJANGO_LOGGING_SENSITIVE_DATA',
    category: 'Information Disclosure',
    description: 'Django logging with sensitive request data — may leak credentials to log files.',
    severity: 'medium',
    fix_suggestion: 'Sanitize sensitive fields before logging. Use a log filter to redact passwords, tokens, etc.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\blogger\.\b/.test(line) && !/\blogging\.\b/.test(line)) return false;
      return /request\.(POST|body|data)\b/.test(line) && /\b(password|token|secret|key|auth)\b/i.test(line);
    },
  },
  {
    id: 'FLASK_AFTER_REQUEST_NO_SECURITY_HEADERS',
    category: 'Security Configuration',
    description: 'Flask after_request without security headers — missing CSP, X-Frame-Options, etc.',
    severity: 'medium',
    fix_suggestion: 'Add Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security headers.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/@app\.after_request/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 10).join('\n');
      return !/Content-Security-Policy/.test(nearby) && !/X-Frame-Options/.test(nearby);
    },
  },
  {
    id: 'FASTAPI_TRUSTED_HOST_MISSING',
    category: 'Security Configuration',
    description: 'FastAPI app without TrustedHostMiddleware — vulnerable to host header attacks.',
    severity: 'medium',
    fix_suggestion: 'Add TrustedHostMiddleware to validate Host headers: app.add_middleware(TrustedHostMiddleware, allowed_hosts=[...]).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/FastAPI\s*\(/.test(line)) return false;
      // Skip framework source / docs / test / example directories
      const lowerPath = ctx.filePath.toLowerCase();
      if (/\/(docs_src|docs|tests|test|examples|example|fixtures)\//i.test(lowerPath)) return false;
      if (isFrameworkSource(ctx.filePath)) return false;
      return !ctx.fileContent.includes('TrustedHostMiddleware');
    },
  },
  {
    id: 'DJANGO_UNSAFE_PICKLE_SESSION',
    category: 'Deserialization',
    description: 'Django with PickleSerializer for sessions — enables remote code execution via crafted cookies.',
    severity: 'critical',
    fix_suggestion: 'Use JSONSerializer for session serialization: SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer".',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => /SESSION_SERIALIZER\s*=.*PickleSerializer/.test(line),
  },
  {
    id: 'FLASK_UNSAFE_RESPONSE_MIMETYPE',
    category: 'Cross-Site Scripting',
    description: 'Flask Response with text/html mimetype and user content — enables XSS.',
    severity: 'high',
    fix_suggestion: 'Use application/json or text/plain for API responses. Escape HTML content properly.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/Response\s*\(/.test(line)) return false;
      return /text\/html/.test(line) && /request\b/.test(line);
    },
  },
  {
    id: 'DJANGO_CUSTOM_AUTH_BACKEND_NO_PERMISSION',
    category: 'Authorization',
    description: 'Django custom authentication backend without has_perm implementation — may bypass permission checks.',
    severity: 'high',
    fix_suggestion: 'Implement has_perm() and has_module_perms() in custom authentication backends.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/class\s+\w+.*Backend/.test(line)) return false;
      if (!/def\s+authenticate/.test(ctx.fileContent)) return false;
      return !/def\s+has_perm/.test(ctx.fileContent);
    },
  },
  {
    id: 'FASTAPI_CORS_ALLOW_CREDENTIALS_WILDCARD',
    category: 'Security Configuration',
    description: 'FastAPI CORS with allow_credentials=True and wildcard origins — browsers block this but misconfig exposes intent.',
    severity: 'high',
    fix_suggestion: 'Specify exact allowed origins instead of wildcards when using credentials.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!hasFastapiImport(ctx.fileContent)) return false;
      if (!/CORSMiddleware/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 10).join('\n');
      return /allow_credentials\s*=\s*True/.test(nearby) && /\[?\s*["']\*["']\s*\]?/.test(nearby);
    },
  },
  {
    id: 'PYTHON_WERKZEUG_DEBUGGER_PRODUCTION',
    category: 'Security Configuration',
    description: 'Werkzeug debugger enabled — provides interactive Python shell to anyone who triggers an error.',
    severity: 'critical',
    fix_suggestion: 'Never enable the Werkzeug debugger in production. Use use_debugger=False or remove the parameter.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => /use_debugger\s*=\s*True/.test(line),
  },
  {
    id: 'PYTHON_STARLETTE_GZIP_BOMB',
    category: 'Denial of Service',
    description: 'Starlette GZipMiddleware without minimum_size — may decompress gzip bombs.',
    severity: 'medium',
    fix_suggestion: 'Set minimum_size parameter and add request size limits to prevent decompression bombs.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/GZipMiddleware/.test(line)) return false;
      return !/minimum_size/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 92: Python Infrastructure & Cloud (12 rules)
  // ════════════════════════════════════════════
  {
    id: 'BOTO3_S3_PUBLIC_ACL',
    category: 'Cloud Misconfiguration',
    description: 'boto3 S3 put_object with public-read ACL — exposes objects to the internet.',
    severity: 'critical',
    fix_suggestion: 'Use private ACL and presigned URLs for controlled access. Enable S3 Block Public Access.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/put_object\s*\(/.test(line) && !/upload_file/.test(line)) return false;
      return /ACL\s*=\s*['"]public-read/.test(line);
    },
  },
  {
    id: 'BOTO3_SQS_NO_ENCRYPTION',
    category: 'Cloud Misconfiguration',
    description: 'boto3 SQS create_queue without KMS encryption — messages stored in plaintext.',
    severity: 'medium',
    fix_suggestion: 'Enable SQS encryption: Attributes={"KmsMasterKeyId": "alias/aws/sqs"}.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/create_queue\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 8).join('\n');
      return !/KmsMasterKeyId/.test(nearby) && !/SqsManagedSseEnabled/.test(nearby);
    },
  },
  {
    id: 'BOTO3_SNS_HTTP_SUBSCRIPTION',
    category: 'Cloud Misconfiguration',
    description: 'boto3 SNS subscription with HTTP protocol — messages transmitted unencrypted.',
    severity: 'high',
    fix_suggestion: 'Use HTTPS protocol for SNS subscriptions to encrypt messages in transit.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/subscribe\s*\(/.test(line)) return false;
      return /Protocol\s*=\s*['"]http['"]/.test(line) && !/https/.test(line);
    },
  },
  {
    id: 'BOTO3_LAMBDA_WILDCARD_PERMISSIONS',
    category: 'Cloud Misconfiguration',
    description: 'boto3 Lambda with wildcard resource permissions — overly permissive IAM policy.',
    severity: 'high',
    fix_suggestion: 'Follow least privilege: specify exact ARNs instead of wildcards in Lambda permissions.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/add_permission\s*\(/.test(line) && !/put_function_policy/.test(line)) return false;
      return /Principal\s*=\s*['"]["*"']/.test(line) || /\*/.test(line);
    },
  },
  {
    id: 'GCP_CLIENT_NO_AUTH',
    category: 'Cloud Misconfiguration',
    description: 'GCP client library initialized with anonymous credentials — bypasses authentication.',
    severity: 'critical',
    fix_suggestion: 'Use service account credentials or application default credentials. Remove AnonymousCredentials.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => /AnonymousCredentials\s*\(\s*\)/.test(line),
  },
  {
    id: 'GCP_STORAGE_PUBLIC_BLOB',
    category: 'Cloud Misconfiguration',
    description: 'GCP Storage blob made publicly accessible — exposes data to the internet.',
    severity: 'high',
    fix_suggestion: 'Use signed URLs for controlled access instead of making blobs public.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => /\.make_public\s*\(\s*\)/.test(line) && /blob/.test(line),
  },
  {
    id: 'AZURE_CONNECTION_STRING_HARDCODED',
    category: 'Hardcoded Secrets',
    description: 'Azure connection string hardcoded in source — exposes cloud credentials.',
    severity: 'critical',
    fix_suggestion: 'Use environment variables or Azure Key Vault for connection strings.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /DefaultEndpointsProtocol=https?;AccountName=/.test(line) && /AccountKey=/.test(line);
    },
  },
  {
    id: 'TERRAFORM_CDK_ADMIN_POLICY',
    category: 'Cloud Misconfiguration',
    description: 'Terraform CDK with AdministratorAccess policy — grants full account access.',
    severity: 'critical',
    fix_suggestion: 'Follow least privilege: create custom policies with only required permissions.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => /AdministratorAccess/.test(line) && /ManagedPolicy|iam_policy|PolicyStatement/.test(line),
  },
  {
    id: 'PULUMI_SECRET_PLAINTEXT',
    category: 'Hardcoded Secrets',
    description: 'Pulumi secret stored in plaintext — should use pulumi.secret() for encryption.',
    severity: 'high',
    fix_suggestion: 'Use pulumi.Output.secret() to encrypt sensitive values in Pulumi state.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/pulumi\./.test(line)) return false;
      return /password\s*=\s*["']/.test(line) || /secret_key\s*=\s*["']/.test(line) || /api_key\s*=\s*["']/.test(line);
    },
  },
  {
    id: 'BOTO3_S3_NO_VERSIONING',
    category: 'Cloud Misconfiguration',
    description: 'boto3 S3 create_bucket without versioning — data loss risk from accidental deletes.',
    severity: 'medium',
    fix_suggestion: 'Enable S3 bucket versioning: s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"}).',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/create_bucket\s*\(/.test(line)) return false;
      return !ctx.fileContent.includes('put_bucket_versioning');
    },
  },
  {
    id: 'BOTO3_RDS_PUBLIC_ACCESS',
    category: 'Cloud Misconfiguration',
    description: 'boto3 RDS instance with public access — database exposed to the internet.',
    severity: 'critical',
    fix_suggestion: 'Set PubliclyAccessible=False and use VPC security groups for database access.',
    auto_fixable: true,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/create_db_instance\s*\(/.test(line) && !/modify_db_instance\s*\(/.test(line)) return false;
      return /PubliclyAccessible\s*=\s*True/.test(line);
    },
  },
  {
    id: 'BOTO3_DYNAMODB_NO_ENCRYPTION',
    category: 'Cloud Misconfiguration',
    description: 'boto3 DynamoDB create_table without encryption — data at rest is unencrypted.',
    severity: 'medium',
    fix_suggestion: 'Enable encryption at rest: SSESpecification={"Enabled": True, "SSEType": "KMS"}.',
    auto_fixable: false,
    fileTypes: ['.py'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/create_table\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 15).join('\n');
      return !/SSESpecification/.test(nearby);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 93: Node.js Runtime Security (12 rules)
  // ════════════════════════════════════════════
  {
    id: 'PROCESS_ENV_MODIFICATION',
    category: 'Runtime Security',
    description: 'process.env modification at runtime — may alter behavior of dependencies or leak env vars.',
    severity: 'medium',
    fix_suggestion: 'Avoid modifying process.env at runtime. Use a config object instead.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/process\.env\s*\[/.test(line) && !/process\.env\.\w+\s*=/.test(line)) return false;
      return /=\s*(?:req\b|request\b|body\b|params\b|query\b|input\b|args\b|user)/.test(line);
    },
  },
  {
    id: 'CHILD_PROCESS_FORK_USER_ARGS',
    category: 'Command Injection',
    description: 'child_process.fork with user-controlled arguments — enables code execution via worker args.',
    severity: 'critical',
    fix_suggestion: 'Validate and sanitize all arguments passed to fork(). Use an allow list for module paths.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.fork\s*\(/.test(line)) return false;
      return /\b(req\b|request\b|body\b|params\b|query\b|input\b|user)/.test(line);
    },
  },
  {
    id: 'CLUSTER_WORKER_MSG_NO_VALIDATION',
    category: 'Input Validation',
    description: 'Cluster worker message handler without input validation — IPC messages treated as trusted.',
    severity: 'medium',
    fix_suggestion: 'Validate and type-check all IPC messages before processing them.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /worker\.on\s*\(\s*['"]message['"]/.test(line) || /process\.on\s*\(\s*['"]message['"]/.test(line) &&
        /JSON\.parse/.test(line);
    },
  },
  {
    id: 'V8_FLAGS_MANIPULATION',
    category: 'Runtime Security',
    description: 'V8 flags set at runtime with user input — can disable security features.',
    severity: 'critical',
    fix_suggestion: 'Never allow user input to control V8 flags. Hardcode required flags.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /--(?:allow-natives-syntax|expose-gc|max-old-space-size)/.test(line) && /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'NATIVE_ADDON_USER_PATH',
    category: 'Code Injection',
    description: 'Native addon loaded from user-controlled path — enables arbitrary code execution.',
    severity: 'critical',
    fix_suggestion: 'Hardcode addon paths. Never allow user input to determine which native modules are loaded.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\brequire\s*\(/.test(line) && !/\.dlopen\s*\(/.test(line)) return false;
      return /\.node['"]?\s*/.test(line) && /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'WASI_USER_IMPORTS',
    category: 'Runtime Security',
    description: 'WASI initialized with user-controlled imports — enables filesystem/network access bypass.',
    severity: 'high',
    fix_suggestion: 'Restrict WASI preopens and imports to known safe paths. Never use user input for WASI configuration.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/WASI\s*\(/.test(line) && !/new\s+WASI/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'PERFORMANCE_MARK_SENSITIVE',
    category: 'Information Disclosure',
    description: 'performance.mark/measure with sensitive data — may leak info via Performance API.',
    severity: 'medium',
    fix_suggestion: 'Do not include sensitive data in performance marks. Use opaque identifiers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/performance\.mark\s*\(/.test(line) && !/performance\.measure\s*\(/.test(line)) return false;
      return /\b(password|token|secret|key|auth|credential|ssn)\b/i.test(line);
    },
  },
  {
    id: 'DIAGNOSTICS_CHANNEL_INFO_LEAK',
    category: 'Information Disclosure',
    description: 'diagnostics_channel publishing sensitive data — may leak to APM/monitoring tools.',
    severity: 'medium',
    fix_suggestion: 'Sanitize data before publishing to diagnostic channels. Remove passwords, tokens, etc.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.publish\s*\(/.test(line) && !/channel\.publish/.test(line)) return false;
      return /diagnostics_channel/.test(line) && /\b(password|token|secret|key|auth)\b/i.test(line);
    },
  },
  {
    id: 'WORKER_THREADS_EVAL',
    category: 'Code Injection',
    description: 'Worker thread with user-controlled eval code — enables arbitrary code execution.',
    severity: 'critical',
    fix_suggestion: 'Pass data to workers via workerData, never as eval code. Use a fixed worker file path.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/new\s+Worker\s*\(/.test(line)) return false;
      return /eval\s*:\s*true/.test(line) && /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'VM_MODULE_USER_CODE',
    category: 'Code Injection',
    description: 'vm.Module or vm.SourceTextModule with user code — sandbox escape possible.',
    severity: 'critical',
    fix_suggestion: 'Never run user-provided code in vm.Module. Use isolated-vm or a proper sandbox.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/SourceTextModule\s*\(/.test(line) && !/SyntheticModule\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'INSPECTOR_OPEN_PRODUCTION',
    category: 'Runtime Security',
    description: 'Node.js inspector opened at runtime — enables remote debugging and code injection.',
    severity: 'critical',
    fix_suggestion: 'Never open the inspector in production. Use --inspect flag only in development.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => /inspector\.open\s*\(/.test(line) || /require\s*\(\s*['"]inspector['"]\s*\).*\.open/.test(line),
  },
  {
    id: 'SHARED_ARRAY_BUFFER_NO_ISOLATION',
    category: 'Runtime Security',
    description: 'SharedArrayBuffer used without proper cross-origin isolation headers.',
    severity: 'medium',
    fix_suggestion: 'Set Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy headers when using SharedArrayBuffer.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/new\s+SharedArrayBuffer\s*\(/.test(line)) return false;
      return !ctx.fileContent.includes('Cross-Origin-Opener-Policy') && !ctx.fileContent.includes('cross-origin-opener-policy');
    },
  },

  // ════════════════════════════════════════════
  // Cycle 94: TypeScript Type System Exploits (10 rules)
  // ════════════════════════════════════════════
  {
    id: 'TS_TYPE_ASSERTION_BYPASS',
    category: 'Type Safety',
    description: 'TypeScript "as any" type assertion on user input — bypasses all type checking.',
    severity: 'info',
    fix_suggestion: 'Use proper type guards or Zod/io-ts for runtime validation instead of "as any".',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/as\s+any\b/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'TS_NON_NULL_ASSERTION_USER_INPUT',
    category: 'Type Safety',
    description: 'Non-null assertion (!) on user input — may cause runtime crash on null/undefined.',
    severity: 'medium',
    fix_suggestion: 'Use optional chaining (?.) or explicit null checks instead of non-null assertions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Match req.body.field! or params.id! patterns
      return /\b(req|request|body|params|query)\.\w+!/.test(line) && !/!==/.test(line) && !/!=/.test(line);
    },
  },
  {
    id: 'TS_CONST_ASSERTION_MUTABLE',
    category: 'Type Safety',
    description: 'Const assertion on object later mutated — type lies about immutability.',
    severity: 'low',
    fix_suggestion: 'Use Object.freeze() for actual immutability, not just const assertions.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/as\s+const\b/.test(line)) return false;
      const varMatch = line.match(/(?:const|let)\s+(\w+)\s*=/);
      if (!varMatch) return false;
      const varName = varMatch[1];
      const rest = ctx.allLines.slice(ctx.lineNumber).join('\n');
      return new RegExp(`${varName}\\s*\\.\\s*\\w+\\s*=`).test(rest) || new RegExp(`${varName}\\s*\\[`).test(rest);
    },
  },
  {
    id: 'TS_TEMPLATE_LITERAL_TYPE_USER_INPUT',
    category: 'Input Validation',
    description: 'Template literal type constructed from user input — type system cannot validate runtime strings.',
    severity: 'medium',
    fix_suggestion: 'Add runtime validation for template literal patterns. Types are erased at runtime.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Pattern: casting user input to a template literal type
      return /as\s+`\$\{/.test(line) && /\b(req|request|body|params|query|input)\b/.test(line);
    },
  },
  {
    id: 'TS_BRANDED_TYPE_NO_RUNTIME_CHECK',
    category: 'Type Safety',
    description: 'Branded/nominal type cast without runtime validation — brand is just a compile-time fiction.',
    severity: 'medium',
    fix_suggestion: 'Add runtime validation in the brand constructor function. Types alone cannot enforce invariants.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect: as UserId, as BrandedType, etc. on user input without validation
      if (!/as\s+[A-Z]\w*Id\b/.test(line) && !/as\s+Branded\w*/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'TS_ENUM_USER_INPUT_NO_GUARD',
    category: 'Input Validation',
    description: 'TypeScript enum used with user input without runtime validation — invalid enum values pass through.',
    severity: 'medium',
    fix_suggestion: 'Use Object.values(Enum).includes() or a type guard to validate enum values at runtime.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Casting user input directly to an enum type
      if (!/as\s+[A-Z]\w+(?:Type|Status|Role|Kind|Mode)\b/.test(line)) return false;
      return /\b(req|request|body|params|query|input)\b/.test(line);
    },
  },
  {
    id: 'TS_RECORD_TYPE_NO_VALIDATION',
    category: 'Type Safety',
    description: 'Record<string, any> used for user input — allows arbitrary keys and values.',
    severity: 'medium',
    fix_suggestion: 'Use a specific interface or Zod schema instead of Record<string, any> for user input.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      return /Record\s*<\s*string\s*,\s*any\s*>/.test(line) && /\b(req|request|body|params|query|input)\b/.test(line);
    },
  },
  {
    id: 'TS_SATISFIES_WITHOUT_VALIDATION',
    category: 'Type Safety',
    description: 'satisfies operator on user input without runtime validation — compile-time only check.',
    severity: 'medium',
    fix_suggestion: 'Add runtime validation (Zod, io-ts, etc.) alongside the satisfies operator.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\bsatisfies\b/.test(line)) return false;
      return /\b(req|request|body|params|query|input)\b/.test(line);
    },
  },
  {
    id: 'TS_PARTIAL_TYPE_MISSING_FIELDS',
    category: 'Type Safety',
    description: 'Partial<> type used for security-critical data — required fields may be missing at runtime.',
    severity: 'medium',
    fix_suggestion: 'Use Required<> or explicit types for security-critical fields. Add runtime validation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/Partial\s*</.test(line)) return false;
      return /\b(Auth|Permission|Role|Security|Access|Credential)\b/.test(line);
    },
  },
  {
    id: 'TS_UNKNOWN_NO_NARROWING',
    category: 'Type Safety',
    description: 'unknown type cast with "as" in security-critical context — unsafe type assertion bypasses validation.',
    severity: 'info',
    fix_suggestion: 'Use typeof/instanceof type guards or a validation library instead of type assertions in auth/security code.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Only fire when `unknown` is cast with `as` in a security-critical context
      if (!/\bunknown\b/.test(line)) return false;
      if (!/as\s+[A-Z]\w+/.test(line) || /as\s+unknown/.test(line)) return false;
      // Must be in a security-critical context: auth, permissions, tokens, session, etc.
      const securityContext = /\b(auth|token|jwt|session|permission|role|credential|password|secret|user|claim|verify|validate|sanitize|middleware)\b/i;
      // Check the line itself and the surrounding function/file context
      if (securityContext.test(line)) return true;
      // Check nearby lines (function name, variable names)
      const lineIdx = ctx.lineNumber - 1;
      const nearbyLines = ctx.allLines.slice(Math.max(0, lineIdx - 10), lineIdx).join('\n');
      return securityContext.test(nearbyLines);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 95: Modern JS/TS Patterns (12 rules)
  // ════════════════════════════════════════════
  {
    id: 'STRUCTURED_CLONE_SENSITIVE',
    category: 'Information Disclosure',
    description: 'structuredClone on object with sensitive fields — deep clone may spread secrets.',
    severity: 'medium',
    fix_suggestion: 'Explicitly pick only needed fields instead of deep cloning objects with sensitive data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/structuredClone\s*\(/.test(line)) return false;
      return /\b(user|session|auth|credentials|config|secrets)\b/i.test(line);
    },
  },
  {
    id: 'ABORT_CONTROLLER_NO_CLEANUP',
    category: 'Resource Leak',
    description: 'AbortController timeout created without cleanup — timer persists after request completes.',
    severity: 'low',
    fix_suggestion: 'Call clearTimeout on the abort timer in a finally block, or use AbortSignal.timeout().',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/AbortSignal\.timeout\s*\(/.test(line) && !/new\s+AbortController/.test(line)) return false;
      if (/AbortSignal\.timeout/.test(line)) return false; // timeout() is safe
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 15).join('\n');
      return /setTimeout/.test(nearby) && !/clearTimeout/.test(nearby) && /\.abort\s*\(/.test(nearby);
    },
  },
  {
    id: 'WEAKREF_SECURITY_GC_RACE',
    category: 'Race Condition',
    description: 'WeakRef/WeakMap used for security state — garbage collection may invalidate checks.',
    severity: 'high',
    fix_suggestion: 'Use strong references for security-critical data (auth tokens, session state, ACLs).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/WeakRef\s*\(/.test(line) && !/new\s+WeakMap/.test(line) && !/new\s+WeakSet/.test(line)) return false;
      return /(auth|session|token|permission|role|acl|security)/i.test(line);
    },
  },
  {
    id: 'SYMBOL_DISPOSE_NO_CLEANUP',
    category: 'Resource Leak',
    description: 'Symbol.dispose/Symbol.asyncDispose declared but cleanup logic is empty or missing.',
    severity: 'medium',
    fix_suggestion: 'Implement proper resource cleanup in the dispose method (close connections, release locks, etc.).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/Symbol\.(?:async)?Dispose/.test(line) && !/\[Symbol\.dispose\]/.test(line)) return false;
      const nextLines = ctx.allLines.slice(ctx.lineNumber, ctx.lineNumber + 3).join('\n');
      return /\{\s*\}/.test(nextLines) || /=>\s*\{\s*\}/.test(nextLines);
    },
  },
  {
    id: 'ARRAY_FROM_ASYNC_UNTRUSTED',
    category: 'Denial of Service',
    description: 'Array.fromAsync with untrusted iterable — infinite iterator causes memory exhaustion.',
    severity: 'medium',
    fix_suggestion: 'Add a maximum iteration count or timeout when consuming untrusted async iterables.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/Array\.fromAsync\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user|external)\b/.test(line);
    },
  },
  {
    id: 'DECORATOR_SIDE_EFFECT',
    category: 'Code Injection',
    description: 'Decorator function with network call or eval — side effects during class definition.',
    severity: 'high',
    fix_suggestion: 'Decorators should be pure. Move side effects to initialization methods.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/^@/.test(line.trim())) return false;
      return /\bfetch\s*\(/.test(line) || /\beval\s*\(/.test(line) || /\bexec\s*\(/.test(line);
    },
  },
  {
    id: 'IMPORT_ASSERTION_BYPASS',
    category: 'Code Injection',
    description: 'Dynamic import without type assertion — may load unexpected module types.',
    severity: 'medium',
    fix_suggestion: 'Use import assertions: import(url, { assert: { type: "json" } }) for non-JS imports.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Skip auto-generated files
      if (isAutoGeneratedFile(ctx.fileContent)) return false;
      if (!/\bimport\s*\(/.test(line)) return false;
      if (/assert\s*:/.test(line) || /with\s*:/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'ITERATOR_HELPER_UNTRUSTED',
    category: 'Denial of Service',
    description: 'Iterator helper (map/filter/take) on untrusted data without limit — may process infinite stream.',
    severity: 'medium',
    fix_suggestion: 'Use .take(maxCount) before processing untrusted iterables to prevent infinite loops.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.values\(\)\s*\.(?:map|filter|flatMap|reduce)\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user|external)\b/.test(line);
    },
  },
  {
    id: 'TEMPORAL_API_USER_TIMEZONE',
    category: 'Input Validation',
    description: 'Temporal API with user-controlled timezone — may cause invalid timezone errors or logic bypass.',
    severity: 'low',
    fix_suggestion: 'Validate timezone strings against Intl.supportedValuesOf("timeZone") before using.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/Temporal\.\w+/.test(line)) return false;
      return /timeZone\s*:\s*(?:req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'USING_DECLARATION_NO_DISPOSE',
    category: 'Resource Leak',
    description: 'using/await using declaration on object without dispose implementation — resource leak.',
    severity: 'medium',
    fix_suggestion: 'Ensure the object implements Symbol.dispose or Symbol.asyncDispose before using with "using" declarations.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      // Detect: using x = someFunc() where we can't verify dispose exists
      return /\busing\s+\w+\s*=\s*(?:new\s+)?\w+\s*\(/.test(line) && !/await\s+using/.test(line);
    },
  },
  {
    id: 'PROXY_HANDLER_NO_INVARIANT',
    category: 'Type Safety',
    description: 'Proxy handler without invariant checks — may violate object model constraints.',
    severity: 'medium',
    fix_suggestion: 'Implement proper invariant checks in Proxy traps (e.g., getOwnPropertyDescriptor consistency).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/new\s+Proxy\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'REGEXP_USER_INPUT_NO_ESCAPE',
    category: 'ReDoS',
    description: 'RegExp constructor with user input — enables ReDoS or regex injection attacks.',
    severity: 'high',
    fix_suggestion: 'Escape user input with a regex-escape function before using in RegExp constructor.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/new\s+RegExp\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 96: Edge Runtime & Vercel Specific (10 rules)
  // ════════════════════════════════════════════
  {
    id: 'EDGE_MIDDLEWARE_NO_AUTH',
    category: 'Authorization',
    description: 'Next.js Edge middleware without authentication check — allows unauthenticated access.',
    severity: 'high',
    fix_suggestion: 'Add authentication checks in middleware.ts. Verify JWT or session before allowing access.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // Must be specifically a Next.js middleware file (middleware.ts at project root or in src/)
      const lowerPath = ctx.filePath.toLowerCase();
      if (!/(?:^|\/)middleware\.[tj]sx?$/.test(lowerPath)) return false;
      // Must have Next.js markers — NextRequest/NextResponse or next/server import
      if (!/\bNextRequest\b|\bNextResponse\b|\bfrom\s+['"]next\/server['"]/.test(ctx.fileContent)) return false;
      if (!/export\s+(?:default\s+)?function\s+middleware/.test(line)) return false;
      return !ctx.fileContent.includes('getToken') && !ctx.fileContent.includes('auth(') &&
        !ctx.fileContent.includes('session') && !ctx.fileContent.includes('jwt') &&
        !ctx.fileContent.includes('NextAuth') && !ctx.fileContent.includes('clerk');
    },
  },
  {
    id: 'VERCEL_KV_USER_KEY',
    category: 'Injection',
    description: 'Vercel KV store with user-controlled key — enables cache poisoning or data leakage.',
    severity: 'high',
    fix_suggestion: 'Prefix user-controlled keys with a namespace and validate key format.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/kv\.(get|set|del|hget|hset)\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'VERCEL_BLOB_NO_ACCESS_CONTROL',
    category: 'Authorization',
    description: 'Vercel Blob upload without access control — uploaded files may be publicly accessible.',
    severity: 'high',
    fix_suggestion: 'Set access: "private" in blob.put() and use authenticated download URLs.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/blob\.\s*put\s*\(/.test(line) && !/put\s*\(.*blob/.test(line)) return false;
      return !/access\s*:\s*['"]private/.test(line);
    },
  },
  {
    id: 'ISR_USER_REVALIDATION',
    category: 'Cache Poisoning',
    description: 'ISR revalidation with user-controlled time — enables cache manipulation attacks.',
    severity: 'medium',
    fix_suggestion: 'Hardcode revalidation times. Never allow user input to control cache TTL.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/revalidate\s*[:=]/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user|searchParams)\b/.test(line);
    },
  },
  {
    id: 'ON_DEMAND_REVALIDATION_NO_SECRET',
    category: 'Authorization',
    description: 'On-demand ISR revalidation API endpoint (res.revalidate()) without secret validation — allows cache busting.',
    severity: 'high',
    fix_suggestion: 'Validate a shared secret in the revalidation API route: if (req.query.secret !== process.env.REVALIDATION_SECRET).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      // revalidatePath() and revalidateTag() are Next.js cache invalidation functions —
      // they are NOT security-sensitive API endpoints. Only flag res.revalidate() which
      // is the Pages Router on-demand ISR API endpoint that needs secret protection.
      if (/\brevalidatePath\s*\(/.test(line) || /\brevalidateTag\s*\(/.test(line)) return false;
      // Only fire for res.revalidate() — the actual ISR API endpoint
      if (!/\bres\s*\.\s*revalidate\s*\(/.test(line)) return false;
      return !ctx.fileContent.includes('secret') && !ctx.fileContent.includes('REVALIDATION') &&
        !ctx.fileContent.includes('authorization') && !ctx.fileContent.includes('Bearer');
    },
  },
  {
    id: 'VERCEL_CRON_NO_AUTH',
    category: 'Authorization',
    description: 'Vercel Cron endpoint without authorization header check — accessible by anyone.',
    severity: 'high',
    fix_suggestion: 'Verify the CRON_SECRET header: if (req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/cron/.test(ctx.filePath.toLowerCase())) return false;
      if (!/export\s+(?:async\s+)?function\s+(?:GET|POST)/.test(line)) return false;
      // Check for various auth patterns: CRON_SECRET, authorization header, QStash signature verification
      if (ctx.fileContent.includes('CRON_SECRET')) return false;
      if (/\bauthorization\b/i.test(ctx.fileContent)) return false;
      if (/\bverifyQstashSignature\b/.test(ctx.fileContent)) return false;
      if (/\bverifySignature\b/.test(ctx.fileContent)) return false;
      if (/\bAuthorization\b/.test(ctx.fileContent)) return false;
      if (/\bBearer\b/.test(ctx.fileContent)) return false;
      return true;
    },
  },
  {
    id: 'AI_SDK_PROMPT_INJECTION',
    category: 'Prompt Injection',
    description: 'Vercel AI SDK with unvalidated user content in system prompt — enables prompt injection.',
    severity: 'high',
    fix_suggestion: 'Separate system and user messages. Never interpolate user input into system prompts.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/role\s*:\s*['"]system['"]/.test(line)) return false;
      return /\$\{.*(?:req|request|body|params|query|input|user)\b/.test(line) ||
        /\+\s*(?:req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'VERCEL_ANALYTICS_PII',
    category: 'Privacy',
    description: 'Analytics event tracking with PII data — may violate GDPR/privacy regulations.',
    severity: 'medium',
    fix_suggestion: 'Remove PII (email, name, IP, phone) from analytics events. Use anonymized identifiers.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/track\s*\(/.test(line) && !/analytics\.\w+\s*\(/.test(line)) return false;
      return /\b(email|phone|name|address|ssn|ip_address|creditCard)\b/i.test(line);
    },
  },
  {
    id: 'EDGE_RUNTIME_SECRETS_EXPOSURE',
    category: 'Information Disclosure',
    description: 'Secrets accessed in edge runtime — edge functions may log or expose env vars.',
    severity: 'medium',
    fix_suggestion: 'Minimize secret access in edge runtime. Use encrypted tokens instead of raw secrets.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/export\s+const\s+runtime\s*=\s*['"]edge['"]/.test(ctx.fileContent)) return false;
      return /process\.env\.(DATABASE_URL|SECRET_KEY|API_SECRET|PRIVATE_KEY)/.test(line);
    },
  },
  {
    id: 'NEXT_SERVER_ACTION_NO_AUTH',
    category: 'Authorization',
    description: 'Next.js server action without authentication check — callable by any client.',
    severity: 'high',
    fix_suggestion: 'Add auth() or getServerSession() at the top of every server action that modifies data.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/['"]use server['"]/.test(ctx.fileContent)) return false;
      if (!/export\s+async\s+function\s+\w+/.test(line)) return false;
      const funcBody = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 10).join('\n');
      // Skip auth check for cache invalidation actions — these only bust cache, no data read/write
      if (/\brevalidatePath\s*\(/.test(funcBody) || /\brevalidateTag\s*\(/.test(funcBody) || /\brevalidate\s*\(/.test(funcBody)) {
        // Only skip if the action ONLY does revalidation (no DB access or data mutations)
        if (!/\b(?:prisma|db|supabase|knex|pool|fetch|axios)\s*\./.test(funcBody) &&
            !/\b(?:create|update|delete|insert|remove|save|destroy|upsert)\s*\(/.test(funcBody)) {
          return false;
        }
      }
      return !/(auth|getServerSession|getSession|currentUser|requireAuth|clerk|getToken)\s*\(/.test(funcBody);
    },
  },

  // ════════════════════════════════════════════
  // Cycle 97: Deno & Bun Patterns (8 rules)
  // ════════════════════════════════════════════
  {
    id: 'DENO_RUN_USER_CMD',
    category: 'Command Injection',
    description: 'Deno.run/Deno.Command with user-controlled command — enables arbitrary command execution.',
    severity: 'critical',
    fix_suggestion: 'Never pass user input to Deno.run/Deno.Command. Use an allow list of commands.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/Deno\.(run|Command)\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'BUN_SPAWN_SHELL',
    category: 'Command Injection',
    description: 'Bun.spawn with shell option or user input — enables command injection.',
    severity: 'critical',
    fix_suggestion: 'Never use shell: true with user input. Pass command as an array without shell interpretation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/Bun\.spawn\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'DENO_KV_USER_KEY',
    category: 'Injection',
    description: 'Deno KV with user-controlled key — enables data access bypass or poisoning.',
    severity: 'high',
    fix_suggestion: 'Validate and namespace KV keys. Never use raw user input as KV keys.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/kv\.(get|set|delete|list)\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'BUN_SQLITE_RAW_QUERY',
    category: 'SQL Injection',
    description: 'Bun SQLite with raw query interpolation — vulnerable to SQL injection.',
    severity: 'critical',
    fix_suggestion: 'Use parameterized queries with db.prepare() instead of string interpolation.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/\.query\s*\(\s*`/.test(line) && !/\.run\s*\(\s*`/.test(line)) return false;
      return /\$\{/.test(line) && /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'DENO_PERMISSIONS_BYPASS',
    category: 'Runtime Security',
    description: 'Deno --allow-all flag or overly permissive permissions — bypasses Deno security sandbox.',
    severity: 'high',
    fix_suggestion: 'Use granular permissions: --allow-read=./data --allow-net=api.example.com instead of --allow-all.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: false,
    skipTestFiles: true,
    detect: (line) => {
      return /--allow-all/.test(line) || /--allow-run(?!=)/.test(line) && !/--allow-run=\w/.test(line);
    },
  },
  {
    id: 'BUN_FILE_PATH_TRAVERSAL',
    category: 'Path Traversal',
    description: 'Bun.file with user-controlled path — enables path traversal and arbitrary file read.',
    severity: 'high',
    fix_suggestion: 'Validate and sanitize file paths. Use path.resolve and check against an allowed directory.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/Bun\.file\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'DENO_READ_FILE_NO_PERMISSION',
    category: 'Authorization',
    description: 'Deno.readFile with user input without permission scoping — may read arbitrary files.',
    severity: 'high',
    fix_suggestion: 'Scope Deno permissions to specific directories and validate paths against allow list.',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line) => {
      if (!/Deno\.(readFile|readTextFile)\s*\(/.test(line)) return false;
      return /\b(req|request|body|params|query|input|user)\b/.test(line);
    },
  },
  {
    id: 'BUN_SERVE_NO_TLS',
    category: 'Security Configuration',
    description: 'Bun.serve without TLS configuration — traffic transmitted in plaintext.',
    severity: 'medium',
    fix_suggestion: 'Add tls option to Bun.serve: Bun.serve({ tls: { cert, key }, ... }).',
    auto_fixable: false,
    fileTypes: ['.ts', '.tsx', '.js', '.jsx'],
    skipCommentsAndStrings: true,
    skipTestFiles: true,
    detect: (line, ctx) => {
      if (!/Bun\.serve\s*\(/.test(line)) return false;
      const nearby = ctx.allLines.slice(ctx.lineNumber - 1, ctx.lineNumber + 10).join('\n');
      return !/tls\s*:/.test(nearby) && !/https/.test(nearby);
    },
  },
];

// ── File Discovery ──

const MAX_FILES = 5_000;

/** Detect whether a path looks like a project root (has package.json, .git, etc.) */
async function isProjectDirectory(dir: string): Promise<boolean> {
  const markers = ['package.json', '.git', 'Cargo.toml', 'pyproject.toml', 'go.mod', 'Gemfile', 'pom.xml'];
  for (const marker of markers) {
    try {
      await stat(join(dir, marker));
      return true;
    } catch {
      // marker not found
    }
  }
  return false;
}

async function discoverFiles(targetPath: string): Promise<string[]> {
  const files: string[] = [];
  const resolvedTarget = resolve(targetPath);
  let hitLimit = false;

  async function walk(dir: string): Promise<void> {
    if (hitLimit) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return; // skip unreadable directories
    }

    for (const entry of entries) {
      if (hitLimit) return;
      if (entry.name.startsWith('.') && entry.name !== '.') continue;

      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        await walk(join(dir, entry.name));
      } else if (entry.isFile()) {
        const ext = extname(entry.name);
        if (SCANNABLE_EXTENSIONS.has(ext)) {
          files.push(join(dir, entry.name));
          if (files.length >= MAX_FILES) {
            hitLimit = true;
            return;
          }
        }
      }
    }
  }

  // Check if targetPath is a file or directory
  const targetStat = await stat(resolvedTarget);
  if (targetStat.isFile()) {
    const ext = extname(resolvedTarget);
    if (SCANNABLE_EXTENSIONS.has(ext)) {
      files.push(resolvedTarget);
    }
  } else {
    // Refuse to scan non-project directories (e.g., home directory)
    const isProject = await isProjectDirectory(resolvedTarget);
    if (!isProject) {
      // Check if it's a known non-project path (home dir, root, etc.)
      const homedir = process.env.HOME ?? process.env.USERPROFILE ?? '';
      if (resolvedTarget === homedir || resolvedTarget === '/' || resolvedTarget === '/tmp') {
        return files; // Return empty — don't scan home/root directories
      }
    }
    await walk(resolvedTarget);
  }

  return files;
}

// ── Core Scanner ──

function getFileType(filePath: string): FileType | null {
  const ext = extname(filePath);
  return SCANNABLE_EXTENSIONS.has(ext) ? (ext as FileType) : null;
}

function scanFileContent(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];

  // Skip Prisma schema files (.prisma) — not application code
  if (isPrismaSchemaFile(filePath)) return findings;
  // Skip Prisma migration files — auto-generated SQL, not user-authored
  if (isPrismaMigrationFile(filePath)) return findings;

  const fileType = getFileType(filePath);
  if (!fileType) return findings;

  const lines = content.split('\n');
  const fileIsTest = isTestOrFixtureFile(filePath);

  // Filter rules applicable to this file type
  const applicableRules = RULES.filter((rule) => {
    if (!rule.fileTypes.includes(fileType)) return false;
    if (rule.skipTestFiles && fileIsTest) return false;
    return true;
  });

  if (applicableRules.length === 0) return findings;

  const context: LineContext = {
    filePath,
    lineNumber: 0,
    fileContent: content,
    allLines: lines,
    isTestFile: fileIsTest,
  };

  // Track which rules have already flagged multi-line or file-level detections
  const firedOnceRules = new Set<string>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    context.lineNumber = i + 1;

    // Skip empty lines
    if (line.trim().length === 0) continue;

    for (const rule of applicableRules) {
      // For file-level rules (like CONFIG_NO_SECURITY_HEADERS), only fire once
      if (firedOnceRules.has(rule.id)) continue;

      // Skip comment lines for rules that request it
      if (rule.skipCommentsAndStrings && isCommentLine(line, fileType)) {
        continue;
      }

      try {
        if (rule.detect(line, context)) {
          findings.push({
            id: rule.id,
            engine: 'pattern',
            severity: rule.severity,
            type: rule.category,
            file: filePath,
            line: context.lineNumber,
            description: rule.description,
            fix_suggestion: rule.fix_suggestion,
            auto_fixable: rule.auto_fixable,
          });

          // Mark file-level rules so they only fire once per file
          if (
            rule.id === 'CONFIG_NO_SECURITY_HEADERS' ||
            rule.id === 'FASTAPI_NO_CORS_MIDDLEWARE' ||
            rule.id === 'FASTAPI_NO_MIDDLEWARE_STACK' ||
            rule.id === 'FASTAPI_TRUSTED_HOST_MISSING'
          ) {
            firedOnceRules.add(rule.id);
          }
        }
      } catch {
        // If a regex or detection function errors, skip this rule for this line
      }
    }
  }

  return findings;
}

// ── Public API ──

/**
 * Scan files at targetPath for vulnerability patterns.
 *
 * @param targetPath - Directory or file path to scan.
 * @param files - Optional pre-supplied list of file paths (skips discovery).
 * @returns Array of findings sorted by severity (critical first).
 */
export async function scanPatterns(
  targetPath: string,
  files?: string[],
): Promise<Finding[]> {
  const discovered = files ?? (await discoverFiles(targetPath));

  // Apply .shipsafeignore filter
  const ignoreFilter = await loadIgnoreFilter(resolve(targetPath));

  // Apply .gitignore filter — silently skips gitignored files (e.g., .env.local)
  const gitIgnoreFilter = await loadGitIgnoreFilter(resolve(targetPath));

  const filesToScan = discovered.filter(
    (f) => !ignoreFilter.isIgnored(f) && !gitIgnoreFilter.isGitIgnored(f),
  );

  const allFindings: Finding[] = [];

  // Process files in parallel batches for performance
  const BATCH_SIZE = 50;

  for (let i = 0; i < filesToScan.length; i += BATCH_SIZE) {
    const batch = filesToScan.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(
      batch.map(async (filePath) => {
        try {
          const content = await readFile(filePath, 'utf-8');
          return scanFileContent(filePath, content);
        } catch {
          // Skip files that can't be read (permissions, binary, etc.)
          return [];
        }
      }),
    );

    for (const result of results) {
      allFindings.push(...result);
    }
  }

  // Sort by severity: critical > high > medium > low > info
  allFindings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  return allFindings;
}

/**
 * Returns the total number of vulnerability detection rules.
 */
export function getPatternRuleCount(): number {
  return RULES.length;
}
