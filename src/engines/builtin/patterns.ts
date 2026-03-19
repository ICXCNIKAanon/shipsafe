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
    lower.endsWith('.spec.js')
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
    detect: (line) => {
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
    detect: (line) => {
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
    detect: (line) => {
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
    detect: (line) => {
      // Catch template literals containing SQL keywords + interpolation, even outside a db method call
      // e.g., const sql = `SELECT * FROM users WHERE id = ${userId}`;
      // But NOT tagged templates like sql`...` or Prisma.$queryRaw`...`
      if (/\b(?:sql|html|css|gql|graphql)\s*`/.test(line)) return false;
      if (/\$queryRaw\s*`/.test(line)) return false;
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
    detect: (line) => {
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
    detect: (line) => {
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
      return /dangerouslySetInnerHTML\s*=/.test(line);
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
      return /\beval\s*\(/.test(line) && !/\bsetInterval\b/.test(line);
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
    detect: (line) => {
      // Handlebars triple-stash {{{, Jinja2 |safe, EJS <%- (unescaped)
      return /\{\{\{[^}]+\}\}\}/.test(line) || /\|\s*safe\b/.test(line) || /<%- /.test(line);
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
      return /\bexec\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*[,)]/.test(line) &&
        !/\bexec\s*\(\s*(?:"|'|`)/.test(line);
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
    detect: (line) => {
      // Flag Math.random() in contexts that suggest security usage
      if (!/\bMath\s*\.\s*random\s*\(\s*\)/.test(line)) return false;
      // Check surrounding context for security-related terms
      const lower = line.toLowerCase();
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
    detect: (line) => {
      const lower = line.toLowerCase();
      if (!/===/.test(line)) return false;
      return (
        (lower.includes('token') || lower.includes('hmac') || lower.includes('digest') || lower.includes('signature')) &&
        !/timingSafeEqual/.test(line)
      );
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
    detect: (line) => {
      // Match Python f-strings that look like prompts with user variables
      // e.g., prompt = f"You are a helpful assistant. The user asks: {user_input}"
      const isPromptAssignment = /\b(?:prompt|system_prompt|system_message|instruction|messages?)\s*=\s*f(?:"|')/.test(line);
      if (!isPromptAssignment) return false;
      // Check for variable interpolation (curly braces in f-string)
      return /\{[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_]+)*\}/.test(line);
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
    detect: (line) => {
      // Match window.location = userInput, window.location.href = req.query.redirect, etc.
      if (!/\bwindow\s*\.\s*location\s*(?:\.href)?\s*=/.test(line)) return false;
      // Must be assigned from a variable, not a string literal
      if (/\bwindow\s*\.\s*location\s*(?:\.href)?\s*=\s*['"`]/.test(line)) return false;
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
      return /\bNEXT_PUBLIC_[A-Z_]*(?:SECRET|PRIVATE|PASSWORD|TOKEN|KEY|CREDENTIAL|AUTH)[A-Z_]*\b/.test(line);
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
    detect: (line) => {
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
    detect: (line) => {
      if (!/\bwindow\s*\.\s*open\s*\(/.test(line)) return false;
      return /\bwindow\s*\.\s*open\s*\(\s*req\s*\.\s*(?:query|body|params)\b/.test(line) ||
        /\bwindow\s*\.\s*open\s*\(\s*(?:userUrl|user_url|url|redirectUrl|redirect_url|targetUrl)\b/.test(line);
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
      // Must not be a hardcoded string
      if (/\bredirect\s*\(\s*['"`]\/[^'"$`]*['"`]\s*\)/.test(line)) return false;
      // Check if it uses user input
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(Math.max(0, lineIdx - 8), lineIdx + 1)
        .join(' ');
      return /\b(?:searchParams|params|req\s*\.\s*(?:query|body|params)|headers\(\)|url)\b/.test(window);
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
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines
        .slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 15))
        .join(' ');
      const hasDbMutation = /\b(?:UPDATE|INSERT|DELETE|create|update|delete|remove)\b/i.test(window);
      const hasCsrfCheck = /\b(?:csrf|origin|referer|csrfToken|verifyOrigin|headers\(\).*origin)\b/i.test(window);
      return hasDbMutation && !hasCsrfCheck;
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
      if (/\$queryRaw\s*`/.test(line)) return false;
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
      return /\bNEXT_PUBLIC_\w*(?:SECRET|PASSWORD|PRIVATE_KEY|ADMIN_KEY|DB_PASS|AUTH_KEY)\b/i.test(line);
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
    detect: (line) => {
      if (!/\bSECRET_KEY\s*=/.test(line)) return false;
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
    detect: (line) => {
      if (!/\bCOPY\b/i.test(line)) return false;
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
    detect: (line) => {
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
    detect: (line) => {
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
    detect: (line) => {
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
      return !/\b(?:DOMPurify|sanitize|purify|dompurify|xss)\b/i.test(line);
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
    detect: (line) => {
      return /\bDEBUG\s*=\s*True\b/.test(line);
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
    detect: (line) => {
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
      return /\b\$(?:executeRawUnsafe|queryRawUnsafe)\s*\(/.test(line);
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
      if (/\b(?:\.ok|\.status|response\.ok)\b/.test(line)) return false;
      const lineIdx = ctx.lineNumber - 1;
      const nextLines = ctx.allLines.slice(lineIdx + 1, Math.min(ctx.allLines.length, lineIdx + 4)).join('\n');
      return !/\b(?:\.ok|\.status|response\.ok|res\.ok)\b/.test(nextLines);
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
    detect: (line) => {
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
    detect: (line) => {
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
    severity: 'medium',
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
      // Check for depth/maxDepth parameter
      return !/\b(?:depth|maxDepth|max_depth|level|maxLevel)\b/.test(line) &&
        !/\b(?:depth|maxDepth|max_depth|level|maxLevel)\b/.test(window);
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
      // Look ahead for default case within 30 lines
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 30)).join('\n');
      return !/\bdefault\s*:/.test(window);
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
    detect: (line) => {
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
      return /\b(?:secret|apiKey|api_key|password|token|privateKey|private_key|dbPassword|secretKey|secret_key)\s*=\s*\{/.test(line) &&
        /<\s*[A-Z]/.test(line);
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
      const lineIdx = ctx.lineNumber - 1;
      const window = ctx.allLines.slice(lineIdx, Math.min(ctx.allLines.length, lineIdx + 10)).join('\n');
      return !/\b(?:csrf|csrfToken|_csrf|xsrf|token)\b/i.test(window) &&
        !/['"]use server['"]/.test(ctx.fileContent);
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
      // Only flag in settings files or if not from env var
      return ctx.filePath.includes('settings') || /^\s*DEBUG\s*=\s*True\s*$/.test(line);
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
      if (!/\bFastAPI\s*\(\s*\)/.test(line)) return false;
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
    detect: (line) => {
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
    detect: (line) => {
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
    skipTestFiles: false,
    detect: (line, ctx) => {
      if (!ctx.filePath.endsWith('.py')) return false;
      // Match common credential patterns in code cells
      return /\b(?:api_key|apikey|secret_key|password|token|credentials)\s*=\s*['"`][a-zA-Z0-9_\-]{8,}['"`]/.test(line) &&
        !/\b(?:os\.environ|os\.getenv|config|env\(|\.env)\b/.test(line) &&
        !/\b(?:test|mock|example|placeholder|xxx|your_)\b/i.test(line);
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
  const fileType = getFileType(filePath);
  if (!fileType) return findings;

  const lines = content.split('\n');
  const fileIsTest = isTestFile(filePath);

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

          // Mark file-level rules so they only fire once
          if (rule.id === 'CONFIG_NO_SECURITY_HEADERS') {
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
