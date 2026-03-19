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
