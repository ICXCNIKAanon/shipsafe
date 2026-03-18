/**
 * ShipSafe Built-in Vulnerability Pattern Scanner
 *
 * Pure TypeScript, zero external dependencies.
 * Detects code-level vulnerabilities across TypeScript, JavaScript, and Python files.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join, relative, resolve } from 'node:path';
import type { Finding, Severity } from '../../types.js';

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
  const filesToScan = files ?? (await discoverFiles(targetPath));
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
