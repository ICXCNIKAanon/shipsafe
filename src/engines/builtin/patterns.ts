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
      // Match patterns like query("SELECT ... " + variable) or execute("INSERT ... " + variable)
      return /\b(?:query|execute|raw|prepare)\s*\(\s*(?:"|')(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^"']*(?:"|')\s*\+/i.test(line);
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
      // Match query(`SELECT ... ${...}`) patterns, but NOT tagged template literals like sql`...`
      return /\b(?:query|execute|raw|prepare)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^`]*\$\{/i.test(line);
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
        /\b(?:execute|executemany)\s*\(\s*(?:"|')(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*(?:"|')\s*%/i.test(line) ||
        /\b(?:execute|executemany)\s*\(\s*(?:"|')(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*(?:"|')\s*\+/i.test(line) ||
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
      // Sequelize, TypeORM, Knex, Django, SQLAlchemy raw queries with interpolation
      return (
        /\b(?:sequelize|connection|entityManager|manager|knex)\s*\.\s*(?:query|raw)\s*\(\s*`[^`]*\$\{/i.test(line) ||
        /\b(?:sequelize|connection|entityManager|manager|knex)\s*\.\s*(?:query|raw)\s*\(\s*(?:"|')[^"']*(?:"|')\s*\+/i.test(line) ||
        /\bRawSQL\s*\(\s*f(?:"|')/i.test(line) ||
        /\.raw\s*\(\s*f(?:"|')(?:SELECT|INSERT|UPDATE|DELETE)/i.test(line)
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
];

// ── File Discovery ──

async function discoverFiles(targetPath: string): Promise<string[]> {
  const files: string[] = [];
  const resolvedTarget = resolve(targetPath);

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return; // skip unreadable directories
    }

    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.') continue;

      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        await walk(join(dir, entry.name));
      } else if (entry.isFile()) {
        const ext = extname(entry.name);
        if (SCANNABLE_EXTENSIONS.has(ext)) {
          files.push(join(dir, entry.name));
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
