/**
 * Import-Level Context for ShipSafe False Positive Reduction
 *
 * Extracts import statements from a file and provides boolean queries about
 * what security-relevant libraries the file imports. Used by the pattern scanner
 * to suppress findings when the file already imports the relevant mitigation.
 *
 * Uses regex (not AST) for speed — import statements have very regular syntax.
 */

// ── Types ──

export interface ImportContext {
  /** Imports auth middleware: passport, clerk, next-auth, @auth, lucia, etc. */
  hasAuthImport: boolean;
  /** Imports stripe */
  hasStripeImport: boolean;
  /** Imports sanitization: DOMPurify, sanitize-html, xss, isomorphic-dompurify, etc. */
  hasSanitizationImport: boolean;
  /** Imports validation: zod, joi, yup, class-validator, express-validator, etc. */
  hasValidationImport: boolean;
  /** Imports ORM/DB: prisma, drizzle, sequelize, typeorm, knex, mongoose, etc. */
  hasORMImport: boolean;
  /** Imports crypto: bcrypt, argon2, node:crypto, crypto */
  hasCryptoImport: boolean;
  /** Imports rate limiting: express-rate-limit, rate-limiter-flexible, etc. */
  hasRateLimitImport: boolean;
  /** Imports CSRF protection: csurf, csrf, csrf-csrf, lusca, etc. */
  hasCSRFImport: boolean;
  /** Imports helmet */
  hasHelmetImport: boolean;
  /** All extracted import sources (module specifiers) */
  imports: string[];
}

// ── Regex patterns ──

// Matches ES6: import ... from 'module'  or  import 'module'
const ES6_IMPORT_RE = /(?:^|\n)\s*import\s+(?:(?:[\w*{}\s,]+)\s+from\s+)?['"]([^'"]+)['"]/g;

// Matches CommonJS: require('module')  or  require("module")
const CJS_REQUIRE_RE = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

// Matches dynamic import: import('module')  or  await import('module')
const DYNAMIC_IMPORT_RE = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

// ── Category matchers ──

const AUTH_PATTERNS = /^(?:passport|@clerk\/|next-auth|@auth\/|lucia|@lucia-auth\/|better-auth|iron-session|express-jwt|jsonwebtoken|jose|@supabase\/auth-helpers|@kinde-oss\/|@auth0\/|firebase-admin\/auth|@firebase\/auth)/;

const STRIPE_PATTERNS = /^stripe$/;

const SANITIZATION_PATTERNS = /^(?:dompurify|isomorphic-dompurify|sanitize-html|xss|xss-filters|@types\/dompurify|he|html-entities|escape-html|validator)/;

const VALIDATION_PATTERNS = /^(?:zod|joi|yup|class-validator|express-validator|superstruct|valibot|io-ts|runtypes|@sinclair\/typebox|ajv|ow)/;

const ORM_PATTERNS = /^(?:@prisma\/client|drizzle-orm|sequelize|typeorm|knex|mongoose|@mikro-orm\/|objection|bookshelf|kysely|@neondatabase\/serverless)/;

const CRYPTO_PATTERNS = /^(?:bcrypt|bcryptjs|argon2|crypto|node:crypto|scrypt|@node-rs\/bcrypt|@node-rs\/argon2)/;

const RATE_LIMIT_PATTERNS = /^(?:express-rate-limit|rate-limiter-flexible|@nestjs\/throttler|bottleneck|p-throttle|limiter|@upstash\/ratelimit)/;

const CSRF_PATTERNS = /^(?:csurf|csrf|csrf-csrf|lusca|@fastify\/csrf-protection|tiny-csrf)/;

const HELMET_PATTERNS = /^helmet$/;

// ── Core function ──

/**
 * Extract import context from file content using regex.
 * Works for ES6 imports, CommonJS requires, and dynamic imports.
 */
export function extractImportContext(fileContent: string, _filePath: string): ImportContext {
  const imports: string[] = [];

  // Extract all import sources
  for (const re of [ES6_IMPORT_RE, CJS_REQUIRE_RE, DYNAMIC_IMPORT_RE]) {
    re.lastIndex = 0; // Reset regex state
    let match;
    while ((match = re.exec(fileContent)) !== null) {
      const source = match[1];
      if (source) {
        imports.push(source);
      }
    }
  }

  // Classify imports
  const ctx: ImportContext = {
    hasAuthImport: imports.some((s) => AUTH_PATTERNS.test(s)),
    hasStripeImport: imports.some((s) => STRIPE_PATTERNS.test(s)),
    hasSanitizationImport: imports.some((s) => SANITIZATION_PATTERNS.test(s)),
    hasValidationImport: imports.some((s) => VALIDATION_PATTERNS.test(s)),
    hasORMImport: imports.some((s) => ORM_PATTERNS.test(s)),
    hasCryptoImport: imports.some((s) => CRYPTO_PATTERNS.test(s)),
    hasRateLimitImport: imports.some((s) => RATE_LIMIT_PATTERNS.test(s)),
    hasCSRFImport: imports.some((s) => CSRF_PATTERNS.test(s)),
    hasHelmetImport: imports.some((s) => HELMET_PATTERNS.test(s)),
    imports,
  };

  return ctx;
}
