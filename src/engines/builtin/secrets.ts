/**
 * ShipSafe Built-in Secret Scanner
 *
 * Pure TypeScript secret detection engine — zero external dependencies.
 * Replaces Gitleaks with 100+ regex patterns, Shannon entropy checks,
 * and context-aware validation for minimal false positives.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, extname, relative, basename, resolve } from 'node:path';
import type { Finding, Severity } from '../../types.js';
import { loadIgnoreFilter } from './ignore.js';
import { loadGitIgnoreFilter } from './gitignore.js';

// ── Types ──────────────────────────────────────────────────────────────────────

interface SecretPattern {
  id: string;
  regex: RegExp;
  description: string;
  severity: Severity;
  type: string;
  autoFixable: boolean;
  /** If true, require Shannon entropy check on the matched group to reduce false positives */
  entropyCheck?: boolean;
  /** Minimum Shannon entropy for the matched secret portion (default 3.5) */
  entropyThreshold?: number;
  /** Additional context keywords that must appear nearby to confirm the match */
  contextKeywords?: string[];
  /** If true, the match is only flagged when value looks non-placeholder */
  skipPlaceholders?: boolean;
}

// ── Shannon Entropy ────────────────────────────────────────────────────────────

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ── Placeholder / example detection ────────────────────────────────────────────

const PLACEHOLDER_PATTERNS = [
  /^[x]{6,}$/i,
  /^[*]{6,}$/,
  /^<[^>]+>$/,
  /^\$\{[^}]+\}$/,
  /^%[^%]+%$/,
  /^\{\{[^}]+\}\}$/,
  /^your[_-]?/i,
  /^example/i,
  /^test[_-]?/i,
  /^dummy/i,
  /^fake/i,
  /^replace[_-]?me/i,
  /^insert[_-]?/i,
  /^todo/i,
  /^fixme/i,
  /^changeme/i,
  /^placeholder/i,
  /^sample/i,
  /^my[_-]?(api|secret|key|token|password)/i,
  /^(xxx+|yyy+|zzz+|aaa+|bbb+|000+|111+|123+)/i,
  /^sk_test_/i,              // Stripe test keys
  /^pk_test_/i,              // Stripe test publishable keys
  /^sk_live_test/i,          // Stripe live test keys
  /^whsec_test/i,            // Stripe webhook test secrets
  /^rk_test_/i,              // Stripe restricted test keys
];

function isPlaceholder(value: string): boolean {
  const trimmed = value.trim().replace(/['"` ]/g, '');
  if (trimmed.length < 8) return true;
  return PLACEHOLDER_PATTERNS.some((p) => p.test(trimmed));
}

/**
 * Detect error code strings / constants that happen to contain "password".
 * Examples: INVALID_PASSWORD, ACCOUNT_PASSWORD_RESET, PASSWORD_TOO_SHORT
 * These are NOT actual passwords — they are error codes or enum values.
 */
function isErrorCodeOrConstant(value: string): boolean {
  const trimmed = value.trim().replace(/['"` ]/g, '');
  // ALL_CAPS_WITH_UNDERSCORES pattern (e.g., INVALID_PASSWORD, ACCOUNT_PASSWORD_RESET)
  if (/^[A-Z][A-Z0-9_]+$/.test(trimmed)) return true;
  // Starts with a verb commonly used in error codes / action names
  if (/^(?:RESET|CHANGE|UPDATE|INVALID|VERIFY|CONFIRM|EXPIRE|REQUIRE|MISSING|WRONG|INCORRECT|SET|GET|CHECK|VALIDATE|CREATE|DELETE|FORGOT|REQUEST)[_A-Z]/i.test(trimmed)) return true;
  return false;
}

// ── Localhost URL detection ─────────────────────────────────────────────────────

function isLocalhostUrl(value: string): boolean {
  return /^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/(?:[^@]*@)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(?:[:\/]|$)/i.test(value);
}

// ── Comment / documentation line detection ─────────────────────────────────────

/**
 * Detect base64 font data or large data blobs that look like tokens.
 * JSON files containing font data (otf, woff, ttf) with very large base64
 * strings are NOT access tokens.
 */
function isFontOrDataFile(filePath: string, content: string): boolean {
  if (!filePath.endsWith('.json')) return false;
  // Check for font-related keys in the file
  const lower = content.toLowerCase();
  return (
    lower.includes('"otf"') ||
    lower.includes('"woff"') ||
    lower.includes('"woff2"') ||
    lower.includes('"ttf"') ||
    lower.includes('"font"') ||
    lower.includes('"data"') && (lower.includes('"font') || lower.includes('font-face'))
  );
}

/**
 * Check if a matched string is too long to be a real token (likely base64 data blob).
 * Real access tokens are typically <500 characters.
 */
function isLargeBase64Blob(value: string): boolean {
  return value.length > 500;
}

function isDocOrCommentExample(line: string): boolean {
  const trimmed = line.trim();
  // Markdown code fence examples
  if (trimmed.startsWith('```')) return true;
  // Lines that are clearly documentation
  if (trimmed.startsWith('* @example')) return true;
  if (trimmed.startsWith('* @param')) return true;
  if (trimmed.startsWith('* @returns')) return true;
  // "e.g." or "for example" context
  if (/\be\.g\.\b/i.test(trimmed)) return true;
  if (/\bfor example\b/i.test(trimmed)) return true;
  // URLs in comments pointing to docs
  if (/^\s*[/*#]+\s*https?:\/\//.test(trimmed)) return true;
  return false;
}

// ── Test / docs / i18n file detection ────────────────────────────────────────

function isTestOrDocsFile(filePath: string): boolean {
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
    lower.includes('/mocks/')
  );
}

// ── File filtering ─────────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '__pycache__',
  '.pytest_cache',
  'vendor',
  '.terraform',
  '.cache',
  '.turbo',
  '.vercel',
  '.output',
  'out',
  '.parcel-cache',
]);

const SKIP_EXTENSIONS = new Set([
  // Minified / bundled
  '.min.js',
  '.min.css',
  '.bundle.js',
  '.chunk.js',
  // Binaries & media
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.bmp',
  '.ico',
  '.svg',
  '.webp',
  '.avif',
  '.mp3',
  '.mp4',
  '.mov',
  '.avi',
  '.mkv',
  '.wav',
  '.flac',
  '.ogg',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.otf',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.bz2',
  '.7z',
  '.rar',
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.o',
  '.a',
  '.class',
  '.jar',
  '.pyc',
  '.pyo',
  '.wasm',
  // Lock files
  '.lock',
  // Maps
  '.map',
]);

const SKIP_FILENAMES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'composer.lock',
  'Gemfile.lock',
  'Cargo.lock',
  'poetry.lock',
  'go.sum',
]);

const MAX_FILE_SIZE = 1_048_576; // 1MB

function shouldSkipFile(filePath: string): boolean {
  const name = basename(filePath);
  if (SKIP_FILENAMES.has(name)) return true;

  const ext = extname(filePath).toLowerCase();
  if (SKIP_EXTENSIONS.has(ext)) return true;

  // Compound extensions like .min.js
  if (filePath.endsWith('.min.js') || filePath.endsWith('.min.css')) return true;
  if (filePath.endsWith('.bundle.js') || filePath.endsWith('.chunk.js')) return true;

  return false;
}

// ── Directory walker ───────────────────────────────────────────────────────────

const MAX_SECRET_FILES = 5_000;

async function walkDirectory(dirPath: string): Promise<string[]> {
  const files: string[] = [];
  let hitLimit = false;

  // Refuse to scan home/root directories
  const homedir = process.env.HOME ?? process.env.USERPROFILE ?? '';
  const resolvedPath = join(dirPath); // normalize
  if (resolvedPath === homedir || resolvedPath === '/' || resolvedPath === '/tmp') {
    return files;
  }

  async function walk(currentPath: string): Promise<void> {
    if (hitLimit) return;
    let entries;
    try {
      entries = await readdir(currentPath, { withFileTypes: true });
    } catch {
      // Permission denied or other read error — skip silently
      return;
    }

    const promises: Promise<void>[] = [];

    for (const entry of entries) {
      if (hitLimit) break;
      const fullPath = join(currentPath, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          // Allow .env directories but skip other dot-dirs (except .github, .gitlab)
          if (
            entry.name === '.env' ||
            entry.name === '.github' ||
            entry.name === '.gitlab' ||
            entry.name === '.circleci' ||
            !entry.name.startsWith('.')
          ) {
            promises.push(walk(fullPath));
          }
        }
        continue;
      }

      if (entry.isFile() && !shouldSkipFile(fullPath)) {
        files.push(fullPath);
        if (files.length >= MAX_SECRET_FILES) {
          hitLimit = true;
          break;
        }
      }
    }

    await Promise.all(promises);
  }

  await walk(dirPath);
  return files;
}

// ── Secret Patterns ────────────────────────────────────────────────────────────
// 100+ patterns organized by category

const SECRET_PATTERNS: SecretPattern[] = [
  // ─── Cloud Providers: AWS ──────────────────────────────────────────────────

  {
    id: 'aws-access-key-id',
    regex: /(?:^|[^0-9A-Z])(AKIA[0-9A-Z]{16})(?:[^0-9A-Z]|$)/,
    description: 'AWS Access Key ID detected',
    severity: 'critical',
    type: 'aws_access_key',
    autoFixable: true,
  },
  {
    id: 'aws-secret-access-key',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret|secret_access_key)\s*[=:]\s*['"]?([0-9a-zA-Z/+=]{40})['"]?/i,
    description: 'AWS Secret Access Key detected',
    severity: 'critical',
    type: 'aws_secret_key',
    autoFixable: true,
    entropyCheck: true,
    entropyThreshold: 4.0,
  },
  {
    id: 'aws-session-token',
    regex: /(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?/i,
    description: 'AWS Session Token detected',
    severity: 'critical',
    type: 'aws_session_token',
    autoFixable: true,
  },
  {
    id: 'aws-mws-key',
    regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/,
    description: 'Amazon MWS Auth Token detected',
    severity: 'critical',
    type: 'aws_mws_token',
    autoFixable: true,
  },
  {
    id: 'aws-arn-with-secret',
    regex: /arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:secret:[A-Za-z0-9/_+=.@-]+/,
    description: 'AWS Secrets Manager ARN detected',
    severity: 'medium',
    type: 'aws_secret_arn',
    autoFixable: false,
  },

  // ─── Cloud Providers: Google ───────────────────────────────────────────────

  {
    id: 'google-api-key',
    regex: /AIza[0-9A-Za-z\-_]{35}/,
    description: 'Google API Key detected',
    severity: 'critical',
    type: 'google_api_key',
    autoFixable: true,
  },
  {
    id: 'google-oauth-client-secret',
    regex: /(?:client_secret|GOOGLE_CLIENT_SECRET|google_client_secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{24,})['"]?/i,
    description: 'Google OAuth Client Secret detected',
    severity: 'critical',
    type: 'google_oauth_secret',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'google-cloud-service-account-key',
    regex: /"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/,
    description: 'Google Cloud Service Account private key detected',
    severity: 'critical',
    type: 'gcp_service_account_key',
    autoFixable: true,
  },
  {
    id: 'google-oauth-access-token',
    regex: /ya29\.[0-9A-Za-z_-]{20,}/,
    description: 'Google OAuth Access Token detected',
    severity: 'critical',
    type: 'google_oauth_token',
    autoFixable: true,
  },
  {
    id: 'google-cloud-api-key',
    regex: /(?:GOOGLE_CLOUD_API_KEY|GCLOUD_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?/i,
    description: 'Google Cloud API key in environment variable detected',
    severity: 'critical',
    type: 'google_cloud_api_key',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Cloud Providers: Azure ────────────────────────────────────────────────

  {
    id: 'azure-storage-account-key',
    regex: /(?:AccountKey|azure_storage_key|AZURE_STORAGE_KEY)\s*[=:]\s*['"]?([A-Za-z0-9+/]{86}==)['"]?/i,
    description: 'Azure Storage Account Key detected',
    severity: 'critical',
    type: 'azure_storage_key',
    autoFixable: true,
  },
  {
    id: 'azure-connection-string',
    regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==/,
    description: 'Azure Storage Connection String detected',
    severity: 'critical',
    type: 'azure_connection_string',
    autoFixable: true,
  },
  {
    id: 'azure-ad-client-secret',
    regex: /(?:AZURE_CLIENT_SECRET|azure_client_secret|client_secret)\s*[=:]\s*['"]?([A-Za-z0-9~._-]{34,})['"]?/i,
    description: 'Azure AD Client Secret detected',
    severity: 'critical',
    type: 'azure_ad_secret',
    autoFixable: true,
    skipPlaceholders: true,
    contextKeywords: ['azure', 'AZURE', 'tenant', 'client_id'],
  },
  {
    id: 'azure-sas-token',
    regex: /[?&]sig=[A-Za-z0-9%+/=]{40,}/,
    description: 'Azure SAS Token detected',
    severity: 'high',
    type: 'azure_sas_token',
    autoFixable: true,
    contextKeywords: ['blob.core.windows.net', 'queue.core.windows.net', 'table.core.windows.net', 'file.core.windows.net'],
  },
  {
    id: 'azure-devops-pat',
    regex: /(?:azure_devops_pat|AZURE_DEVOPS_PAT|ADO_PAT)\s*[=:]\s*['"]?([a-z0-9]{52})['"]?/i,
    description: 'Azure DevOps Personal Access Token detected',
    severity: 'critical',
    type: 'azure_devops_pat',
    autoFixable: true,
  },

  // ─── Cloud Providers: DigitalOcean ─────────────────────────────────────────

  {
    id: 'digitalocean-pat',
    regex: /dop_v1_[a-f0-9]{64}/,
    description: 'DigitalOcean Personal Access Token detected',
    severity: 'critical',
    type: 'digitalocean_token',
    autoFixable: true,
  },
  {
    id: 'digitalocean-oauth-token',
    regex: /doo_v1_[a-f0-9]{64}/,
    description: 'DigitalOcean OAuth Token detected',
    severity: 'critical',
    type: 'digitalocean_oauth_token',
    autoFixable: true,
  },
  {
    id: 'digitalocean-refresh-token',
    regex: /dor_v1_[a-f0-9]{64}/,
    description: 'DigitalOcean Refresh Token detected',
    severity: 'critical',
    type: 'digitalocean_refresh_token',
    autoFixable: true,
  },
  {
    id: 'digitalocean-spaces-key',
    regex: /(?:SPACES_ACCESS_KEY_ID|DO_SPACES_KEY)\s*[=:]\s*['"]?([A-Z0-9]{20})['"]?/i,
    description: 'DigitalOcean Spaces Access Key detected',
    severity: 'critical',
    type: 'digitalocean_spaces_key',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Cloud Providers: Heroku ───────────────────────────────────────────────

  {
    id: 'heroku-api-key',
    regex: /(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/i,
    description: 'Heroku API Key detected',
    severity: 'critical',
    type: 'heroku_api_key',
    autoFixable: true,
  },
  {
    id: 'heroku-api-key-direct',
    regex: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/,
    description: 'Heroku API Key (UUID format) detected',
    severity: 'high',
    type: 'heroku_api_key',
    autoFixable: true,
    contextKeywords: ['heroku', 'HEROKU'],
  },

  // ─── Cloud Providers: Cloudflare ───────────────────────────────────────────

  {
    id: 'cloudflare-api-key',
    regex: /(?:CLOUDFLARE_API_KEY|CF_API_KEY|cloudflare_api_key)\s*[=:]\s*['"]?([a-f0-9]{37})['"]?/i,
    description: 'Cloudflare API Key detected',
    severity: 'critical',
    type: 'cloudflare_api_key',
    autoFixable: true,
  },
  {
    id: 'cloudflare-api-token',
    regex: /(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?/i,
    description: 'Cloudflare API Token detected',
    severity: 'critical',
    type: 'cloudflare_api_token',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'cloudflare-origin-ca-key',
    regex: /v1\.0-[a-f0-9]{24}-[a-f0-9]{146}/,
    description: 'Cloudflare Origin CA Key detected',
    severity: 'critical',
    type: 'cloudflare_origin_ca',
    autoFixable: true,
  },

  // ─── Cloud Providers: Vercel ───────────────────────────────────────────────

  {
    id: 'vercel-access-token',
    regex: /(?:VERCEL_TOKEN|vercel_token|VERCEL_ACCESS_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?/i,
    description: 'Vercel Access Token detected',
    severity: 'critical',
    type: 'vercel_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Cloud Providers: Alibaba Cloud ────────────────────────────────────────

  {
    id: 'alibaba-access-key',
    regex: /(?:^|[^0-9A-Z])(LTAI[0-9A-Za-z]{12,20})(?:[^0-9A-Za-z]|$)/,
    description: 'Alibaba Cloud Access Key ID detected',
    severity: 'critical',
    type: 'alibaba_access_key',
    autoFixable: true,
  },

  // ─── Cloud Providers: IBM ──────────────────────────────────────────────────

  {
    id: 'ibm-cloud-api-key',
    regex: /(?:IBM_CLOUD_API_KEY|IBMCLOUD_API_KEY|ibm_api_key)\s*[=:]\s*['"]?([A-Za-z0-9_-]{44})['"]?/i,
    description: 'IBM Cloud API Key detected',
    severity: 'critical',
    type: 'ibm_cloud_api_key',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Payment: Stripe ──────────────────────────────────────────────────────

  {
    id: 'stripe-secret-key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/,
    description: 'Stripe Live Secret Key detected',
    severity: 'critical',
    type: 'stripe_secret_key',
    autoFixable: true,
  },
  {
    id: 'stripe-publishable-key',
    regex: /pk_live_[0-9a-zA-Z]{24,}/,
    description: 'Stripe Live Publishable Key detected',
    severity: 'high',
    type: 'stripe_publishable_key',
    autoFixable: true,
  },
  {
    id: 'stripe-test-secret-key',
    regex: /sk_test_[0-9a-zA-Z]{24,}/,
    description: 'Stripe Test Secret Key detected (still sensitive)',
    severity: 'high',
    type: 'stripe_test_secret_key',
    autoFixable: true,
  },
  {
    id: 'stripe-test-publishable-key',
    regex: /pk_test_[0-9a-zA-Z]{24,}/,
    description: 'Stripe Test Publishable Key detected',
    severity: 'medium',
    type: 'stripe_test_publishable_key',
    autoFixable: true,
  },
  {
    id: 'stripe-webhook-secret',
    regex: /whsec_[0-9a-zA-Z]{32,}/,
    description: 'Stripe Webhook Secret detected',
    severity: 'critical',
    type: 'stripe_webhook_secret',
    autoFixable: true,
  },
  {
    id: 'stripe-restricted-key',
    regex: /rk_live_[0-9a-zA-Z]{24,}/,
    description: 'Stripe Restricted Key detected',
    severity: 'critical',
    type: 'stripe_restricted_key',
    autoFixable: true,
  },

  // ─── Payment: PayPal ──────────────────────────────────────────────────────

  {
    id: 'paypal-client-secret',
    regex: /(?:PAYPAL_CLIENT_SECRET|PAYPAL_SECRET|paypal_client_secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,80})['"]?/i,
    description: 'PayPal Client Secret detected',
    severity: 'critical',
    type: 'paypal_secret',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'paypal-braintree-access-token',
    regex: /access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}/,
    description: 'PayPal/Braintree Access Token detected',
    severity: 'critical',
    type: 'paypal_braintree_token',
    autoFixable: true,
  },

  // ─── Payment: Square ──────────────────────────────────────────────────────

  {
    id: 'square-access-token',
    regex: /sq0atp-[0-9A-Za-z\-_]{22}/,
    description: 'Square Access Token detected',
    severity: 'critical',
    type: 'square_access_token',
    autoFixable: true,
  },
  {
    id: 'square-oauth-secret',
    regex: /sq0csp-[0-9A-Za-z\-_]{43}/,
    description: 'Square OAuth Secret detected',
    severity: 'critical',
    type: 'square_oauth_secret',
    autoFixable: true,
  },

  // ─── Auth & Identity: JWT ──────────────────────────────────────────────────

  {
    id: 'jwt-token',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    description: 'JSON Web Token (JWT) detected',
    severity: 'high',
    type: 'jwt_token',
    autoFixable: true,
  },
  {
    id: 'jwt-secret',
    regex: /(?:JWT_SECRET|jwt_secret|JWT_SIGNING_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+_=-]{16,})['"]?/i,
    description: 'JWT signing secret detected',
    severity: 'critical',
    type: 'jwt_secret',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Auth & Identity: GitHub ───────────────────────────────────────────────

  {
    id: 'github-pat',
    regex: /ghp_[0-9a-zA-Z]{36}/,
    description: 'GitHub Personal Access Token detected',
    severity: 'critical',
    type: 'github_pat',
    autoFixable: true,
  },
  {
    id: 'github-oauth-token',
    regex: /gho_[0-9a-zA-Z]{36}/,
    description: 'GitHub OAuth Access Token detected',
    severity: 'critical',
    type: 'github_oauth_token',
    autoFixable: true,
  },
  {
    id: 'github-app-token',
    regex: /ghs_[0-9a-zA-Z]{36}/,
    description: 'GitHub App Installation Token detected',
    severity: 'critical',
    type: 'github_app_token',
    autoFixable: true,
  },
  {
    id: 'github-refresh-token',
    regex: /ghr_[0-9a-zA-Z]{36}/,
    description: 'GitHub Refresh Token detected',
    severity: 'critical',
    type: 'github_refresh_token',
    autoFixable: true,
  },
  {
    id: 'github-fine-grained-pat',
    regex: /github_pat_[0-9a-zA-Z_]{82}/,
    description: 'GitHub Fine-Grained Personal Access Token detected',
    severity: 'critical',
    type: 'github_fine_grained_pat',
    autoFixable: true,
  },

  // ─── Auth & Identity: GitLab ───────────────────────────────────────────────

  {
    id: 'gitlab-pat',
    regex: /glpat-[0-9a-zA-Z\-_]{20,}/,
    description: 'GitLab Personal Access Token detected',
    severity: 'critical',
    type: 'gitlab_pat',
    autoFixable: true,
  },
  {
    id: 'gitlab-pipeline-trigger',
    regex: /glptt-[0-9a-zA-Z\-_]{20,}/,
    description: 'GitLab Pipeline Trigger Token detected',
    severity: 'high',
    type: 'gitlab_pipeline_token',
    autoFixable: true,
  },
  {
    id: 'gitlab-runner-token',
    regex: /glrt-[0-9a-zA-Z\-_]{20,}/,
    description: 'GitLab Runner Registration Token detected',
    severity: 'critical',
    type: 'gitlab_runner_token',
    autoFixable: true,
  },

  // ─── Auth & Identity: Slack ────────────────────────────────────────────────

  {
    id: 'slack-bot-token',
    regex: /xoxb-[0-9]{10,}-[0-9a-zA-Z]{24,}/,
    description: 'Slack Bot Token detected',
    severity: 'critical',
    type: 'slack_bot_token',
    autoFixable: true,
  },
  {
    id: 'slack-user-token',
    regex: /xoxp-[0-9]{10,}-[0-9]{10,}-[0-9a-zA-Z]{24,}/,
    description: 'Slack User Token detected',
    severity: 'critical',
    type: 'slack_user_token',
    autoFixable: true,
  },
  {
    id: 'slack-app-token',
    regex: /xapp-[0-9]-[A-Za-z0-9]{10,}-[0-9]{10,}-[a-f0-9]{64}/,
    description: 'Slack App-Level Token detected',
    severity: 'critical',
    type: 'slack_app_token',
    autoFixable: true,
  },
  {
    id: 'slack-webhook-url',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24,}/,
    description: 'Slack Incoming Webhook URL detected',
    severity: 'high',
    type: 'slack_webhook',
    autoFixable: true,
  },
  {
    id: 'slack-config-token',
    regex: /xoxe\.xoxp-[0-9]-[A-Za-z0-9]{146,}/,
    description: 'Slack Configuration Token detected',
    severity: 'critical',
    type: 'slack_config_token',
    autoFixable: true,
  },

  // ─── Auth & Identity: Discord ──────────────────────────────────────────────

  {
    id: 'discord-bot-token',
    regex: /(?:DISCORD_TOKEN|DISCORD_BOT_TOKEN|discord_token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})['"]?/i,
    description: 'Discord Bot Token detected',
    severity: 'critical',
    type: 'discord_bot_token',
    autoFixable: true,
  },
  {
    id: 'discord-webhook-url',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/,
    description: 'Discord Webhook URL detected',
    severity: 'high',
    type: 'discord_webhook',
    autoFixable: true,
  },

  // ─── Auth & Identity: Auth0 ────────────────────────────────────────────────

  {
    id: 'auth0-client-secret',
    regex: /(?:AUTH0_CLIENT_SECRET|auth0_client_secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{32,})['"]?/i,
    description: 'Auth0 Client Secret detected',
    severity: 'critical',
    type: 'auth0_client_secret',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'auth0-management-api-token',
    regex: /(?:AUTH0_MANAGEMENT_API_TOKEN|AUTH0_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{30,})['"]?/i,
    description: 'Auth0 Management API Token detected',
    severity: 'critical',
    type: 'auth0_mgmt_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Auth & Identity: Firebase ─────────────────────────────────────────────

  {
    id: 'firebase-api-key',
    regex: /(?:FIREBASE_API_KEY|NEXT_PUBLIC_FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY|firebase_api_key)\s*[=:]\s*['"]?(AIza[0-9A-Za-z\-_]{35})['"]?/i,
    description: 'Firebase API Key detected',
    severity: 'high',
    type: 'firebase_api_key',
    autoFixable: true,
  },
  {
    id: 'firebase-admin-sdk-json',
    regex: /"type"\s*:\s*"service_account"[^}]*"private_key"\s*:/,
    description: 'Firebase Admin SDK service account JSON detected',
    severity: 'critical',
    type: 'firebase_service_account',
    autoFixable: true,
  },

  // ─── Auth & Identity: Supabase ─────────────────────────────────────────────

  {
    id: 'supabase-anon-key',
    regex: /(?:SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY|SUPABASE_KEY)\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]{100,})['"]?/i,
    description: 'Supabase anon/public key detected',
    severity: 'medium',
    type: 'supabase_anon_key',
    autoFixable: true,
  },
  {
    id: 'supabase-service-role-key',
    regex: /(?:SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY)\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_-]{100,})['"]?/i,
    description: 'Supabase service role key detected (admin access!)',
    severity: 'critical',
    type: 'supabase_service_key',
    autoFixable: true,
  },

  // ─── Auth & Identity: Clerk ────────────────────────────────────────────────

  {
    id: 'clerk-secret-key',
    regex: /sk_live_[A-Za-z0-9]{40,}/,
    description: 'Clerk Secret Key detected',
    severity: 'critical',
    type: 'clerk_secret_key',
    autoFixable: true,
  },
  {
    id: 'clerk-publishable-key',
    regex: /pk_live_[A-Za-z0-9]{40,}/,
    description: 'Clerk Publishable Key detected',
    severity: 'medium',
    type: 'clerk_publishable_key',
    autoFixable: true,
  },

  // ─── Auth & Identity: OAuth generic ────────────────────────────────────────

  {
    id: 'generic-oauth-client-secret',
    regex: /(?:OAUTH_CLIENT_SECRET|oauth_client_secret|CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9_-]{20,})['"]?/i,
    description: 'OAuth Client Secret detected',
    severity: 'high',
    type: 'oauth_client_secret',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },

  // ─── Auth & Identity: Okta ─────────────────────────────────────────────────

  {
    id: 'okta-api-token',
    regex: /(?:OKTA_API_TOKEN|OKTA_TOKEN|okta_token)\s*[=:]\s*['"]?([0-9a-zA-Z_-]{42})['"]?/i,
    description: 'Okta API Token detected',
    severity: 'critical',
    type: 'okta_api_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Databases ─────────────────────────────────────────────────────────────

  {
    id: 'postgres-connection-string',
    regex: /postgres(?:ql)?:\/\/[^:]+:[^@]{3,}@[^/\s]+\/[^\s'"]+/i,
    description: 'PostgreSQL connection string with credentials detected',
    severity: 'critical',
    type: 'database_url',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'mysql-connection-string',
    regex: /mysql:\/\/[^:]+:[^@]{3,}@[^/\s]+\/[^\s'"]+/i,
    description: 'MySQL connection string with credentials detected',
    severity: 'critical',
    type: 'database_url',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'mongodb-connection-string',
    regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]{3,}@[^\s'"]+/i,
    description: 'MongoDB connection string with credentials detected',
    severity: 'critical',
    type: 'database_url',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'redis-connection-string',
    regex: /redis(?:s)?:\/\/[^:]*:[^@]{3,}@[^\s'"]+/i,
    description: 'Redis connection string with credentials detected',
    severity: 'critical',
    type: 'database_url',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'database-url-generic',
    regex: /(?:DATABASE_URL|DB_URL|DATABASE_CONNECTION)\s*[=:]\s*['"]?(\w+:\/\/[^:]+:[^@]{3,}@[^\s'"]+)['"]?/i,
    description: 'Database connection URL with credentials detected',
    severity: 'critical',
    type: 'database_url',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'database-password',
    regex: /(?:DB_PASSWORD|DATABASE_PASSWORD|DB_PASS|MYSQL_PASSWORD|POSTGRES_PASSWORD|PGPASSWORD|MONGO_PASSWORD)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?/i,
    description: 'Database password detected',
    severity: 'critical',
    type: 'database_password',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Communication: Twilio ─────────────────────────────────────────────────

  {
    id: 'twilio-account-sid',
    regex: /AC[0-9a-f]{32}/,
    description: 'Twilio Account SID detected',
    severity: 'high',
    type: 'twilio_account_sid',
    autoFixable: true,
  },
  {
    id: 'twilio-auth-token',
    regex: /(?:TWILIO_AUTH_TOKEN|twilio_auth_token)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i,
    description: 'Twilio Auth Token detected',
    severity: 'critical',
    type: 'twilio_auth_token',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'twilio-api-key',
    regex: /SK[0-9a-f]{32}/,
    description: 'Twilio API Key detected',
    severity: 'critical',
    type: 'twilio_api_key',
    autoFixable: true,
    contextKeywords: ['twilio', 'TWILIO'],
  },

  // ─── Communication: SendGrid ───────────────────────────────────────────────

  {
    id: 'sendgrid-api-key',
    regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/,
    description: 'SendGrid API Key detected',
    severity: 'critical',
    type: 'sendgrid_api_key',
    autoFixable: true,
  },

  // ─── Communication: Mailgun ────────────────────────────────────────────────

  {
    id: 'mailgun-api-key',
    regex: /key-[0-9a-f]{32}/,
    description: 'Mailgun API Key detected',
    severity: 'critical',
    type: 'mailgun_api_key',
    autoFixable: true,
    contextKeywords: ['mailgun', 'MAILGUN'],
  },
  {
    id: 'mailgun-api-key-env',
    regex: /(?:MAILGUN_API_KEY|mailgun_api_key)\s*[=:]\s*['"]?(key-[0-9a-f]{32})['"]?/i,
    description: 'Mailgun API Key in env variable detected',
    severity: 'critical',
    type: 'mailgun_api_key',
    autoFixable: true,
  },

  // ─── Communication: Postmark ───────────────────────────────────────────────

  {
    id: 'postmark-server-token',
    regex: /(?:POSTMARK_SERVER_TOKEN|POSTMARK_API_TOKEN|postmark_token)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/i,
    description: 'Postmark Server Token detected',
    severity: 'critical',
    type: 'postmark_token',
    autoFixable: true,
  },

  // ─── Communication: Messagebird ────────────────────────────────────────────

  {
    id: 'messagebird-api-key',
    regex: /(?:MESSAGEBIRD_API_KEY|messagebird_api_key)\s*[=:]\s*['"]?([a-zA-Z0-9]{25})['"]?/i,
    description: 'MessageBird API Key detected',
    severity: 'critical',
    type: 'messagebird_api_key',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Infrastructure: SSH / PGP ─────────────────────────────────────────────

  {
    id: 'ssh-rsa-private-key',
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    description: 'SSH RSA Private Key detected',
    severity: 'critical',
    type: 'ssh_private_key',
    autoFixable: false,
  },
  {
    id: 'ssh-dsa-private-key',
    regex: /-----BEGIN DSA PRIVATE KEY-----/,
    description: 'SSH DSA Private Key detected',
    severity: 'critical',
    type: 'ssh_private_key',
    autoFixable: false,
  },
  {
    id: 'ssh-ec-private-key',
    regex: /-----BEGIN EC PRIVATE KEY-----/,
    description: 'SSH EC Private Key detected',
    severity: 'critical',
    type: 'ssh_private_key',
    autoFixable: false,
  },
  {
    id: 'ssh-openssh-private-key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    description: 'OpenSSH Private Key detected',
    severity: 'critical',
    type: 'ssh_private_key',
    autoFixable: false,
  },
  {
    id: 'generic-private-key',
    regex: /-----BEGIN PRIVATE KEY-----/,
    description: 'Private Key (PKCS#8) detected',
    severity: 'critical',
    type: 'private_key',
    autoFixable: false,
  },
  {
    id: 'encrypted-private-key',
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
    description: 'Encrypted Private Key detected',
    severity: 'high',
    type: 'encrypted_private_key',
    autoFixable: false,
  },
  {
    id: 'pgp-private-key',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    description: 'PGP Private Key Block detected',
    severity: 'critical',
    type: 'pgp_private_key',
    autoFixable: false,
  },
  {
    id: 'x509-certificate-private-key',
    regex: /-----BEGIN CERTIFICATE-----/,
    description: 'X.509 Certificate detected (may contain private material)',
    severity: 'medium',
    type: 'x509_certificate',
    autoFixable: false,
  },

  // ─── Infrastructure: Docker ────────────────────────────────────────────────

  {
    id: 'docker-registry-password',
    regex: /(?:DOCKER_PASSWORD|DOCKER_REGISTRY_PASSWORD|DOCKER_AUTH)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?/i,
    description: 'Docker Registry Password detected',
    severity: 'critical',
    type: 'docker_password',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'docker-config-auth',
    regex: /"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"/,
    description: 'Docker config.json auth token detected',
    severity: 'critical',
    type: 'docker_auth_token',
    autoFixable: true,
    contextKeywords: ['docker', '.docker', 'registry'],
  },

  // ─── Infrastructure: npm ───────────────────────────────────────────────────

  {
    id: 'npm-token',
    regex: /npm_[0-9a-zA-Z]{36}/,
    description: 'npm Access Token detected',
    severity: 'critical',
    type: 'npm_token',
    autoFixable: true,
  },
  {
    id: 'npm-token-legacy',
    regex: /\/\/registry\.npmjs\.org\/:_authToken=[0-9a-f-]{36,}/,
    description: 'npm legacy auth token in .npmrc detected',
    severity: 'critical',
    type: 'npm_token',
    autoFixable: true,
  },

  // ─── Infrastructure: PyPI ──────────────────────────────────────────────────

  {
    id: 'pypi-token',
    regex: /pypi-[0-9a-zA-Z_-]{50,}/,
    description: 'PyPI API Token detected',
    severity: 'critical',
    type: 'pypi_token',
    autoFixable: true,
  },

  // ─── Infrastructure: NuGet ─────────────────────────────────────────────────

  {
    id: 'nuget-api-key',
    regex: /oy2[A-Za-z0-9]{43}/,
    description: 'NuGet API Key detected',
    severity: 'critical',
    type: 'nuget_api_key',
    autoFixable: true,
  },

  // ─── Infrastructure: RubyGems ──────────────────────────────────────────────

  {
    id: 'rubygems-api-key',
    regex: /rubygems_[0-9a-f]{48}/,
    description: 'RubyGems API Key detected',
    severity: 'critical',
    type: 'rubygems_api_key',
    autoFixable: true,
  },

  // ─── Infrastructure: Terraform ─────────────────────────────────────────────

  {
    id: 'terraform-cloud-token',
    regex: /(?:TFE_TOKEN|TF_API_TOKEN|TERRAFORM_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9.]{14,})['"]?/i,
    description: 'Terraform Cloud/Enterprise Token detected',
    severity: 'critical',
    type: 'terraform_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Infrastructure: Vault ─────────────────────────────────────────────────

  {
    id: 'hashicorp-vault-token',
    regex: /(?:VAULT_TOKEN|vault_token)\s*[=:]\s*['"]?(hvs\.[A-Za-z0-9_-]{24,})['"]?/i,
    description: 'HashiCorp Vault Token detected',
    severity: 'critical',
    type: 'vault_token',
    autoFixable: true,
  },
  {
    id: 'hashicorp-vault-token-direct',
    regex: /hvs\.[A-Za-z0-9_-]{24,}/,
    description: 'HashiCorp Vault Token detected',
    severity: 'critical',
    type: 'vault_token',
    autoFixable: true,
  },

  // ─── CI/CD: CircleCI ──────────────────────────────────────────────────────

  {
    id: 'circleci-token',
    regex: /(?:CIRCLECI_TOKEN|CIRCLE_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?/i,
    description: 'CircleCI Token detected',
    severity: 'critical',
    type: 'circleci_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── CI/CD: Travis CI ─────────────────────────────────────────────────────

  {
    id: 'travis-ci-token',
    regex: /(?:TRAVIS_TOKEN|TRAVIS_API_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{22,})['"]?/i,
    description: 'Travis CI Token detected',
    severity: 'critical',
    type: 'travis_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Monitoring: Datadog ───────────────────────────────────────────────────

  {
    id: 'datadog-api-key',
    regex: /(?:DD_API_KEY|DATADOG_API_KEY|datadog_api_key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i,
    description: 'Datadog API Key detected',
    severity: 'critical',
    type: 'datadog_api_key',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'datadog-app-key',
    regex: /(?:DD_APP_KEY|DATADOG_APP_KEY|datadog_app_key)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?/i,
    description: 'Datadog Application Key detected',
    severity: 'critical',
    type: 'datadog_app_key',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Monitoring: New Relic ─────────────────────────────────────────────────

  {
    id: 'newrelic-license-key',
    regex: /(?:NEW_RELIC_LICENSE_KEY|NEWRELIC_LICENSE_KEY|newrelic_key)\s*[=:]\s*['"]?([a-f0-9]{40})['"]?/i,
    description: 'New Relic License Key detected',
    severity: 'high',
    type: 'newrelic_license_key',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'newrelic-api-key',
    regex: /NRAK-[A-Z0-9]{27}/,
    description: 'New Relic API Key detected',
    severity: 'critical',
    type: 'newrelic_api_key',
    autoFixable: true,
  },

  // ─── Monitoring: Sentry ────────────────────────────────────────────────────

  {
    id: 'sentry-dsn',
    regex: /https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io\/\d+/,
    description: 'Sentry DSN detected',
    severity: 'medium',
    type: 'sentry_dsn',
    autoFixable: true,
  },
  {
    id: 'sentry-auth-token',
    regex: /(?:SENTRY_AUTH_TOKEN|sentry_auth_token)\s*[=:]\s*['"]?([a-f0-9]{64})['"]?/i,
    description: 'Sentry Auth Token detected',
    severity: 'critical',
    type: 'sentry_auth_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Analytics: Segment ────────────────────────────────────────────────────

  {
    id: 'segment-write-key',
    regex: /(?:SEGMENT_WRITE_KEY|segment_write_key)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?/i,
    description: 'Segment Write Key detected',
    severity: 'high',
    type: 'segment_write_key',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Analytics: Mixpanel ───────────────────────────────────────────────────

  {
    id: 'mixpanel-token',
    regex: /(?:MIXPANEL_TOKEN|MIXPANEL_PROJECT_TOKEN|mixpanel_token)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i,
    description: 'Mixpanel Project Token detected',
    severity: 'medium',
    type: 'mixpanel_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Messaging: Telegram ───────────────────────────────────────────────────

  {
    id: 'telegram-bot-token',
    regex: /\d{8,10}:[A-Za-z0-9_-]{35}/,
    description: 'Telegram Bot Token detected',
    severity: 'critical',
    type: 'telegram_bot_token',
    autoFixable: true,
    contextKeywords: ['telegram', 'TELEGRAM', 'bot', 'BOT_TOKEN'],
  },

  // ─── Social: Twitter ──────────────────────────────────────────────────────

  {
    id: 'twitter-api-key',
    regex: /(?:TWITTER_API_KEY|TWITTER_CONSUMER_KEY|twitter_api_key)\s*[=:]\s*['"]?([A-Za-z0-9]{25})['"]?/i,
    description: 'Twitter/X API Key detected',
    severity: 'critical',
    type: 'twitter_api_key',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'twitter-bearer-token',
    regex: /(?:TWITTER_BEARER_TOKEN|twitter_bearer)\s*[=:]\s*['"]?(AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+)['"]?/i,
    description: 'Twitter/X Bearer Token detected',
    severity: 'critical',
    type: 'twitter_bearer_token',
    autoFixable: true,
  },

  // ─── Social: Facebook ─────────────────────────────────────────────────────

  {
    id: 'facebook-access-token',
    regex: /EAA[A-Za-z0-9]{100,}/,
    description: 'Facebook Access Token detected',
    severity: 'critical',
    type: 'facebook_access_token',
    autoFixable: true,
  },
  {
    id: 'facebook-app-secret',
    regex: /(?:FACEBOOK_APP_SECRET|FB_APP_SECRET|facebook_secret)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i,
    description: 'Facebook App Secret detected',
    severity: 'critical',
    type: 'facebook_app_secret',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Maps / Location ──────────────────────────────────────────────────────

  {
    id: 'mapbox-access-token',
    regex: /(?:pk|sk)\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/,
    description: 'Mapbox Access Token detected',
    severity: 'high',
    type: 'mapbox_token',
    autoFixable: true,
  },

  // ─── E-commerce: Shopify ───────────────────────────────────────────────────

  {
    id: 'shopify-private-app-password',
    regex: /shppa_[a-f0-9]{32}/,
    description: 'Shopify Private App Password detected',
    severity: 'critical',
    type: 'shopify_private_app',
    autoFixable: true,
  },
  {
    id: 'shopify-access-token',
    regex: /shpat_[a-f0-9]{32}/,
    description: 'Shopify Admin Access Token detected',
    severity: 'critical',
    type: 'shopify_access_token',
    autoFixable: true,
  },
  {
    id: 'shopify-shared-secret',
    regex: /shpss_[a-f0-9]{32}/,
    description: 'Shopify Shared Secret detected',
    severity: 'critical',
    type: 'shopify_shared_secret',
    autoFixable: true,
  },
  {
    id: 'shopify-custom-app-token',
    regex: /shpca_[a-f0-9]{32}/,
    description: 'Shopify Custom App Access Token detected',
    severity: 'critical',
    type: 'shopify_custom_app',
    autoFixable: true,
  },

  // ─── Atlassian: Jira / Confluence ──────────────────────────────────────────

  {
    id: 'atlassian-api-token',
    regex: /(?:ATLASSIAN_API_TOKEN|JIRA_API_TOKEN|CONFLUENCE_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9]{24,})['"]?/i,
    description: 'Atlassian API Token detected',
    severity: 'critical',
    type: 'atlassian_api_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Bitbucket ─────────────────────────────────────────────────────────────

  {
    id: 'bitbucket-app-password',
    regex: /(?:BITBUCKET_APP_PASSWORD|BITBUCKET_PASSWORD)\s*[=:]\s*['"]?([A-Za-z0-9]{18,})['"]?/i,
    description: 'Bitbucket App Password detected',
    severity: 'critical',
    type: 'bitbucket_app_password',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Snyk ──────────────────────────────────────────────────────────────────

  {
    id: 'snyk-api-token',
    regex: /(?:SNYK_TOKEN|SNYK_API_TOKEN)\s*[=:]\s*['"]?([a-f0-9-]{36,})['"]?/i,
    description: 'Snyk API Token detected',
    severity: 'critical',
    type: 'snyk_api_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── OpenAI / AI Providers ─────────────────────────────────────────────────

  {
    id: 'openai-api-key',
    regex: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/,
    description: 'OpenAI API Key detected',
    severity: 'critical',
    type: 'openai_api_key',
    autoFixable: true,
  },
  {
    id: 'openai-api-key-v2',
    regex: /sk-proj-[A-Za-z0-9_-]{40,}/,
    description: 'OpenAI Project API Key detected',
    severity: 'critical',
    type: 'openai_api_key',
    autoFixable: true,
  },
  {
    id: 'openai-api-key-env',
    regex: /(?:OPENAI_API_KEY|openai_api_key)\s*[=:]\s*['"]?(sk-[A-Za-z0-9_-]{20,})['"]?/i,
    description: 'OpenAI API Key in environment variable detected',
    severity: 'critical',
    type: 'openai_api_key',
    autoFixable: true,
  },
  {
    id: 'anthropic-api-key',
    regex: /sk-ant-[A-Za-z0-9_-]{90,}/,
    description: 'Anthropic API Key detected',
    severity: 'critical',
    type: 'anthropic_api_key',
    autoFixable: true,
  },
  {
    id: 'anthropic-api-key-env',
    regex: /(?:ANTHROPIC_API_KEY|anthropic_api_key)\s*[=:]\s*['"]?(sk-ant-[A-Za-z0-9_-]{20,})['"]?/i,
    description: 'Anthropic API Key in environment variable detected',
    severity: 'critical',
    type: 'anthropic_api_key',
    autoFixable: true,
  },
  {
    id: 'cohere-api-key',
    regex: /(?:COHERE_API_KEY|cohere_api_key|CO_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?/i,
    description: 'Cohere API Key detected',
    severity: 'critical',
    type: 'cohere_api_key',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'huggingface-token',
    regex: /hf_[A-Za-z0-9]{34}/,
    description: 'Hugging Face Access Token detected',
    severity: 'critical',
    type: 'huggingface_token',
    autoFixable: true,
  },
  {
    id: 'replicate-api-token',
    regex: /r8_[A-Za-z0-9]{38}/,
    description: 'Replicate API Token detected',
    severity: 'critical',
    type: 'replicate_api_token',
    autoFixable: true,
  },

  // ─── Encryption / Signing ──────────────────────────────────────────────────

  {
    id: 'encryption-key',
    regex: /(?:ENCRYPTION_KEY|ENCRYPT_KEY|encryption_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{32,})['"]?/i,
    description: 'Encryption key detected',
    severity: 'critical',
    type: 'encryption_key',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.5,
  },
  {
    id: 'signing-secret',
    regex: /(?:SIGNING_SECRET|signing_secret|WEBHOOK_SECRET|HMAC_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9/+=_-]{16,})['"]?/i,
    description: 'Signing secret detected',
    severity: 'critical',
    type: 'signing_secret',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },

  // ─── Session / Cookie Secrets ──────────────────────────────────────────────

  {
    id: 'session-secret',
    regex: /(?:SESSION_SECRET|session_secret|COOKIE_SECRET|cookie_secret|EXPRESS_SESSION_SECRET)\s*[=:]\s*['"]?([^\s'"]{16,})['"]?/i,
    description: 'Session/cookie secret detected',
    severity: 'high',
    type: 'session_secret',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },

  // ─── Plaid ─────────────────────────────────────────────────────────────────

  {
    id: 'plaid-client-id',
    regex: /(?:PLAID_CLIENT_ID|plaid_client_id)\s*[=:]\s*['"]?([a-f0-9]{24})['"]?/i,
    description: 'Plaid Client ID detected',
    severity: 'high',
    type: 'plaid_client_id',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'plaid-secret',
    regex: /(?:PLAID_SECRET|plaid_secret)\s*[=:]\s*['"]?([a-f0-9]{30})['"]?/i,
    description: 'Plaid Secret detected',
    severity: 'critical',
    type: 'plaid_secret',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Airtable ──────────────────────────────────────────────────────────────

  {
    id: 'airtable-api-key',
    regex: /(?:AIRTABLE_API_KEY|airtable_api_key)\s*[=:]\s*['"]?(key[A-Za-z0-9]{14})['"]?/i,
    description: 'Airtable API Key detected',
    severity: 'critical',
    type: 'airtable_api_key',
    autoFixable: true,
  },
  {
    id: 'airtable-pat',
    regex: /pat[A-Za-z0-9]{14}\.[a-f0-9]{64}/,
    description: 'Airtable Personal Access Token detected',
    severity: 'critical',
    type: 'airtable_pat',
    autoFixable: true,
  },

  // ─── Algolia ───────────────────────────────────────────────────────────────

  {
    id: 'algolia-admin-api-key',
    regex: /(?:ALGOLIA_ADMIN_API_KEY|ALGOLIA_API_KEY|algolia_admin_key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i,
    description: 'Algolia Admin API Key detected',
    severity: 'critical',
    type: 'algolia_api_key',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Zendesk ───────────────────────────────────────────────────────────────

  {
    id: 'zendesk-api-token',
    regex: /(?:ZENDESK_API_TOKEN|zendesk_token)\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?/i,
    description: 'Zendesk API Token detected',
    severity: 'critical',
    type: 'zendesk_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Intercom ──────────────────────────────────────────────────────────────

  {
    id: 'intercom-access-token',
    regex: /(?:INTERCOM_ACCESS_TOKEN|intercom_token)\s*[=:]\s*['"]?([A-Za-z0-9=]{40,})['"]?/i,
    description: 'Intercom Access Token detected',
    severity: 'critical',
    type: 'intercom_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── LaunchDarkly ──────────────────────────────────────────────────────────

  {
    id: 'launchdarkly-sdk-key',
    regex: /sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/,
    description: 'LaunchDarkly SDK Key detected',
    severity: 'high',
    type: 'launchdarkly_sdk_key',
    autoFixable: true,
  },

  // ─── Doppler ───────────────────────────────────────────────────────────────

  {
    id: 'doppler-token',
    regex: /dp\.st\.[a-z0-9_-]{40,}/,
    description: 'Doppler Service Token detected',
    severity: 'critical',
    type: 'doppler_token',
    autoFixable: true,
  },

  // ─── Linear ────────────────────────────────────────────────────────────────

  {
    id: 'linear-api-key',
    regex: /lin_api_[A-Za-z0-9]{40}/,
    description: 'Linear API Key detected',
    severity: 'critical',
    type: 'linear_api_key',
    autoFixable: true,
  },

  // ─── Notion ────────────────────────────────────────────────────────────────

  {
    id: 'notion-integration-token',
    regex: /(?:secret_|ntn_)[A-Za-z0-9]{43}/,
    description: 'Notion Integration Token detected',
    severity: 'critical',
    type: 'notion_token',
    autoFixable: true,
    contextKeywords: ['notion', 'NOTION'],
  },

  // ─── Figma ─────────────────────────────────────────────────────────────────

  {
    id: 'figma-pat',
    regex: /figd_[A-Za-z0-9_-]{40,}/,
    description: 'Figma Personal Access Token detected',
    severity: 'critical',
    type: 'figma_pat',
    autoFixable: true,
  },

  // ─── Fly.io ────────────────────────────────────────────────────────────────

  {
    id: 'flyio-access-token',
    regex: /FlyV1\s+fm[12]_[A-Za-z0-9_]+/,
    description: 'Fly.io Access Token detected',
    severity: 'critical',
    type: 'flyio_token',
    autoFixable: true,
  },

  // ─── Netlify ───────────────────────────────────────────────────────────────

  {
    id: 'netlify-access-token',
    regex: /(?:NETLIFY_AUTH_TOKEN|NETLIFY_TOKEN|netlify_token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?/i,
    description: 'Netlify Access Token detected',
    severity: 'critical',
    type: 'netlify_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Supabase / PostgREST ──────────────────────────────────────────────────

  {
    id: 'supabase-url-with-key',
    regex: /https:\/\/[a-z0-9]+\.supabase\.co\/rest\/v1\/[^\s]*\?apikey=[A-Za-z0-9._-]+/,
    description: 'Supabase REST URL with API key detected',
    severity: 'high',
    type: 'supabase_url_with_key',
    autoFixable: true,
  },

  // ─── Generic: Password assignments ─────────────────────────────────────────

  {
    id: 'password-assignment-double-quote',
    regex: /(?:password|passwd|pwd|pass)\s*[=:]\s*"([^"]{8,})"/i,
    description: 'Hardcoded password in double-quoted string detected',
    severity: 'high',
    type: 'hardcoded_password',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 2.5,
  },
  {
    id: 'password-assignment-single-quote',
    regex: /(?:password|passwd|pwd|pass)\s*[=:]\s*'([^']{8,})'/i,
    description: 'Hardcoded password in single-quoted string detected',
    severity: 'high',
    type: 'hardcoded_password',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 2.5,
  },
  {
    id: 'secret-assignment-double-quote',
    regex: /(?:secret|SECRET)\s*[=:]\s*"([^"]{8,})"/,
    description: 'Hardcoded secret in double-quoted string detected',
    severity: 'high',
    type: 'hardcoded_secret',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },
  {
    id: 'secret-assignment-single-quote',
    regex: /(?:secret|SECRET)\s*[=:]\s*'([^']{8,})'/,
    description: 'Hardcoded secret in single-quoted string detected',
    severity: 'high',
    type: 'hardcoded_secret',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },

  // ─── Generic: API key assignments ──────────────────────────────────────────

  {
    id: 'api-key-assignment-double-quote',
    regex: /(?:api_key|apikey|api-key|API_KEY|APIKEY)\s*[=:]\s*"([^"]{16,})"/i,
    description: 'Hardcoded API key in double-quoted string detected',
    severity: 'high',
    type: 'hardcoded_api_key',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },
  {
    id: 'api-key-assignment-single-quote',
    regex: /(?:api_key|apikey|api-key|API_KEY|APIKEY)\s*[=:]\s*'([^']{16,})'/i,
    description: 'Hardcoded API key in single-quoted string detected',
    severity: 'high',
    type: 'hardcoded_api_key',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },
  {
    id: 'access-token-assignment-double-quote',
    regex: /(?:access_token|ACCESS_TOKEN|accessToken)\s*[=:]\s*"([^"]{16,})"/i,
    description: 'Hardcoded access token in double-quoted string detected',
    severity: 'high',
    type: 'hardcoded_access_token',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },
  {
    id: 'access-token-assignment-single-quote',
    regex: /(?:access_token|ACCESS_TOKEN|accessToken)\s*[=:]\s*'([^']{16,})'/i,
    description: 'Hardcoded access token in single-quoted string detected',
    severity: 'high',
    type: 'hardcoded_access_token',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },
  {
    id: 'secret-key-assignment-double-quote',
    regex: /(?:secret_key|SECRET_KEY|secretKey)\s*[=:]\s*"([^"]{16,})"/i,
    description: 'Hardcoded secret key in double-quoted string detected',
    severity: 'high',
    type: 'hardcoded_secret_key',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },
  {
    id: 'secret-key-assignment-single-quote',
    regex: /(?:secret_key|SECRET_KEY|secretKey)\s*[=:]\s*'([^']{16,})'/i,
    description: 'Hardcoded secret key in single-quoted string detected',
    severity: 'high',
    type: 'hardcoded_secret_key',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },
  {
    id: 'private-key-assignment',
    regex: /(?:private_key|PRIVATE_KEY|privateKey)\s*[=:]\s*['"]([^'"]{16,})['"]/i,
    description: 'Hardcoded private key value detected',
    severity: 'critical',
    type: 'hardcoded_private_key',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.5,
  },
  {
    id: 'auth-token-assignment',
    regex: /(?:auth_token|AUTH_TOKEN|authToken|authorization_token)\s*[=:]\s*['"]([^'"]{16,})['"]/i,
    description: 'Hardcoded auth token detected',
    severity: 'high',
    type: 'hardcoded_auth_token',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },

  // ─── Generic: Bearer tokens ────────────────────────────────────────────────

  {
    id: 'bearer-token-in-string',
    regex: /['"]Bearer\s+([A-Za-z0-9_-]{20,})['"]/,
    description: 'Hardcoded Bearer token in string detected',
    severity: 'high',
    type: 'bearer_token',
    autoFixable: true,
    entropyCheck: true,
    entropyThreshold: 3.5,
  },
  {
    id: 'basic-auth-in-string',
    regex: /['"]Basic\s+([A-Za-z0-9+/=]{20,})['"]/,
    description: 'Hardcoded Basic Auth credential in string detected',
    severity: 'high',
    type: 'basic_auth',
    autoFixable: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },

  // ─── Generic: Authorization headers ────────────────────────────────────────

  {
    id: 'authorization-header-bearer',
    regex: /[Aa]uthorization['":\s]+['"]?Bearer\s+([A-Za-z0-9._~+/=-]{20,})/,
    description: 'Authorization header with Bearer token detected',
    severity: 'high',
    type: 'authorization_header',
    autoFixable: true,
    entropyCheck: true,
    entropyThreshold: 3.5,
  },

  // ─── Generic: High-entropy base64 strings with context ─────────────────────

  {
    id: 'high-entropy-base64-with-key-context',
    regex: /(?:key|token|secret|credential|auth)\s*[=:]\s*['"]([A-Za-z0-9+/]{40,}={0,2})['"]/i,
    description: 'High-entropy base64 string in secret context detected',
    severity: 'medium',
    type: 'high_entropy_secret',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 4.0,
  },

  // ─── .env file patterns ────────────────────────────────────────────────────

  {
    id: 'env-file-generic-secret',
    regex: /^[A-Z_]*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*\s*=\s*['"]?([^\s'"#]{12,})['"]?\s*(?:#.*)?$/i,
    description: 'Secret value in .env file detected',
    severity: 'high',
    type: 'env_file_secret',
    autoFixable: true,
    skipPlaceholders: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
    contextKeywords: ['.env'],
  },

  // ─── Webhook URLs ──────────────────────────────────────────────────────────

  {
    id: 'generic-webhook-url',
    regex: /https?:\/\/[^\s'"]*\/webhook[s]?\/[A-Za-z0-9_-]{20,}/i,
    description: 'Webhook URL with token detected',
    severity: 'medium',
    type: 'webhook_url',
    autoFixable: true,
    entropyCheck: true,
    entropyThreshold: 3.0,
  },

  // ─── Connection strings with inline creds ──────────────────────────────────

  {
    id: 'jdbc-connection-string',
    regex: /jdbc:[a-z]+:\/\/[^:]+:[^@]{3,}@[^\s'"]+/i,
    description: 'JDBC connection string with credentials detected',
    severity: 'critical',
    type: 'database_url',
    autoFixable: true,
    skipPlaceholders: true,
  },
  {
    id: 'amqp-connection-string',
    regex: /amqps?:\/\/[^:]+:[^@]{3,}@[^\s'"]+/i,
    description: 'AMQP connection string with credentials detected',
    severity: 'critical',
    type: 'amqp_connection_string',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Grafana ───────────────────────────────────────────────────────────────

  {
    id: 'grafana-api-key',
    regex: /eyJrIjoi[A-Za-z0-9_-]{30,}/,
    description: 'Grafana API Key / Service Account Token detected',
    severity: 'critical',
    type: 'grafana_api_key',
    autoFixable: true,
  },

  // ─── Contentful ────────────────────────────────────────────────────────────

  {
    id: 'contentful-delivery-token',
    regex: /(?:CONTENTFUL_ACCESS_TOKEN|CONTENTFUL_DELIVERY_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_-]{43,})['"]?/i,
    description: 'Contentful Delivery/Preview Token detected',
    severity: 'high',
    type: 'contentful_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Pulumi ────────────────────────────────────────────────────────────────

  {
    id: 'pulumi-access-token',
    regex: /pul-[A-Za-z0-9]{40}/,
    description: 'Pulumi Access Token detected',
    severity: 'critical',
    type: 'pulumi_token',
    autoFixable: true,
  },

  // ─── Fastly ────────────────────────────────────────────────────────────────

  {
    id: 'fastly-api-token',
    regex: /(?:FASTLY_API_TOKEN|FASTLY_KEY|fastly_api_token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{32})['"]?/i,
    description: 'Fastly API Token detected',
    severity: 'critical',
    type: 'fastly_api_token',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Lob ───────────────────────────────────────────────────────────────────

  {
    id: 'lob-api-key',
    regex: /(?:live|test)_[a-f0-9]{35}/,
    description: 'Lob API Key detected',
    severity: 'high',
    type: 'lob_api_key',
    autoFixable: true,
    contextKeywords: ['lob', 'LOB'],
  },

  // ─── Dynatrace ─────────────────────────────────────────────────────────────

  {
    id: 'dynatrace-api-token',
    regex: /dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}/,
    description: 'Dynatrace API Token detected',
    severity: 'critical',
    type: 'dynatrace_api_token',
    autoFixable: true,
  },

  // ─── Elastic / Kibana ──────────────────────────────────────────────────────

  {
    id: 'elastic-cloud-api-key',
    regex: /(?:ELASTIC_API_KEY|ELASTICSEARCH_API_KEY)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40,})['"]?/i,
    description: 'Elastic Cloud API Key detected',
    severity: 'critical',
    type: 'elastic_api_key',
    autoFixable: true,
    skipPlaceholders: true,
  },

  // ─── Age encryption key ────────────────────────────────────────────────────

  {
    id: 'age-secret-key',
    regex: /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/,
    description: 'age encryption secret key detected',
    severity: 'critical',
    type: 'age_secret_key',
    autoFixable: false,
  },

  // ─── PKCS12 / PFX ─────────────────────────────────────────────────────────

  {
    id: 'pkcs12-password',
    regex: /(?:PKCS12_PASSWORD|PFX_PASSWORD|pkcs12_pass|pfx_pass)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?/i,
    description: 'PKCS12/PFX password detected',
    severity: 'critical',
    type: 'pkcs12_password',
    autoFixable: true,
    skipPlaceholders: true,
  },
];

// ── Pattern count export ───────────────────────────────────────────────────────

export function getSecretPatternCount(): number {
  return SECRET_PATTERNS.length;
}

// ── Severity ordering (for sorting) ────────────────────────────────────────────

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

// ── Main scanner ───────────────────────────────────────────────────────────────

export async function scanSecrets(
  targetPath: string,
  files?: string[],
): Promise<Finding[]> {
  // 1. Determine file list
  let discovered: string[];
  if (files && files.length > 0) {
    // Map relative paths to absolute
    discovered = files.map((f) =>
      f.startsWith('/') ? f : join(targetPath, f),
    );
  } else {
    discovered = await walkDirectory(targetPath);
  }

  // Apply .shipsafeignore filter
  const ignoreFilter = await loadIgnoreFilter(resolve(targetPath));

  // Apply .gitignore filter — silently skips gitignored files (e.g., .env.local)
  const gitIgnoreFilter = await loadGitIgnoreFilter(resolve(targetPath));

  const filesToScan = discovered.filter(
    (f) => !ignoreFilter.isIgnored(f) && !gitIgnoreFilter.isGitIgnored(f),
  );

  // 2. Scan all files concurrently in controlled batches
  const findings: Finding[] = [];
  const BATCH_SIZE = 50;

  for (let i = 0; i < filesToScan.length; i += BATCH_SIZE) {
    const batch = filesToScan.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map((filePath) => scanFile(filePath, targetPath)),
    );
    for (const result of batchResults) {
      findings.push(...result);
    }
  }

  // 3. Deduplicate: same pattern + same file + same line
  const seen = new Set<string>();
  const deduped: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.id}:${finding.file}:${finding.line}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(finding);
    }
  }

  // 4. Sort by severity (critical first), then file, then line
  deduped.sort((a, b) => {
    const sevDiff = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (sevDiff !== 0) return sevDiff;
    const fileDiff = a.file.localeCompare(b.file);
    if (fileDiff !== 0) return fileDiff;
    return a.line - b.line;
  });

  return deduped;
}

// ── Single-file scanner ────────────────────────────────────────────────────────

async function scanFile(
  filePath: string,
  basePath: string,
): Promise<Finding[]> {
  // Check file size — skip files > 1MB
  let fileStat;
  try {
    fileStat = await stat(filePath);
  } catch {
    return [];
  }
  if (fileStat.size > MAX_FILE_SIZE) return [];
  if (!fileStat.isFile()) return [];

  // Read file contents
  let content: string;
  try {
    content = await readFile(filePath, 'utf-8');
  } catch {
    // Binary file or permission error — skip
    return [];
  }

  // Quick binary check: if file contains null bytes in first 8KB, skip
  const sample = content.slice(0, 8192);
  if (sample.includes('\0')) return [];

  const relativePath = relative(basePath, filePath);
  const fileName = basename(filePath);
  const isEnvFile = fileName.startsWith('.env');
  const isEnvExample = fileName === '.env.example' || fileName === '.env.sample';
  const fileIsTestOrDocs = isTestOrDocsFile(filePath);
  const fileIsFontData = isFontOrDataFile(filePath, content);
  const lines = content.split('\n');
  const findings: Finding[] = [];

  // Generic pattern IDs that should be skipped in test/docs/i18n files
  const SKIP_IN_TEST_DOCS = new Set([
    'password-assignment-double-quote',
    'password-assignment-single-quote',
    'api-key-assignment-double-quote',
    'api-key-assignment-single-quote',
    'secret-assignment-double-quote',
    'secret-assignment-single-quote',
    'access-token-assignment-double-quote',
    'access-token-assignment-single-quote',
  ]);

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];

    // Skip empty lines and very short lines
    if (line.length < 8) continue;

    // Skip documentation / example comment lines
    if (isDocOrCommentExample(line)) continue;

    for (const pattern of SECRET_PATTERNS) {
      // Context keyword filter for .env patterns
      if (
        pattern.contextKeywords?.includes('.env') &&
        !isEnvFile
      ) {
        continue;
      }

      // Skip generic secret patterns in test/docs/i18n files
      if (fileIsTestOrDocs && SKIP_IN_TEST_DOCS.has(pattern.id)) {
        continue;
      }

      const match = pattern.regex.exec(line);
      if (!match) continue;

      // Extract the captured group (secret value) or the full match
      const secretValue = match[1] ?? match[0];

      // Skip large base64 blobs in font/data JSON files (not real tokens)
      if (fileIsFontData && isLargeBase64Blob(secretValue)) {
        continue;
      }
      // Also skip any token-like pattern where the matched value is >500 chars (data blob, not a token)
      if (isLargeBase64Blob(secretValue) && (
        pattern.type === 'facebook_access_token' ||
        pattern.type === 'hardcoded_access_token' ||
        pattern.type === 'bearer_token'
      )) {
        continue;
      }

      // Skip localhost connection strings — not real secrets
      if (isLocalhostUrl(secretValue) || isLocalhostUrl(line)) {
        continue;
      }

      // Placeholder check
      if (pattern.skipPlaceholders && isPlaceholder(secretValue)) {
        continue;
      }

      // Skip error code constants that happen to contain "password" (e.g., INVALID_PASSWORD)
      if (pattern.type === 'hardcoded_password' && isErrorCodeOrConstant(secretValue)) {
        continue;
      }

      // Skip env var references (process.env.XXX) — not hardcoded secrets
      if (/\bprocess\.env\.\w+/.test(line) || /\bos\.environ\b/.test(line) || /\bos\.getenv\b/.test(line)) {
        continue;
      }

      // Entropy check
      if (pattern.entropyCheck) {
        const threshold = pattern.entropyThreshold ?? 3.5;
        const entropy = shannonEntropy(secretValue);
        if (entropy < threshold) continue;
      }

      // Context keyword validation (for patterns that need nearby keywords)
      if (
        pattern.contextKeywords &&
        !pattern.contextKeywords.includes('.env')
      ) {
        const contextWindow = getContextWindow(lines, lineIdx, 3);
        const hasContext = pattern.contextKeywords.some((kw) =>
          contextWindow.toLowerCase().includes(kw.toLowerCase()),
        );
        if (!hasContext) continue;
      }

      // Downgrade severity for .env.example / .env.sample files and test/docs files
      const effectiveSeverity: Severity = (isEnvExample || fileIsTestOrDocs) ? 'info' : pattern.severity;

      findings.push({
        id: `builtin_${pattern.id}_${lineIdx + 1}`,
        engine: 'pattern',
        severity: effectiveSeverity,
        type: pattern.type,
        file: relativePath,
        line: lineIdx + 1,
        description: isEnvExample
          ? `${pattern.description} (in example file — likely placeholder)`
          : pattern.description,
        fix_suggestion:
          'Move this secret to an environment variable or secrets manager. Never commit secrets to source control.',
        auto_fixable: pattern.autoFixable,
        ...(isEnvExample ? { context: 'env-example' as const } : {}),
      });
    }
  }

  return findings;
}

// ── Context window helper ──────────────────────────────────────────────────────

function getContextWindow(
  lines: string[],
  lineIdx: number,
  radius: number,
): string {
  const start = Math.max(0, lineIdx - radius);
  const end = Math.min(lines.length - 1, lineIdx + radius);
  return lines.slice(start, end + 1).join('\n');
}
