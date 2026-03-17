import * as fs from 'node:fs/promises';
import * as path from 'node:path';

export interface ProjectTemplate {
  framework: string; // 'nextjs', 'express', 'fastify', 'hono', etc.
  recommendations: SecurityRecommendation[];
}

export interface SecurityRecommendation {
  type:
    | 'missing_helmet'
    | 'missing_cors'
    | 'missing_rate_limit'
    | 'missing_csp'
    | 'missing_env_config'
    | 'insecure_cookie';
  description: string;
  fix: string; // Code snippet to add
  file: string; // Where to add it
  priority: 'high' | 'medium' | 'low';
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

/**
 * Detect the framework from package.json dependencies.
 */
export function detectFramework(packageJson: PackageJson): string | null {
  const allDeps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  // Order matters — more specific frameworks first
  if (allDeps['next']) return 'nextjs';
  if (allDeps['hono']) return 'hono';
  if (allDeps['fastify']) return 'fastify';
  if (allDeps['express']) return 'express';

  return null;
}

/**
 * Check if a package is present in the project dependencies.
 */
function hasDep(packageJson: PackageJson, name: string): boolean {
  return !!(packageJson.dependencies?.[name] || packageJson.devDependencies?.[name]);
}

/**
 * Check if .env is listed in .gitignore.
 */
async function checkEnvInGitignore(projectDir: string): Promise<boolean> {
  try {
    const content = await fs.readFile(path.join(projectDir, '.gitignore'), 'utf-8');
    return content.split('\n').some((line) => {
      const trimmed = line.trim();
      return trimmed === '.env' || trimmed === '.env*' || trimmed === '.env.*';
    });
  } catch {
    return false;
  }
}

/**
 * Generate Express-specific security recommendations.
 */
function getExpressRecommendations(packageJson: PackageJson): SecurityRecommendation[] {
  const recs: SecurityRecommendation[] = [];

  if (!hasDep(packageJson, 'helmet')) {
    recs.push({
      type: 'missing_helmet',
      description:
        'Express app is missing Helmet — HTTP headers are not secured against common attacks (XSS, clickjacking, MIME sniffing).',
      fix: `// npm install helmet
import helmet from 'helmet';
app.use(helmet());`,
      file: 'src/app.ts',
      priority: 'high',
    });
  }

  if (!hasDep(packageJson, 'cors')) {
    recs.push({
      type: 'missing_cors',
      description:
        'No CORS middleware detected. Without explicit CORS configuration, the API may reject legitimate cross-origin requests or allow unintended origins.',
      fix: `// npm install cors
import cors from 'cors';
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') ?? [] }));`,
      file: 'src/app.ts',
      priority: 'medium',
    });
  }

  if (!hasDep(packageJson, 'express-rate-limit') && !hasDep(packageJson, 'rate-limiter-flexible')) {
    recs.push({
      type: 'missing_rate_limit',
      description:
        'No rate limiting middleware detected. API endpoints are vulnerable to brute-force and denial-of-service attacks.',
      fix: `// npm install express-rate-limit
import rateLimit from 'express-rate-limit';
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));`,
      file: 'src/app.ts',
      priority: 'high',
    });
  }

  return recs;
}

/**
 * Generate Next.js-specific security recommendations.
 */
function getNextjsRecommendations(packageJson: PackageJson): SecurityRecommendation[] {
  const recs: SecurityRecommendation[] = [];

  // Next.js CSP headers
  recs.push({
    type: 'missing_csp',
    description:
      'No Content Security Policy headers detected. CSP prevents XSS, data injection, and other code-injection attacks.',
    fix: `// In next.config.js or middleware.ts:
const cspHeader = \`
  default-src 'self';
  script-src 'self' 'unsafe-eval' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
\`;

// next.config.js
const nextConfig = {
  async headers() {
    return [{
      source: '/(.*)',
      headers: [{ key: 'Content-Security-Policy', value: cspHeader.replace(/\\n/g, '') }],
    }];
  },
};`,
    file: 'next.config.js',
    priority: 'high',
  });

  if (!hasDep(packageJson, 'rate-limiter-flexible') && !hasDep(packageJson, '@upstash/ratelimit')) {
    recs.push({
      type: 'missing_rate_limit',
      description:
        'No rate limiting detected for API routes. Next.js API routes are vulnerable to abuse without rate limiting.',
      fix: `// npm install @upstash/ratelimit @upstash/redis
// In your API route or middleware:
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '10 s'),
});`,
      file: 'src/middleware.ts',
      priority: 'medium',
    });
  }

  return recs;
}

/**
 * Generate Fastify-specific security recommendations.
 */
function getFastifyRecommendations(packageJson: PackageJson): SecurityRecommendation[] {
  const recs: SecurityRecommendation[] = [];

  if (!hasDep(packageJson, '@fastify/helmet')) {
    recs.push({
      type: 'missing_helmet',
      description:
        'Fastify app is missing @fastify/helmet — HTTP security headers are not configured.',
      fix: `// npm install @fastify/helmet
import helmet from '@fastify/helmet';
await app.register(helmet);`,
      file: 'src/app.ts',
      priority: 'high',
    });
  }

  if (!hasDep(packageJson, '@fastify/cors')) {
    recs.push({
      type: 'missing_cors',
      description: 'No CORS plugin registered. Cross-origin requests may not be handled correctly.',
      fix: `// npm install @fastify/cors
import cors from '@fastify/cors';
await app.register(cors, { origin: process.env.ALLOWED_ORIGINS?.split(',') ?? [] });`,
      file: 'src/app.ts',
      priority: 'medium',
    });
  }

  if (!hasDep(packageJson, '@fastify/rate-limit')) {
    recs.push({
      type: 'missing_rate_limit',
      description:
        'No rate limiting plugin detected. API endpoints are vulnerable to brute-force attacks.',
      fix: `// npm install @fastify/rate-limit
import rateLimit from '@fastify/rate-limit';
await app.register(rateLimit, { max: 100, timeWindow: '15 minutes' });`,
      file: 'src/app.ts',
      priority: 'high',
    });
  }

  return recs;
}

/**
 * Generate Hono-specific security recommendations.
 */
function getHonoRecommendations(packageJson: PackageJson): SecurityRecommendation[] {
  const recs: SecurityRecommendation[] = [];

  recs.push({
    type: 'missing_cors',
    description:
      'Ensure CORS middleware is configured for your Hono app to control cross-origin access.',
    fix: `import { cors } from 'hono/cors';
app.use('*', cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') ?? [] }));`,
    file: 'src/index.ts',
    priority: 'medium',
  });

  recs.push({
    type: 'missing_csp',
    description: 'Add security headers middleware to protect against common web attacks.',
    fix: `import { secureHeaders } from 'hono/secure-headers';
app.use('*', secureHeaders());`,
    file: 'src/index.ts',
    priority: 'high',
  });

  return recs;
}

/**
 * Detect the project framework and generate security recommendations.
 * Returns null if the framework cannot be detected.
 */
export async function detectAndRecommend(
  projectDir?: string,
): Promise<ProjectTemplate | null> {
  const dir = projectDir ?? process.cwd();
  const packageJsonPath = path.join(dir, 'package.json');

  let packageJson: PackageJson;
  try {
    const raw = await fs.readFile(packageJsonPath, 'utf-8');
    packageJson = JSON.parse(raw) as PackageJson;
  } catch {
    return null; // No package.json — can't detect framework
  }

  const framework = detectFramework(packageJson);
  if (!framework) return null;

  // Get framework-specific recommendations
  let recommendations: SecurityRecommendation[];
  switch (framework) {
    case 'express':
      recommendations = getExpressRecommendations(packageJson);
      break;
    case 'nextjs':
      recommendations = getNextjsRecommendations(packageJson);
      break;
    case 'fastify':
      recommendations = getFastifyRecommendations(packageJson);
      break;
    case 'hono':
      recommendations = getHonoRecommendations(packageJson);
      break;
    default:
      recommendations = [];
  }

  // Common check: .env in .gitignore
  const hasEnvInGitignore = await checkEnvInGitignore(dir);
  if (!hasEnvInGitignore) {
    recommendations.push({
      type: 'missing_env_config',
      description:
        '.env file is not listed in .gitignore. Environment variables containing secrets may be committed to version control.',
      fix: `# Add to .gitignore:
.env
.env.*
.env.local`,
      file: '.gitignore',
      priority: 'high',
    });
  }

  return { framework, recommendations };
}
