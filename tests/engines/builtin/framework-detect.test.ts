import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { detectFramework, type FrameworkProfile } from '../../../src/engines/builtin/framework-detect.js';
import { scanPatterns } from '../../../src/engines/builtin/patterns.js';

// ── Helpers ──

let baseDir: string;

beforeAll(async () => {
  baseDir = join(tmpdir(), `shipsafe-fw-test-${randomUUID().slice(0, 8)}`);
  await mkdir(baseDir, { recursive: true });
});

afterAll(async () => {
  await rm(baseDir, { recursive: true, force: true });
});

async function createProject(
  name: string,
  files: Record<string, string>,
): Promise<string> {
  const dir = join(baseDir, name);
  await mkdir(dir, { recursive: true });
  for (const [filePath, content] of Object.entries(files)) {
    const fullPath = join(dir, filePath);
    const parentDir = fullPath.substring(0, fullPath.lastIndexOf('/'));
    await mkdir(parentDir, { recursive: true });
    await writeFile(fullPath, content, 'utf-8');
  }
  return dir;
}

// ════════════════════════════════════════════
// Framework Detection
// ════════════════════════════════════════════

describe('detectFramework', () => {
  describe('JavaScript/TypeScript projects', () => {
    it('detects Next.js', async () => {
      const dir = await createProject('nextjs-app', {
        'package.json': JSON.stringify({
          dependencies: { next: '14.0.0', react: '18.0.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('nextjs');
      expect(profile.isNextJs).toBe(true);
      expect(profile.isExpress).toBe(false);
      expect(profile.isFastify).toBe(false);
    });

    it('detects Express', async () => {
      const dir = await createProject('express-app', {
        'package.json': JSON.stringify({
          dependencies: { express: '4.18.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('express');
      expect(profile.isExpress).toBe(true);
      expect(profile.isNextJs).toBe(false);
    });

    it('detects Fastify', async () => {
      const dir = await createProject('fastify-app', {
        'package.json': JSON.stringify({
          dependencies: { fastify: '4.0.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('fastify');
      expect(profile.isFastify).toBe(true);
    });

    it('detects Hono', async () => {
      const dir = await createProject('hono-app', {
        'package.json': JSON.stringify({
          dependencies: { hono: '3.0.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('hono');
      expect(profile.isHono).toBe(true);
    });

    it('Next.js takes priority over Express', async () => {
      const dir = await createProject('nextjs-with-express', {
        'package.json': JSON.stringify({
          dependencies: { next: '14.0.0', express: '4.18.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('nextjs');
      expect(profile.isNextJs).toBe(true);
      expect(profile.isExpress).toBe(false);
    });

    it('detects Clerk auth', async () => {
      const dir = await createProject('clerk-app', {
        'package.json': JSON.stringify({
          dependencies: { next: '14.0.0', '@clerk/nextjs': '4.0.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.hasAuth).toBe('clerk');
    });

    it('detects next-auth', async () => {
      const dir = await createProject('nextauth-app', {
        'package.json': JSON.stringify({
          dependencies: { next: '14.0.0', 'next-auth': '5.0.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.hasAuth).toBe('next-auth');
    });

    it('detects Passport', async () => {
      const dir = await createProject('passport-app', {
        'package.json': JSON.stringify({
          dependencies: { express: '4.18.0', passport: '0.7.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.hasAuth).toBe('passport');
    });

    it('detects Prisma ORM', async () => {
      const dir = await createProject('prisma-app', {
        'package.json': JSON.stringify({
          dependencies: { next: '14.0.0', '@prisma/client': '5.0.0' },
          devDependencies: { prisma: '5.0.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.hasORM).toBe('prisma');
    });

    it('detects Drizzle ORM', async () => {
      const dir = await createProject('drizzle-app', {
        'package.json': JSON.stringify({
          dependencies: { 'drizzle-orm': '0.30.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.hasORM).toBe('drizzle');
    });

    it('detects Supabase', async () => {
      const dir = await createProject('supabase-app', {
        'package.json': JSON.stringify({
          dependencies: { '@supabase/supabase-js': '2.0.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.hasSupabase).toBe(true);
    });

    it('detects Stripe', async () => {
      const dir = await createProject('stripe-app', {
        'package.json': JSON.stringify({
          dependencies: { stripe: '14.0.0', '@stripe/stripe-js': '2.0.0' },
        }),
      });
      const profile = await detectFramework(dir);
      expect(profile.hasStripe).toBe(true);
    });

    it('returns unknown for empty package.json', async () => {
      const dir = await createProject('empty-app', {
        'package.json': JSON.stringify({}),
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('unknown');
      expect(profile.isNextJs).toBe(false);
      expect(profile.hasAuth).toBeNull();
      expect(profile.hasORM).toBeNull();
    });
  });

  describe('Python projects', () => {
    it('detects Django from requirements.txt', async () => {
      const dir = await createProject('django-app', {
        'requirements.txt': 'Django==4.2\npsycopg2-binary==2.9.0\n',
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('django');
      expect(profile.isDjango).toBe(true);
    });

    it('detects Flask from requirements.txt', async () => {
      const dir = await createProject('flask-app', {
        'requirements.txt': 'flask==3.0.0\ngunicorn==21.2.0\n',
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('flask');
      expect(profile.isFlask).toBe(true);
    });

    it('detects FastAPI from requirements.txt', async () => {
      const dir = await createProject('fastapi-app', {
        'requirements.txt': 'fastapi==0.104.0\nuvicorn==0.24.0\n',
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('fastapi');
      expect(profile.isFastAPI).toBe(true);
    });

    it('detects Django from pyproject.toml', async () => {
      const dir = await createProject('django-pyproject', {
        'pyproject.toml': '[project]\ndependencies = ["django>=4.2"]\n',
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('django');
      expect(profile.isDjango).toBe(true);
    });
  });

  describe('no project files', () => {
    it('returns unknown when no package.json or requirements.txt', async () => {
      const dir = await createProject('no-deps', {
        'README.md': '# Hello',
      });
      const profile = await detectFramework(dir);
      expect(profile.name).toBe('unknown');
    });
  });
});

// ════════════════════════════════════════════
// Framework-Gated Rule Suppression
// ════════════════════════════════════════════

describe('framework-gated rule suppression', () => {
  async function scanWithFramework(
    code: string,
    pkgJson: Record<string, unknown>,
    filename = 'server.ts',
  ) {
    const dir = await createProject(`fw-gate-${randomUUID().slice(0, 8)}`, {
      'package.json': JSON.stringify(pkgJson),
      [filename]: code,
    });
    const filePath = join(dir, filename);
    return scanPatterns(dir, [filePath]);
  }

  it('suppresses MISSING_CSRF_PROTECTION in Next.js projects', async () => {
    const code = `
import express from 'express';
const app = express();
app.post('/submit', (req, res) => { res.send('ok'); });
`;
    const findings = await scanWithFramework(code, {
      dependencies: { next: '14.0.0', express: '4.18.0' },
    });
    const csrfFindings = findings.filter((f) => f.id === 'MISSING_CSRF_PROTECTION');
    expect(csrfFindings).toHaveLength(0);
  });

  it('fires MISSING_CSRF_PROTECTION in Express-only projects', async () => {
    const code = `
import express from 'express';
const app = express();
app.post('/submit', (req, res) => { res.send('ok'); });
`;
    const findings = await scanWithFramework(code, {
      dependencies: { express: '4.18.0' },
    });
    const csrfFindings = findings.filter((f) => f.id === 'MISSING_CSRF_PROTECTION');
    expect(csrfFindings.length).toBeGreaterThan(0);
  });

  it('suppresses CONFIG_NO_SECURITY_HEADERS in Next.js projects', async () => {
    const code = `
import express from 'express';
const app = express();
app.get('/', (req, res) => { res.send('ok'); });
`;
    const findings = await scanWithFramework(code, {
      dependencies: { next: '14.0.0', express: '4.18.0' },
    });
    const headerFindings = findings.filter((f) => f.id === 'CONFIG_NO_SECURITY_HEADERS');
    expect(headerFindings).toHaveLength(0);
  });

  it('fires CONFIG_NO_SECURITY_HEADERS in Express-only projects', async () => {
    const code = `
import express from 'express';
const app = express();
app.get('/', (req, res) => { res.send('ok'); });
`;
    const findings = await scanWithFramework(code, {
      dependencies: { express: '4.18.0' },
    });
    const headerFindings = findings.filter((f) => f.id === 'CONFIG_NO_SECURITY_HEADERS');
    expect(headerFindings.length).toBeGreaterThan(0);
  });
});
