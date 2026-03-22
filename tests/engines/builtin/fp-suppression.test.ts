import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { scanPatterns } from '../../../src/engines/builtin/patterns.js';
import type { Finding } from '../../../src/types.js';

// ── Helpers ──

let testDir: string;

beforeAll(async () => {
  testDir = join(tmpdir(), `shipsafe-fp-test-${randomUUID().slice(0, 8)}`);
  await mkdir(testDir, { recursive: true });
});

afterAll(async () => {
  await rm(testDir, { recursive: true, force: true });
});

async function scanCode(code: string, filename = 'test.ts'): Promise<Finding[]> {
  const filePath = join(testDir, filename);
  const parentDir = filePath.substring(0, filePath.lastIndexOf('/'));
  await mkdir(parentDir, { recursive: true });
  await writeFile(filePath, code, 'utf-8');
  return scanPatterns(testDir, [filePath]);
}

function hasRule(findings: Finding[], ruleId: string): boolean {
  return findings.some((f) => f.id === ruleId);
}

// ════════════════════════════════════════════
// Import Context FP Suppression Tests
// ════════════════════════════════════════════

describe('Import-level FP suppression', () => {
  describe('AUTH_MISSING_AUTH_MIDDLEWARE', () => {
    it('flags route without auth import', async () => {
      const findings = await scanCode(`
import express from 'express';
const app = express();
app.get("/api/admin/users", (req, res) => { res.json([]); });
`, 'no-auth-route.ts');
      expect(hasRule(findings, 'AUTH_MISSING_AUTH_MIDDLEWARE')).toBe(true);
    });

    it('suppresses when passport is imported', async () => {
      const findings = await scanCode(`
import express from 'express';
import passport from 'passport';
const app = express();
app.get("/api/admin/users", (req, res) => { res.json([]); });
`, 'passport-route.ts');
      expect(hasRule(findings, 'AUTH_MISSING_AUTH_MIDDLEWARE')).toBe(false);
    });

    it('suppresses when @clerk/nextjs is imported', async () => {
      const findings = await scanCode(`
import { auth } from '@clerk/nextjs';
import express from 'express';
const app = express();
app.get("/api/admin/users", (req, res) => { res.json([]); });
`, 'clerk-route.ts');
      expect(hasRule(findings, 'AUTH_MISSING_AUTH_MIDDLEWARE')).toBe(false);
    });
  });

  describe('NEXT_API_NO_AUTH', () => {
    it('flags handler without auth import', async () => {
      const findings = await scanCode(`
export default function handler(req, res) {
  res.json({ data: 'secret' });
}
`, 'api-no-auth.ts');
      expect(hasRule(findings, 'NEXT_API_NO_AUTH')).toBe(true);
    });

    it('suppresses when next-auth is imported', async () => {
      const findings = await scanCode(`
import { getServerSession } from 'next-auth';
export default function handler(req, res) {
  res.json({ data: 'secret' });
}
`, 'api-with-auth.ts');
      expect(hasRule(findings, 'NEXT_API_NO_AUTH')).toBe(false);
    });
  });

  describe('NEXT_SERVER_ACTION_NO_AUTH', () => {
    it('flags server action without auth import', async () => {
      const findings = await scanCode(`
'use server';
export async function deleteUser(id: string) {
  await prisma.user.delete({ where: { id } });
}
`, 'action-no-auth.ts');
      expect(hasRule(findings, 'NEXT_SERVER_ACTION_NO_AUTH')).toBe(true);
    });

    it('suppresses when @clerk/nextjs is imported', async () => {
      const findings = await scanCode(`
'use server';
import { auth } from '@clerk/nextjs';
export async function deleteUser(id: string) {
  await prisma.user.delete({ where: { id } });
}
`, 'action-with-clerk.ts');
      expect(hasRule(findings, 'NEXT_SERVER_ACTION_NO_AUTH')).toBe(false);
    });
  });

  describe('XSS_DANGEROUSLY_SET_INNERHTML', () => {
    it('flags dangerouslySetInnerHTML without sanitization import', async () => {
      const findings = await scanCode(`
const Component = ({ html }) => (
  <div dangerouslySetInnerHTML={{ __html: html }} />
);
`, 'xss-no-sanitize.tsx');
      expect(hasRule(findings, 'XSS_DANGEROUSLY_SET_INNERHTML')).toBe(true);
    });

    it('suppresses when DOMPurify is imported', async () => {
      const findings = await scanCode(`
import DOMPurify from 'dompurify';
const Component = ({ html }) => (
  <div dangerouslySetInnerHTML={{ __html: html }} />
);
`, 'xss-with-dompurify.tsx');
      expect(hasRule(findings, 'XSS_DANGEROUSLY_SET_INNERHTML')).toBe(false);
    });

    it('suppresses when sanitize-html is imported', async () => {
      const findings = await scanCode(`
import sanitize from 'sanitize-html';
const Component = ({ html }) => (
  <div dangerouslySetInnerHTML={{ __html: html }} />
);
`, 'xss-with-sanitize-html.tsx');
      expect(hasRule(findings, 'XSS_DANGEROUSLY_SET_INNERHTML')).toBe(false);
    });
  });

  describe('REACT_DANGEROUSLYSETINNERHTML_VARIABLE', () => {
    it('flags without sanitization import', async () => {
      const findings = await scanCode(`
const Component = ({ content }) => (
  <div dangerouslySetInnerHTML={{ __html: content }} />
);
`, 'react-xss-no-sanitize.tsx');
      expect(hasRule(findings, 'REACT_DANGEROUSLYSETINNERHTML_VARIABLE')).toBe(true);
    });

    it('suppresses when xss library is imported', async () => {
      const findings = await scanCode(`
import xss from 'xss';
const Component = ({ content }) => (
  <div dangerouslySetInnerHTML={{ __html: content }} />
);
`, 'react-xss-with-xss.tsx');
      expect(hasRule(findings, 'REACT_DANGEROUSLYSETINNERHTML_VARIABLE')).toBe(false);
    });
  });

  describe('CONFIG_NO_SECURITY_HEADERS', () => {
    it('flags express app without helmet import', async () => {
      const findings = await scanCode(`
import express from 'express';
const app = express();
app.get('/', (req, res) => res.send('ok'));
`, 'no-helmet.ts');
      expect(hasRule(findings, 'CONFIG_NO_SECURITY_HEADERS')).toBe(true);
    });

    it('suppresses when helmet is imported', async () => {
      const findings = await scanCode(`
import express from 'express';
import helmet from 'helmet';
const app = express();
app.get('/', (req, res) => res.send('ok'));
`, 'with-helmet.ts');
      expect(hasRule(findings, 'CONFIG_NO_SECURITY_HEADERS')).toBe(false);
    });
  });

  describe('MISSING_CSRF_PROTECTION', () => {
    it('flags POST route without CSRF import', async () => {
      const findings = await scanCode(`
import express from 'express';
const app = express();
app.post('/submit', (req, res) => res.json({ ok: true }));
`, 'no-csrf.ts');
      expect(hasRule(findings, 'MISSING_CSRF_PROTECTION')).toBe(true);
    });

    it('suppresses when csurf is imported', async () => {
      const findings = await scanCode(`
import express from 'express';
import csurf from 'csurf';
const app = express();
app.post('/submit', (req, res) => res.json({ ok: true }));
`, 'with-csurf.ts');
      expect(hasRule(findings, 'MISSING_CSRF_PROTECTION')).toBe(false);
    });

    it('suppresses when lusca is imported', async () => {
      const findings = await scanCode(`
import express from 'express';
import lusca from 'lusca';
const app = express();
app.post('/submit', (req, res) => res.json({ ok: true }));
`, 'with-lusca.ts');
      expect(hasRule(findings, 'MISSING_CSRF_PROTECTION')).toBe(false);
    });
  });

  describe('RATE_LIMIT_AUTH_ENDPOINT', () => {
    it('flags auth endpoint without rate limit import', async () => {
      const findings = await scanCode(`
import express from 'express';
const app = express();
app.post('/api/auth/login', (req, res) => res.json({ token: '123' }));
`, 'no-ratelimit.ts');
      expect(hasRule(findings, 'RATE_LIMIT_AUTH_ENDPOINT')).toBe(true);
    });

    it('suppresses when express-rate-limit is imported', async () => {
      const findings = await scanCode(`
import express from 'express';
import rateLimit from 'express-rate-limit';
const app = express();
app.post('/api/auth/login', (req, res) => res.json({ token: '123' }));
`, 'with-ratelimit.ts');
      expect(hasRule(findings, 'RATE_LIMIT_AUTH_ENDPOINT')).toBe(false);
    });

    it('suppresses when rate-limiter-flexible is imported', async () => {
      const findings = await scanCode(`
import express from 'express';
import { RateLimiterMemory } from 'rate-limiter-flexible';
const app = express();
app.post('/api/auth/login', (req, res) => res.json({ token: '123' }));
`, 'with-rate-limiter.ts');
      expect(hasRule(findings, 'RATE_LIMIT_AUTH_ENDPOINT')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Ensure real findings are NOT suppressed
// ════════════════════════════════════════════

describe('Real findings are NOT suppressed by import context', () => {
  it('still flags SQL injection even with auth import', async () => {
    const findings = await scanCode(`
import passport from 'passport';
function getUser(id) {
  db.get("SELECT * FROM users WHERE id = '" + id + "'");
}
`, 'sql-with-auth.ts');
    expect(hasRule(findings, 'SQL_INJECTION_CONCAT')).toBe(true);
  });

  it('still flags eval even with validation import', async () => {
    const findings = await scanCode(`
import { z } from 'zod';
function execute(code) {
  eval(code);
}
`, 'eval-with-zod.ts');
    expect(hasRule(findings, 'XSS_EVAL')).toBe(true);
  });

  it('still flags NEXT_API_NO_AUTH without auth import even with other imports', async () => {
    const findings = await scanCode(`
import { z } from 'zod';
import helmet from 'helmet';
export default function handler(req, res) {
  res.json({ data: 'secret' });
}
`, 'api-no-auth-with-other.ts');
    expect(hasRule(findings, 'NEXT_API_NO_AUTH')).toBe(true);
  });

  it('still flags XSS when only validation (not sanitization) is imported', async () => {
    const findings = await scanCode(`
import { z } from 'zod';
const Component = ({ html }) => (
  <div dangerouslySetInnerHTML={{ __html: html }} />
);
`, 'xss-with-zod-only.tsx');
    expect(hasRule(findings, 'XSS_DANGEROUSLY_SET_INNERHTML')).toBe(true);
  });
});
