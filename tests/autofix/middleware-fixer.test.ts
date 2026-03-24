import { describe, it, expect } from 'vitest';
import { fixMissingHelmet, fixMissingRateLimit } from '../../src/autofix/middleware-fixer.js';
import type { Finding } from '../../src/types.js';

// ── Helpers ──

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'CONFIG_NO_SECURITY_HEADERS',
    engine: 'pattern',
    severity: 'low',
    type: 'Insecure Configuration',
    file: 'src/server.ts',
    line: 3,
    description: 'Express app created without security headers middleware',
    fix_suggestion: 'Install and use helmet',
    auto_fixable: true,
    ...overrides,
  };
}

// ════════════════════════════════════════════
// fixMissingHelmet
// ════════════════════════════════════════════

describe('fixMissingHelmet', () => {
  it('adds helmet import and app.use(helmet()) after express() call', () => {
    const code = [
      "import express from 'express';",
      '',
      'const app = express();',
      '',
      "app.get('/', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const result = fixMissingHelmet(code, makeFinding({ line: 3 }));

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain("import helmet from 'helmet';");
    expect(result!.fixed).toContain('app.use(helmet());');
    expect(result!.description).toContain('helmet');

    // Verify ordering: helmet import should come after express import
    const lines = result!.fixed.split('\n');
    const helmetImportIdx = lines.findIndex((l) => l.includes("import helmet"));
    const expressImportIdx = lines.findIndex((l) => l.includes("import express"));
    const helmetUseIdx = lines.findIndex((l) => l.includes('app.use(helmet())'));
    const expressCallIdx = lines.findIndex((l) => l.includes('express()'));

    expect(helmetImportIdx).toBeGreaterThan(expressImportIdx);
    expect(helmetUseIdx).toBeGreaterThan(expressCallIdx);
  });

  it('uses require() for CJS-style files', () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.get('/', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const result = fixMissingHelmet(code, makeFinding({ line: 2 }));

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain("const helmet = require('helmet');");
    expect(result!.fixed).toContain('app.use(helmet());');
  });

  it('detects custom app variable names', () => {
    const code = [
      "import express from 'express';",
      'const server = express();',
      "server.get('/', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const result = fixMissingHelmet(code, makeFinding({ line: 2 }));

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('server.use(helmet());');
  });

  it('preserves indentation', () => {
    const code = [
      "import express from 'express';",
      '',
      '  const app = express();',
      "  app.get('/', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const result = fixMissingHelmet(code, makeFinding({ line: 3 }));

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('  app.use(helmet());');
  });

  it('returns null when no express() call is found', () => {
    const code = [
      "import Koa from 'koa';",
      'const app = new Koa();',
    ].join('\n');

    const result = fixMissingHelmet(code, makeFinding({ line: 2 }));
    expect(result).toBeNull();
  });

  it('does not add duplicate helmet import', () => {
    const code = [
      "import express from 'express';",
      "import helmet from 'helmet';",
      '',
      'const app = express();',
      "app.get('/', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const result = fixMissingHelmet(code, makeFinding({ line: 4 }));

    expect(result).not.toBeNull();
    // Should contain only one helmet import
    const helmetImports = result!.fixed.match(/import helmet/g);
    expect(helmetImports).toHaveLength(1);
  });
});

// ════════════════════════════════════════════
// fixMissingRateLimit
// ════════════════════════════════════════════

describe('fixMissingRateLimit', () => {
  it('adds rate limiter to auth route', () => {
    const code = [
      "import express from 'express';",
      '',
      'const app = express();',
      '',
      "app.post('/login', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const finding = makeFinding({
      id: 'RATE_LIMIT_AUTH_ENDPOINT',
      severity: 'medium',
      type: 'Missing Rate Limiting',
      line: 5,
    });

    const result = fixMissingRateLimit(code, finding);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain("import rateLimit from 'express-rate-limit';");
    expect(result!.fixed).toContain('const authLimiter = rateLimit({');
    expect(result!.fixed).toContain('windowMs: 15 * 60 * 1000');
    expect(result!.fixed).toContain('max: 10');
    expect(result!.fixed).toContain('authLimiter,');
    expect(result!.description).toContain('rate limiting');
  });

  it('adds rate limiter to register route', () => {
    const code = [
      "import express from 'express';",
      'const app = express();',
      "app.post('/register', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const finding = makeFinding({
      id: 'RATE_LIMIT_AUTH_ENDPOINT',
      line: 3,
    });

    const result = fixMissingRateLimit(code, finding);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('authLimiter');
  });

  it('adds rate limiter to /api/auth/login route', () => {
    const code = [
      "import express from 'express';",
      'const app = express();',
      "app.post('/api/auth/login', handleLogin);",
    ].join('\n');

    const finding = makeFinding({
      id: 'RATE_LIMIT_AUTH_ENDPOINT',
      line: 3,
    });

    const result = fixMissingRateLimit(code, finding);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('authLimiter');
  });

  it('uses require() for CJS-style files', () => {
    const code = [
      "const express = require('express');",
      'const app = express();',
      "app.post('/login', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const finding = makeFinding({
      id: 'RATE_LIMIT_AUTH_ENDPOINT',
      line: 3,
    });

    const result = fixMissingRateLimit(code, finding);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain("const rateLimit = require('express-rate-limit');");
  });

  it('does not duplicate import when express-rate-limit already imported', () => {
    const code = [
      "import express from 'express';",
      "import rateLimit from 'express-rate-limit';",
      '',
      'const app = express();',
      "app.post('/login', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const finding = makeFinding({
      id: 'RATE_LIMIT_AUTH_ENDPOINT',
      line: 5,
    });

    const result = fixMissingRateLimit(code, finding);

    expect(result).not.toBeNull();
    const rateLimitImports = result!.fixed.match(/import rateLimit/g);
    expect(rateLimitImports).toHaveLength(1);
  });

  it('reuses existing limiter variable name', () => {
    const code = [
      "import express from 'express';",
      "import rateLimit from 'express-rate-limit';",
      '',
      'const loginLimiter = rateLimit({ windowMs: 60000, max: 5 });',
      '',
      'const app = express();',
      "app.post('/login', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const finding = makeFinding({
      id: 'RATE_LIMIT_AUTH_ENDPOINT',
      line: 7,
    });

    const result = fixMissingRateLimit(code, finding);

    expect(result).not.toBeNull();
    // Should use the existing limiter name
    expect(result!.fixed).toContain('loginLimiter,');
    // Should NOT add another rate limiter config block
    const configBlocks = result!.fixed.match(/const \w+Limiter = rateLimit\(/g);
    expect(configBlocks).toHaveLength(1);
  });

  it('returns null for non-auth routes', () => {
    const code = [
      "import express from 'express';",
      'const app = express();',
      "app.post('/api/users', (req, res) => { res.send('ok'); });",
    ].join('\n');

    const finding = makeFinding({
      id: 'RATE_LIMIT_AUTH_ENDPOINT',
      line: 3,
    });

    const result = fixMissingRateLimit(code, finding);
    expect(result).toBeNull();
  });

  it('returns null for out-of-bounds line number', () => {
    const code = "app.post('/login', handler);";

    const finding = makeFinding({
      id: 'RATE_LIMIT_AUTH_ENDPOINT',
      line: 999,
    });

    const result = fixMissingRateLimit(code, finding);
    expect(result).toBeNull();
  });
});
