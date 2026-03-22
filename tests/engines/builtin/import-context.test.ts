import { describe, it, expect } from 'vitest';
import { extractImportContext } from '../../../src/engines/builtin/import-context.js';

describe('extractImportContext', () => {
  describe('ES6 imports', () => {
    it('detects auth imports (passport)', () => {
      const ctx = extractImportContext(
        `import passport from 'passport';\nimport express from 'express';`,
        'server.ts',
      );
      expect(ctx.hasAuthImport).toBe(true);
      expect(ctx.imports).toContain('passport');
    });

    it('detects auth imports (@clerk/nextjs)', () => {
      const ctx = extractImportContext(
        `import { auth } from '@clerk/nextjs';`,
        'page.tsx',
      );
      expect(ctx.hasAuthImport).toBe(true);
    });

    it('detects auth imports (next-auth)', () => {
      const ctx = extractImportContext(
        `import NextAuth from 'next-auth';`,
        'auth.ts',
      );
      expect(ctx.hasAuthImport).toBe(true);
    });

    it('detects auth imports (lucia)', () => {
      const ctx = extractImportContext(
        `import { lucia } from 'lucia';`,
        'auth.ts',
      );
      expect(ctx.hasAuthImport).toBe(true);
    });

    it('detects stripe imports', () => {
      const ctx = extractImportContext(
        `import Stripe from 'stripe';`,
        'billing.ts',
      );
      expect(ctx.hasStripeImport).toBe(true);
    });

    it('detects sanitization imports (DOMPurify)', () => {
      const ctx = extractImportContext(
        `import DOMPurify from 'dompurify';`,
        'render.tsx',
      );
      expect(ctx.hasSanitizationImport).toBe(true);
    });

    it('detects sanitization imports (sanitize-html)', () => {
      const ctx = extractImportContext(
        `import sanitizeHtml from 'sanitize-html';`,
        'content.ts',
      );
      expect(ctx.hasSanitizationImport).toBe(true);
    });

    it('detects sanitization imports (isomorphic-dompurify)', () => {
      const ctx = extractImportContext(
        `import DOMPurify from 'isomorphic-dompurify';`,
        'render.tsx',
      );
      expect(ctx.hasSanitizationImport).toBe(true);
    });

    it('detects validation imports (zod)', () => {
      const ctx = extractImportContext(
        `import { z } from 'zod';`,
        'schema.ts',
      );
      expect(ctx.hasValidationImport).toBe(true);
    });

    it('detects validation imports (joi)', () => {
      const ctx = extractImportContext(
        `import Joi from 'joi';`,
        'validation.ts',
      );
      expect(ctx.hasValidationImport).toBe(true);
    });

    it('detects ORM imports (prisma)', () => {
      const ctx = extractImportContext(
        `import { PrismaClient } from '@prisma/client';`,
        'db.ts',
      );
      expect(ctx.hasORMImport).toBe(true);
    });

    it('detects ORM imports (drizzle-orm)', () => {
      const ctx = extractImportContext(
        `import { drizzle } from 'drizzle-orm';`,
        'db.ts',
      );
      expect(ctx.hasORMImport).toBe(true);
    });

    it('detects crypto imports (bcrypt)', () => {
      const ctx = extractImportContext(
        `import bcrypt from 'bcrypt';`,
        'auth.ts',
      );
      expect(ctx.hasCryptoImport).toBe(true);
    });

    it('detects rate limit imports', () => {
      const ctx = extractImportContext(
        `import rateLimit from 'express-rate-limit';`,
        'middleware.ts',
      );
      expect(ctx.hasRateLimitImport).toBe(true);
    });

    it('detects CSRF imports (csurf)', () => {
      const ctx = extractImportContext(
        `import csurf from 'csurf';`,
        'middleware.ts',
      );
      expect(ctx.hasCSRFImport).toBe(true);
    });

    it('detects CSRF imports (csrf-csrf)', () => {
      const ctx = extractImportContext(
        `import { doubleCsrf } from 'csrf-csrf';`,
        'middleware.ts',
      );
      expect(ctx.hasCSRFImport).toBe(true);
    });

    it('detects CSRF imports (lusca)', () => {
      const ctx = extractImportContext(
        `import lusca from 'lusca';`,
        'middleware.ts',
      );
      expect(ctx.hasCSRFImport).toBe(true);
    });

    it('detects helmet imports', () => {
      const ctx = extractImportContext(
        `import helmet from 'helmet';`,
        'server.ts',
      );
      expect(ctx.hasHelmetImport).toBe(true);
    });

    it('returns false for unrelated imports', () => {
      const ctx = extractImportContext(
        `import express from 'express';\nimport { join } from 'path';`,
        'server.ts',
      );
      expect(ctx.hasAuthImport).toBe(false);
      expect(ctx.hasStripeImport).toBe(false);
      expect(ctx.hasSanitizationImport).toBe(false);
      expect(ctx.hasValidationImport).toBe(false);
      expect(ctx.hasORMImport).toBe(false);
      expect(ctx.hasCryptoImport).toBe(false);
      expect(ctx.hasRateLimitImport).toBe(false);
      expect(ctx.hasCSRFImport).toBe(false);
      expect(ctx.hasHelmetImport).toBe(false);
      expect(ctx.imports).toEqual(['express', 'path']);
    });
  });

  describe('CommonJS requires', () => {
    it('detects auth require (passport)', () => {
      const ctx = extractImportContext(
        `const passport = require('passport');`,
        'server.js',
      );
      expect(ctx.hasAuthImport).toBe(true);
    });

    it('detects helmet require', () => {
      const ctx = extractImportContext(
        `const helmet = require('helmet');`,
        'server.js',
      );
      expect(ctx.hasHelmetImport).toBe(true);
    });

    it('detects rate limit require', () => {
      const ctx = extractImportContext(
        `const rateLimit = require('express-rate-limit');`,
        'middleware.js',
      );
      expect(ctx.hasRateLimitImport).toBe(true);
    });

    it('detects zod require', () => {
      const ctx = extractImportContext(
        `const { z } = require('zod');`,
        'validation.js',
      );
      expect(ctx.hasValidationImport).toBe(true);
    });

    it('detects stripe require', () => {
      const ctx = extractImportContext(
        `const Stripe = require('stripe');`,
        'billing.js',
      );
      expect(ctx.hasStripeImport).toBe(true);
    });
  });

  describe('dynamic imports', () => {
    it('detects dynamic import of dompurify', () => {
      const ctx = extractImportContext(
        `const DOMPurify = await import('dompurify');`,
        'render.ts',
      );
      expect(ctx.hasSanitizationImport).toBe(true);
    });

    it('detects dynamic import of bcrypt', () => {
      const ctx = extractImportContext(
        `const bcrypt = await import('bcrypt');`,
        'auth.ts',
      );
      expect(ctx.hasCryptoImport).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('handles empty file content', () => {
      const ctx = extractImportContext('', 'empty.ts');
      expect(ctx.imports).toEqual([]);
      expect(ctx.hasAuthImport).toBe(false);
    });

    it('handles file with no imports', () => {
      const ctx = extractImportContext(
        `const x = 5;\nfunction foo() { return x; }`,
        'plain.ts',
      );
      expect(ctx.imports).toEqual([]);
    });

    it('handles multiple imports of the same category', () => {
      const ctx = extractImportContext(
        `import { z } from 'zod';\nimport Joi from 'joi';`,
        'schema.ts',
      );
      expect(ctx.hasValidationImport).toBe(true);
      expect(ctx.imports).toContain('zod');
      expect(ctx.imports).toContain('joi');
    });

    it('detects @auth/ scoped packages', () => {
      const ctx = extractImportContext(
        `import { signIn } from '@auth/core';`,
        'auth.ts',
      );
      expect(ctx.hasAuthImport).toBe(true);
    });
  });
});
