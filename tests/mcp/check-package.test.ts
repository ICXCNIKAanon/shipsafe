import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  handleCheckPackage,
  editDistance,
  checkTyposquat,
} from '../../src/mcp/tools/check-package.js';

// Store the original fetch
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('editDistance', () => {
  it('returns 0 for identical strings', () => {
    expect(editDistance('lodash', 'lodash')).toBe(0);
  });

  it('returns correct distance for single character difference', () => {
    expect(editDistance('lodash', 'lodasx')).toBe(1);
  });

  it('returns correct distance for two character difference', () => {
    expect(editDistance('lodassh', 'lodash')).toBe(1);
  });

  it('returns string length for empty comparison', () => {
    expect(editDistance('abc', '')).toBe(3);
    expect(editDistance('', 'abc')).toBe(3);
  });
});

describe('checkTyposquat', () => {
  it('flags "lodassh" as typosquat of "lodash"', () => {
    const result = checkTyposquat('lodassh');
    expect(result.isTyposquat).toBe(true);
    expect(result.similarTo).toBe('lodash');
  });

  it('flags "recat" as typosquat of "react"', () => {
    const result = checkTyposquat('recat');
    expect(result.isTyposquat).toBe(true);
    expect(result.similarTo).toBe('react');
  });

  it('does not flag exact match as typosquat', () => {
    const result = checkTyposquat('react');
    expect(result.isTyposquat).toBe(false);
  });

  it('does not flag unrelated package name', () => {
    const result = checkTyposquat('my-custom-package');
    expect(result.isTyposquat).toBe(false);
  });

  it('flags "expresss" as typosquat of "express"', () => {
    const result = checkTyposquat('expresss');
    expect(result.isTyposquat).toBe(true);
    expect(result.similarTo).toBe('express');
  });
});

describe('handleCheckPackage', () => {
  it('returns safe=true for known safe packages', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        name: 'lodash',
        'dist-tags': { latest: '4.17.21' },
        license: 'MIT',
        time: {
          modified: new Date().toISOString(),
          '4.17.21': new Date().toISOString(),
        },
        versions: {},
      }),
    });

    const result = await handleCheckPackage({ name: 'lodash' });

    expect(result.safe).toBe(true);
    expect(result.name).toBe('lodash');
    expect(result.license).toBe('MIT');
    expect(result.license_compatible).toBe(true);
    expect(result.maintained).toBe(true);
    expect(result.typosquat_warning).toBe(false);
    expect(result.recommendation).toContain('appears safe');
  });

  it('detects typosquatting', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        name: 'lodassh',
        'dist-tags': { latest: '1.0.0' },
        license: 'MIT',
        time: {
          modified: new Date().toISOString(),
        },
        versions: {},
      }),
    });

    const result = await handleCheckPackage({ name: 'lodassh' });

    expect(result.typosquat_warning).toBe(true);
    expect(result.safe).toBe(false);
    expect(result.recommendation).toContain('TYPOSQUAT WARNING');
    expect(result.recommendation).toContain('lodash');
  });

  it('reports unmaintained packages', async () => {
    const threeYearsAgo = new Date();
    threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        name: 'old-package',
        'dist-tags': { latest: '1.0.0' },
        license: 'MIT',
        time: {
          modified: threeYearsAgo.toISOString(),
          '1.0.0': threeYearsAgo.toISOString(),
        },
        versions: {},
      }),
    });

    const result = await handleCheckPackage({ name: 'old-package' });

    expect(result.maintained).toBe(false);
    expect(result.safe).toBe(false);
    expect(result.recommendation).toContain('not been updated in over 2 years');
  });

  it('returns package metadata', async () => {
    const publishDate = '2026-03-10T12:00:00Z';
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        name: 'zod',
        'dist-tags': { latest: '3.24.1' },
        license: 'MIT',
        time: {
          modified: publishDate,
          '3.24.1': publishDate,
        },
        versions: {},
      }),
    });

    const result = await handleCheckPackage({ name: 'zod' });

    expect(result.name).toBe('zod');
    expect(result.version).toBe('3.24.1');
    expect(result.license).toBe('MIT');
    expect(result.last_publish).toBe(publishDate);
  });

  it('handles package not found on registry', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    });

    const result = await handleCheckPackage({ name: 'nonexistent-pkg-xyz' });

    expect(result.safe).toBe(false);
    expect(result.recommendation).toContain('not found on npm registry');
  });

  it('handles typosquat of not-found package', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    });

    const result = await handleCheckPackage({ name: 'expresss' });

    expect(result.safe).toBe(false);
    expect(result.typosquat_warning).toBe(true);
    expect(result.recommendation).toContain('possible typosquat');
  });

  it('handles network errors gracefully', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ENOTFOUND'));

    const result = await handleCheckPackage({ name: 'some-pkg' });

    expect(result.safe).toBe(false);
    expect(result.recommendation).toContain('Failed to fetch package info');
  });

  it('returns unsupported message for non-npm registries', async () => {
    const result = await handleCheckPackage({ name: 'requests', registry: 'pip' });

    expect(result.safe).toBe(false);
    expect(result.recommendation).toContain('not yet supported');
  });

  it('flags incompatible license', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        name: 'gpl-pkg',
        'dist-tags': { latest: '1.0.0' },
        license: 'GPL-3.0',
        time: {
          modified: new Date().toISOString(),
        },
        versions: {},
      }),
    });

    const result = await handleCheckPackage({ name: 'gpl-pkg' });

    expect(result.license_compatible).toBe(false);
    expect(result.safe).toBe(false);
    expect(result.recommendation).toContain('may not be compatible');
  });

  it('uses specified version', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        name: 'lodash',
        'dist-tags': { latest: '4.17.21' },
        license: 'MIT',
        time: {
          modified: new Date().toISOString(),
          '4.17.20': new Date().toISOString(),
        },
        versions: {},
      }),
    });

    const result = await handleCheckPackage({ name: 'lodash', version: '4.17.20' });

    expect(result.version).toBe('4.17.20');
  });

  it('flags deprecated versions', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        name: 'some-pkg',
        'dist-tags': { latest: '2.0.0' },
        license: 'MIT',
        time: {
          modified: new Date().toISOString(),
          '1.0.0': new Date().toISOString(),
        },
        versions: {
          '1.0.0': { deprecated: 'Use v2 instead' },
        },
      }),
    });

    const result = await handleCheckPackage({ name: 'some-pkg', version: '1.0.0' });

    expect(result.safe).toBe(false);
    expect(result.recommendation).toContain('deprecated');
  });
});
