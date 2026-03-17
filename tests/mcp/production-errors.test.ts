import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock dependencies before importing handler
vi.mock('../../src/config/manager.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/config/manager.js')>('../../src/config/manager.js');
  return {
    loadConfig: vi.fn(),
    getApiEndpoint: actual.getApiEndpoint,
  };
});

import { handleProductionErrors } from '../../src/mcp/tools/production-errors.js';
import { loadConfig } from '../../src/config/manager.js';

const mockedLoadConfig = vi.mocked(loadConfig);

// Store the original fetch
const originalFetch = globalThis.fetch;

describe('handleProductionErrors', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedLoadConfig.mockResolvedValue({
      projectId: 'proj_123',
      apiEndpoint: 'https://api.shipsafe.dev',
      licenseKey: 'sk_test_abc',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('returns production errors from API', async () => {
    const mockErrors = [
      {
        id: 'err_1',
        message: 'TypeError: Cannot read property "foo" of undefined',
        severity: 'critical',
        status: 'open',
        stack_trace: 'at handler (/src/api/route.ts:42)',
        root_cause: 'Null check missing',
        suggested_fix: 'Add optional chaining',
        first_seen: '2026-03-15T10:00:00Z',
        last_seen: '2026-03-16T08:00:00Z',
        count: 15,
      },
    ];

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ errors: mockErrors, count: 1 }),
    });

    const result = await handleProductionErrors({});

    expect(result.errors).toEqual(mockErrors);
    expect(result.total).toBe(1);
    expect(result.warning).toBeUndefined();
  });

  it('filters by severity', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ errors: [], count: 0 }),
    });

    await handleProductionErrors({ severity: 'critical' });

    const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
    const url = fetchCall[0] as string;
    expect(url).toContain('severity=critical');
  });

  it('filters by status', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ errors: [], count: 0 }),
    });

    await handleProductionErrors({ status: 'resolved' });

    const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
    const url = fetchCall[0] as string;
    expect(url).toContain('status=resolved');
  });

  it('defaults to severity=all and status=open', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ errors: [], count: 0 }),
    });

    await handleProductionErrors({});

    const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
    const url = fetchCall[0] as string;
    expect(url).toContain('severity=all');
    expect(url).toContain('status=open');
  });

  it('returns empty array when API unavailable', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await handleProductionErrors({});

    expect(result.errors).toEqual([]);
    expect(result.total).toBe(0);
    expect(result.warning).toContain('Failed to fetch production errors');
    expect(result.warning).toContain('ECONNREFUSED');
  });

  it('returns empty array when no project ID configured', async () => {
    mockedLoadConfig.mockResolvedValue({
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    const result = await handleProductionErrors({});

    expect(result.errors).toEqual([]);
    expect(result.total).toBe(0);
    expect(result.warning).toContain('No project ID configured');
  });

  it('uses default endpoint when no API endpoint configured', async () => {
    mockedLoadConfig.mockResolvedValue({
      projectId: 'proj_123',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ errors: [], count: 0 }),
    });

    const result = await handleProductionErrors({});

    expect(result.errors).toEqual([]);
    expect(result.total).toBe(0);
    // Should have used default endpoint
    const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
    const url = fetchCall[0] as string;
    expect(url).toContain('shipsafe-m9nc6.ondigitalocean.app');
  });

  it('returns warning when API returns non-OK response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    });

    const result = await handleProductionErrors({});

    expect(result.errors).toEqual([]);
    expect(result.total).toBe(0);
    expect(result.warning).toContain('API returned 500');
  });

  it('includes Authorization header when licenseKey is set', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ errors: [], count: 0 }),
    });

    await handleProductionErrors({});

    const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
    const options = fetchCall[1] as RequestInit;
    expect((options.headers as Record<string, string>).Authorization).toBe('Bearer sk_test_abc');
  });

  it('omits Authorization header when no licenseKey', async () => {
    mockedLoadConfig.mockResolvedValue({
      projectId: 'proj_123',
      apiEndpoint: 'https://api.shipsafe.dev',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ errors: [], count: 0 }),
    });

    await handleProductionErrors({});

    const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
    const options = fetchCall[1] as RequestInit;
    expect((options.headers as Record<string, string>).Authorization).toBeUndefined();
  });
});
