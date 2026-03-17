import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../../src/config/manager.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/config/manager.js')>('../../src/config/manager.js');
  return {
    loadConfig: vi.fn(),
    getApiEndpoint: actual.getApiEndpoint,
  };
});

import { handleVerifyResolution } from '../../src/mcp/tools/verify-resolution.js';
import { loadConfig } from '../../src/config/manager.js';

const mockedLoadConfig = vi.mocked(loadConfig);
const originalFetch = globalThis.fetch;

describe('handleVerifyResolution', () => {
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

  it('returns resolved status from API', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'resolved',
        last_occurrence: '2026-03-15T10:00:00Z',
        hours_since_last: 48,
        confidence: 0.95,
      }),
    });

    const result = await handleVerifyResolution({ error_id: 'err_1' });

    expect(result.error_id).toBe('err_1');
    expect(result.status).toBe('resolved');
    expect(result.confidence).toBe(0.95);
    expect(result.hours_since_last).toBe(48);
  });

  it('returns recurring status from API', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'recurring',
        last_occurrence: '2026-03-17T01:00:00Z',
        hours_since_last: 1,
        confidence: 0.99,
      }),
    });

    const result = await handleVerifyResolution({ error_id: 'err_2' });

    expect(result.status).toBe('recurring');
    expect(result.confidence).toBe(0.99);
  });

  it('returns unknown when no project ID configured', async () => {
    mockedLoadConfig.mockResolvedValue({
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    const result = await handleVerifyResolution({ error_id: 'err_3' });

    expect(result.status).toBe('unknown');
    expect(result.confidence).toBe(0);
  });

  it('returns unknown when API returns non-OK', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    });

    const result = await handleVerifyResolution({ error_id: 'err_4' });

    expect(result.status).toBe('unknown');
    expect(result.confidence).toBe(0);
  });

  it('returns unknown on network error', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await handleVerifyResolution({ error_id: 'err_5' });

    expect(result.status).toBe('unknown');
    expect(result.confidence).toBe(0);
  });

  it('uses default endpoint when no apiEndpoint in config', async () => {
    mockedLoadConfig.mockResolvedValue({
      projectId: 'proj_123',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'resolved',
        last_occurrence: '2026-03-15T10:00:00Z',
        hours_since_last: 48,
        confidence: 0.9,
      }),
    });

    const result = await handleVerifyResolution({ error_id: 'err_6' });

    expect(result.status).toBe('resolved');
    const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
    const url = fetchCall[0] as string;
    expect(url).toContain('localhost:3747');
  });

  it('includes Authorization header when licenseKey is set', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'resolved',
        last_occurrence: '2026-03-15T10:00:00Z',
        hours_since_last: 48,
        confidence: 0.9,
      }),
    });

    await handleVerifyResolution({ error_id: 'err_7' });

    const fetchCall = vi.mocked(globalThis.fetch).mock.calls[0];
    const options = fetchCall[1] as RequestInit;
    expect((options.headers as Record<string, string>).Authorization).toBe('Bearer sk_test_abc');
  });
});
