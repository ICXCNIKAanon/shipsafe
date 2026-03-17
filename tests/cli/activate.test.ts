import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock chalk to return plain strings for testability
vi.mock('chalk', () => {
  const passthrough = (str: string) => str;
  const chainable: any = new Proxy(passthrough, {
    get: () => chainable,
    apply: (_target: any, _thisArg: any, args: any[]) => args[0],
  });
  return { default: chainable };
});

// Mock config manager
vi.mock('../../src/config/manager.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/config/manager.js')>('../../src/config/manager.js');
  return {
    loadGlobalConfig: vi.fn(),
    saveGlobalConfig: vi.fn(),
    getApiEndpoint: actual.getApiEndpoint,
  };
});

import { handleActivateAction } from '../../src/cli/activate.js';
import { loadGlobalConfig, saveGlobalConfig } from '../../src/config/manager.js';

const mockLoadGlobalConfig = vi.mocked(loadGlobalConfig);
const mockSaveGlobalConfig = vi.mocked(saveGlobalConfig);

describe('handleActivateAction', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    mockSaveGlobalConfig.mockResolvedValue(undefined);
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    vi.restoreAllMocks();
  });

  it('saves licenseValidatedAt and licenseTier on successful API validation', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, tier: 'pro', expires_at: '2027-01-01', project_limit: 10 }),
    } as Response);

    await handleActivateAction('VALID-KEY-123');

    // Should save twice: once with just the key, once with validation metadata
    expect(mockSaveGlobalConfig).toHaveBeenCalledTimes(2);

    const secondCall = mockSaveGlobalConfig.mock.calls[1]![0];
    expect(secondCall).toMatchObject({
      licenseKey: 'VALID-KEY-123',
      licenseTier: 'pro',
    });
    expect(typeof secondCall.licenseValidatedAt).toBe('string');
    // Ensure the timestamp is a valid ISO date
    expect(new Date(secondCall.licenseValidatedAt!).getTime()).toBeGreaterThan(0);
  });

  it('prints success message after successful online validation', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, tier: 'pro', expires_at: '2027-01-01', project_limit: 10 }),
    } as Response);

    await handleActivateAction('VALID-KEY-123');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('ShipSafe Pro activated successfully!');
  });

  it('works offline — saves key without validation timestamp', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));

    await handleActivateAction('MY-LICENSE-KEY');

    // Should save the license key (first call)
    const firstCall = mockSaveGlobalConfig.mock.calls[0]![0];
    expect(firstCall).toMatchObject({ licenseKey: 'MY-LICENSE-KEY' });

    // Should NOT have saved licenseValidatedAt (only one save call — the initial key save)
    expect(mockSaveGlobalConfig).toHaveBeenCalledTimes(1);

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Could not validate online. License saved locally.');
  });

  it('uses default endpoint when no apiEndpoint is configured', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, tier: 'pro', expires_at: '2027-01-01', project_limit: 10 }),
    } as Response);

    await handleActivateAction('MY-LICENSE-KEY');

    // Should attempt validation against default endpoint
    expect(fetchSpy).toHaveBeenCalledOnce();
    expect(fetchSpy.mock.calls[0]![0]).toContain('/v1/license/validate');

    // Should save key + validation metadata
    expect(mockSaveGlobalConfig).toHaveBeenCalledTimes(2);
    const secondCall = mockSaveGlobalConfig.mock.calls[1]![0];
    expect(secondCall.licenseKey).toBe('MY-LICENSE-KEY');
    expect(secondCall.licenseTier).toBe('pro');
  });

  it('prints error and rolls back when API returns invalid key', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      json: async () => ({ message: 'License key not found' }),
    } as Response);

    await handleActivateAction('BAD-KEY');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('License validation failed');

    // Second save call should roll back the key
    expect(mockSaveGlobalConfig).toHaveBeenCalledTimes(2);
    const rollbackCall = mockSaveGlobalConfig.mock.calls[1]![0];
    expect(rollbackCall.licenseKey).toBeUndefined();
  });

  it('rolls back when API returns valid:false', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ valid: false, tier: 'free', expires_at: '', project_limit: 0 }),
    } as Response);

    await handleActivateAction('INVALID-KEY');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('not valid');

    const rollbackCall = mockSaveGlobalConfig.mock.calls[1]![0];
    expect(rollbackCall.licenseKey).toBeUndefined();
  });
});
