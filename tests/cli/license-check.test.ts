import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock config manager
vi.mock('../../src/config/manager.js', () => ({
  loadGlobalConfig: vi.fn(),
  saveGlobalConfig: vi.fn(),
}));

import { checkLicense } from '../../src/cli/license-check.js';
import { loadGlobalConfig, saveGlobalConfig } from '../../src/config/manager.js';

const mockLoadGlobalConfig = vi.mocked(loadGlobalConfig);
const mockSaveGlobalConfig = vi.mocked(saveGlobalConfig);

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

describe('checkLicense', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockSaveGlobalConfig.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── No license key ──────────────────────────────────────────────────────────

  it('returns invalid with reason "No license key" when no key is set', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    const result = await checkLicense();

    expect(result.valid).toBe(false);
    expect(result.tier).toBe('free');
    expect(result.reason).toBe('No license key');
  });

  // ── Fresh cache (< 30 days) ─────────────────────────────────────────────────

  it('returns valid for fresh cache (< 30 days old)', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      licenseValidatedAt: daysAgo(5),
      licenseTier: 'pro',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    const result = await checkLicense();

    expect(result.valid).toBe(true);
    expect(result.tier).toBe('pro');
    expect(result.reason).toBeUndefined();
  });

  it('returns valid for cache validated 29 days ago', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      licenseValidatedAt: daysAgo(29),
      licenseTier: 'team',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    const result = await checkLicense();

    expect(result.valid).toBe(true);
    expect(result.tier).toBe('team');
  });

  it('does not make a network request when cache is fresh', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      licenseValidatedAt: daysAgo(1),
      licenseTier: 'pro',
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch');

    await checkLicense();

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // ── Expired cache (> 30 days) + offline ─────────────────────────────────────

  it('returns invalid with expired-cache reason when offline and cache > 30 days old', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      licenseValidatedAt: daysAgo(31),
      licenseTier: 'pro',
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));

    const result = await checkLicense();

    expect(result.valid).toBe(false);
    expect(result.tier).toBe('pro');
    expect(result.reason).toContain('License cache expired');
    expect(result.reason).toContain('re-validate');
  });

  // ── Expired cache + successful online re-validation ─────────────────────────

  it('re-validates online when cache is expired and updates cache', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      licenseValidatedAt: daysAgo(35),
      licenseTier: 'pro',
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, tier: 'pro' }),
    } as Response);

    const result = await checkLicense();

    expect(result.valid).toBe(true);
    expect(result.tier).toBe('pro');
    expect(result.reason).toBeUndefined();

    // Cache should be updated
    expect(mockSaveGlobalConfig).toHaveBeenCalledOnce();
    const savedConfig = mockSaveGlobalConfig.mock.calls[0]![0];
    expect(typeof savedConfig.licenseValidatedAt).toBe('string');
    expect(new Date(savedConfig.licenseValidatedAt!).getTime()).toBeGreaterThan(
      Date.now() - 5000,
    );
  });

  it('uses new tier from re-validation response', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      licenseValidatedAt: daysAgo(40),
      licenseTier: 'pro',
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, tier: 'agency' }),
    } as Response);

    const result = await checkLicense();

    expect(result.tier).toBe('agency');
    expect(mockSaveGlobalConfig.mock.calls[0]![0].licenseTier).toBe('agency');
  });

  // ── No licenseValidatedAt (first-time) ─────────────────────────────────────

  it('returns valid with tier "unknown" when no validation timestamp and offline (first-time grace)', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Network error'));

    const result = await checkLicense();

    expect(result.valid).toBe(true);
    expect(result.tier).toBe('unknown');
  });

  it('validates online and caches when no validation timestamp and online', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      apiEndpoint: 'https://api.shipsafe.org',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ valid: true, tier: 'pro' }),
    } as Response);

    const result = await checkLicense();

    expect(result.valid).toBe(true);
    expect(result.tier).toBe('pro');

    // Should update cache
    expect(mockSaveGlobalConfig).toHaveBeenCalledOnce();
    const savedConfig = mockSaveGlobalConfig.mock.calls[0]![0];
    expect(savedConfig.licenseValidatedAt).toBeDefined();
    expect(savedConfig.licenseTier).toBe('pro');
  });

  it('returns valid: unknown tier when no apiEndpoint and no validation timestamp', async () => {
    mockLoadGlobalConfig.mockResolvedValue({
      licenseKey: 'MY-KEY',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    const result = await checkLicense();

    expect(result.valid).toBe(true);
    expect(result.tier).toBe('unknown');
    expect(mockSaveGlobalConfig).not.toHaveBeenCalled();
  });
});
