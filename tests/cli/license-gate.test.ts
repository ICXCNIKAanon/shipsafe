import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/cli/license-check.js', () => ({
  checkLicense: vi.fn(),
}));

import { tierHasFeature, gateFeature } from '../../src/cli/license-gate.js';
import { checkLicense } from '../../src/cli/license-check.js';
import type { Feature } from '../../src/cli/license-gate.js';

const mockCheckLicense = vi.mocked(checkLicense);

describe('tierHasFeature', () => {
  it('free tier only has scan', () => {
    expect(tierHasFeature('free', 'scan')).toBe(true);
    expect(tierHasFeature('free', 'autofix')).toBe(false);
    expect(tierHasFeature('free', 'knowledge_graph')).toBe(false);
    expect(tierHasFeature('free', 'monitoring')).toBe(false);
    expect(tierHasFeature('free', 'upload_sourcemaps')).toBe(false);
  });

  it('pro tier adds autofix, knowledge_graph, monitoring, mcp_server', () => {
    expect(tierHasFeature('pro', 'scan')).toBe(true);
    expect(tierHasFeature('pro', 'autofix')).toBe(true);
    expect(tierHasFeature('pro', 'knowledge_graph')).toBe(true);
    expect(tierHasFeature('pro', 'monitoring')).toBe(true);
    expect(tierHasFeature('pro', 'mcp_server')).toBe(true);
    expect(tierHasFeature('pro', 'upload_sourcemaps')).toBe(false);
    expect(tierHasFeature('pro', 'github_app')).toBe(false);
  });

  it('team tier has all features', () => {
    const allFeatures: Feature[] = [
      'scan', 'autofix', 'knowledge_graph', 'monitoring',
      'upload_sourcemaps', 'github_app', 'mcp_server',
    ];
    for (const feature of allFeatures) {
      expect(tierHasFeature('team', feature)).toBe(true);
    }
  });

  it('agency tier has all features', () => {
    const allFeatures: Feature[] = [
      'scan', 'autofix', 'knowledge_graph', 'monitoring',
      'upload_sourcemaps', 'github_app', 'mcp_server',
    ];
    for (const feature of allFeatures) {
      expect(tierHasFeature('agency', feature)).toBe(true);
    }
  });

  it('unknown tier falls back to scan only', () => {
    expect(tierHasFeature('unknown', 'scan')).toBe(true);
    expect(tierHasFeature('unknown', 'autofix')).toBe(false);
  });

  it('unrecognized tier falls back to free', () => {
    expect(tierHasFeature('nonexistent', 'scan')).toBe(true);
    expect(tierHasFeature('nonexistent', 'autofix')).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(tierHasFeature('PRO', 'autofix')).toBe(true);
    expect(tierHasFeature('Pro', 'knowledge_graph')).toBe(true);
  });
});

describe('gateFeature', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('allows feature when tier includes it', async () => {
    mockCheckLicense.mockResolvedValue({ valid: true, tier: 'pro' });

    const result = await gateFeature('autofix');

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe('pro');
    expect(result.reason).toBeUndefined();
  });

  it('denies feature when tier does not include it', async () => {
    mockCheckLicense.mockResolvedValue({ valid: true, tier: 'free' });

    const result = await gateFeature('knowledge_graph');

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe('free');
    expect(result.reason).toContain('higher license tier');
    expect(result.reason).toContain('shipsafe.org/pricing');
  });

  it('allows scan for free tier', async () => {
    mockCheckLicense.mockResolvedValue({ valid: false, tier: 'free' });

    const result = await gateFeature('scan');

    expect(result.allowed).toBe(true);
  });

  it('denies upload_sourcemaps for pro tier', async () => {
    mockCheckLicense.mockResolvedValue({ valid: true, tier: 'pro' });

    const result = await gateFeature('upload_sourcemaps');

    expect(result.allowed).toBe(false);
  });

  it('allows upload_sourcemaps for team tier', async () => {
    mockCheckLicense.mockResolvedValue({ valid: true, tier: 'team' });

    const result = await gateFeature('upload_sourcemaps');

    expect(result.allowed).toBe(true);
  });

  it('propagates exception when checkLicense throws', async () => {
    mockCheckLicense.mockRejectedValue(new Error('fs read failed'));

    await expect(gateFeature('scan')).rejects.toThrow('fs read failed');
  });

  it('uses tier from license even when valid is false', async () => {
    mockCheckLicense.mockResolvedValue({
      valid: false,
      tier: 'pro',
      reason: 'License cache expired',
    });

    const result = await gateFeature('autofix');

    expect(result.allowed).toBe(true);
    expect(result.tier).toBe('pro');
  });
});
