import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanResult, ScannerAvailability } from '../../src/types.js';

// Mock dependencies before importing handlers
vi.mock('../../src/engines/pattern/index.js', () => ({
  runPatternEngine: vi.fn(),
  getAvailableScanners: vi.fn(),
}));

vi.mock('../../src/config/manager.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/config/manager.js')>('../../src/config/manager.js');
  return {
    getProjectName: vi.fn(),
    loadConfig: vi.fn(),
    getApiEndpoint: actual.getApiEndpoint,
  };
});

vi.mock('../../src/hooks/installer.js', () => ({
  checkHooksInstalled: vi.fn(),
}));

import { handleScan } from '../../src/mcp/tools/scan.js';
import { handleStatus } from '../../src/mcp/tools/status.js';
import { runPatternEngine, getAvailableScanners } from '../../src/engines/pattern/index.js';
import { getProjectName, loadConfig } from '../../src/config/manager.js';
import { checkHooksInstalled } from '../../src/hooks/installer.js';

const mockedRunPatternEngine = vi.mocked(runPatternEngine);
const mockedGetAvailableScanners = vi.mocked(getAvailableScanners);
const mockedGetProjectName = vi.mocked(getProjectName);
const mockedLoadConfig = vi.mocked(loadConfig);
const mockedCheckHooksInstalled = vi.mocked(checkHooksInstalled);

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    status: 'pass',
    score: 'A',
    findings: [],
    scan_duration_ms: 42,
    ...overrides,
  };
}

describe('handleScan', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedRunPatternEngine.mockResolvedValue(makeScanResult());
  });

  it('calls pattern engine with default scope "all"', async () => {
    await handleScan({});

    expect(mockedRunPatternEngine).toHaveBeenCalledOnce();
    expect(mockedRunPatternEngine).toHaveBeenCalledWith({
      targetPath: process.cwd(),
      scope: 'all',
    });
  });

  it('calls pattern engine with scope "all" when specified', async () => {
    await handleScan({ scope: 'all' });

    expect(mockedRunPatternEngine).toHaveBeenCalledWith({
      targetPath: process.cwd(),
      scope: 'all',
    });
  });

  it('calls pattern engine with file scope when specified', async () => {
    await handleScan({ scope: 'file:src/index.ts' });

    expect(mockedRunPatternEngine).toHaveBeenCalledWith({
      targetPath: process.cwd(),
      scope: 'file:src/index.ts',
    });
  });

  it('returns object matching ScanResult shape', async () => {
    const expected = makeScanResult({
      status: 'fail',
      score: 'D',
      findings: [
        {
          id: 'test_1',
          engine: 'pattern',
          severity: 'high',
          type: 'hardcoded-secret',
          file: 'config.ts',
          line: 10,
          description: 'Hardcoded API key',
          fix_suggestion: 'Use environment variable',
          auto_fixable: false,
        },
      ],
      scan_duration_ms: 150,
    });
    mockedRunPatternEngine.mockResolvedValue(expected);

    const result = await handleScan({});

    expect(result).toEqual(expected);
    expect(result).toHaveProperty('status');
    expect(result).toHaveProperty('score');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('scan_duration_ms');
  });

  it('accepts fix param without error (Phase 1 stub)', async () => {
    await handleScan({ fix: true });

    expect(mockedRunPatternEngine).toHaveBeenCalledOnce();
  });
});

describe('handleStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetProjectName.mockReturnValue('my-project');
    mockedCheckHooksInstalled.mockResolvedValue(true);
    mockedGetAvailableScanners.mockResolvedValue({
      semgrep: true,
      gitleaks: true,
      trivy: false,
    });
    mockedLoadConfig.mockResolvedValue({
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });
  });

  it('returns object with project name', async () => {
    const result = await handleStatus();

    expect(result.project).toBe('my-project');
  });

  it('returns hooks installation status', async () => {
    const result = await handleStatus();

    expect(result.hooks_installed).toBe(true);
  });

  it('returns hooks_installed false when hooks not installed', async () => {
    mockedCheckHooksInstalled.mockResolvedValue(false);

    const result = await handleStatus();

    expect(result.hooks_installed).toBe(false);
  });

  it('returns available scanners', async () => {
    const result = await handleStatus();

    expect(result.scanners).toEqual({
      semgrep: true,
      gitleaks: true,
      trivy: false,
    });
  });

  it('returns correct shape matching McpProjectStatus', async () => {
    const result = await handleStatus();

    expect(result).toHaveProperty('project');
    expect(result).toHaveProperty('hooks_installed');
    expect(result).toHaveProperty('scanners');
    expect(result).toHaveProperty('license');
    expect(typeof result.project).toBe('string');
    expect(typeof result.hooks_installed).toBe('boolean');
    expect(typeof result.scanners).toBe('object');
    expect(typeof result.license).toBe('string');
  });

  it('returns "free" license when no licenseKey', async () => {
    const result = await handleStatus();

    expect(result.license).toBe('free');
  });

  it('returns "pro" license when licenseKey is set', async () => {
    mockedLoadConfig.mockResolvedValue({
      licenseKey: 'sk_test_123',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    const result = await handleStatus();

    expect(result.license).toBe('pro');
  });
});
