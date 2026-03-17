import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('chalk', () => {
  const passthrough = (str: string) => str;
  const chainable: any = new Proxy(passthrough, {
    get: () => chainable,
    apply: (_target: any, _thisArg: any, args: any[]) => args[0],
  });
  return { default: chainable };
});

vi.mock('../../src/config/manager.js', () => ({
  loadConfig: vi.fn(),
  getProjectName: vi.fn(),
}));

vi.mock('../../src/engines/pattern/index.js', () => ({
  getAvailableScanners: vi.fn(),
}));

import { handleStatusAction } from '../../src/cli/status.js';
import { loadConfig, getProjectName } from '../../src/config/manager.js';
import { getAvailableScanners } from '../../src/engines/pattern/index.js';

const mockedLoadConfig = vi.mocked(loadConfig);
const mockedGetProjectName = vi.mocked(getProjectName);
const mockedGetAvailableScanners = vi.mocked(getAvailableScanners);

describe('handleStatusAction', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    mockedGetProjectName.mockReturnValue('my-app');
    mockedLoadConfig.mockResolvedValue({
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });
    mockedGetAvailableScanners.mockResolvedValue({
      semgrep: true,
      gitleaks: true,
      trivy: false,
    });
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('displays project name', async () => {
    await handleStatusAction();
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('my-app');
  });

  it('shows Free tier when no license key', async () => {
    await handleStatusAction();
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Free tier');
  });

  it('shows Pro when license key is present', async () => {
    mockedLoadConfig.mockResolvedValue({
      licenseKey: 'SS-PRO-abc123',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    await handleStatusAction();
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Pro');
  });

  it('shows scanner availability', async () => {
    await handleStatusAction();
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('semgrep');
    expect(output).toContain('gitleaks');
    expect(output).toContain('trivy');
  });

  it('displays ShipSafe Status header', async () => {
    await handleStatusAction();
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('ShipSafe Status');
  });
});
