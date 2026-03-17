import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/config/manager.js', () => ({
  getProjectName: vi.fn(),
  loadConfig: vi.fn(),
}));

vi.mock('../../src/hooks/installer.js', () => ({
  checkHooksInstalled: vi.fn(),
}));

vi.mock('../../src/engines/pattern/index.js', () => ({
  getAvailableScanners: vi.fn(),
}));

import { handleStatus } from '../../src/mcp/tools/status.js';
import { getProjectName, loadConfig } from '../../src/config/manager.js';
import { checkHooksInstalled } from '../../src/hooks/installer.js';
import { getAvailableScanners } from '../../src/engines/pattern/index.js';

const mockedGetProjectName = vi.mocked(getProjectName);
const mockedLoadConfig = vi.mocked(loadConfig);
const mockedCheckHooksInstalled = vi.mocked(checkHooksInstalled);
const mockedGetAvailableScanners = vi.mocked(getAvailableScanners);

describe('handleStatus (MCP tool)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetProjectName.mockReturnValue('test-project');
    mockedLoadConfig.mockResolvedValue({
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });
    mockedCheckHooksInstalled.mockResolvedValue(true);
    mockedGetAvailableScanners.mockResolvedValue({
      semgrep: true,
      gitleaks: false,
      trivy: true,
    });
  });

  it('returns project name', async () => {
    const result = await handleStatus();
    expect(result.project).toBe('test-project');
  });

  it('returns hooks_installed status', async () => {
    const result = await handleStatus();
    expect(result.hooks_installed).toBe(true);
  });

  it('returns scanner availability', async () => {
    const result = await handleStatus();
    expect(result.scanners).toEqual({ semgrep: true, gitleaks: false, trivy: true });
  });

  it('returns free license when no key', async () => {
    const result = await handleStatus();
    expect(result.license).toBe('free');
  });

  it('returns pro license when key is present', async () => {
    mockedLoadConfig.mockResolvedValue({
      licenseKey: 'SS-PRO-abc123',
      monitoring: { enabled: true, error_sample_rate: 1, performance_sample_rate: 1 },
      scan: { ignore_paths: [], ignore_rules: [], severity_threshold: 'high' },
    });

    const result = await handleStatus();
    expect(result.license).toBe('pro');
  });

  it('returns hooks_installed false when not installed', async () => {
    mockedCheckHooksInstalled.mockResolvedValue(false);
    const result = await handleStatus();
    expect(result.hooks_installed).toBe(false);
  });
});
