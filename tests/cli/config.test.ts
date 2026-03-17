import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ShipSafeConfig } from '../../src/types.js';

// Mock config manager before importing
vi.mock('../../src/config/manager.js', () => ({
  loadConfig: vi.fn(),
  loadGlobalConfig: vi.fn(),
  saveGlobalConfig: vi.fn(),
  saveProjectConfig: vi.fn(),
}));

import {
  handleConfigList,
  handleConfigGet,
  handleConfigSet,
} from '../../src/cli/config.js';
import {
  loadConfig,
  loadGlobalConfig,
  saveGlobalConfig,
  saveProjectConfig,
} from '../../src/config/manager.js';

const mockedLoadConfig = vi.mocked(loadConfig);
const mockedLoadGlobalConfig = vi.mocked(loadGlobalConfig);
const mockedSaveGlobalConfig = vi.mocked(saveGlobalConfig);
const mockedSaveProjectConfig = vi.mocked(saveProjectConfig);

const SAMPLE_CONFIG: ShipSafeConfig = {
  licenseKey: 'test-key-123',
  apiEndpoint: 'https://api.shipsafe.org',
  monitoring: {
    enabled: true,
    error_sample_rate: 1.0,
    performance_sample_rate: 0.1,
  },
  scan: {
    ignore_paths: ['node_modules', 'dist'],
    ignore_rules: [],
    severity_threshold: 'low',
  },
};

describe('handleConfigList', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    mockedLoadConfig.mockResolvedValue(SAMPLE_CONFIG);
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('prints merged config as pretty JSON', async () => {
    await handleConfigList();

    expect(mockedLoadConfig).toHaveBeenCalledOnce();
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(output);
    expect(parsed).toEqual(SAMPLE_CONFIG);
  });

  it('output is formatted with 2-space indentation', async () => {
    await handleConfigList();

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toBe(JSON.stringify(SAMPLE_CONFIG, null, 2));
  });
});

describe('handleConfigGet', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {}) as any);
    mockedLoadConfig.mockResolvedValue(SAMPLE_CONFIG);
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it('returns a top-level string value', async () => {
    await handleConfigGet('licenseKey');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toBe('test-key-123');
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it('returns a top-level string value for apiEndpoint', async () => {
    await handleConfigGet('apiEndpoint');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toBe('https://api.shipsafe.org');
  });

  it('returns nested boolean via dot notation', async () => {
    await handleConfigGet('monitoring.enabled');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toBe('true');
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it('returns nested number via dot notation', async () => {
    await handleConfigGet('monitoring.error_sample_rate');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toBe('1');
  });

  it('returns array as JSON string', async () => {
    await handleConfigGet('scan.ignore_paths');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(output);
    expect(parsed).toEqual(['node_modules', 'dist']);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it('returns nested object as JSON string', async () => {
    await handleConfigGet('monitoring');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(output);
    expect(parsed).toEqual(SAMPLE_CONFIG.monitoring);
  });

  it('prints "Key not found" for unknown top-level key', async () => {
    await handleConfigGet('unknownKey');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Key not found: unknownKey');
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it('prints "Key not found" for unknown nested key', async () => {
    await handleConfigGet('monitoring.nonexistent');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Key not found: monitoring.nonexistent');
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it('prints "Key not found" for deeply invalid path', async () => {
    await handleConfigGet('scan.ignore_paths.bad');

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Key not found: scan.ignore_paths.bad');
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

describe('handleConfigSet', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    mockedLoadGlobalConfig.mockResolvedValue({ ...SAMPLE_CONFIG });
    mockedLoadConfig.mockResolvedValue({ ...SAMPLE_CONFIG });
    mockedSaveGlobalConfig.mockResolvedValue(undefined);
    mockedSaveProjectConfig.mockResolvedValue(undefined);
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('saves to project config by default', async () => {
    await handleConfigSet('licenseKey', 'new-key', { global: false });

    expect(mockedSaveProjectConfig).toHaveBeenCalledOnce();
    expect(mockedSaveGlobalConfig).not.toHaveBeenCalled();
  });

  it('saves to global config when --global flag is set', async () => {
    await handleConfigSet('licenseKey', 'new-key', { global: true });

    expect(mockedSaveGlobalConfig).toHaveBeenCalledOnce();
    expect(mockedSaveProjectConfig).not.toHaveBeenCalled();
  });

  it('prints confirmation for project config set', async () => {
    await handleConfigSet('licenseKey', 'new-key', { global: false });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Set licenseKey = new-key in project config');
  });

  it('prints confirmation for global config set', async () => {
    await handleConfigSet('licenseKey', 'new-key', { global: true });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Set licenseKey = new-key in global config');
  });

  it('parses "true" string to boolean true', async () => {
    await handleConfigSet('monitoring.enabled', 'true', { global: false });

    const savedConfig = mockedSaveProjectConfig.mock.calls[0][0] as Record<string, unknown>;
    const monitoring = savedConfig['monitoring'] as Record<string, unknown>;
    expect(monitoring['enabled']).toBe(true);
  });

  it('parses "false" string to boolean false', async () => {
    await handleConfigSet('monitoring.enabled', 'false', { global: false });

    const savedConfig = mockedSaveProjectConfig.mock.calls[0][0] as Record<string, unknown>;
    const monitoring = savedConfig['monitoring'] as Record<string, unknown>;
    expect(monitoring['enabled']).toBe(false);
  });

  it('parses numeric string to number', async () => {
    await handleConfigSet('monitoring.error_sample_rate', '0.5', { global: false });

    const savedConfig = mockedSaveProjectConfig.mock.calls[0][0] as Record<string, unknown>;
    const monitoring = savedConfig['monitoring'] as Record<string, unknown>;
    expect(monitoring['error_sample_rate']).toBe(0.5);
  });

  it('keeps string value when not boolean or number', async () => {
    await handleConfigSet('apiEndpoint', 'https://custom.example.com', { global: false });

    const savedConfig = mockedSaveProjectConfig.mock.calls[0][0] as Record<string, unknown>;
    expect(savedConfig['apiEndpoint']).toBe('https://custom.example.com');
  });

  it('supports dot notation for nested keys in project config', async () => {
    await handleConfigSet('monitoring.enabled', 'false', { global: false });

    const savedConfig = mockedSaveProjectConfig.mock.calls[0][0] as Record<string, unknown>;
    const monitoring = savedConfig['monitoring'] as Record<string, unknown>;
    expect(monitoring).toBeDefined();
    expect(monitoring['enabled']).toBe(false);
    // Other nested values preserved
    expect(monitoring['error_sample_rate']).toBe(1.0);
  });

  it('supports dot notation for nested keys in global config', async () => {
    await handleConfigSet('monitoring.enabled', 'false', { global: true });

    const savedConfig = mockedSaveGlobalConfig.mock.calls[0][0] as Record<string, unknown>;
    const monitoring = savedConfig['monitoring'] as Record<string, unknown>;
    expect(monitoring['enabled']).toBe(false);
  });

  it('sets a top-level key on a fresh config', async () => {
    mockedLoadConfig.mockResolvedValue({});
    mockedLoadGlobalConfig.mockResolvedValue({});

    await handleConfigSet('licenseKey', 'abc123', { global: false });

    const savedConfig = mockedSaveProjectConfig.mock.calls[0][0] as Record<string, unknown>;
    expect(savedConfig['licenseKey']).toBe('abc123');
  });
});
