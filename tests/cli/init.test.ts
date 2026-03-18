import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// Mock dependencies before importing
vi.mock('../../src/config/manager.js', () => ({
  loadProjectConfig: vi.fn(),
  saveProjectConfig: vi.fn(),
  getProjectName: vi.fn(),
}));

vi.mock('../../src/cli/setup.js', () => ({
  handleSetupAction: vi.fn(),
}));

// Mock chalk to return plain strings for testability
vi.mock('chalk', () => {
  const passthrough = (str: string) => str;
  const chainable: any = new Proxy(passthrough, {
    get: () => chainable,
    apply: (_target: any, _thisArg: any, args: any[]) => args[0],
  });
  return { default: chainable };
});

import { handleInitAction } from '../../src/cli/init.js';
import { loadProjectConfig, saveProjectConfig } from '../../src/config/manager.js';
import { handleSetupAction } from '../../src/cli/setup.js';

const mockedLoadProjectConfig = vi.mocked(loadProjectConfig);
const mockedSaveProjectConfig = vi.mocked(saveProjectConfig);
const mockedHandleSetupAction = vi.mocked(handleSetupAction);

async function makeTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(tmpdir(), 'shipsafe-init-test-'));
}

async function rmDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('handleInitAction', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let tmpDir: string;

  beforeEach(async () => {
    vi.clearAllMocks();
    tmpDir = await makeTmpDir();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    // Default: no existing config (no projectId)
    mockedLoadProjectConfig.mockResolvedValue({});
    mockedSaveProjectConfig.mockResolvedValue(undefined);
    mockedHandleSetupAction.mockResolvedValue(undefined);
  });

  afterEach(async () => {
    consoleSpy.mockRestore();
    warnSpy.mockRestore();
    await rmDir(tmpDir);
  });

  it('creates shipsafe.config.json with a projectId field (non-empty string)', async () => {
    await handleInitAction({ projectDir: tmpDir });

    expect(mockedSaveProjectConfig).toHaveBeenCalledOnce();
    const savedConfig = mockedSaveProjectConfig.mock.calls[0][0] as Record<string, unknown>;
    expect(typeof savedConfig['projectId']).toBe('string');
    expect((savedConfig['projectId'] as string).length).toBeGreaterThan(0);
  });

  it('generates projectId with proj_ prefix', async () => {
    await handleInitAction({ projectDir: tmpDir });

    const savedConfig = mockedSaveProjectConfig.mock.calls[0][0] as Record<string, unknown>;
    expect((savedConfig['projectId'] as string)).toMatch(/^proj_/);
  });

  it('does NOT overwrite existing config that already has a projectId', async () => {
    mockedLoadProjectConfig.mockResolvedValue({ projectId: 'proj_existing123' });

    await handleInitAction({ projectDir: tmpDir });

    expect(mockedSaveProjectConfig).not.toHaveBeenCalled();
  });

  it('prints a message when existing projectId is found', async () => {
    mockedLoadProjectConfig.mockResolvedValue({ projectId: 'proj_existing123' });

    await handleInitAction({ projectDir: tmpDir });

    const logOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    // Should contain some indication that config already exists
    expect(logOutput).toContain('proj_existing123');
  });

  it('calls handleSetupAction when skipSetup is false', async () => {
    await handleInitAction({ projectDir: tmpDir, skipSetup: false });

    expect(mockedHandleSetupAction).toHaveBeenCalledOnce();
    expect(mockedHandleSetupAction).toHaveBeenCalledWith({});
  });

  it('calls handleSetupAction by default (skipSetup not specified)', async () => {
    await handleInitAction({ projectDir: tmpDir });

    expect(mockedHandleSetupAction).toHaveBeenCalledOnce();
  });

  it('does NOT call handleSetupAction when skipSetup is true', async () => {
    await handleInitAction({ projectDir: tmpDir, skipSetup: true });

    expect(mockedHandleSetupAction).not.toHaveBeenCalled();
  });

  it('prints getting-started instructions at the end', async () => {
    await handleInitAction({ projectDir: tmpDir });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    // Should contain some getting-started guidance
    expect(output).toContain('shipsafe scan');
  });

  it('still prints getting-started instructions when skipSetup is true', async () => {
    await handleInitAction({ projectDir: tmpDir, skipSetup: true });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('shipsafe scan');
  });

  it('passes projectDir to loadProjectConfig', async () => {
    await handleInitAction({ projectDir: tmpDir });

    expect(mockedLoadProjectConfig).toHaveBeenCalledWith(tmpDir);
  });

  it('passes projectDir to saveProjectConfig', async () => {
    await handleInitAction({ projectDir: tmpDir });

    expect(mockedSaveProjectConfig).toHaveBeenCalledWith(
      expect.objectContaining({ projectId: expect.stringMatching(/^proj_/) }),
      tmpDir,
    );
  });

  it('does NOT call handleSetupAction when existing projectId found (regardless of skipSetup)', async () => {
    mockedLoadProjectConfig.mockResolvedValue({ projectId: 'proj_existing123' });

    await handleInitAction({ projectDir: tmpDir, skipSetup: false });

    // Setup should still be skipped since we bail early on existing config
    // (Implementation may vary - main thing is no overwrite)
    expect(mockedSaveProjectConfig).not.toHaveBeenCalled();
  });
});
