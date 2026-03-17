import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// Mock chalk to return plain strings for testability
vi.mock('chalk', () => {
  const passthrough = (str: string) => str;
  const chainable: any = new Proxy(passthrough, {
    get: () => chainable,
    apply: (_target: any, _thisArg: any, args: any[]) => args[0],
  });
  return { default: chainable };
});

// Mock child_process.execFile to avoid opening a real browser
vi.mock('node:child_process', () => ({
  execFile: vi.fn((_cmd: string, _args: string[], _cb: Function) => {}),
}));

import {
  handleConnectAction,
  isConnected,
  saveConnectionConfig,
  getGitHubConfigPath,
  getGlobalConfigDir,
} from '../../src/cli/connect.js';

async function makeTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(tmpdir(), 'shipsafe-connect-test-'));
}

async function rmDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('connect command', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let tmpDir: string;
  let originalHome: string;

  beforeEach(async () => {
    vi.clearAllMocks();
    tmpDir = await makeTmpDir();
    originalHome = process.env.HOME ?? '';
    process.env.HOME = tmpDir;
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(async () => {
    consoleSpy.mockRestore();
    process.env.HOME = originalHome;
    await rmDir(tmpDir);
  });

  it('shows connection instructions when not yet connected', async () => {
    await handleConnectAction();

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Connect ShipSafe to GitHub');
    expect(output).toContain('https://github.com/apps/shipsafe');
  });

  it('saves connection info to global config', async () => {
    await handleConnectAction();

    const configPath = getGitHubConfigPath();
    const raw = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(raw);

    expect(config.connected).toBe(true);
    expect(config.connectedAt).toBeDefined();
    expect(config.appUrl).toBe('https://github.com/apps/shipsafe');
  });

  it('prints success message after connecting', async () => {
    await handleConnectAction();

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('GitHub App connected! PRs will now be scanned automatically.');
  });

  it('shows already-connected message if previously connected', async () => {
    // First connection
    await handleConnectAction();
    consoleSpy.mockClear();

    // Second connection
    await handleConnectAction();

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('already connected');
  });
});

describe('isConnected', () => {
  let tmpDir: string;
  let originalHome: string;

  beforeEach(async () => {
    tmpDir = await makeTmpDir();
    originalHome = process.env.HOME ?? '';
    process.env.HOME = tmpDir;
  });

  afterEach(async () => {
    process.env.HOME = originalHome;
    await rmDir(tmpDir);
  });

  it('returns false when no config exists', async () => {
    expect(await isConnected()).toBe(false);
  });

  it('returns true when config exists with connected: true', async () => {
    await saveConnectionConfig();
    expect(await isConnected()).toBe(true);
  });

  it('returns false when config has connected: false', async () => {
    const configDir = getGlobalConfigDir();
    await fs.mkdir(configDir, { recursive: true });
    await fs.writeFile(
      getGitHubConfigPath(),
      JSON.stringify({ connected: false }),
      'utf-8',
    );

    expect(await isConnected()).toBe(false);
  });
});

describe('saveConnectionConfig', () => {
  let tmpDir: string;
  let originalHome: string;

  beforeEach(async () => {
    tmpDir = await makeTmpDir();
    originalHome = process.env.HOME ?? '';
    process.env.HOME = tmpDir;
  });

  afterEach(async () => {
    process.env.HOME = originalHome;
    await rmDir(tmpDir);
  });

  it('creates the config directory if it does not exist', async () => {
    await saveConnectionConfig();

    const configDir = getGlobalConfigDir();
    const stat = await fs.stat(configDir);
    expect(stat.isDirectory()).toBe(true);
  });

  it('writes valid JSON config', async () => {
    await saveConnectionConfig();

    const raw = await fs.readFile(getGitHubConfigPath(), 'utf-8');
    const config = JSON.parse(raw);

    expect(config).toEqual(
      expect.objectContaining({
        connected: true,
        appUrl: 'https://github.com/apps/shipsafe',
      }),
    );
    expect(typeof config.connectedAt).toBe('string');
  });
});
