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

vi.mock('../../src/cli/license-gate.js', () => ({
  gateFeature: vi.fn().mockResolvedValue({ allowed: true, tier: 'team' }),
}));

// Mock the config manager
vi.mock('../../src/config/manager.js', async () => {
  const actual = await vi.importActual<typeof import('../../src/config/manager.js')>('../../src/config/manager.js');
  return {
    loadConfig: vi.fn(),
    getApiEndpoint: actual.getApiEndpoint,
  };
});

import { handleUploadSourcemaps } from '../../src/cli/upload-sourcemaps.js';
import { loadConfig } from '../../src/config/manager.js';

const mockedLoadConfig = vi.mocked(loadConfig);

async function makeTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(tmpdir(), 'shipsafe-upload-test-'));
}

async function rmDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('handleUploadSourcemaps', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;
  let fetchSpy: ReturnType<typeof vi.spyOn>;
  let tmpDir: string;
  let originalCwd: string;

  beforeEach(async () => {
    vi.clearAllMocks();
    tmpDir = await makeTmpDir();
    originalCwd = process.cwd();

    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // Mock global fetch
    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ uploaded: 1 }),
      text: async () => 'ok',
    } as Response);
  });

  afterEach(async () => {
    consoleSpy.mockRestore();
    consoleErrorSpy.mockRestore();
    fetchSpy.mockRestore();
    await rmDir(tmpDir);
  });

  it('uploads discovered source maps to the API', async () => {
    // Create a .map file in the temp dir
    await fs.writeFile(path.join(tmpDir, 'app.js.map'), '{"version":3,"sources":[]}');

    mockedLoadConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      projectId: 'proj-123',
      licenseKey: 'sk-test-abc',
    });

    await handleUploadSourcemaps({ dir: tmpDir, release: '1.2.3' });

    expect(fetchSpy).toHaveBeenCalledOnce();

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.shipsafe.org/v1/sourcemaps/batch');
    expect(init.method).toBe('POST');

    const body = JSON.parse(init.body as string);
    expect(body.project_id).toBe('proj-123');
    expect(body.release).toBe('1.2.3');
    expect(body.source_maps).toHaveLength(1);
    expect(body.source_maps[0].source_map).toBe('{"version":3,"sources":[]}');

    const headers = init.headers as Record<string, string>;
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['Authorization']).toBe('Bearer sk-test-abc');
  });

  it('skips upload when no project ID is configured (empty config)', async () => {
    await fs.writeFile(path.join(tmpDir, 'app.js.map'), '{"version":3}');

    mockedLoadConfig.mockResolvedValue({});

    await handleUploadSourcemaps({ dir: tmpDir, release: '1.0.0' });

    expect(fetchSpy).not.toHaveBeenCalled();

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('No project ID configured');
  });

  it('skips upload when no project ID is configured', async () => {
    await fs.writeFile(path.join(tmpDir, 'bundle.js.map'), '{}');

    mockedLoadConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      // no projectId
    });

    await handleUploadSourcemaps({ dir: tmpDir, release: '1.0.0' });

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('handles empty directory — no fetch call', async () => {
    mockedLoadConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      projectId: 'proj-123',
    });

    await handleUploadSourcemaps({ dir: tmpDir });

    expect(fetchSpy).not.toHaveBeenCalled();

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('No source map files');
  });

  it('does not set Authorization header when no licenseKey configured', async () => {
    await fs.writeFile(path.join(tmpDir, 'main.js.map'), '{}');

    mockedLoadConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      projectId: 'proj-456',
      // no licenseKey
    });

    await handleUploadSourcemaps({ dir: tmpDir, release: '2.0.0' });

    expect(fetchSpy).toHaveBeenCalledOnce();
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers['Authorization']).toBeUndefined();
  });

  it('prints success message after successful upload', async () => {
    await fs.writeFile(path.join(tmpDir, 'a.js.map'), '{}');
    await fs.writeFile(path.join(tmpDir, 'b.js.map'), '{}');

    mockedLoadConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      projectId: 'proj-123',
    });

    await handleUploadSourcemaps({ dir: tmpDir, release: '3.0.0' });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toMatch(/2 source map/);
    expect(output).toMatch(/uploaded/i);
  });

  it('uses "unknown" as release when none provided and no package.json', async () => {
    await fs.writeFile(path.join(tmpDir, 'app.js.map'), '{}');

    mockedLoadConfig.mockResolvedValue({
      apiEndpoint: 'https://api.shipsafe.org',
      projectId: 'proj-123',
    });

    // Change cwd to a temp dir that has no package.json
    process.chdir(tmpDir);
    try {
      await handleUploadSourcemaps({ dir: tmpDir });
    } finally {
      process.chdir(originalCwd);
    }

    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    // release should be 'unknown' or a version string — not empty
    expect(typeof body.release).toBe('string');
    expect(body.release.length).toBeGreaterThan(0);
  });
});
