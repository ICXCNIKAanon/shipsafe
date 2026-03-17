import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

let mockHomedir: string = tmpdir();

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    default: {
      ...actual,
      homedir: () => mockHomedir,
    },
    homedir: () => mockHomedir,
  };
});

// Import after vi.mock so the mock is applied
import {
  getGlobalConfigDir,
  loadGlobalConfig,
  loadProjectConfig,
  loadConfig,
  saveGlobalConfig,
  saveProjectConfig,
  getProjectName,
} from '../../src/config/manager.js';
import { DEFAULT_CONFIG } from '../../src/constants.js';

async function makeTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(tmpdir(), 'shipsafe-test-'));
}

async function rmDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('getGlobalConfigDir', () => {
  let tmpHome: string;

  beforeEach(async () => {
    tmpHome = await makeTmpDir();
    mockHomedir = tmpHome;
  });

  afterEach(async () => {
    await rmDir(tmpHome);
  });

  it('returns a path ending with .shipsafe', () => {
    const dir = getGlobalConfigDir();
    expect(dir).toMatch(/\.shipsafe$/);
  });

  it('is rooted at the home directory', () => {
    const dir = getGlobalConfigDir();
    expect(dir).toBe(path.join(tmpHome, '.shipsafe'));
  });
});

describe('loadGlobalConfig', () => {
  let tmpHome: string;

  beforeEach(async () => {
    tmpHome = await makeTmpDir();
    mockHomedir = tmpHome;
  });

  afterEach(async () => {
    await rmDir(tmpHome);
  });

  it('returns defaults when no config file exists', async () => {
    const config = await loadGlobalConfig();
    expect(config.monitoring).toEqual(DEFAULT_CONFIG.monitoring);
    expect(config.scan).toEqual(DEFAULT_CONFIG.scan);
  });

  it('reads and returns values from existing config file', async () => {
    const configDir = path.join(tmpHome, '.shipsafe');
    await fs.mkdir(configDir, { recursive: true });
    await fs.writeFile(
      path.join(configDir, 'config.json'),
      JSON.stringify({ licenseKey: 'abc-123', scan: { severity_threshold: 'low' } }),
    );

    const config = await loadGlobalConfig();
    expect(config.licenseKey).toBe('abc-123');
  });
});

describe('loadProjectConfig', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('returns defaults when no project config file exists', async () => {
    const config = await loadProjectConfig(tmpProject);
    expect(config.monitoring).toEqual(DEFAULT_CONFIG.monitoring);
    expect(config.scan).toEqual(DEFAULT_CONFIG.scan);
  });

  it('reads project config from specified directory', async () => {
    await fs.writeFile(
      path.join(tmpProject, 'shipsafe.config.json'),
      JSON.stringify({ projectId: 'proj-42', monitoring: { enabled: false } }),
    );

    const config = await loadProjectConfig(tmpProject);
    expect(config.projectId).toBe('proj-42');
  });
});

describe('loadConfig', () => {
  let tmpHome: string;
  let tmpProject: string;

  beforeEach(async () => {
    tmpHome = await makeTmpDir();
    tmpProject = await makeTmpDir();
    mockHomedir = tmpHome;
  });

  afterEach(async () => {
    await rmDir(tmpHome);
    await rmDir(tmpProject);
  });

  it('merges global and project config with project taking precedence', async () => {
    // Write global config
    const configDir = path.join(tmpHome, '.shipsafe');
    await fs.mkdir(configDir, { recursive: true });
    await fs.writeFile(
      path.join(configDir, 'config.json'),
      JSON.stringify({
        licenseKey: 'global-key',
        scan: {
          ignore_paths: ['node_modules', 'dist', '.git', 'coverage'],
          ignore_rules: ['rule-a'],
          severity_threshold: 'medium',
        },
      }),
    );

    // Write project config with overriding values
    await fs.writeFile(
      path.join(tmpProject, 'shipsafe.config.json'),
      JSON.stringify({
        projectId: 'proj-99',
        scan: {
          ignore_paths: ['node_modules', 'dist', '.git', 'coverage', 'vendor'],
          ignore_rules: ['rule-b'],
          severity_threshold: 'low',
        },
      }),
    );

    const config = await loadConfig(tmpProject);

    // Global value preserved when not overridden
    expect(config.licenseKey).toBe('global-key');
    // Project value takes precedence
    expect(config.projectId).toBe('proj-99');
    // Deep merge: project scan overrides global scan
    expect(config.scan?.severity_threshold).toBe('low');
    expect(config.scan?.ignore_rules).toEqual(['rule-b']);
    expect(config.scan?.ignore_paths).toContain('vendor');
  });

  it('returns defaults when neither config exists', async () => {
    const config = await loadConfig(tmpProject);
    expect(config.monitoring).toEqual(DEFAULT_CONFIG.monitoring);
    expect(config.scan).toEqual(DEFAULT_CONFIG.scan);
  });

  it('deep merges nested objects instead of shallow replacing', async () => {
    const configDir = path.join(tmpHome, '.shipsafe');
    await fs.mkdir(configDir, { recursive: true });
    await fs.writeFile(
      path.join(configDir, 'config.json'),
      JSON.stringify({
        monitoring: {
          enabled: true,
          error_sample_rate: 0.5,
          performance_sample_rate: 0.8,
        },
      }),
    );

    await fs.writeFile(
      path.join(tmpProject, 'shipsafe.config.json'),
      JSON.stringify({
        monitoring: {
          enabled: false,
        },
      }),
    );

    const config = await loadConfig(tmpProject);
    // Project override
    expect(config.monitoring?.enabled).toBe(false);
    // Global values preserved via deep merge
    expect(config.monitoring?.error_sample_rate).toBe(0.5);
    expect(config.monitoring?.performance_sample_rate).toBe(0.8);
  });
});

describe('saveGlobalConfig', () => {
  let tmpHome: string;

  beforeEach(async () => {
    tmpHome = await makeTmpDir();
    mockHomedir = tmpHome;
  });

  afterEach(async () => {
    await rmDir(tmpHome);
  });

  it('writes config to ~/.shipsafe/config.json', async () => {
    await saveGlobalConfig({ licenseKey: 'saved-key' });

    const filePath = path.join(tmpHome, '.shipsafe', 'config.json');
    const raw = await fs.readFile(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    expect(parsed.licenseKey).toBe('saved-key');
  });

  it('creates the .shipsafe directory if it does not exist', async () => {
    const dirPath = path.join(tmpHome, '.shipsafe');
    // Confirm directory doesn't exist yet
    await expect(fs.access(dirPath)).rejects.toThrow();

    await saveGlobalConfig({ licenseKey: 'new-key' });

    // Now it should exist
    const stat = await fs.stat(dirPath);
    expect(stat.isDirectory()).toBe(true);
  });

  it('writes well-formatted JSON with indentation', async () => {
    await saveGlobalConfig({ licenseKey: 'fmt-key' });

    const filePath = path.join(tmpHome, '.shipsafe', 'config.json');
    const raw = await fs.readFile(filePath, 'utf-8');
    // Should contain newlines (formatted, not single-line)
    expect(raw).toContain('\n');
    // Verify roundtrip
    expect(JSON.parse(raw).licenseKey).toBe('fmt-key');
  });
});

describe('saveProjectConfig', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('writes config to shipsafe.config.json in the project directory', async () => {
    await saveProjectConfig({ projectId: 'proj-saved' }, tmpProject);

    const filePath = path.join(tmpProject, 'shipsafe.config.json');
    const raw = await fs.readFile(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    expect(parsed.projectId).toBe('proj-saved');
  });

  it('overwrites existing project config', async () => {
    const filePath = path.join(tmpProject, 'shipsafe.config.json');
    await fs.writeFile(filePath, JSON.stringify({ projectId: 'old' }));

    await saveProjectConfig({ projectId: 'new' }, tmpProject);

    const raw = await fs.readFile(filePath, 'utf-8');
    expect(JSON.parse(raw).projectId).toBe('new');
  });
});

describe('getProjectName', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('reads name from package.json when available', async () => {
    await fs.writeFile(
      path.join(tmpProject, 'package.json'),
      JSON.stringify({ name: 'my-cool-project' }),
    );

    const name = getProjectName(tmpProject);
    expect(name).toBe('my-cool-project');
  });

  it('falls back to directory name when package.json is missing', () => {
    const name = getProjectName(tmpProject);
    // tmpProject is something like /tmp/shipsafe-test-XXXXXX
    expect(name).toBe(path.basename(tmpProject));
  });

  it('falls back to directory name when package.json has no name field', async () => {
    await fs.writeFile(
      path.join(tmpProject, 'package.json'),
      JSON.stringify({ version: '1.0.0' }),
    );

    const name = getProjectName(tmpProject);
    expect(name).toBe(path.basename(tmpProject));
  });
});
