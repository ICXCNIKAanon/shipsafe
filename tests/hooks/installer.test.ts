import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { execSync } from 'node:child_process';
import { installHooks, uninstallHooks, checkHooksInstalled } from '../../src/hooks/installer.js';
import { HOOK_MARKER } from '../../src/constants.js';

async function makeTmpGitDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(tmpdir(), 'shipsafe-hook-test-'));
  execSync('git init', { cwd: dir, stdio: 'ignore' });
  return dir;
}

async function makeTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(tmpdir(), 'shipsafe-hook-test-'));
}

async function rmDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('installHooks', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpGitDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('creates pre-commit and pre-push in .git/hooks/', async () => {
    await installHooks(tmpProject);

    const preCommit = path.join(tmpProject, '.git', 'hooks', 'pre-commit');
    const prePush = path.join(tmpProject, '.git', 'hooks', 'pre-push');

    const preCommitStat = await fs.stat(preCommit);
    const prePushStat = await fs.stat(prePush);

    expect(preCommitStat.isFile()).toBe(true);
    expect(prePushStat.isFile()).toBe(true);
  });

  it('hook files contain SHIPSAFE_HOOK marker', async () => {
    await installHooks(tmpProject);

    const preCommit = await fs.readFile(
      path.join(tmpProject, '.git', 'hooks', 'pre-commit'),
      'utf-8',
    );
    const prePush = await fs.readFile(
      path.join(tmpProject, '.git', 'hooks', 'pre-push'),
      'utf-8',
    );

    expect(preCommit).toContain(HOOK_MARKER);
    expect(prePush).toContain(HOOK_MARKER);
  });

  it('hook files have correct content', async () => {
    await installHooks(tmpProject);

    const preCommit = await fs.readFile(
      path.join(tmpProject, '.git', 'hooks', 'pre-commit'),
      'utf-8',
    );
    const prePush = await fs.readFile(
      path.join(tmpProject, '.git', 'hooks', 'pre-push'),
      'utf-8',
    );

    expect(preCommit).toContain('scan --scope staged');
    expect(prePush).toContain('scan --scope all');
  });

  it('hook files are executable (mode 755)', async () => {
    await installHooks(tmpProject);

    const preCommitStat = await fs.stat(
      path.join(tmpProject, '.git', 'hooks', 'pre-commit'),
    );
    const prePushStat = await fs.stat(
      path.join(tmpProject, '.git', 'hooks', 'pre-push'),
    );

    // Check owner execute bit (0o100) is set
    expect(preCommitStat.mode & 0o755).toBe(0o755);
    expect(prePushStat.mode & 0o755).toBe(0o755);
  });

  it('backs up existing non-ShipSafe hooks to .pre-shipsafe', async () => {
    const hooksDir = path.join(tmpProject, '.git', 'hooks');
    await fs.mkdir(hooksDir, { recursive: true });

    const existingContent = '#!/bin/sh\necho "existing hook"\n';
    await fs.writeFile(path.join(hooksDir, 'pre-commit'), existingContent);

    await installHooks(tmpProject);

    const backup = await fs.readFile(
      path.join(hooksDir, 'pre-commit.pre-shipsafe'),
      'utf-8',
    );
    expect(backup).toBe(existingContent);

    // New hook should be ShipSafe
    const hook = await fs.readFile(path.join(hooksDir, 'pre-commit'), 'utf-8');
    expect(hook).toContain(HOOK_MARKER);
  });

  it('is idempotent — running twice does not duplicate or create extra backups', async () => {
    await installHooks(tmpProject);
    const firstContent = await fs.readFile(
      path.join(tmpProject, '.git', 'hooks', 'pre-commit'),
      'utf-8',
    );

    await installHooks(tmpProject);
    const secondContent = await fs.readFile(
      path.join(tmpProject, '.git', 'hooks', 'pre-commit'),
      'utf-8',
    );

    expect(firstContent).toBe(secondContent);

    // No .pre-shipsafe backup should exist (since original was ShipSafe)
    await expect(
      fs.access(path.join(tmpProject, '.git', 'hooks', 'pre-commit.pre-shipsafe')),
    ).rejects.toThrow();
  });

  it('throws when not in a git repo', async () => {
    const nonGitDir = await makeTmpDir();
    try {
      await expect(installHooks(nonGitDir)).rejects.toThrow('Not a git repository');
    } finally {
      await rmDir(nonGitDir);
    }
  });

  it('creates .git/hooks/ directory if it does not exist', async () => {
    // Remove hooks dir if git init created it
    const hooksDir = path.join(tmpProject, '.git', 'hooks');
    await fs.rm(hooksDir, { recursive: true, force: true });

    await installHooks(tmpProject);

    const stat = await fs.stat(hooksDir);
    expect(stat.isDirectory()).toBe(true);
  });
});

describe('uninstallHooks', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpGitDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('removes ShipSafe hooks', async () => {
    await installHooks(tmpProject);
    await uninstallHooks(tmpProject);

    const hooksDir = path.join(tmpProject, '.git', 'hooks');

    await expect(
      fs.access(path.join(hooksDir, 'pre-commit')),
    ).rejects.toThrow();
    await expect(
      fs.access(path.join(hooksDir, 'pre-push')),
    ).rejects.toThrow();
  });

  it('restores .pre-shipsafe backups', async () => {
    const hooksDir = path.join(tmpProject, '.git', 'hooks');
    await fs.mkdir(hooksDir, { recursive: true });

    const originalContent = '#!/bin/sh\necho "original"\n';
    await fs.writeFile(path.join(hooksDir, 'pre-commit'), originalContent);

    await installHooks(tmpProject);
    await uninstallHooks(tmpProject);

    const restored = await fs.readFile(
      path.join(hooksDir, 'pre-commit'),
      'utf-8',
    );
    expect(restored).toBe(originalContent);

    // Backup file should be gone
    await expect(
      fs.access(path.join(hooksDir, 'pre-commit.pre-shipsafe')),
    ).rejects.toThrow();
  });

  it('does nothing when no hooks are installed', async () => {
    // Should not throw
    await expect(uninstallHooks(tmpProject)).resolves.toBeUndefined();
  });
});

describe('checkHooksInstalled', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpGitDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('returns true when hooks are installed', async () => {
    await installHooks(tmpProject);
    const result = await checkHooksInstalled(tmpProject);
    expect(result).toBe(true);
  });

  it('returns false when hooks are not installed', async () => {
    const result = await checkHooksInstalled(tmpProject);
    expect(result).toBe(false);
  });

  it('returns false when pre-commit exists but is not a ShipSafe hook', async () => {
    const hooksDir = path.join(tmpProject, '.git', 'hooks');
    await fs.mkdir(hooksDir, { recursive: true });
    await fs.writeFile(
      path.join(hooksDir, 'pre-commit'),
      '#!/bin/sh\necho "not shipsafe"\n',
    );

    const result = await checkHooksInstalled(tmpProject);
    expect(result).toBe(false);
  });
});
