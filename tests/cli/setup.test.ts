import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// Mock dependencies before importing
vi.mock('../../src/hooks/installer.js', () => ({
  installHooks: vi.fn(),
}));

vi.mock('../../src/claude-md/manager.js', () => ({
  injectClaudeMd: vi.fn(),
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

import { handleSetupAction, registerMcpClaudeCode, registerMcpCursor } from '../../src/cli/setup.js';
import { installHooks } from '../../src/hooks/installer.js';
import { injectClaudeMd } from '../../src/claude-md/manager.js';

const mockedInstallHooks = vi.mocked(installHooks);
const mockedInjectClaudeMd = vi.mocked(injectClaudeMd);

async function makeTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(tmpdir(), 'shipsafe-setup-test-'));
}

async function rmDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('handleSetupAction', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let cwdSpy: ReturnType<typeof vi.spyOn>;
  let tmpDir: string;

  beforeEach(async () => {
    vi.clearAllMocks();
    tmpDir = await makeTmpDir();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    cwdSpy = vi.spyOn(process, 'cwd').mockReturnValue(tmpDir);
  });

  afterEach(async () => {
    consoleSpy.mockRestore();
    warnSpy.mockRestore();
    cwdSpy.mockRestore();
    await rmDir(tmpDir);
  });

  it('prints "Setting up ShipSafe..." at start', async () => {
    await handleSetupAction({});

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Setting up ShipSafe...');
  });

  it('calls installHooks', async () => {
    await handleSetupAction({});

    expect(mockedInstallHooks).toHaveBeenCalledWith(tmpDir, { commitOnly: undefined });
  });

  it('calls injectClaudeMd', async () => {
    await handleSetupAction({});

    expect(mockedInjectClaudeMd).toHaveBeenCalledWith(tmpDir);
  });

  it('prints success messages for all steps', async () => {
    await handleSetupAction({});

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Git pre-commit hook installed');
    expect(output).toContain('MCP server registered');
    expect(output).toContain('CLAUDE.md updated');
  });

  it('prints ready message at end', async () => {
    await handleSetupAction({});

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain("ShipSafe is ready! Run 'shipsafe scan' to run your first scan.");
  });

  it('does not call installHooks when --skip-hooks is set', async () => {
    await handleSetupAction({ skipHooks: true });

    expect(mockedInstallHooks).not.toHaveBeenCalled();
  });

  it('does not call injectClaudeMd when --skip-claude-md is set', async () => {
    await handleSetupAction({ skipClaudeMd: true });

    expect(mockedInjectClaudeMd).not.toHaveBeenCalled();
  });

  it('does not register MCP when --skip-mcp is set', async () => {
    await handleSetupAction({ skipMcp: true });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).not.toContain('MCP server registered');
  });

  it('continues if hooks fail (e.g., not a git repo) and only warns', async () => {
    mockedInstallHooks.mockRejectedValue(new Error('Not a git repository'));

    await handleSetupAction({});

    // Should warn about hooks
    const warnings = warnSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(warnings).toContain('Not a git repository');

    // Should still complete other steps
    expect(mockedInjectClaudeMd).toHaveBeenCalled();

    // Should still print the ready message
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain("ShipSafe is ready!");
  });

  it('continues if injectClaudeMd fails and only warns', async () => {
    mockedInjectClaudeMd.mockRejectedValue(new Error('Permission denied'));

    await handleSetupAction({});

    // Should warn about CLAUDE.md
    const warnings = warnSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(warnings).toContain('Permission denied');

    // Hooks should still have been called
    expect(mockedInstallHooks).toHaveBeenCalled();

    // Should still print the ready message
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain("ShipSafe is ready!");
  });

  it('is idempotent — running twice works without errors', async () => {
    mockedInstallHooks.mockResolvedValue(undefined);
    mockedInjectClaudeMd.mockResolvedValue(undefined);

    await handleSetupAction({});

    // Reset call counts but keep implementations
    mockedInstallHooks.mockClear();
    mockedInjectClaudeMd.mockClear();
    consoleSpy.mockClear();
    warnSpy.mockClear();

    await handleSetupAction({});

    expect(warnSpy).not.toHaveBeenCalled();
    expect(mockedInstallHooks).toHaveBeenCalledTimes(1);
    expect(mockedInjectClaudeMd).toHaveBeenCalledTimes(1);
    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain("ShipSafe is ready!");
  });

  it('skips all steps when all skip flags are set', async () => {
    await handleSetupAction({ skipHooks: true, skipMcp: true, skipClaudeMd: true });

    expect(mockedInstallHooks).not.toHaveBeenCalled();
    expect(mockedInjectClaudeMd).not.toHaveBeenCalled();

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).not.toContain('Git hooks installed');
    expect(output).not.toContain('MCP server registered');
    expect(output).not.toContain('CLAUDE.md updated');
    // Still prints ready message
    expect(output).toContain("ShipSafe is ready!");
  });
});

describe('registerMcpCursor', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await makeTmpDir();
  });

  afterEach(async () => {
    await rmDir(tmpDir);
  });

  it('creates .cursor/mcp.json with shipsafe entry when no file exists', async () => {
    await registerMcpCursor(tmpDir);

    const configPath = path.join(tmpDir, '.cursor', 'mcp.json');
    const raw = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(raw);

    expect(config.mcpServers.shipsafe).toEqual({
      command: 'npx',
      args: ['-y', 'shipsafe', 'mcp-server'],
    });
  });

  it('merges into existing .cursor/mcp.json without overwriting other servers', async () => {
    const cursorDir = path.join(tmpDir, '.cursor');
    await fs.mkdir(cursorDir, { recursive: true });

    const existing = {
      mcpServers: {
        'other-server': { command: 'node', args: ['other.js'] },
      },
    };
    await fs.writeFile(
      path.join(cursorDir, 'mcp.json'),
      JSON.stringify(existing, null, 2),
    );

    await registerMcpCursor(tmpDir);

    const raw = await fs.readFile(path.join(cursorDir, 'mcp.json'), 'utf-8');
    const config = JSON.parse(raw);

    // Other server preserved
    expect(config.mcpServers['other-server']).toEqual({
      command: 'node',
      args: ['other.js'],
    });
    // ShipSafe added
    expect(config.mcpServers.shipsafe).toEqual({
      command: 'npx',
      args: ['-y', 'shipsafe', 'mcp-server'],
    });
  });

  it('updates existing shipsafe entry in .cursor/mcp.json', async () => {
    const cursorDir = path.join(tmpDir, '.cursor');
    await fs.mkdir(cursorDir, { recursive: true });

    const existing = {
      mcpServers: {
        shipsafe: { command: 'old-command', args: ['old'] },
      },
    };
    await fs.writeFile(
      path.join(cursorDir, 'mcp.json'),
      JSON.stringify(existing, null, 2),
    );

    await registerMcpCursor(tmpDir);

    const raw = await fs.readFile(path.join(cursorDir, 'mcp.json'), 'utf-8');
    const config = JSON.parse(raw);

    expect(config.mcpServers.shipsafe).toEqual({
      command: 'npx',
      args: ['-y', 'shipsafe', 'mcp-server'],
    });
  });
});

describe('registerMcpClaudeCode', () => {
  let tmpDir: string;
  let originalHome: string;

  beforeEach(async () => {
    tmpDir = await makeTmpDir();
    originalHome = process.env.HOME ?? '';
    // Point homedir to tmpDir so we don't touch real ~/.claude
    process.env.HOME = tmpDir;
  });

  afterEach(async () => {
    process.env.HOME = originalHome;
    await rmDir(tmpDir);
  });

  it('creates ~/.claude/claude_desktop_config.json when none exists', async () => {
    // We need to mock homedir since os.homedir() caches
    // Instead, we'll directly test the file operations via a workaround:
    // registerMcpClaudeCode uses homedir() which reads HOME env var
    await registerMcpClaudeCode();

    const configPath = path.join(tmpDir, '.claude', 'claude_desktop_config.json');
    const raw = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(raw);

    expect(config.mcpServers.shipsafe).toEqual({
      command: 'npx',
      args: ['-y', 'shipsafe', 'mcp-server'],
    });
  });

  it('merges into existing claude_desktop_config.json without overwriting other servers', async () => {
    const claudeDir = path.join(tmpDir, '.claude');
    await fs.mkdir(claudeDir, { recursive: true });

    const existing = {
      mcpServers: {
        'existing-server': { command: 'node', args: ['server.js'] },
      },
      otherConfig: true,
    };
    await fs.writeFile(
      path.join(claudeDir, 'claude_desktop_config.json'),
      JSON.stringify(existing, null, 2),
    );

    await registerMcpClaudeCode();

    const raw = await fs.readFile(
      path.join(claudeDir, 'claude_desktop_config.json'),
      'utf-8',
    );
    const config = JSON.parse(raw);

    // Other server preserved
    expect(config.mcpServers['existing-server']).toEqual({
      command: 'node',
      args: ['server.js'],
    });
    // Other config preserved
    expect(config.otherConfig).toBe(true);
    // ShipSafe added
    expect(config.mcpServers.shipsafe).toEqual({
      command: 'npx',
      args: ['-y', 'shipsafe', 'mcp-server'],
    });
  });
});
