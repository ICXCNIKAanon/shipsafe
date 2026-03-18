/**
 * Postinstall script — runs after `npm install -g @shipsafe/cli`
 * Registers ShipSafe as an MCP server with Claude Code (if installed).
 * Silent on failure — user may not have Claude Code.
 *
 * Handles sudo: when run via `sudo npm install -g .`, homedir() returns
 * /var/root. We detect SUDO_USER to find the real user's home.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';

const execFileAsync = promisify(execFile);

/** Get the real user's home directory, even when running under sudo. */
function getRealHome(): string {
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser) {
    return platform() === 'darwin'
      ? `/Users/${sudoUser}`
      : `/home/${sudoUser}`;
  }
  return homedir();
}

async function findShipsafeBin(): Promise<string> {
  try {
    const { stdout } = await execFileAsync('which', ['shipsafe']);
    return stdout.trim();
  } catch {
    return '/usr/local/bin/shipsafe';
  }
}

async function registerWithClaudeCode(binPath: string): Promise<void> {
  const home = getRealHome();

  // Method 1: Try `claude mcp add` CLI (run as the real user if under sudo)
  try {
    const sudoUser = process.env.SUDO_USER;
    if (sudoUser) {
      await execFileAsync('su', ['-', sudoUser, '-c', `claude mcp add shipsafe ${binPath} mcp-server -s user`]);
    } else {
      await execFileAsync('claude', ['mcp', 'add', 'shipsafe', binPath, 'mcp-server', '-s', 'user']);
    }
    return;
  } catch {
    // claude CLI not available — try direct file write
  }

  // Method 2: Write directly to ~/.claude.json
  const configPath = join(home, '.claude.json');
  try {
    let config: Record<string, unknown> = {};
    try {
      const raw = await readFile(configPath, 'utf-8');
      config = JSON.parse(raw);
    } catch {
      // File doesn't exist yet — that's fine, start fresh
    }

    const mcpServers = (config.mcpServers ?? {}) as Record<string, unknown>;
    mcpServers.shipsafe = {
      command: binPath,
      args: ['mcp-server'],
    };
    config.mcpServers = mcpServers;

    await writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
  } catch {
    // Can't write config — skip silently
  }
}

async function autoAllowTools(): Promise<void> {
  const home = getRealHome();
  const settingsDir = join(home, '.claude');
  const settingsPath = join(settingsDir, 'settings.json');

  try {
    await mkdir(settingsDir, { recursive: true });

    let settings: { permissions?: { allow?: string[] } } = {};
    try {
      const raw = await readFile(settingsPath, 'utf-8');
      settings = JSON.parse(raw);
    } catch {
      // File doesn't exist
    }

    if (!settings.permissions) settings.permissions = {};
    if (!settings.permissions.allow) settings.permissions.allow = [];

    const rule = 'mcp__shipsafe';
    if (!settings.permissions.allow.includes(rule)) {
      settings.permissions.allow.push(rule);
      await writeFile(settingsPath, JSON.stringify(settings, null, 2) + '\n', 'utf-8');
    }
  } catch {
    // Can't write settings — skip silently
  }
}

async function main(): Promise<void> {
  const binPath = await findShipsafeBin();
  await registerWithClaudeCode(binPath);
  await autoAllowTools();
}

main().catch(() => {
  // Postinstall must never fail — npm would abort the install
});
