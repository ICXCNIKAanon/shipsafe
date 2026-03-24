import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { homedir } from 'node:os';
import { Command } from 'commander';
import chalk from 'chalk';
import { installHooks } from '../hooks/installer.js';
import { injectClaudeMd } from '../claude-md/manager.js';

export interface SetupOptions {
  skipHooks?: boolean;
  skipMcp?: boolean;
  skipClaudeMd?: boolean;
  commitOnly?: boolean;
  withPrePush?: boolean;
}

const MCP_SERVER_ENTRY = {
  command: 'npx',
  args: ['-y', 'shipsafe', 'mcp-server'],
};

/**
 * Reads a JSON file, returning null if it doesn't exist or is invalid.
 */
async function readJsonFile(filePath: string): Promise<Record<string, any> | null> {
  try {
    const raw = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Writes a JSON file, creating parent directories as needed.
 */
async function writeJsonFile(filePath: string, data: Record<string, any>): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2) + '\n', 'utf-8');
}

/**
 * Registers the ShipSafe MCP server in Claude Code's global config.
 * Merges into existing config if present; creates new config otherwise.
 */
export async function registerMcpClaudeCode(): Promise<void> {
  const configPath = path.join(homedir(), '.claude', 'claude_desktop_config.json');
  const existing = await readJsonFile(configPath);

  if (existing) {
    existing.mcpServers = existing.mcpServers ?? {};
    existing.mcpServers.shipsafe = MCP_SERVER_ENTRY;
    await writeJsonFile(configPath, existing);
  } else {
    await writeJsonFile(configPath, {
      mcpServers: {
        shipsafe: MCP_SERVER_ENTRY,
      },
    });
  }
}

/**
 * Registers the ShipSafe MCP server in Cursor's project-level config.
 * Merges into existing config if present; creates new config otherwise.
 */
export async function registerMcpCursor(projectDir: string): Promise<void> {
  const configPath = path.join(projectDir, '.cursor', 'mcp.json');
  const existing = await readJsonFile(configPath);

  if (existing) {
    existing.mcpServers = existing.mcpServers ?? {};
    existing.mcpServers.shipsafe = MCP_SERVER_ENTRY;
    await writeJsonFile(configPath, existing);
  } else {
    await writeJsonFile(configPath, {
      mcpServers: {
        shipsafe: MCP_SERVER_ENTRY,
      },
    });
  }
}

/**
 * Registers the ShipSafe MCP server in all known editor configs.
 */
export async function registerMcpServers(projectDir: string): Promise<void> {
  await registerMcpClaudeCode();
  await registerMcpCursor(projectDir);
}

/**
 * Main setup action — orchestrates hooks, MCP, and CLAUDE.md.
 * Each step is independent; failures are warned but don't block other steps.
 */
export async function handleSetupAction(options: SetupOptions): Promise<void> {
  const projectDir = process.cwd();

  console.log('Setting up ShipSafe...');

  // Step 1: Install git hooks
  if (!options.skipHooks) {
    try {
      await installHooks(projectDir, { withPrePush: options.withPrePush, commitOnly: options.commitOnly });
      const hookMsg = options.withPrePush ? 'Git hooks installed (pre-commit + pre-push)' : 'Git pre-commit hook installed';
      console.log(chalk.green('✓') + ' ' + hookMsg);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(chalk.yellow('⚠') + ` Git hooks: ${msg}`);
    }
  }

  // Step 2: Register MCP servers
  if (!options.skipMcp) {
    try {
      await registerMcpServers(projectDir);
      console.log(chalk.green('✓') + ' MCP server registered');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(chalk.yellow('⚠') + ` MCP registration: ${msg}`);
    }
  }

  // Step 3: Inject CLAUDE.md
  if (!options.skipClaudeMd) {
    try {
      await injectClaudeMd(projectDir);
      console.log(chalk.green('✓') + ' CLAUDE.md updated');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(chalk.yellow('⚠') + ` CLAUDE.md: ${msg}`);
    }
  }

  console.log(`\nShipSafe is ready! Run 'shipsafe scan' to run your first scan.`);
}

export function registerSetupCommand(program: Command): void {
  program
    .command('setup')
    .description('Set up ShipSafe for current project (hooks, MCP, CLAUDE.md)')
    .option('--skip-hooks', 'Skip git hook installation')
    .option('--skip-mcp', 'Skip MCP server registration')
    .option('--skip-claude-md', 'Skip CLAUDE.md injection')
    .option('--with-pre-push', 'Also install pre-push hook (full scan before push)')
    .option('--commit-only', 'Only install pre-commit hook (default behavior)')
    .action(async (options) => {
      await handleSetupAction({
        skipHooks: options.skipHooks,
        skipMcp: options.skipMcp,
        skipClaudeMd: options.skipClaudeMd,
        withPrePush: options.withPrePush,
        commitOnly: options.commitOnly,
      });
    });
}
