import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Command } from 'commander';
import chalk from 'chalk';
import { loadProjectConfig, saveProjectConfig } from '../config/manager.js';
import { handleSetupAction } from './setup.js';

const execFileAsync = promisify(execFile);

export interface InitOptions {
  projectDir?: string;
  skipSetup?: boolean;
}

const SHIPSAFE_AI_INSTRUCTION = `
# ShipSafe Security

This project uses ShipSafe for security scanning. When the shipsafe MCP tools are available:

1. Run shipsafe_scan at the start of every task to check for security issues
2. After writing or modifying code, run shipsafe_scan to verify no vulnerabilities were introduced
3. Before completing any task, confirm the security score is passing
4. If findings are reported, explain them to the user and suggest fixes
5. Use shipsafe_check_package before recommending new dependencies
`.trim();

const AI_CONFIG_FILES: Array<{
  filename: string;
  tool: string;
  wrapStart?: string;
  wrapEnd?: string;
}> = [
  { filename: 'CLAUDE.md', tool: 'Claude Code' },
  { filename: '.cursorrules', tool: 'Cursor' },
  { filename: '.windsurfrules', tool: 'Windsurf' },
  { filename: '.github/copilot-instructions.md', tool: 'GitHub Copilot' },
  { filename: '.clinerules', tool: 'Cline' },
];

async function registerMCPServers(): Promise<string[]> {
  const registered: string[] = [];
  const shipsafePath = process.argv[1]?.replace(/\/bin\/shipsafe\.(js|ts)$/, '/bin/shipsafe.js')
    || '/usr/local/bin/shipsafe';

  // Try to find the actual shipsafe binary
  let binPath = '/usr/local/bin/shipsafe';
  try {
    const { stdout } = await execFileAsync('which', ['shipsafe']);
    binPath = stdout.trim();
  } catch {
    // Fall back to default
  }

  // Register with Claude Code
  try {
    await execFileAsync('claude', ['mcp', 'add', 'shipsafe', binPath, 'mcp-server']);
    registered.push('Claude Code');
  } catch {
    // Claude CLI not installed — skip silently
  }

  return registered;
}

async function writeAIConfigs(projectDir: string): Promise<string[]> {
  const dir = projectDir ?? process.cwd();
  const written: string[] = [];

  for (const config of AI_CONFIG_FILES) {
    const filePath = path.join(dir, config.filename);

    // Create parent directory if needed (for .github/copilot-instructions.md)
    const parentDir = path.dirname(filePath);
    await fs.mkdir(parentDir, { recursive: true });

    try {
      // Check if file exists and already has ShipSafe section
      let existing = '';
      try {
        existing = await fs.readFile(filePath, 'utf-8');
      } catch {
        // File doesn't exist — that's fine
      }

      if (existing.includes('ShipSafe Security')) {
        continue; // Already configured
      }

      // Append to existing content or create new
      const content = existing
        ? existing.trimEnd() + '\n\n' + SHIPSAFE_AI_INSTRUCTION + '\n'
        : SHIPSAFE_AI_INSTRUCTION + '\n';

      await fs.writeFile(filePath, content, 'utf-8');
      written.push(config.tool);
    } catch {
      // Skip files we can't write
    }
  }

  return written;
}

/**
 * Main init action — bootstraps a project with a project ID, config file,
 * and optional setup (hooks, MCP, CLAUDE.md).
 */
export async function handleInitAction(options: InitOptions): Promise<void> {
  const { projectDir, skipSetup = false } = options;

  // Load existing config to check for an existing projectId
  const existingConfig = await loadProjectConfig(projectDir);

  let projectId = existingConfig.projectId;
  if (projectId) {
    console.log(chalk.dim('  Project already initialized (projectId: ' + projectId + ')'));
  } else {
    projectId = `proj_${randomUUID().slice(0, 12)}`;
    await saveProjectConfig({ projectId }, projectDir);
    console.log(chalk.green('✓') + ` Created shipsafe.config.json (projectId: ${projectId})`);
  }

  // Write AI assistant config files
  const aiTools = await writeAIConfigs(projectDir ?? process.cwd());
  if (aiTools.length > 0) {
    console.log(chalk.green('✓') + ` AI security rules added for: ${aiTools.join(', ')}`);
  }

  // Register MCP server with AI coding tools
  const mcpTools = await registerMCPServers();
  if (mcpTools.length > 0) {
    console.log(chalk.green('✓') + ` MCP server registered for: ${mcpTools.join(', ')}`);
  }

  // Run setup unless explicitly skipped
  if (!skipSetup) {
    await handleSetupAction({});
  }

  console.log('');
  console.log(chalk.green.bold('  ShipSafe is ready.'));
  console.log('');
  console.log('  Your AI assistant will now auto-scan for security issues.');
  console.log('  Run ' + chalk.cyan('shipsafe scan') + ' anytime for a manual scan.');
  console.log('');
}

export function registerInitCommand(program: Command): void {
  program
    .command('init')
    .description('Initialize ShipSafe for the current project')
    .option('--skip-setup', 'Skip hooks, MCP, and CLAUDE.md setup')
    .action(async (options) => {
      await handleInitAction({
        skipSetup: options.skipSetup,
      });
    });
}
