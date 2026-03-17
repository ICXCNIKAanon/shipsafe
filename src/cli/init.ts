import { randomUUID } from 'node:crypto';
import { Command } from 'commander';
import chalk from 'chalk';
import { loadProjectConfig, saveProjectConfig } from '../config/manager.js';
import { handleSetupAction } from './setup.js';

export interface InitOptions {
  projectDir?: string;
  skipSetup?: boolean;
}

/**
 * Main init action — bootstraps a project with a project ID, config file,
 * and optional setup (hooks, MCP, CLAUDE.md).
 */
export async function handleInitAction(options: InitOptions): Promise<void> {
  const { projectDir, skipSetup = false } = options;

  // Load existing config to check for an existing projectId
  const existingConfig = await loadProjectConfig(projectDir);

  if (existingConfig.projectId) {
    console.warn(
      chalk.yellow('⚠') +
        ` ShipSafe is already initialized (projectId: ${existingConfig.projectId}). Skipping config creation.`,
    );
    return;
  }

  // Generate a new project ID
  const projectId = `proj_${randomUUID().slice(0, 12)}`;

  // Write the project config
  await saveProjectConfig({ projectId }, projectDir);
  console.log(chalk.green('✓') + ` Created shipsafe.config.json (projectId: ${projectId})`);

  // Run setup unless explicitly skipped
  if (!skipSetup) {
    await handleSetupAction({});
  }

  // Print getting-started instructions
  console.log('');
  console.log(chalk.bold('ShipSafe initialized! Next steps:'));
  console.log('  1. Run ' + chalk.cyan('shipsafe scan') + ' to run your first security scan');
  console.log('  2. Run ' + chalk.cyan('shipsafe status') + ' to view your project security score');
  console.log(
    '  3. Run ' + chalk.cyan('shipsafe activate') + ' to unlock full scanning with a license key',
  );
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
