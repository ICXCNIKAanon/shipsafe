import { existsSync, readFileSync } from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig, getProjectName } from '../config/manager.js';
import { getAvailableScanners } from '../engines/pattern/index.js';
import { HOOK_MARKER } from '../constants.js';

/**
 * Checks whether the ShipSafe pre-commit hook is installed in the
 * current project's .git/hooks directory.
 */
function checkHooksInstalled(projectDir: string): boolean {
  const hookPath = path.join(projectDir, '.git', 'hooks', 'pre-commit');

  try {
    if (!existsSync(hookPath)) return false;
    const contents = readFileSync(hookPath, 'utf-8');
    return contents.includes(HOOK_MARKER);
  } catch {
    return false;
  }
}

export async function handleStatusAction(): Promise<void> {
  const projectDir = process.cwd();
  const config = await loadConfig(projectDir);
  const projectName = getProjectName(projectDir);
  const hooksInstalled = checkHooksInstalled(projectDir);
  const scanners = await getAvailableScanners();

  const check = chalk.green('\u2713');
  const cross = chalk.red('\u2717');

  const semgrepLabel = `semgrep ${scanners.semgrep ? check : cross}`;
  const gitleaksLabel = `gitleaks ${scanners.gitleaks ? check : cross}`;
  const trivyLabel = `trivy ${scanners.trivy ? check : cross}`;

  const license = config.licenseKey ? 'Pro' : 'Free tier';

  console.log(chalk.bold('\nShipSafe Status'));
  console.log(chalk.bold('\u2500'.repeat(40)));
  console.log(`Project:        ${projectName}`);
  console.log(`Security Score: ${chalk.dim("\u2014 (run 'shipsafe scan' first)")}`);
  console.log(`Hooks Installed: ${hooksInstalled ? chalk.green('Yes') : chalk.red('No')}`);
  console.log(`Scanners:       ${semgrepLabel}  ${gitleaksLabel}  ${trivyLabel}`);
  console.log(`License:        ${license}`);
  console.log('');
}

export function registerStatusCommand(program: Command): void {
  program
    .command('status')
    .description('Show ShipSafe status for current project')
    .action(async () => {
      await handleStatusAction();
    });
}
