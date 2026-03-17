import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { homedir } from 'node:os';
import { exec } from 'node:child_process';
import { Command } from 'commander';
import chalk from 'chalk';
import { GLOBAL_DIR_NAME } from '../constants.js';

const GITHUB_APP_URL = 'https://github.com/apps/shipsafe';
const CONFIG_FILE_NAME = 'github.json';

export interface GitHubConnectionConfig {
  connected: boolean;
  connectedAt: string;
  appUrl: string;
}

/**
 * Get the path to the global ShipSafe config directory.
 */
export function getGlobalConfigDir(): string {
  return path.join(homedir(), GLOBAL_DIR_NAME);
}

/**
 * Get the path to the GitHub connection config file.
 */
export function getGitHubConfigPath(): string {
  return path.join(getGlobalConfigDir(), CONFIG_FILE_NAME);
}

/**
 * Check if the GitHub App is already connected.
 */
export async function isConnected(): Promise<boolean> {
  try {
    const configPath = getGitHubConfigPath();
    const raw = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(raw) as GitHubConnectionConfig;
    return config.connected === true;
  } catch {
    return false;
  }
}

/**
 * Save the GitHub connection config.
 */
export async function saveConnectionConfig(): Promise<void> {
  const configDir = getGlobalConfigDir();
  await fs.mkdir(configDir, { recursive: true });

  const config: GitHubConnectionConfig = {
    connected: true,
    connectedAt: new Date().toISOString(),
    appUrl: GITHUB_APP_URL,
  };

  await fs.writeFile(getGitHubConfigPath(), JSON.stringify(config, null, 2) + '\n', 'utf-8');
}

/**
 * Open a URL in the default browser.
 * Uses platform-appropriate command.
 */
export function openInBrowser(url: string): void {
  const platform = process.platform;
  let command: string;

  if (platform === 'darwin') {
    command = `open "${url}"`;
  } else if (platform === 'win32') {
    command = `start "${url}"`;
  } else {
    command = `xdg-open "${url}"`;
  }

  exec(command, () => {
    // Silently ignore errors — user can open the URL manually
  });
}

/**
 * Main connect action — guides user through GitHub App installation.
 */
export async function handleConnectAction(): Promise<void> {
  // 1. Check if already connected
  const alreadyConnected = await isConnected();
  if (alreadyConnected) {
    console.log(chalk.green('GitHub App is already connected!'));
    console.log(`PRs will be scanned automatically.`);
    console.log(`\nTo reinstall, visit: ${GITHUB_APP_URL}`);
    return;
  }

  // 2. Print instructions
  console.log(chalk.bold('Connect ShipSafe to GitHub\n'));
  console.log(`Install the ShipSafe GitHub App to enable automatic PR scanning.`);
  console.log(`\nVisit: ${chalk.cyan(GITHUB_APP_URL)}`);

  // 3. Open the URL in the default browser
  openInBrowser(GITHUB_APP_URL);
  console.log(`\nOpening browser...`);

  // 4. Save connection info (the user will complete setup on GitHub)
  await saveConnectionConfig();

  // 5. Print confirmation
  console.log(chalk.green('\nGitHub App connected! PRs will now be scanned automatically.'));
}

/**
 * Register the 'connect' command with the CLI program.
 */
export function registerConnectCommand(program: Command): void {
  program
    .command('connect')
    .description('Connect ShipSafe to GitHub (install GitHub App)')
    .action(async () => {
      await handleConnectAction();
    });
}
