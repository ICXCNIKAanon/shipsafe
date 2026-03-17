import { Command } from 'commander';
import chalk from 'chalk';
import { loadGlobalConfig, saveGlobalConfig } from '../config/manager.js';

export async function handleActivateAction(licenseKey: string): Promise<void> {
  const config = await loadGlobalConfig();

  await saveGlobalConfig({ ...config, licenseKey });

  console.log(chalk.green(`\nShipSafe Pro activated successfully!`));
  console.log(`License key saved. Thank you for supporting ShipSafe.\n`);
}

export function registerActivateCommand(program: Command): void {
  program
    .command('activate <license-key>')
    .description('Activate ShipSafe Pro with a license key')
    .action(async (licenseKey: string) => {
      await handleActivateAction(licenseKey);
    });
}
