import { Command } from 'commander';
import chalk from 'chalk';
import { loadGlobalConfig, saveGlobalConfig } from '../config/manager.js';

export async function handleActivateAction(licenseKey: string): Promise<void> {
  const config = await loadGlobalConfig();

  // First save the license key
  await saveGlobalConfig({ ...config, licenseKey });

  // Attempt online validation if apiEndpoint is configured
  if (config.apiEndpoint) {
    try {
      const response = await fetch(`${config.apiEndpoint}/v1/license/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ license_key: licenseKey }),
      });

      if (!response.ok) {
        // API returned an error — invalid key
        const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
        const message =
          typeof body['message'] === 'string' ? body['message'] : 'Invalid license key.';
        console.log(chalk.red(`\nLicense validation failed: ${message}`));
        // Roll back — remove the key we just saved
        const { licenseKey: _removed, ...rest } = { ...config, licenseKey };
        void _removed;
        await saveGlobalConfig(rest);
        return;
      }

      const data = (await response.json()) as {
        valid: boolean;
        tier: string;
        expires_at: string;
        project_limit: number;
      };

      if (!data.valid) {
        console.log(chalk.red(`\nLicense key is not valid.`));
        const { licenseKey: _removed, ...rest } = { ...config, licenseKey };
        void _removed;
        await saveGlobalConfig(rest);
        return;
      }

      // Save with validation metadata
      await saveGlobalConfig({
        ...config,
        licenseKey,
        licenseValidatedAt: new Date().toISOString(),
        licenseTier: data.tier,
      });

      console.log(chalk.green(`\nShipSafe Pro activated successfully!`));
      console.log(`License key saved. Thank you for supporting ShipSafe.\n`);
    } catch {
      // Network error — offline
      console.log(
        chalk.yellow(`\nCould not validate online. License saved locally.`),
      );
    }
  } else {
    console.log(chalk.green(`\nShipSafe Pro activated successfully!`));
    console.log(`License key saved. Thank you for supporting ShipSafe.\n`);
  }
}

export function registerActivateCommand(program: Command): void {
  program
    .command('activate <license-key>')
    .description('Activate ShipSafe Pro with a license key')
    .action(async (licenseKey: string) => {
      await handleActivateAction(licenseKey);
    });
}
