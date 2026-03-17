import { Command } from 'commander';
import chalk from 'chalk';
import { loadGlobalConfig, saveGlobalConfig, getApiEndpoint } from '../config/manager.js';

export async function handleActivateAction(licenseKey: string): Promise<void> {
  const config = await loadGlobalConfig();

  // First save the license key
  await saveGlobalConfig({ ...config, licenseKey });

  // Attempt online validation
  const apiEndpoint = getApiEndpoint(config);
  try {
    const response = await fetch(`${apiEndpoint}/v1/license/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: licenseKey }),
    });

    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      const message =
        typeof body['message'] === 'string' ? body['message'] : 'Invalid license key.';
      console.log(chalk.red(`\nLicense validation failed: ${message}`));
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

    await saveGlobalConfig({
      ...config,
      licenseKey,
      licenseValidatedAt: new Date().toISOString(),
      licenseTier: data.tier,
    });

    console.log(chalk.green(`\nShipSafe Pro activated successfully!`));
    console.log(`License key saved. Thank you for supporting ShipSafe.\n`);
  } catch {
    console.log(
      chalk.yellow(`\nCould not validate online. License saved locally.`),
    );
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
