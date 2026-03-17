import { loadGlobalConfig, saveGlobalConfig } from '../config/manager.js';

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

export interface LicenseCheckResult {
  valid: boolean;
  tier: string;
  reason?: string;
}

async function validateOnline(
  apiEndpoint: string,
  licenseKey: string,
): Promise<{ valid: boolean; tier: string } | null> {
  try {
    const response = await fetch(`${apiEndpoint}/v1/license/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: licenseKey }),
    });

    if (!response.ok) {
      return { valid: false, tier: 'free' };
    }

    const data = (await response.json()) as { valid: boolean; tier: string };
    return { valid: data.valid, tier: data.tier };
  } catch {
    // Network error
    return null;
  }
}

export async function checkLicense(): Promise<LicenseCheckResult> {
  const config = await loadGlobalConfig();

  // No license key at all
  if (!config.licenseKey) {
    return { valid: false, tier: 'free', reason: 'No license key' };
  }

  const now = Date.now();

  if (config.licenseValidatedAt) {
    const validatedAt = new Date(config.licenseValidatedAt).getTime();
    const age = now - validatedAt;

    if (age < THIRTY_DAYS_MS) {
      // Fresh cache — return cached result
      return { valid: true, tier: config.licenseTier ?? 'unknown' };
    }

    // Cache expired — try to re-validate online
    if (config.apiEndpoint) {
      const result = await validateOnline(config.apiEndpoint, config.licenseKey);

      if (result !== null) {
        // Online validation succeeded — update cache
        await saveGlobalConfig({
          ...config,
          licenseValidatedAt: new Date().toISOString(),
          licenseTier: result.tier,
        });
        return { valid: result.valid, tier: result.tier };
      }
    }

    // Offline with expired cache
    return {
      valid: false,
      tier: config.licenseTier ?? 'unknown',
      reason: 'License cache expired. Connect to internet to re-validate.',
    };
  }

  // No licenseValidatedAt — try online validation, fallback to first-time grace
  if (config.apiEndpoint) {
    const result = await validateOnline(config.apiEndpoint, config.licenseKey);

    if (result !== null) {
      // Online validation succeeded — update cache
      await saveGlobalConfig({
        ...config,
        licenseValidatedAt: new Date().toISOString(),
        licenseTier: result.tier,
      });
      return { valid: result.valid, tier: result.tier };
    }
  }

  // No validation timestamp and offline — first-time grace
  return { valid: true, tier: 'unknown' };
}
