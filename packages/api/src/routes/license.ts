import { Hono } from 'hono';
import type { LicenseInfo, LicenseTier, AppVariables } from '../types.js';
import { rateLimiter } from '../middleware/rate-limit.js';

export const licenseRoutes = new Hono<{ Variables: AppVariables }>();

/**
 * License key format: SS-{TIER}-{RANDOM}
 * Example: SS-PRO-abc123def456
 *
 * In Phase 6, this will validate against Stripe.
 * For now, we do a simple format check.
 */
const TIER_MAP: Record<string, { tier: LicenseTier; projectLimit: number }> = {
  FREE: { tier: 'free', projectLimit: 1 },
  PRO: { tier: 'pro', projectLimit: 5 },
  TEAM: { tier: 'team', projectLimit: 20 },
  AGENCY: { tier: 'agency', projectLimit: 100 },
};

function validateLicenseKey(key: string): LicenseInfo | null {
  if (!key || typeof key !== 'string') return null;

  const match = key.match(/^SS-(FREE|PRO|TEAM|AGENCY)-[a-zA-Z0-9]{8,}$/);
  if (!match) return null;

  const tierKey = match[1];
  const tierInfo = TIER_MAP[tierKey];
  if (!tierInfo) return null;

  // For now, all valid keys expire 1 year from now
  const expiresAt = new Date();
  expiresAt.setFullYear(expiresAt.getFullYear() + 1);

  return {
    valid: true,
    tier: tierInfo.tier,
    expires_at: expiresAt.toISOString(),
    project_limit: tierInfo.projectLimit,
  };
}

licenseRoutes.post('/license/validate', rateLimiter(30, 60_000), async (c) => {
  let body: { license_key?: string };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  if (!body.license_key) {
    return c.json({ error: 'Missing license_key in request body' }, 400);
  }

  const result = validateLicenseKey(body.license_key);

  if (!result) {
    return c.json(
      {
        valid: false,
        error: 'Invalid license key format. Expected: SS-{TIER}-{key}',
      },
      400,
    );
  }

  return c.json(result);
});
