import { checkLicense } from './license-check.js';

export type Feature =
  | 'scan'
  | 'autofix'
  | 'knowledge_graph'
  | 'monitoring'
  | 'upload_sourcemaps'
  | 'github_app'
  | 'mcp_server';

const TIER_FEATURES: Record<string, Feature[]> = {
  free: ['scan'],
  pro: ['scan', 'autofix', 'knowledge_graph', 'monitoring', 'mcp_server'],
  team: ['scan', 'autofix', 'knowledge_graph', 'monitoring', 'upload_sourcemaps', 'github_app', 'mcp_server'],
  agency: ['scan', 'autofix', 'knowledge_graph', 'monitoring', 'upload_sourcemaps', 'github_app', 'mcp_server'],
  unknown: ['scan'], // first-time grace / offline fallback
};

export function tierHasFeature(tier: string, feature: Feature): boolean {
  const features = TIER_FEATURES[tier.toLowerCase()] ?? TIER_FEATURES['free']!;
  return features.includes(feature);
}

export interface GateResult {
  allowed: boolean;
  tier: string;
  reason?: string;
}

export async function gateFeature(feature: Feature): Promise<GateResult> {
  const license = await checkLicense();
  const tier = license.tier;

  if (tierHasFeature(tier, feature)) {
    return { allowed: true, tier };
  }

  return {
    allowed: false,
    tier,
    reason: `The "${feature}" feature requires a higher license tier. Current tier: ${tier}. Upgrade at https://shipsafe.org/pricing`,
  };
}
