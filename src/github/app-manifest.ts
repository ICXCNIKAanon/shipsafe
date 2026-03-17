/**
 * GitHub App manifest for ShipSafe registration.
 *
 * This manifest defines the permissions and events the ShipSafe GitHub App
 * requires. The actual App registration is done manually on GitHub; this
 * manifest serves as the canonical source of truth for the configuration.
 *
 * See: https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
 */
export const APP_MANIFEST = {
  name: 'ShipSafe',
  url: 'https://shipsafe.org',
  hook_attributes: {
    url: '', // filled in during setup with the webhook endpoint URL
  },
  redirect_url: '',
  setup_url: '',
  public: true,
  default_permissions: {
    checks: 'write' as const,
    contents: 'read' as const,
    pull_requests: 'write' as const,
    statuses: 'write' as const,
  },
  default_events: ['pull_request', 'push'] as const,
};

export type AppManifest = typeof APP_MANIFEST;
