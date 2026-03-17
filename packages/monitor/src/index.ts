import { ShipSafeClient } from './core/client.js';
import type { ShipSafeConfig, ShipSafeEvent, ErrorEvent } from './core/types.js';
import { setupErrorCapture } from './capture/errors.js';
import { setupPerformanceCapture } from './capture/performance.js';
import { setupApiCapture } from './capture/api.js';

let client: ShipSafeClient | null = null;
let userId: string | undefined;
let cleanupFns: Array<() => void> = [];

export function getClient(): ShipSafeClient | null {
  return client;
}

function isBrowser(): boolean {
  return typeof window !== 'undefined';
}

export const ShipSafe = {
  init(config: ShipSafeConfig): void {
    if (client) {
      client.destroy();
      for (const cleanup of cleanupFns) {
        cleanup();
      }
      cleanupFns = [];
    }

    client = new ShipSafeClient(config);

    // Set up automatic capture in browser environments
    if (isBrowser()) {
      cleanupFns.push(setupErrorCapture(client));
      cleanupFns.push(setupPerformanceCapture(client));
      cleanupFns.push(setupApiCapture(client));
    }
  },

  captureError(error: Error, context?: Record<string, unknown>): void {
    if (!client) return;

    const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
      type: 'error',
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
        handled: true,
      },
      context: {
        url: context?.url as string | undefined,
        method: context?.method as string | undefined,
        status_code: context?.status_code as number | undefined,
        user_agent: context?.user_agent as string | undefined,
      },
    };

    client.capture(errorEvent);
  },

  captureMessage(message: string, level: 'info' | 'warning' | 'error' = 'info'): void {
    if (!client) return;

    const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
      type: 'error',
      error: {
        name: level.charAt(0).toUpperCase() + level.slice(1),
        message,
        handled: true,
      },
      context: {},
    };

    client.capture(errorEvent);
  },

  setUser(user: { id: string }): void {
    userId = user.id;
  },

  async flush(): Promise<void> {
    if (!client) return;
    await client.flush();
  },

  destroy(): void {
    if (client) {
      client.destroy();
      client = null;
    }
    for (const cleanup of cleanupFns) {
      cleanup();
    }
    cleanupFns = [];
    userId = undefined;
  },
};

// Re-export types
export type {
  ShipSafeConfig,
  ShipSafeEvent,
  ErrorEvent,
  PerformanceEvent,
  ApiErrorEvent,
} from './core/types.js';

// Re-export client for advanced usage
export { ShipSafeClient } from './core/client.js';
export { scrubEvent } from './core/scrubber.js';

// Re-export adapters
export { errorHandler } from './adapters/express.js';
export { setupNextjs } from './adapters/nextjs.js';
export { createErrorHandler } from './adapters/react.js';
