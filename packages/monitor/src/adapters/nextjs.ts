import { getClient } from '../index.js';
import type { ErrorEvent } from '../core/types.js';

export function setupNextjs(): () => void {
  const originalConsoleError = console.error;

  console.error = (...args: unknown[]) => {
    const client = getClient();
    if (client) {
      // Try to extract an Error object from the arguments
      let error: Error | undefined;
      let message = '';

      for (const arg of args) {
        if (arg instanceof Error) {
          error = arg;
          break;
        }
      }

      if (!error) {
        message = args.map((arg) => (typeof arg === 'string' ? arg : String(arg))).join(' ');
      }

      const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
        type: 'error',
        error: {
          name: error?.name ?? 'ConsoleError',
          message: error?.message ?? message,
          stack: error?.stack,
          handled: false,
        },
        context: {},
      };

      client.capture(errorEvent);
    }

    originalConsoleError.apply(console, args);
  };

  return () => {
    console.error = originalConsoleError;
  };
}
