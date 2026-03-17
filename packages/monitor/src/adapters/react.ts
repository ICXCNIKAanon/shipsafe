import { getClient } from '../index.js';
import type { ErrorEvent } from '../core/types.js';

/**
 * Creates an error handler compatible with React's ErrorBoundary onError callback.
 * No React dependency required.
 *
 * Usage with React ErrorBoundary:
 *   <ErrorBoundary onError={createErrorHandler()}>
 *     <App />
 *   </ErrorBoundary>
 */
export function createErrorHandler(): (error: Error, errorInfo: { componentStack: string }) => void {
  return (error: Error, errorInfo: { componentStack: string }) => {
    const client = getClient();
    if (!client) return;

    const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
      type: 'error',
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
          ? error.stack + '\n\nComponent Stack:' + errorInfo.componentStack
          : errorInfo.componentStack,
        handled: true,
      },
      context: {
        url: typeof window !== 'undefined' ? window.location.href : undefined,
      },
    };

    client.capture(errorEvent);
  };
}
