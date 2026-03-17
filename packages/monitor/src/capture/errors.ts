import type { ShipSafeClient } from '../core/client.js';
import type { ErrorEvent } from '../core/types.js';

function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof window.addEventListener === 'function';
}

function isNode(): boolean {
  return typeof process !== 'undefined' && typeof process.on === 'function';
}

function setupBrowserErrorCapture(client: ShipSafeClient): () => void {
  const originalOnError = window.onerror;
  const originalOnUnhandledRejection = window.onunhandledrejection;

  window.onerror = (
    message: string | Event,
    source?: string,
    lineno?: number,
    colno?: number,
    error?: Error,
  ) => {
    const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
      type: 'error',
      error: {
        name: error?.name ?? 'Error',
        message: typeof message === 'string' ? message : message?.toString() ?? 'Unknown error',
        stack: error?.stack,
        handled: false,
      },
      context: {
        url: source,
        user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : undefined,
      },
    };

    client.capture(errorEvent);

    if (typeof originalOnError === 'function') {
      return originalOnError.call(window, message, source, lineno, colno, error);
    }
    return false;
  };

  window.onunhandledrejection = (event: PromiseRejectionEvent) => {
    const reason = event.reason;
    const isError = reason instanceof Error;

    const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
      type: 'error',
      error: {
        name: isError ? reason.name : 'UnhandledRejection',
        message: isError ? reason.message : String(reason),
        stack: isError ? reason.stack : undefined,
        handled: false,
      },
      context: {
        url: typeof location !== 'undefined' ? location.href : undefined,
        user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : undefined,
      },
    };

    client.capture(errorEvent);

    if (typeof originalOnUnhandledRejection === 'function') {
      return originalOnUnhandledRejection.call(window, event);
    }
  };

  return () => {
    window.onerror = originalOnError;
    window.onunhandledrejection = originalOnUnhandledRejection;
  };
}

function setupNodeErrorCapture(client: ShipSafeClient): () => void {
  const onUncaughtException = (error: Error) => {
    const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
      type: 'error',
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
        handled: false,
      },
      context: {},
    };

    client.capture(errorEvent);
  };

  const onUnhandledRejection = (reason: unknown) => {
    const isError = reason instanceof Error;

    const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
      type: 'error',
      error: {
        name: isError ? reason.name : 'UnhandledRejection',
        message: isError ? reason.message : String(reason),
        stack: isError ? reason.stack : undefined,
        handled: false,
      },
      context: {},
    };

    client.capture(errorEvent);
  };

  process.on('uncaughtException', onUncaughtException);
  process.on('unhandledRejection', onUnhandledRejection);

  return () => {
    process.removeListener('uncaughtException', onUncaughtException);
    process.removeListener('unhandledRejection', onUnhandledRejection);
  };
}

export function setupErrorCapture(client: ShipSafeClient): () => void {
  if (isBrowser()) {
    return setupBrowserErrorCapture(client);
  }
  if (isNode()) {
    return setupNodeErrorCapture(client);
  }
  // Unknown environment — no-op cleanup
  return () => {};
}
