import type { ShipSafeClient } from '../core/client.js';
import type { ApiErrorEvent } from '../core/types.js';

export function setupApiCapture(client: ShipSafeClient): () => void {
  if (typeof globalThis.fetch !== 'function') {
    return () => {};
  }

  const originalFetch = globalThis.fetch;

  globalThis.fetch = async function patchedFetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const startTime = Date.now();
    const method = init?.method?.toUpperCase() ?? 'GET';

    let url: string;
    if (typeof input === 'string') {
      url = input;
    } else if (input instanceof URL) {
      url = input.toString();
    } else {
      url = (input as Request).url;
    }

    // Extract path from URL
    let path: string;
    try {
      path = new URL(url, typeof location !== 'undefined' ? location.href : undefined).pathname;
    } catch {
      path = url;
    }

    try {
      const response = await originalFetch.call(globalThis, input, init);
      const duration = Date.now() - startTime;

      // Capture API errors (4xx and 5xx responses)
      if (response.status >= 400) {
        const apiEvent: Omit<ApiErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
          type: 'api_error',
          request: {
            method,
            path,
            status_code: response.status,
            duration_ms: duration,
          },
        };
        client.capture(apiEvent);
      }

      return response;
    } catch (err) {
      const duration = Date.now() - startTime;
      const isError = err instanceof Error;

      const apiEvent: Omit<ApiErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
        type: 'api_error',
        request: {
          method,
          path,
          status_code: 0,
          duration_ms: duration,
        },
        error: {
          name: isError ? err.name : 'FetchError',
          message: isError ? err.message : String(err),
          stack: isError ? err.stack : undefined,
        },
      };
      client.capture(apiEvent);

      throw err;
    }
  };

  return () => {
    globalThis.fetch = originalFetch;
  };
}
