import { getClient } from '../index.js';
import type { ErrorEvent } from '../core/types.js';

export function errorHandler(): (err: Error, req: any, res: any, next: any) => void {
  return (err: Error, req: any, res: any, next: any) => {
    const client = getClient();
    if (client) {
      const errorEvent: Omit<ErrorEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'> = {
        type: 'error',
        error: {
          name: err.name,
          message: err.message,
          stack: err.stack,
          handled: true,
        },
        context: {
          method: req?.method,
          url: req?.originalUrl ?? req?.url,
          status_code: res?.statusCode,
        },
      };
      client.capture(errorEvent);
    }

    next(err);
  };
}
