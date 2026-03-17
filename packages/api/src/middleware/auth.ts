import type { Context, Next } from 'hono';
import type { AppVariables } from '../types.js';

/**
 * Validates that a project ID is present in the request.
 * Checks both the X-Project-ID header and the request body.
 */
export async function projectAuth(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
): Promise<Response | void> {
  const headerProjectId = c.req.header('X-Project-ID');

  if (headerProjectId && headerProjectId.length > 0) {
    c.set('projectId', headerProjectId);
    return next();
  }

  // For POST requests, also check the body
  if (c.req.method === 'POST') {
    try {
      const body = await c.req.json();
      if (body?.project_id && typeof body.project_id === 'string') {
        c.set('projectId', body.project_id);
        // Store the parsed body so routes don't need to parse again
        c.set('parsedBody', body);
        return next();
      }
    } catch {
      // Body parse failed — fall through to 401
    }
  }

  return c.json(
    { error: 'Missing project ID. Provide X-Project-ID header or project_id in body.' },
    401,
  );
}
