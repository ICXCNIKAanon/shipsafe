import { Hono } from 'hono';
import { projectAuth } from '../middleware/auth.js';
import { rateLimiter } from '../middleware/rate-limit.js';
import { deduplicateError } from '../services/dedup.js';
import { storeError, getAllProjectErrors } from '../services/error-store.js';
import { resolveStackFrame } from '../services/sourcemap-resolver.js';
import type { ErrorEvent, IngestBody, AppVariables } from '../types.js';

export const ingestRoutes = new Hono<{ Variables: AppVariables }>();

ingestRoutes.post('/events', projectAuth, rateLimiter(), async (c) => {
  // Use pre-parsed body from auth middleware, or parse fresh
  let body: IngestBody;
  const parsedBody = c.get('parsedBody');

  if (parsedBody) {
    body = parsedBody;
  } else {
    try {
      body = await c.req.json<IngestBody>();
    } catch {
      return c.json({ error: 'Invalid JSON body' }, 400);
    }
  }

  if (!body.events || !Array.isArray(body.events)) {
    return c.json({ error: 'Missing or invalid events array' }, 400);
  }

  const projectId = c.get('projectId') ?? body.project_id;
  let processedCount = 0;

  for (const event of body.events) {
    // Ensure each event has the correct project_id
    event.project_id = projectId;

    if (event.type === 'error') {
      const errorEvent = event as ErrorEvent;
      const existingErrors = getAllProjectErrors(projectId);
      const processed = deduplicateError(errorEvent, existingErrors);

      // Enrich new errors with source map resolution when release info is present
      if (processed.occurrences === 1 && event.release) {
        const resolved = resolveStackFrame(projectId, event.release, processed.file, processed.line);
        processed.file = resolved.file;
        processed.line = resolved.line;
      }

      storeError(processed);
      processedCount++;
    }

    // Performance and api_error events — store later (Phase 5+)
    // For now, we accept them but only process error events
  }

  return c.json(
    {
      accepted: body.events.length,
      processed: processedCount,
    },
    202,
  );
});
