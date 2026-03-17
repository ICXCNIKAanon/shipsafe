import { Hono } from 'hono';
import { projectAuth } from '../middleware/auth.js';
import { rateLimiter } from '../middleware/rate-limit.js';
import { deduplicateError } from '../services/dedup.js';
import { dbStoreError, dbGetAllProjectErrors } from '../db/error-repo.js';
import { dbStorePerformanceMetric } from '../db/performance-repo.js';
import { dbStoreApiError } from '../db/api-error-repo.js';
import { resolveStackFrame } from '../services/sourcemap-resolver.js';
import type { ErrorEvent, PerformanceEvent, ApiErrorEvent, IngestBody, AppVariables } from '../types.js';

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
      const existingErrors = dbGetAllProjectErrors(projectId);
      const processed = deduplicateError(errorEvent, existingErrors);

      // Enrich new errors with source map resolution when release info is present
      if (processed.occurrences === 1 && event.release) {
        const resolved = resolveStackFrame(projectId, event.release, processed.file, processed.line);
        processed.file = resolved.file;
        processed.line = resolved.line;
      }

      dbStoreError(processed);
      processedCount++;
    }

    if (event.type === 'performance') {
      const perfEvent = event as PerformanceEvent;
      dbStorePerformanceMetric({
        id: crypto.randomUUID(),
        project_id: projectId,
        url: perfEvent.url,
        ...perfEvent.metrics,
        environment: perfEvent.environment,
        timestamp: perfEvent.timestamp,
      });
      processedCount++;
    }

    if (event.type === 'api_error') {
      const apiEvent = event as ApiErrorEvent;
      dbStoreApiError({
        id: crypto.randomUUID(),
        project_id: projectId,
        method: apiEvent.request.method,
        path: apiEvent.request.path,
        status_code: apiEvent.request.status_code,
        duration_ms: apiEvent.request.duration_ms,
        error_name: apiEvent.error?.name,
        error_message: apiEvent.error?.message,
        error_stack: apiEvent.error?.stack,
        environment: apiEvent.environment,
        timestamp: apiEvent.timestamp,
      });
      processedCount++;
    }
  }

  return c.json(
    {
      accepted: body.events.length,
      processed: processedCount,
    },
    202,
  );
});
