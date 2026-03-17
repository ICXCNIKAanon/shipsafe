import { Hono } from 'hono';
import { dbGetApiErrors } from '../db/api-error-repo.js';

export const apiErrorRoutes = new Hono();

apiErrorRoutes.get('/api-errors/:projectId', (c) => {
  const projectId = c.req.param('projectId');
  const path = c.req.query('path');
  const limitParam = c.req.query('limit');
  let limit: number | undefined;
  if (limitParam) {
    const parsed = parseInt(limitParam, 10);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      return c.json({ error: 'Invalid limit. Must be a positive integer.' }, 400);
    }
    limit = parsed;
  }

  const errors = dbGetApiErrors(projectId, { path, limit });

  return c.json({
    project_id: projectId,
    count: errors.length,
    errors,
  });
});
