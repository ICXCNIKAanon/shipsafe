import { Hono } from 'hono';
import { dbGetApiErrors } from '../db/api-error-repo.js';

export const apiErrorRoutes = new Hono();

apiErrorRoutes.get('/api-errors/:projectId', (c) => {
  const projectId = c.req.param('projectId');
  const path = c.req.query('path');
  const limitParam = c.req.query('limit');
  const limit = limitParam ? parseInt(limitParam, 10) : undefined;

  const errors = dbGetApiErrors(projectId, { path, limit });

  return c.json({
    project_id: projectId,
    count: errors.length,
    errors,
  });
});
