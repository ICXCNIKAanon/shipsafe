import { Hono } from 'hono';
import { getErrors } from '../services/error-store.js';

export const errorRoutes = new Hono();

errorRoutes.get('/errors/:projectId', (c) => {
  const projectId = c.req.param('projectId');
  const severity = c.req.query('severity');
  const status = c.req.query('status') ?? 'open';

  const errors = getErrors(projectId, { severity, status });

  return c.json({
    project_id: projectId,
    count: errors.length,
    errors,
  });
});
