import { Hono } from 'hono';
import { dbGetPerformanceMetrics } from '../db/performance-repo.js';

export const performanceRoutes = new Hono();

performanceRoutes.get('/performance/:projectId', (c) => {
  const projectId = c.req.param('projectId');
  const url = c.req.query('url');
  const limitParam = c.req.query('limit');
  let limit: number | undefined;
  if (limitParam) {
    const parsed = parseInt(limitParam, 10);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      return c.json({ error: 'Invalid limit. Must be a positive integer.' }, 400);
    }
    limit = parsed;
  }

  const metrics = dbGetPerformanceMetrics(projectId, { url, limit });

  return c.json({
    project_id: projectId,
    count: metrics.length,
    metrics,
  });
});
