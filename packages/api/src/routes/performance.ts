import { Hono } from 'hono';
import { dbGetPerformanceMetrics } from '../db/performance-repo.js';

export const performanceRoutes = new Hono();

performanceRoutes.get('/performance/:projectId', (c) => {
  const projectId = c.req.param('projectId');
  const url = c.req.query('url');
  const limitParam = c.req.query('limit');
  const limit = limitParam ? parseInt(limitParam, 10) : undefined;

  const metrics = dbGetPerformanceMetrics(projectId, { url, limit });

  return c.json({
    project_id: projectId,
    count: metrics.length,
    metrics,
  });
});
