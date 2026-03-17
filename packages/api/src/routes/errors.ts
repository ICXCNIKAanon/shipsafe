import { Hono } from 'hono';
import { dbGetErrors } from '../db/error-repo.js';

export const errorRoutes = new Hono();

const VALID_SEVERITIES = new Set(['all', 'critical', 'high', 'medium', 'low']);
const VALID_STATUSES = new Set(['open', 'resolved', 'all']);

errorRoutes.get('/errors/:projectId', (c) => {
  const projectId = c.req.param('projectId');
  const severity = c.req.query('severity');
  const status = c.req.query('status') ?? 'open';

  if (severity && !VALID_SEVERITIES.has(severity)) {
    return c.json({ error: `Invalid severity. Must be one of: ${[...VALID_SEVERITIES].join(', ')}` }, 400);
  }
  if (!VALID_STATUSES.has(status)) {
    return c.json({ error: `Invalid status. Must be one of: ${[...VALID_STATUSES].join(', ')}` }, 400);
  }

  const errors = dbGetErrors(projectId, { severity, status });

  return c.json({
    project_id: projectId,
    count: errors.length,
    errors,
  });
});
