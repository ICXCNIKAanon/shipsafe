import { Hono } from 'hono';
import { dbGetErrors } from '../db/error-repo.js';

export const errorStatusRoutes = new Hono();

errorStatusRoutes.get('/errors/:projectId/:errorId/status', (c) => {
  const projectId = c.req.param('projectId');
  const errorId = c.req.param('errorId');

  const allErrors = dbGetErrors(projectId, { status: 'all' });
  const error = allErrors.find((e) => e.id === errorId);

  if (!error) {
    return c.json({ error: 'Error not found' }, 404);
  }

  const hoursSinceLast =
    (Date.now() - new Date(error.last_seen).getTime()) / (1000 * 60 * 60);

  const isResolved = error.status === 'resolved';
  const confidence = isResolved
    ? Math.min(hoursSinceLast / 24, 1)
    : Math.min(error.occurrences / 10, 1);

  return c.json({
    status: isResolved ? 'resolved' : 'recurring',
    last_occurrence: error.last_seen,
    hours_since_last: hoursSinceLast,
    confidence,
  });
});
