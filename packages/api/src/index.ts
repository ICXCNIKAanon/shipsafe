import { Hono } from 'hono';
import { ingestRoutes } from './routes/ingest.js';
import { errorRoutes } from './routes/errors.js';
import { healthRoutes } from './routes/health.js';
import { licenseRoutes } from './routes/license.js';

const app = new Hono();

app.route('/v1', ingestRoutes);
app.route('/v1', errorRoutes);
app.route('/', healthRoutes);
app.route('/v1', licenseRoutes);

export default app;
export { app };
