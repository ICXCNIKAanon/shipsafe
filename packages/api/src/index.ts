import { Hono } from 'hono';
import { createDatabase } from './db/database.js';
import * as path from 'node:path';
import * as os from 'node:os';
import * as fs from 'node:fs';
import { ingestRoutes } from './routes/ingest.js';
import { errorRoutes } from './routes/errors.js';
import { errorStatusRoutes } from './routes/error-status.js';
import { healthRoutes } from './routes/health.js';
import { licenseRoutes } from './routes/license.js';
import { sourcemapRoutes } from './routes/sourcemaps.js';
import { performanceRoutes } from './routes/performance.js';
import { apiErrorRoutes } from './routes/api-errors.js';

// Initialize database — env var override or default to ~/.shipsafe/shipsafe.db
if (process.env.NODE_ENV !== 'test') {
  const dbPath = process.env.SHIPSAFE_DB_PATH
    ?? path.join(os.homedir(), '.shipsafe', 'shipsafe.db');
  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  createDatabase(dbPath);
}

const app = new Hono();

app.route('/v1', ingestRoutes);
app.route('/v1', errorRoutes);
app.route('/v1', errorStatusRoutes);
app.route('/v1', sourcemapRoutes);
app.route('/v1', performanceRoutes);
app.route('/v1', apiErrorRoutes);
app.route('/', healthRoutes);
app.route('/v1', licenseRoutes);

export default app;
export { app };
