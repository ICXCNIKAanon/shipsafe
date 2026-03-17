import { serve } from '@hono/node-server';
import app from './index.js';
import { closeDatabase } from './db/database.js';

const port = parseInt(process.env.PORT ?? '3747', 10);

const server = serve({ fetch: app.fetch, port }, (info) => {
  console.log(`ShipSafe API listening on http://localhost:${info.port}`);
});

function shutdown() {
  console.log('Shutting down...');
  closeDatabase();
  server.close();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
