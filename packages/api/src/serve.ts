import { serve } from '@hono/node-server';
import app from './index.js';

const port = parseInt(process.env.PORT ?? '3747', 10);

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`ShipSafe API listening on http://localhost:${info.port}`);
});
