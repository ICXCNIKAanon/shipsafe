import { Hono } from 'hono';
import {
  storeSourceMap,
} from '../services/sourcemap-store.js';

export const sourcemapRoutes = new Hono();

sourcemapRoutes.post('/sourcemaps', async (c) => {
  let body: {
    project_id?: string;
    release?: string;
    file_path?: string;
    source_map?: string;
  };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  if (!body.project_id || !body.release || !body.file_path || !body.source_map) {
    return c.json({ error: 'Missing required fields: project_id, release, file_path, source_map' }, 400);
  }

  storeSourceMap(body.project_id, body.release, body.file_path, body.source_map);

  return c.json(
    {
      stored: true,
      file_path: body.file_path,
      release: body.release,
    },
    201,
  );
});

sourcemapRoutes.post('/sourcemaps/batch', async (c) => {
  let body: {
    project_id?: string;
    release?: string;
    source_maps?: Array<{ file_path: string; source_map: string }>;
  };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  if (!body.project_id || !body.release || !body.source_maps) {
    return c.json({ error: 'Missing required fields: project_id, release, source_maps' }, 400);
  }

  for (const entry of body.source_maps) {
    storeSourceMap(body.project_id, body.release, entry.file_path, entry.source_map);
  }

  return c.json(
    {
      stored: body.source_maps.length,
      release: body.release,
    },
    201,
  );
});
