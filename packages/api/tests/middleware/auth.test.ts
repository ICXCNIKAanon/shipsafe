import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { projectAuth } from '../../src/middleware/auth.js';
import type { AppVariables } from '../../src/types.js';

function createTestApp() {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use('*', projectAuth);
  app.all('/test', (c) => c.json({ projectId: c.get('projectId') }));
  return app;
}

describe('projectAuth middleware', () => {
  it('passes with X-Project-ID header', async () => {
    const app = createTestApp();
    const res = await app.request('/test', {
      headers: { 'X-Project-ID': 'proj_123' },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.projectId).toBe('proj_123');
  });

  it('passes with project_id in POST body', async () => {
    const app = createTestApp();
    const res = await app.request('/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: 'proj_456' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.projectId).toBe('proj_456');
  });

  it('returns 401 when no project ID provided', async () => {
    const app = createTestApp();
    const res = await app.request('/test');
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toContain('Missing project ID');
  });

  it('returns 401 for POST with invalid JSON', async () => {
    const app = createTestApp();
    const res = await app.request('/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not-json',
    });
    expect(res.status).toBe(401);
  });

  it('returns 401 for POST body without project_id', async () => {
    const app = createTestApp();
    const res = await app.request('/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ other: 'field' }),
    });
    expect(res.status).toBe(401);
  });

  it('prefers header over body', async () => {
    const app = createTestApp();
    const res = await app.request('/test', {
      method: 'POST',
      headers: {
        'X-Project-ID': 'from-header',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ project_id: 'from-body' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.projectId).toBe('from-header');
  });

  it('rejects empty X-Project-ID header', async () => {
    const app = createTestApp();
    const res = await app.request('/test', {
      headers: { 'X-Project-ID': '' },
    });
    expect(res.status).toBe(401);
  });
});
