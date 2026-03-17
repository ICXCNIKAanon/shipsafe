import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import app from '../../src/index.js';

describe('full error loop (integration)', () => {
  beforeEach(() => {
    createDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('ingest → query → verify status', async () => {
    // 1. Ingest an error event
    const ingestRes = await app.request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Project-ID': 'proj-1' },
      body: JSON.stringify({
        project_id: 'proj-1',
        events: [{
          type: 'error',
          timestamp: new Date().toISOString(),
          project_id: 'proj-1',
          environment: 'production',
          session_id: 'sess-1',
          error: {
            name: 'TypeError',
            message: 'Cannot read properties of undefined',
            stack: 'TypeError: Cannot read properties of undefined\n    at handler (src/app.ts:42:5)',
            handled: false,
          },
          context: { url: '/api/data' },
        }],
      }),
    });
    expect(ingestRes.status).toBe(202);
    const ingestData = await ingestRes.json();
    expect(ingestData.processed).toBe(1);

    // 2. Query errors for the project
    const errorsRes = await app.request('/v1/errors/proj-1');
    expect(errorsRes.status).toBe(200);
    const errorsData = await errorsRes.json();
    expect(errorsData.count).toBe(1);
    expect(errorsData.errors[0].title).toContain('TypeError');

    const errorId = errorsData.errors[0].id;

    // 3. Check error status
    const statusRes = await app.request(`/v1/errors/proj-1/${errorId}/status`);
    expect(statusRes.status).toBe(200);
    const statusData = await statusRes.json();
    expect(statusData.status).toBe('recurring');
  });
});
