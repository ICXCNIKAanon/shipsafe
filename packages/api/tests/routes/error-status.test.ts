import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import app from '../../src/index.js';
import { dbStoreError } from '../../src/db/error-repo.js';
import type { ProcessedError } from '../../src/types.js';

function makeProcessedError(overrides: Partial<ProcessedError> = {}): ProcessedError {
  return {
    id: crypto.randomUUID(),
    project_id: 'proj_test',
    severity: 'high',
    title: 'TypeError: Cannot read properties of undefined',
    file: '/app/src/components/Button.tsx',
    line: 15,
    root_cause: 'A TypeError occurred in handleClick',
    suggested_fix: 'Add a null check',
    users_affected: 5,
    occurrences: 10,
    first_seen: '2026-03-15T00:00:00.000Z',
    last_seen: '2026-03-16T00:00:00.000Z',
    status: 'open',
    stack_trace:
      'TypeError: Cannot read properties of undefined\n    at handleClick (/app/src/components/Button.tsx:15:10)',
    ...overrides,
  };
}

describe('GET /v1/errors/:projectId/:errorId/status', () => {
  beforeEach(() => {
    createDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('returns recurring status for an existing open error', async () => {
    const error = makeProcessedError({ status: 'open', occurrences: 5 });
    dbStoreError(error);

    const res = await app.request(`/v1/errors/proj_test/${error.id}/status`);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.status).toBe('recurring');
    expect(body.last_occurrence).toBe(error.last_seen);
    expect(typeof body.hours_since_last).toBe('number');
    expect(body.confidence).toBe(Math.min(5 / 10, 1));
  });

  it('returns resolved status for a resolved error', async () => {
    // Use a last_seen 24 hours ago so confidence calculation is deterministic
    const lastSeen = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const error = makeProcessedError({ status: 'resolved', last_seen: lastSeen });
    dbStoreError(error);

    const res = await app.request(`/v1/errors/proj_test/${error.id}/status`);
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.status).toBe('resolved');
    expect(body.last_occurrence).toBe(lastSeen);
    expect(typeof body.hours_since_last).toBe('number');
    // Confidence should be ~1 since ~24 hours have passed
    expect(body.confidence).toBeCloseTo(1, 1);
  });

  it('returns 404 for unknown error ID', async () => {
    const res = await app.request('/v1/errors/proj_test/non-existent-id/status');
    expect(res.status).toBe(404);

    const body = await res.json();
    expect(body.error).toBe('Error not found');
  });
});

describe('POST /v1/errors/:projectId/:errorId/resolve', () => {
  beforeEach(() => {
    createDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('resolves an open error and returns 200', async () => {
    const error = makeProcessedError({ status: 'open' });
    dbStoreError(error);

    const res = await app.request(`/v1/errors/proj_test/${error.id}/resolve`, {
      method: 'POST',
    });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.resolved).toBe(true);
    expect(body.error_id).toBe(error.id);

    // Verify GET status now shows resolved
    const statusRes = await app.request(`/v1/errors/proj_test/${error.id}/status`);
    expect(statusRes.status).toBe(200);
    const statusBody = await statusRes.json();
    expect(statusBody.status).toBe('resolved');
  });

  it('returns 404 when resolving an unknown error', async () => {
    const res = await app.request('/v1/errors/proj_test/non-existent-id/resolve', {
      method: 'POST',
    });
    expect(res.status).toBe(404);

    const body = await res.json();
    expect(body.error).toBe('Error not found');
  });
});
