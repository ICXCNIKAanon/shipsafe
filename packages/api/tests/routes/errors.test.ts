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
    stack_trace: 'TypeError: Cannot read properties of undefined\n    at handleClick (/app/src/components/Button.tsx:15:10)',
    ...overrides,
  };
}

describe('GET /v1/errors/:projectId', () => {
  beforeEach(() => {
    createDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('returns queued errors for a project', async () => {
    const error1 = makeProcessedError({ severity: 'critical' });
    const error2 = makeProcessedError({ severity: 'medium', title: 'ReferenceError: x is not defined' });
    dbStoreError(error1);
    dbStoreError(error2);

    const res = await app.request('/v1/errors/proj_test');
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.project_id).toBe('proj_test');
    expect(body.count).toBe(2);
    expect(body.errors).toHaveLength(2);
    // Critical should come first
    expect(body.errors[0].severity).toBe('critical');
  });

  it('filters by severity', async () => {
    dbStoreError(makeProcessedError({ severity: 'critical' }));
    dbStoreError(makeProcessedError({ severity: 'low', title: 'SyntaxError: unexpected token' }));

    const res = await app.request('/v1/errors/proj_test?severity=critical');
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.count).toBe(1);
    expect(body.errors[0].severity).toBe('critical');
  });

  it('filters by status', async () => {
    dbStoreError(makeProcessedError({ status: 'open' }));
    dbStoreError(makeProcessedError({ status: 'resolved', title: 'Resolved error' }));

    const res = await app.request('/v1/errors/proj_test?status=all');
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.count).toBe(2);
  });

  it('returns empty array for unknown project', async () => {
    const res = await app.request('/v1/errors/proj_unknown');
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.project_id).toBe('proj_unknown');
    expect(body.count).toBe(0);
    expect(body.errors).toEqual([]);
  });

  it('defaults to status=open filter', async () => {
    dbStoreError(makeProcessedError({ status: 'open' }));
    dbStoreError(makeProcessedError({ status: 'resolved', title: 'Resolved error' }));

    const res = await app.request('/v1/errors/proj_test');
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.count).toBe(1);
    expect(body.errors[0].status).toBe('open');
  });
});
