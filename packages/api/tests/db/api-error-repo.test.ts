import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import {
  dbStoreApiError,
  dbGetApiErrors,
} from '../../src/db/api-error-repo.js';
import type { ApiError } from '../../src/db/api-error-repo.js';

function makeApiError(overrides: Partial<ApiError> = {}): ApiError {
  return {
    id: 'apierr-1',
    project_id: 'proj-1',
    method: 'GET',
    path: '/api/users',
    status_code: 500,
    duration_ms: 250,
    error_name: 'InternalServerError',
    error_message: 'Something went wrong',
    error_stack: 'Error: Something went wrong\n  at handler (server.ts:42)',
    environment: 'production',
    timestamp: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

beforeEach(() => createDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('dbStoreApiError', () => {
  it('stores and retrieves an API error', () => {
    dbStoreApiError(makeApiError());
    const results = dbGetApiErrors('proj-1');
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      id: 'apierr-1',
      project_id: 'proj-1',
      method: 'GET',
      path: '/api/users',
      status_code: 500,
      duration_ms: 250,
      error_name: 'InternalServerError',
    });
  });

  it('stores API errors without optional error fields', () => {
    dbStoreApiError(
      makeApiError({
        id: 'apierr-2',
        error_name: undefined,
        error_message: undefined,
        error_stack: undefined,
      }),
    );
    const results = dbGetApiErrors('proj-1');
    expect(results).toHaveLength(1);
    expect(results[0].error_name).toBeNull();
    expect(results[0].error_message).toBeNull();
  });

  it('stores multiple API errors', () => {
    dbStoreApiError(makeApiError({ id: 'apierr-1' }));
    dbStoreApiError(makeApiError({ id: 'apierr-2', path: '/api/orders' }));
    const results = dbGetApiErrors('proj-1');
    expect(results).toHaveLength(2);
  });
});

describe('dbGetApiErrors', () => {
  it('filters by path', () => {
    dbStoreApiError(makeApiError({ id: 'apierr-1', path: '/api/users' }));
    dbStoreApiError(makeApiError({ id: 'apierr-2', path: '/api/orders' }));
    const results = dbGetApiErrors('proj-1', { path: '/api/users' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('apierr-1');
  });

  it('limits results', () => {
    for (let i = 0; i < 5; i++) {
      dbStoreApiError(makeApiError({ id: `apierr-${i}` }));
    }
    const results = dbGetApiErrors('proj-1', { limit: 2 });
    expect(results).toHaveLength(2);
  });

  it('isolates by project', () => {
    dbStoreApiError(makeApiError({ id: 'apierr-1', project_id: 'proj-1' }));
    dbStoreApiError(makeApiError({ id: 'apierr-2', project_id: 'proj-2' }));
    expect(dbGetApiErrors('proj-1')).toHaveLength(1);
    expect(dbGetApiErrors('proj-2')).toHaveLength(1);
    expect(dbGetApiErrors('proj-3')).toHaveLength(0);
  });
});
