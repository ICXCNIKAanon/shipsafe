import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import {
  dbStoreError,
  dbGetErrors,
  dbResolveError,
  dbGetAllProjectErrors,
} from '../../src/db/error-repo.js';
import type { ProcessedError } from '../../src/types.js';

function makeError(overrides: Partial<ProcessedError> = {}): ProcessedError {
  return {
    id: 'err-1',
    project_id: 'proj-1',
    severity: 'high',
    title: 'TypeError: Cannot read property',
    file: 'src/index.ts',
    line: 42,
    root_cause: 'Null dereference',
    suggested_fix: 'Add null check',
    users_affected: 5,
    occurrences: 10,
    first_seen: '2026-01-01T00:00:00Z',
    last_seen: '2026-01-02T00:00:00Z',
    status: 'open',
    stack_trace: 'Error: ...\n  at foo (index.ts:42)',
    ...overrides,
  };
}

beforeEach(() => createDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('dbStoreError', () => {
  it('stores and retrieves an error', () => {
    const error = makeError();
    dbStoreError(error);
    const results = dbGetErrors('proj-1');
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      id: 'err-1',
      project_id: 'proj-1',
      severity: 'high',
      title: 'TypeError: Cannot read property',
      users_affected: 5,
      occurrences: 10,
      status: 'open',
    });
  });

  it('updates existing error by ID (upsert)', () => {
    const error = makeError();
    dbStoreError(error);
    const updated = makeError({
      occurrences: 25,
      users_affected: 12,
      last_seen: '2026-01-03T00:00:00Z',
      severity: 'critical',
      root_cause: 'Updated root cause',
      suggested_fix: 'Updated fix',
      status: 'open',
    });
    dbStoreError(updated);
    const results = dbGetErrors('proj-1');
    expect(results).toHaveLength(1);
    expect(results[0].occurrences).toBe(25);
    expect(results[0].users_affected).toBe(12);
    expect(results[0].last_seen).toBe('2026-01-03T00:00:00Z');
    expect(results[0].severity).toBe('critical');
    expect(results[0].root_cause).toBe('Updated root cause');
  });
});

describe('dbGetErrors', () => {
  it('filters by severity', () => {
    dbStoreError(makeError({ id: 'err-1', severity: 'high' }));
    dbStoreError(makeError({ id: 'err-2', severity: 'low' }));
    const results = dbGetErrors('proj-1', { severity: 'high' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('err-1');
  });

  it('filters by status', () => {
    dbStoreError(makeError({ id: 'err-1', status: 'open' }));
    dbStoreError(makeError({ id: 'err-2', status: 'resolved' }));
    const open = dbGetErrors('proj-1', { status: 'open' });
    expect(open).toHaveLength(1);
    expect(open[0].id).toBe('err-1');

    const resolved = dbGetErrors('proj-1', { status: 'resolved' });
    expect(resolved).toHaveLength(1);
    expect(resolved[0].id).toBe('err-2');

    const all = dbGetErrors('proj-1', { status: 'all' });
    expect(all).toHaveLength(2);
  });

  it('sorts by severity then last_seen descending', () => {
    dbStoreError(makeError({ id: 'err-1', severity: 'low', last_seen: '2026-01-01T00:00:00Z' }));
    dbStoreError(makeError({ id: 'err-2', severity: 'critical', last_seen: '2026-01-01T00:00:00Z' }));
    dbStoreError(makeError({ id: 'err-3', severity: 'high', last_seen: '2026-01-03T00:00:00Z' }));
    dbStoreError(makeError({ id: 'err-4', severity: 'high', last_seen: '2026-01-02T00:00:00Z' }));
    const results = dbGetErrors('proj-1', { status: 'all' });
    expect(results[0].id).toBe('err-2'); // critical
    expect(results[1].id).toBe('err-3'); // high, newer
    expect(results[2].id).toBe('err-4'); // high, older
    expect(results[3].id).toBe('err-1'); // low
  });

  it('defaults to open status filter when no status provided', () => {
    dbStoreError(makeError({ id: 'err-1', status: 'open' }));
    dbStoreError(makeError({ id: 'err-2', status: 'resolved' }));
    const results = dbGetErrors('proj-1');
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('err-1');
  });

  it('isolates projects', () => {
    dbStoreError(makeError({ id: 'err-1', project_id: 'proj-1' }));
    dbStoreError(makeError({ id: 'err-2', project_id: 'proj-2' }));
    const proj1 = dbGetErrors('proj-1');
    expect(proj1).toHaveLength(1);
    expect(proj1[0].project_id).toBe('proj-1');
    const proj2 = dbGetErrors('proj-2');
    expect(proj2).toHaveLength(1);
    expect(proj2[0].project_id).toBe('proj-2');
  });
});

describe('dbResolveError', () => {
  it('resolves an error', () => {
    dbStoreError(makeError({ id: 'err-1', status: 'open' }));
    const result = dbResolveError('err-1');
    expect(result).toBe(true);
    const errors = dbGetErrors('proj-1', { status: 'resolved' });
    expect(errors).toHaveLength(1);
    expect(errors[0].status).toBe('resolved');
  });

  it('returns false when resolving unknown error', () => {
    const result = dbResolveError('nonexistent-id');
    expect(result).toBe(false);
  });
});

describe('dbGetAllProjectErrors', () => {
  it('returns all errors for a project regardless of status', () => {
    dbStoreError(makeError({ id: 'err-1', status: 'open' }));
    dbStoreError(makeError({ id: 'err-2', status: 'resolved' }));
    const results = dbGetAllProjectErrors('proj-1');
    expect(results).toHaveLength(2);
  });
});
