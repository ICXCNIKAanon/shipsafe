import { describe, it, expect, afterEach } from 'vitest';
import { createDatabase, getDatabase, closeDatabase } from '../../src/db/database.js';

afterEach(() => closeDatabase());

describe('createDatabase', () => {
  it('creates an in-memory database with schema — both tables exist', () => {
    const db = createDatabase();

    const tables = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('errors', 'source_maps') ORDER BY name"
      )
      .all() as { name: string }[];

    const tableNames = tables.map((t) => t.name);
    expect(tableNames).toContain('errors');
    expect(tableNames).toContain('source_maps');
  });

  it('errors table has all expected columns', () => {
    createDatabase();
    const db = getDatabase();

    const columns = db
      .prepare('PRAGMA table_info(errors)')
      .all() as { name: string }[];

    const columnNames = columns.map((c) => c.name);
    const expected = [
      'id',
      'project_id',
      'severity',
      'title',
      'file',
      'line',
      'root_cause',
      'suggested_fix',
      'users_affected',
      'occurrences',
      'first_seen',
      'last_seen',
      'status',
      'stack_trace',
    ];

    for (const col of expected) {
      expect(columnNames, `expected column '${col}' to exist`).toContain(col);
    }
  });

  it('source_maps table has correct columns', () => {
    createDatabase();
    const db = getDatabase();

    const columns = db
      .prepare('PRAGMA table_info(source_maps)')
      .all() as { name: string }[];

    const columnNames = columns.map((c) => c.name);
    const expected = ['project_id', 'release_version', 'file_path', 'content'];

    for (const col of expected) {
      expect(columnNames, `expected column '${col}' to exist`).toContain(col);
    }
  });
});

describe('getDatabase', () => {
  it('throws if database has not been initialized', () => {
    expect(() => getDatabase()).toThrow();
  });
});
