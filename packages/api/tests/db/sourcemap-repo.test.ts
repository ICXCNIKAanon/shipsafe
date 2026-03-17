import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import {
  dbStoreSourceMap,
  dbGetSourceMap,
  dbListSourceMaps,
} from '../../src/db/sourcemap-repo.js';

beforeEach(() => createDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('dbStoreSourceMap / dbGetSourceMap', () => {
  it('stores and retrieves a source map', () => {
    dbStoreSourceMap('proj-1', '1.0.0', 'src/index.js', '{"version":3}');
    const content = dbGetSourceMap('proj-1', '1.0.0', 'src/index.js');
    expect(content).toBe('{"version":3}');
  });

  it('returns undefined for unknown source map', () => {
    const content = dbGetSourceMap('proj-1', '1.0.0', 'nonexistent.js');
    expect(content).toBeUndefined();
  });

  it('upserts on conflict (updates content)', () => {
    dbStoreSourceMap('proj-1', '1.0.0', 'src/index.js', '{"version":3,"original":"first"}');
    dbStoreSourceMap('proj-1', '1.0.0', 'src/index.js', '{"version":3,"original":"second"}');
    const content = dbGetSourceMap('proj-1', '1.0.0', 'src/index.js');
    expect(content).toBe('{"version":3,"original":"second"}');
  });
});

describe('dbListSourceMaps', () => {
  it('lists source maps for a project and release, sorted', () => {
    dbStoreSourceMap('proj-1', '1.0.0', 'src/utils.js', 'content-b');
    dbStoreSourceMap('proj-1', '1.0.0', 'src/index.js', 'content-a');
    dbStoreSourceMap('proj-1', '1.0.0', 'src/app.js', 'content-c');
    dbStoreSourceMap('proj-1', '2.0.0', 'src/index.js', 'other-release');
    dbStoreSourceMap('proj-2', '1.0.0', 'src/index.js', 'other-project');

    const files = dbListSourceMaps('proj-1', '1.0.0');
    expect(files).toHaveLength(3);
    expect(files).toEqual(['src/app.js', 'src/index.js', 'src/utils.js']);
  });
});
