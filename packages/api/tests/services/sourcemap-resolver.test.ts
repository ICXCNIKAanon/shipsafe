import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import { resolveStackFrame } from '../../src/services/sourcemap-resolver.js';
import { dbStoreSourceMap } from '../../src/db/sourcemap-repo.js';

beforeEach(() => {
  createDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('resolveStackFrame', () => {
  it('returns original frame when no source map is available', () => {
    const result = resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 42, 5);
    expect(result).toEqual({ file: 'dist/bundle.js', line: 42 });
  });

  it('returns original frame for invalid source map JSON (graceful degradation)', () => {
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', 'not valid json {{{');
    const result = resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 10, 3);
    expect(result).toEqual({ file: 'dist/bundle.js', line: 10 });
  });

  it('extracts source file from a valid source map', () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: ['src/components/Button.tsx'],
      mappings: 'AAAA',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    const result = resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 15, 8);
    expect(result.file).toBe('src/components/Button.tsx');
    expect(result.line).toBe(15);
  });

  it('skips node_modules sources and picks the first non-node_modules source', () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: [
        'node_modules/react/index.js',
        'node_modules/react-dom/cjs/react-dom.development.js',
        'src/app.ts',
      ],
      mappings: 'AAAA',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    const result = resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 22);
    expect(result.file).toBe('src/app.ts');
    expect(result.line).toBe(22);
  });

  it('strips relative path prefixes from source paths', () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: ['../../src/utils/helpers.ts'],
      mappings: 'AAAA',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    const result = resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 7, 1);
    expect(result.file).toBe('src/utils/helpers.ts');
    expect(result.line).toBe(7);
  });

  it('falls back to looking up the file directly when .map variant is not found', () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: ['src/index.ts'],
      mappings: 'AAAA',
    });
    // Store under the file path itself (no .map suffix)
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js', sourceMap);
    const result = resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 5);
    expect(result.file).toBe('src/index.ts');
    expect(result.line).toBe(5);
  });

  it('returns original frame when sources array is empty', () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: [],
      mappings: '',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    const result = resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 3);
    expect(result).toEqual({ file: 'dist/bundle.js', line: 3 });
  });

  it('returns original frame when all sources are from node_modules', () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: ['node_modules/lodash/lodash.js', 'node_modules/react/index.js'],
      mappings: 'AAAA',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    const result = resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 99);
    expect(result).toEqual({ file: 'dist/bundle.js', line: 99 });
  });
});
