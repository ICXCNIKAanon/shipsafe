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
  it('returns original frame when no source map is available', async () => {
    const result = await resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 42, 5);
    expect(result).toEqual({ file: 'dist/bundle.js', line: 42 });
  });

  it('returns original frame for invalid source map JSON (graceful degradation)', async () => {
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', 'not valid json {{{');
    const result = await resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 10, 3);
    expect(result).toEqual({ file: 'dist/bundle.js', line: 10 });
  });

  it('extracts source file from a valid source map (no column, uses fallback)', async () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: ['src/components/Button.tsx'],
      mappings: 'AAAA',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    // No column → extractSourceFallback path
    const result = await resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 15);
    expect(result.file).toBe('src/components/Button.tsx');
    expect(result.line).toBe(15);
  });

  it('skips node_modules sources and picks the first non-node_modules source', async () => {
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
    const result = await resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 22);
    expect(result.file).toBe('src/app.ts');
    expect(result.line).toBe(22);
  });

  it('strips relative path prefixes from source paths', async () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: ['../../src/utils/helpers.ts'],
      mappings: 'AAAA',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    const result = await resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 7, 1);
    expect(result.file).toBe('src/utils/helpers.ts');
  });

  it('falls back to looking up the file directly when .map variant is not found', async () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: ['src/index.ts'],
      mappings: 'AAAA',
    });
    // Store under the file path itself (no .map suffix)
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js', sourceMap);
    const result = await resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 5);
    expect(result.file).toBe('src/index.ts');
    expect(result.line).toBe(5);
  });

  it('returns original frame when sources array is empty', async () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: [],
      mappings: '',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    const result = await resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 3);
    expect(result).toEqual({ file: 'dist/bundle.js', line: 3 });
  });

  it('returns original frame when all sources are from node_modules', async () => {
    const sourceMap = JSON.stringify({
      version: 3,
      sources: ['node_modules/lodash/lodash.js', 'node_modules/react/index.js'],
      mappings: 'AAAA',
    });
    dbStoreSourceMap('proj_a', '1.0.0', 'dist/bundle.js.map', sourceMap);
    const result = await resolveStackFrame('proj_a', '1.0.0', 'dist/bundle.js', 99);
    expect(result).toEqual({ file: 'dist/bundle.js', line: 99 });
  });

  it('performs real VLQ decoding when line and column are provided', async () => {
    // This source map maps generated.js line 1 col 0 → original.ts line 5 col 0
    // 'AAIA' is the VLQ-encoded segment: [0, 0, 4, 0] meaning:
    //   generated col delta 0, source index delta 0, orig line delta 4 (0-based → line 5), orig col delta 0
    // Verified by round-tripping through SourceMapGenerator + SourceMapConsumer.
    const validSourceMap = JSON.stringify({
      version: 3,
      file: 'generated.js',
      sources: ['original.ts'],
      names: [],
      mappings: 'AAIA', // generated line 1, col 0 → source 0, orig line 5, col 0
    });
    dbStoreSourceMap('proj_vlq', '2.0.0', 'dist/generated.js.map', validSourceMap);

    const result = await resolveStackFrame('proj_vlq', '2.0.0', 'dist/generated.js', 1, 0);

    // Real VLQ decoding should map back to original.ts at line 5
    expect(result.file).toBe('original.ts');
    expect(result.line).toBe(5);
  });
});
