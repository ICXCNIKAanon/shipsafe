import { describe, it, expect, beforeEach } from 'vitest';
import {
  storeSourceMap,
  getSourceMap,
  listSourceMaps,
  clearSourceMapStore,
} from '../../src/services/sourcemap-store.js';

beforeEach(() => {
  clearSourceMapStore();
});

describe('storeSourceMap / getSourceMap', () => {
  it('stores and retrieves a source map', () => {
    storeSourceMap('proj_a', '1.0.0', 'dist/index.js', '{"version":3}');
    expect(getSourceMap('proj_a', '1.0.0', 'dist/index.js')).toBe('{"version":3}');
  });

  it('returns undefined for an unknown source map', () => {
    expect(getSourceMap('proj_a', '1.0.0', 'dist/missing.js')).toBeUndefined();
  });

  it('overwrites an existing source map for the same key', () => {
    storeSourceMap('proj_a', '1.0.0', 'dist/index.js', 'original');
    storeSourceMap('proj_a', '1.0.0', 'dist/index.js', 'updated');
    expect(getSourceMap('proj_a', '1.0.0', 'dist/index.js')).toBe('updated');
  });
});

describe('listSourceMaps', () => {
  it('lists all file paths for a project and release, sorted alphabetically', () => {
    storeSourceMap('proj_a', '1.0.0', 'dist/z.js', 'z');
    storeSourceMap('proj_a', '1.0.0', 'dist/a.js', 'a');
    storeSourceMap('proj_a', '1.0.0', 'dist/m.js', 'm');

    expect(listSourceMaps('proj_a', '1.0.0')).toEqual([
      'dist/a.js',
      'dist/m.js',
      'dist/z.js',
    ]);
  });

  it('isolates projects — different projects do not see each other\'s maps', () => {
    storeSourceMap('proj_a', '1.0.0', 'dist/index.js', 'a');
    storeSourceMap('proj_b', '1.0.0', 'dist/bundle.js', 'b');

    expect(listSourceMaps('proj_a', '1.0.0')).toEqual(['dist/index.js']);
    expect(listSourceMaps('proj_b', '1.0.0')).toEqual(['dist/bundle.js']);
  });
});
