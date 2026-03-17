import { describe, it, expect, beforeEach } from 'vitest';
import app from '../../src/index.js';
import {
  getSourceMap,
  clearSourceMapStore,
} from '../../src/services/sourcemap-store.js';

describe('POST /v1/sourcemaps', () => {
  beforeEach(() => {
    clearSourceMapStore();
  });

  it('uploads a single source map and returns 201', async () => {
    const body = {
      project_id: 'proj_abc',
      release: '1.0.0',
      file_path: 'dist/main.js',
      source_map: '{"version":3,"sources":["main.ts"]}',
    };

    const res = await app.request('/v1/sourcemaps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    expect(res.status).toBe(201);

    const json = await res.json();
    expect(json.stored).toBe(true);
    expect(json.file_path).toBe('dist/main.js');
    expect(json.release).toBe('1.0.0');

    // Verify it was actually stored
    const stored = getSourceMap('proj_abc', '1.0.0', 'dist/main.js');
    expect(stored).toBe('{"version":3,"sources":["main.ts"]}');
  });

  it('rejects missing project_id with 400', async () => {
    const res = await app.request('/v1/sourcemaps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        release: '1.0.0',
        file_path: 'dist/main.js',
        source_map: '{}',
      }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
  });

  it('rejects missing release with 400', async () => {
    const res = await app.request('/v1/sourcemaps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj_abc',
        file_path: 'dist/main.js',
        source_map: '{}',
      }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
  });

  it('rejects missing file_path with 400', async () => {
    const res = await app.request('/v1/sourcemaps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj_abc',
        release: '1.0.0',
        source_map: '{}',
      }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
  });

  it('rejects missing source_map with 400', async () => {
    const res = await app.request('/v1/sourcemaps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj_abc',
        release: '1.0.0',
        file_path: 'dist/main.js',
      }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
  });
});

describe('POST /v1/sourcemaps/batch', () => {
  beforeEach(() => {
    clearSourceMapStore();
  });

  it('uploads multiple source maps in batch and returns 201', async () => {
    const body = {
      project_id: 'proj_abc',
      release: '2.0.0',
      source_maps: [
        { file_path: 'dist/main.js', source_map: '{"version":3,"sources":["main.ts"]}' },
        { file_path: 'dist/vendor.js', source_map: '{"version":3,"sources":["vendor.ts"]}' },
        { file_path: 'dist/utils.js', source_map: '{"version":3,"sources":["utils.ts"]}' },
      ],
    };

    const res = await app.request('/v1/sourcemaps/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    expect(res.status).toBe(201);

    const json = await res.json();
    expect(json.stored).toBe(3);
    expect(json.release).toBe('2.0.0');

    // Verify all were stored
    expect(getSourceMap('proj_abc', '2.0.0', 'dist/main.js')).toBe(
      '{"version":3,"sources":["main.ts"]}',
    );
    expect(getSourceMap('proj_abc', '2.0.0', 'dist/vendor.js')).toBe(
      '{"version":3,"sources":["vendor.ts"]}',
    );
    expect(getSourceMap('proj_abc', '2.0.0', 'dist/utils.js')).toBe(
      '{"version":3,"sources":["utils.ts"]}',
    );
  });

  it('rejects missing project_id with 400', async () => {
    const res = await app.request('/v1/sourcemaps/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        release: '2.0.0',
        source_maps: [{ file_path: 'dist/main.js', source_map: '{}' }],
      }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
  });

  it('rejects missing release with 400', async () => {
    const res = await app.request('/v1/sourcemaps/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj_abc',
        source_maps: [{ file_path: 'dist/main.js', source_map: '{}' }],
      }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
  });

  it('rejects missing source_maps with 400', async () => {
    const res = await app.request('/v1/sourcemaps/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj_abc',
        release: '2.0.0',
      }),
    });

    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBeDefined();
  });
});
