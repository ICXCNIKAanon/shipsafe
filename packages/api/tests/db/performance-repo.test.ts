import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createDatabase, closeDatabase } from '../../src/db/database.js';
import {
  dbStorePerformanceMetric,
  dbGetPerformanceMetrics,
} from '../../src/db/performance-repo.js';
import type { PerformanceMetric } from '../../src/db/performance-repo.js';

function makeMetric(overrides: Partial<PerformanceMetric> = {}): PerformanceMetric {
  return {
    id: 'perf-1',
    project_id: 'proj-1',
    url: 'https://example.com/',
    page_load_ms: 1200,
    first_contentful_paint_ms: 800,
    largest_contentful_paint_ms: 1000,
    cumulative_layout_shift: 0.05,
    interaction_to_next_paint_ms: 120,
    time_to_first_byte_ms: 200,
    environment: 'production',
    timestamp: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

beforeEach(() => createDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('dbStorePerformanceMetric', () => {
  it('stores and retrieves a performance metric', () => {
    dbStorePerformanceMetric(makeMetric());
    const results = dbGetPerformanceMetrics('proj-1');
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      id: 'perf-1',
      project_id: 'proj-1',
      url: 'https://example.com/',
      page_load_ms: 1200,
      environment: 'production',
    });
  });

  it('stores metrics with partial metric fields (some undefined)', () => {
    dbStorePerformanceMetric(
      makeMetric({
        id: 'perf-2',
        page_load_ms: undefined,
        first_contentful_paint_ms: undefined,
      }),
    );
    const results = dbGetPerformanceMetrics('proj-1');
    expect(results).toHaveLength(1);
    expect(results[0].page_load_ms).toBeNull();
  });

  it('stores multiple metrics', () => {
    dbStorePerformanceMetric(makeMetric({ id: 'perf-1' }));
    dbStorePerformanceMetric(makeMetric({ id: 'perf-2', url: 'https://example.com/about' }));
    const results = dbGetPerformanceMetrics('proj-1');
    expect(results).toHaveLength(2);
  });
});

describe('dbGetPerformanceMetrics', () => {
  it('filters by url', () => {
    dbStorePerformanceMetric(makeMetric({ id: 'perf-1', url: 'https://example.com/' }));
    dbStorePerformanceMetric(makeMetric({ id: 'perf-2', url: 'https://example.com/about' }));
    const results = dbGetPerformanceMetrics('proj-1', { url: 'https://example.com/' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('perf-1');
  });

  it('limits results', () => {
    for (let i = 0; i < 5; i++) {
      dbStorePerformanceMetric(makeMetric({ id: `perf-${i}` }));
    }
    const results = dbGetPerformanceMetrics('proj-1', { limit: 3 });
    expect(results).toHaveLength(3);
  });

  it('isolates by project', () => {
    dbStorePerformanceMetric(makeMetric({ id: 'perf-1', project_id: 'proj-1' }));
    dbStorePerformanceMetric(makeMetric({ id: 'perf-2', project_id: 'proj-2' }));
    expect(dbGetPerformanceMetrics('proj-1')).toHaveLength(1);
    expect(dbGetPerformanceMetrics('proj-2')).toHaveLength(1);
    expect(dbGetPerformanceMetrics('proj-3')).toHaveLength(0);
  });
});
