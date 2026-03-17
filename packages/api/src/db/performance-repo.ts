import { getDatabase } from './database.js';

export interface PerformanceMetric {
  id: string;
  project_id: string;
  url: string;
  page_load_ms?: number | null;
  first_contentful_paint_ms?: number | null;
  largest_contentful_paint_ms?: number | null;
  cumulative_layout_shift?: number | null;
  interaction_to_next_paint_ms?: number | null;
  time_to_first_byte_ms?: number | null;
  environment: string;
  timestamp: string;
}

function rowToMetric(row: Record<string, unknown>): PerformanceMetric {
  return {
    id: row.id as string,
    project_id: row.project_id as string,
    url: row.url as string,
    page_load_ms: row.page_load_ms as number | null,
    first_contentful_paint_ms: row.first_contentful_paint_ms as number | null,
    largest_contentful_paint_ms: row.largest_contentful_paint_ms as number | null,
    cumulative_layout_shift: row.cumulative_layout_shift as number | null,
    interaction_to_next_paint_ms: row.interaction_to_next_paint_ms as number | null,
    time_to_first_byte_ms: row.time_to_first_byte_ms as number | null,
    environment: row.environment as string,
    timestamp: row.timestamp as string,
  };
}

export function dbStorePerformanceMetric(metric: PerformanceMetric): void {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO performance_metrics (
      id, project_id, url,
      page_load_ms, first_contentful_paint_ms, largest_contentful_paint_ms,
      cumulative_layout_shift, interaction_to_next_paint_ms, time_to_first_byte_ms,
      environment, timestamp
    ) VALUES (
      @id, @project_id, @url,
      @page_load_ms, @first_contentful_paint_ms, @largest_contentful_paint_ms,
      @cumulative_layout_shift, @interaction_to_next_paint_ms, @time_to_first_byte_ms,
      @environment, @timestamp
    )
  `).run({
    id: metric.id,
    project_id: metric.project_id,
    url: metric.url,
    page_load_ms: metric.page_load_ms ?? null,
    first_contentful_paint_ms: metric.first_contentful_paint_ms ?? null,
    largest_contentful_paint_ms: metric.largest_contentful_paint_ms ?? null,
    cumulative_layout_shift: metric.cumulative_layout_shift ?? null,
    interaction_to_next_paint_ms: metric.interaction_to_next_paint_ms ?? null,
    time_to_first_byte_ms: metric.time_to_first_byte_ms ?? null,
    environment: metric.environment,
    timestamp: metric.timestamp,
  });
}

export function dbGetPerformanceMetrics(
  projectId: string,
  options?: { url?: string; limit?: number },
): PerformanceMetric[] {
  const db = getDatabase();

  const conditions: string[] = ['project_id = ?'];
  const params: unknown[] = [projectId];

  if (options?.url) {
    conditions.push('url = ?');
    params.push(options.url);
  }

  const where = conditions.join(' AND ');
  const limitClause = options?.limit ? ` LIMIT ${options.limit}` : '';

  const rows = db
    .prepare(`SELECT * FROM performance_metrics WHERE ${where} ORDER BY timestamp DESC${limitClause}`)
    .all(...params) as Record<string, unknown>[];

  return rows.map(rowToMetric);
}
