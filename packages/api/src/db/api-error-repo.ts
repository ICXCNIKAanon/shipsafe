import { getDatabase } from './database.js';

export interface ApiError {
  id: string;
  project_id: string;
  method: string;
  path: string;
  status_code: number;
  duration_ms: number;
  error_name?: string | null;
  error_message?: string | null;
  error_stack?: string | null;
  environment: string;
  timestamp: string;
}

function rowToApiError(row: Record<string, unknown>): ApiError {
  return {
    id: row.id as string,
    project_id: row.project_id as string,
    method: row.method as string,
    path: row.path as string,
    status_code: row.status_code as number,
    duration_ms: row.duration_ms as number,
    error_name: row.error_name as string | null,
    error_message: row.error_message as string | null,
    error_stack: row.error_stack as string | null,
    environment: row.environment as string,
    timestamp: row.timestamp as string,
  };
}

export function dbStoreApiError(error: ApiError): void {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO api_errors (
      id, project_id, method, path, status_code, duration_ms,
      error_name, error_message, error_stack,
      environment, timestamp
    ) VALUES (
      @id, @project_id, @method, @path, @status_code, @duration_ms,
      @error_name, @error_message, @error_stack,
      @environment, @timestamp
    )
  `).run({
    id: error.id,
    project_id: error.project_id,
    method: error.method,
    path: error.path,
    status_code: error.status_code,
    duration_ms: error.duration_ms,
    error_name: error.error_name ?? null,
    error_message: error.error_message ?? null,
    error_stack: error.error_stack ?? null,
    environment: error.environment,
    timestamp: error.timestamp,
  });
}

export function dbGetApiErrors(
  projectId: string,
  options?: { path?: string; limit?: number },
): ApiError[] {
  const db = getDatabase();

  const conditions: string[] = ['project_id = ?'];
  const params: unknown[] = [projectId];

  if (options?.path) {
    conditions.push('path = ?');
    params.push(options.path);
  }

  const where = conditions.join(' AND ');
  const limitClause = options?.limit ? ` LIMIT ${options.limit}` : '';

  const rows = db
    .prepare(`SELECT * FROM api_errors WHERE ${where} ORDER BY timestamp DESC${limitClause}`)
    .all(...params) as Record<string, unknown>[];

  return rows.map(rowToApiError);
}
