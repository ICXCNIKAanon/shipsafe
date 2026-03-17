import { getDatabase } from './database.js';
import type { ProcessedError } from '../types.js';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function rowToError(row: Record<string, unknown>): ProcessedError {
  return {
    id: row.id as string,
    project_id: row.project_id as string,
    severity: row.severity as ProcessedError['severity'],
    title: row.title as string,
    file: row.file as string,
    line: row.line as number,
    root_cause: row.root_cause as string,
    suggested_fix: row.suggested_fix as string,
    users_affected: row.users_affected as number,
    occurrences: row.occurrences as number,
    first_seen: row.first_seen as string,
    last_seen: row.last_seen as string,
    status: row.status as ProcessedError['status'],
    stack_trace: row.stack_trace as string,
  };
}

export function dbStoreError(error: ProcessedError): void {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO errors (
      id, project_id, severity, title, file, line,
      root_cause, suggested_fix, users_affected, occurrences,
      first_seen, last_seen, status, stack_trace
    ) VALUES (
      @id, @project_id, @severity, @title, @file, @line,
      @root_cause, @suggested_fix, @users_affected, @occurrences,
      @first_seen, @last_seen, @status, @stack_trace
    )
    ON CONFLICT(id) DO UPDATE SET
      severity = excluded.severity,
      users_affected = excluded.users_affected,
      occurrences = excluded.occurrences,
      last_seen = excluded.last_seen,
      status = excluded.status,
      root_cause = excluded.root_cause,
      suggested_fix = excluded.suggested_fix
  `).run(error);
}

export function dbGetErrors(
  projectId: string,
  options?: { severity?: string; status?: string }
): ProcessedError[] {
  const db = getDatabase();
  const status = options?.status;
  const severity = options?.severity;

  const conditions: string[] = ['project_id = ?'];
  const params: unknown[] = [projectId];

  if (!status || status !== 'all') {
    conditions.push('status = ?');
    params.push(status ?? 'open');
  }

  if (severity && severity !== 'all') {
    conditions.push('severity = ?');
    params.push(severity);
  }

  const where = conditions.join(' AND ');
  const rows = db
    .prepare(`SELECT * FROM errors WHERE ${where}`)
    .all(...params) as Record<string, unknown>[];

  return rows
    .map(rowToError)
    .sort((a, b) => {
      const severityDiff =
        (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
      if (severityDiff !== 0) return severityDiff;
      return b.last_seen.localeCompare(a.last_seen);
    });
}

export function dbResolveError(errorId: string): boolean {
  const db = getDatabase();
  const result = db
    .prepare(`UPDATE errors SET status = 'resolved' WHERE id = ?`)
    .run(errorId);
  return result.changes > 0;
}

export function dbGetAllProjectErrors(projectId: string): ProcessedError[] {
  const db = getDatabase();
  const rows = db
    .prepare(`SELECT * FROM errors WHERE project_id = ?`)
    .all(projectId) as Record<string, unknown>[];
  return rows.map(rowToError);
}
