import type { ProcessedError } from '../types.js';

/**
 * In-memory error store. Stores processed errors grouped by project.
 * Phase 6 will add a PostgreSQL adapter.
 */
const store = new Map<string, ProcessedError[]>();

export function storeError(error: ProcessedError): void {
  const projectErrors = store.get(error.project_id) ?? [];

  // Check if this error already exists (by ID) and update in place
  const existingIndex = projectErrors.findIndex((e) => e.id === error.id);
  if (existingIndex >= 0) {
    projectErrors[existingIndex] = error;
  } else {
    projectErrors.push(error);
  }

  store.set(error.project_id, projectErrors);
}

export function getErrors(
  projectId: string,
  options?: { severity?: string; status?: string },
): ProcessedError[] {
  const projectErrors = store.get(projectId) ?? [];

  let filtered = projectErrors;

  if (options?.severity && options.severity !== 'all') {
    filtered = filtered.filter((e) => e.severity === options.severity);
  }

  if (options?.status && options.status !== 'all') {
    filtered = filtered.filter((e) => e.status === options.status);
  }

  // Sort by severity (critical first) then by last_seen (most recent first)
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  return filtered.sort((a, b) => {
    const sevDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
    if (sevDiff !== 0) return sevDiff;
    return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
  });
}

export function resolveError(errorId: string): boolean {
  for (const [, projectErrors] of store) {
    const error = projectErrors.find((e) => e.id === errorId);
    if (error) {
      error.status = 'resolved';
      return true;
    }
  }
  return false;
}

export function getAllProjectErrors(projectId: string): ProcessedError[] {
  return store.get(projectId) ?? [];
}

export function clearStore(): void {
  store.clear();
}
