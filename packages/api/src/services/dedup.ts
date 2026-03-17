import type { ErrorEvent, ProcessedError } from '../types.js';
import { analyzeRootCause } from './root-cause.js';
import { scoreSeverity } from './severity.js';

/**
 * Generate a dedup key from an error event.
 * Groups by: error.name + error.message + first stack frame location.
 */
export function dedupKey(event: ErrorEvent): string {
  const name = event.error.name;
  const message = event.error.message;
  const firstFrame = extractFirstFrame(event.error.stack);
  return `${name}::${message}::${firstFrame}`;
}

function extractFirstFrame(stack?: string): string {
  if (!stack) return 'unknown';

  const lines = stack.split('\n');
  // Skip the first line (error message), find first "at" frame
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('at ')) {
      return trimmed;
    }
  }
  return 'unknown';
}

/**
 * Parse file and line number from a stack trace.
 */
function parseFileAndLine(stack?: string): { file: string; line: number } {
  if (!stack) return { file: 'unknown', line: 0 };

  const lines = stack.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('at ')) continue;

    // Match patterns like:
    //   at functionName (file.js:10:5)
    //   at file.js:10:5
    const parenMatch = trimmed.match(/\((.+?):(\d+):\d+\)/);
    if (parenMatch) {
      return { file: parenMatch[1], line: parseInt(parenMatch[2], 10) };
    }

    const directMatch = trimmed.match(/at (.+?):(\d+):\d+/);
    if (directMatch) {
      return { file: directMatch[1], line: parseInt(directMatch[2], 10) };
    }
  }

  return { file: 'unknown', line: 0 };
}

/**
 * Deduplicate an error event against existing processed errors.
 * If a matching group exists, increments occurrence count and updates last_seen.
 * If new, creates a new ProcessedError entry.
 */
export function deduplicateError(
  event: ErrorEvent,
  existingErrors: ProcessedError[],
): ProcessedError {
  const key = dedupKey(event);

  // Check for an existing group
  const existing = existingErrors.find(
    (e) => dedupKeyFromProcessed(e) === key && e.project_id === event.project_id,
  );

  if (existing) {
    existing.occurrences += 1;
    existing.last_seen = event.timestamp;

    // Track unique sessions as proxy for users_affected
    existing.users_affected = Math.max(existing.users_affected, existing.occurrences);

    // Re-score severity with updated counts
    existing.severity = scoreSeverity(existing);

    return existing;
  }

  // Create new error group
  const { file, line } = parseFileAndLine(event.error.stack);
  const rootCause = analyzeRootCause({
    name: event.error.name,
    message: event.error.message,
    stack: event.error.stack,
  });

  const processed: ProcessedError = {
    id: generateId(),
    project_id: event.project_id,
    severity: 'low',
    title: `${event.error.name}: ${event.error.message}`,
    file,
    line,
    root_cause: rootCause.root_cause,
    suggested_fix: rootCause.suggested_fix,
    users_affected: 1,
    occurrences: 1,
    first_seen: event.timestamp,
    last_seen: event.timestamp,
    status: 'open',
    stack_trace: event.error.stack ?? '',
  };

  // Score initial severity
  processed.severity = scoreSeverity(processed);

  return processed;
}

/**
 * Reconstruct a dedup key from a ProcessedError for comparison.
 */
function dedupKeyFromProcessed(error: ProcessedError): string {
  // title is "name: message"
  const colonIndex = error.title.indexOf(': ');
  const name = colonIndex >= 0 ? error.title.substring(0, colonIndex) : error.title;
  const message = colonIndex >= 0 ? error.title.substring(colonIndex + 2) : '';
  const firstFrame = extractFirstFrame(error.stack_trace);
  return `${name}::${message}::${firstFrame}`;
}

function generateId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
