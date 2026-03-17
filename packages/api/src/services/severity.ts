import type { ProcessedError, Severity } from '../types.js';

/**
 * Score the severity of a processed error based on:
 * - User impact (users_affected)
 * - Error frequency (occurrences)
 * - Error type (extracted from title)
 *
 * Returns the highest severity from all three signals.
 */
export function scoreSeverity(error: ProcessedError): Severity {
  const userImpact = scoreUserImpact(error.users_affected);
  const frequency = scoreFrequency(error.occurrences);
  const errorType = scoreErrorType(error.title);

  return highestSeverity([userImpact, frequency, errorType]);
}

function scoreUserImpact(usersAffected: number): Severity {
  if (usersAffected > 100) return 'critical';
  if (usersAffected > 10) return 'high';
  if (usersAffected > 1) return 'medium';
  return 'low';
}

function scoreFrequency(occurrences: number): Severity {
  if (occurrences > 100) return 'critical';
  if (occurrences > 10) return 'high';
  if (occurrences > 1) return 'medium';
  return 'low';
}

function scoreErrorType(title: string): Severity {
  const lowerTitle = title.toLowerCase();

  // Critical error types
  if (lowerTitle.startsWith('securityerror')) return 'critical';

  // Medium error types
  if (lowerTitle.startsWith('typeerror')) return 'medium';
  if (lowerTitle.startsWith('referenceerror')) return 'medium';

  // Low error types
  if (lowerTitle.startsWith('syntaxerror')) return 'low';

  // Default for unknown types
  return 'low';
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function highestSeverity(severities: Severity[]): Severity {
  let highest: Severity = 'low';
  for (const s of severities) {
    if (SEVERITY_RANK[s] > SEVERITY_RANK[highest]) {
      highest = s;
    }
  }
  return highest;
}
