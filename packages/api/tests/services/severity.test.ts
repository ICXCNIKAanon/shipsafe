import { describe, it, expect } from 'vitest';
import { scoreSeverity } from '../../src/services/severity.js';
import type { ProcessedError } from '../../src/types.js';

function makeProcessedError(overrides: Partial<ProcessedError> = {}): ProcessedError {
  return {
    id: 'test-id',
    project_id: 'proj_test',
    severity: 'low',
    title: 'Error: test error',
    file: '/app/src/index.ts',
    line: 10,
    root_cause: 'Test root cause',
    suggested_fix: 'Test fix',
    users_affected: 1,
    occurrences: 1,
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    status: 'open',
    stack_trace: '',
    ...overrides,
  };
}

describe('scoreSeverity', () => {
  it('scores critical for high user impact (>100 users)', () => {
    const error = makeProcessedError({ users_affected: 150 });
    expect(scoreSeverity(error)).toBe('critical');
  });

  it('scores high for medium user impact (>10 users)', () => {
    const error = makeProcessedError({ users_affected: 25 });
    expect(scoreSeverity(error)).toBe('high');
  });

  it('scores medium for >1 user', () => {
    const error = makeProcessedError({ users_affected: 3 });
    expect(scoreSeverity(error)).toBe('medium');
  });

  it('scores low for single occurrence', () => {
    const error = makeProcessedError({ users_affected: 1, occurrences: 1 });
    expect(scoreSeverity(error)).toBe('low');
  });

  it('scores critical for high frequency (>100 occurrences)', () => {
    const error = makeProcessedError({ occurrences: 200 });
    expect(scoreSeverity(error)).toBe('critical');
  });

  it('scores high for medium frequency (>10 occurrences)', () => {
    const error = makeProcessedError({ occurrences: 50 });
    expect(scoreSeverity(error)).toBe('high');
  });

  it('scores critical for SecurityError regardless of count', () => {
    const error = makeProcessedError({
      title: 'SecurityError: blocked by CORS policy',
      users_affected: 1,
      occurrences: 1,
    });
    expect(scoreSeverity(error)).toBe('critical');
  });

  it('scores medium for TypeError (single occurrence)', () => {
    const error = makeProcessedError({
      title: 'TypeError: Cannot read properties of undefined',
      users_affected: 1,
      occurrences: 1,
    });
    expect(scoreSeverity(error)).toBe('medium');
  });

  it('takes the highest severity from all signals', () => {
    // Low user impact, low frequency, but SecurityError type -> critical
    const error = makeProcessedError({
      title: 'SecurityError: something',
      users_affected: 1,
      occurrences: 1,
    });
    expect(scoreSeverity(error)).toBe('critical');
  });

  it('scores low for SyntaxError with single occurrence', () => {
    const error = makeProcessedError({
      title: 'SyntaxError: Unexpected token',
      users_affected: 1,
      occurrences: 1,
    });
    expect(scoreSeverity(error)).toBe('low');
  });
});
