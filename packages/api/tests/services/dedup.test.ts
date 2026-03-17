import { describe, it, expect } from 'vitest';
import { deduplicateError, dedupKey } from '../../src/services/dedup.js';
import type { ErrorEvent, ProcessedError } from '../../src/types.js';

function makeErrorEvent(overrides: Partial<ErrorEvent> = {}): ErrorEvent {
  return {
    type: 'error',
    timestamp: new Date().toISOString(),
    project_id: 'proj_test',
    environment: 'production',
    session_id: 'session_1',
    error: {
      name: 'TypeError',
      message: 'Cannot read properties of undefined',
      stack: `TypeError: Cannot read properties of undefined
    at handleClick (/app/src/components/Button.tsx:15:10)
    at HTMLButtonElement.dispatch (/app/node_modules/react-dom/cjs/react-dom.development.js:3945:16)`,
      handled: false,
    },
    context: {
      url: 'https://example.com',
    },
    ...overrides,
  } as ErrorEvent;
}

describe('deduplicateError', () => {
  it('creates a new error group for a new error', () => {
    const event = makeErrorEvent();
    const result = deduplicateError(event, []);

    expect(result.id).toBeDefined();
    expect(result.title).toBe('TypeError: Cannot read properties of undefined');
    expect(result.occurrences).toBe(1);
    expect(result.users_affected).toBe(1);
    expect(result.status).toBe('open');
    expect(result.file).toContain('Button.tsx');
    expect(result.line).toBe(15);
    expect(result.root_cause).toBeTruthy();
    expect(result.suggested_fix).toBeTruthy();
  });

  it('increments occurrence count for same error reported twice', () => {
    const event1 = makeErrorEvent();
    const first = deduplicateError(event1, []);
    expect(first.occurrences).toBe(1);

    const event2 = makeErrorEvent({
      timestamp: new Date(Date.now() + 60000).toISOString(),
      session_id: 'session_2',
    } as Partial<ErrorEvent>);

    const second = deduplicateError(event2, [first]);
    expect(second.id).toBe(first.id); // Same group
    expect(second.occurrences).toBe(2);
  });

  it('creates separate groups for different errors', () => {
    const event1 = makeErrorEvent();
    const first = deduplicateError(event1, []);

    const event2 = makeErrorEvent({
      error: {
        name: 'ReferenceError',
        message: 'x is not defined',
        stack: `ReferenceError: x is not defined
    at render (/app/src/pages/Home.tsx:22:5)`,
        handled: false,
      },
    } as Partial<ErrorEvent>);

    const second = deduplicateError(event2, [first]);
    expect(second.id).not.toBe(first.id);
    expect(second.occurrences).toBe(1);
  });

  it('groups by name + message + first stack frame', () => {
    const event1 = makeErrorEvent();
    const event2 = makeErrorEvent(); // Same error, same stack
    const event3 = makeErrorEvent({
      error: {
        name: 'TypeError',
        message: 'Cannot read properties of undefined',
        stack: `TypeError: Cannot read properties of undefined
    at differentFunction (/app/src/other/File.tsx:99:3)`,
        handled: false,
      },
    } as Partial<ErrorEvent>);

    // event1 and event2 should have the same key
    expect(dedupKey(event1)).toBe(dedupKey(event2));

    // event3 has a different first stack frame
    expect(dedupKey(event1)).not.toBe(dedupKey(event3));
  });

  it('handles errors without stack traces', () => {
    const event = makeErrorEvent({
      error: {
        name: 'Error',
        message: 'Something went wrong',
        handled: false,
      },
    } as Partial<ErrorEvent>);

    const result = deduplicateError(event, []);
    expect(result.file).toBe('unknown');
    expect(result.line).toBe(0);
    expect(result.occurrences).toBe(1);
  });
});
