import { describe, it, expect } from 'vitest';
import { scrubEvent } from '../../src/core/scrubber.js';
import type { ErrorEvent, ShipSafeEvent } from '../../src/core/types.js';

function makeEvent(overrides: Partial<ErrorEvent> = {}): ErrorEvent {
  return {
    type: 'error',
    timestamp: new Date().toISOString(),
    project_id: 'test',
    environment: 'test',
    session_id: 'abc-123',
    error: {
      name: 'Error',
      message: 'test error',
      handled: true,
    },
    context: {},
    ...overrides,
  };
}

describe('scrubEvent', () => {
  it('scrubs email addresses', () => {
    const event = makeEvent({
      error: { name: 'Error', message: 'User test@example.com failed', handled: true },
    });
    const scrubbed = scrubEvent(event);
    expect(scrubbed.error.message).toBe('User [email] failed');
    expect(scrubbed.error.message).not.toContain('test@example.com');
  });

  it('scrubs phone numbers', () => {
    const event = makeEvent({
      error: { name: 'Error', message: 'Call 555-123-4567 for support', handled: true },
    });
    const scrubbed = scrubEvent(event);
    expect(scrubbed.error.message).toContain('[phone]');
    expect(scrubbed.error.message).not.toContain('555-123-4567');
  });

  it('scrubs SSN patterns', () => {
    const event = makeEvent({
      error: { name: 'Error', message: 'SSN: 123-45-6789', handled: true },
    });
    const scrubbed = scrubEvent(event);
    expect(scrubbed.error.message).toContain('[ssn]');
    expect(scrubbed.error.message).not.toContain('123-45-6789');
  });

  it('scrubs credit card numbers', () => {
    const event = makeEvent({
      error: { name: 'Error', message: 'Card 4111111111111111 declined', handled: true },
    });
    const scrubbed = scrubEvent(event);
    expect(scrubbed.error.message).toContain('[card]');
    expect(scrubbed.error.message).not.toContain('4111111111111111');
  });

  it('scrubs JWT tokens', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A';
    const event = makeEvent({
      error: { name: 'Error', message: `Token: ${jwt}`, handled: true },
    });
    const scrubbed = scrubEvent(event);
    expect(scrubbed.error.message).toContain('[token]');
    expect(scrubbed.error.message).not.toContain(jwt);
  });

  it('scrubs IP addresses', () => {
    const event = makeEvent({
      error: { name: 'Error', message: 'Request from 192.168.1.100', handled: true },
    });
    const scrubbed = scrubEvent(event);
    expect(scrubbed.error.message).toContain('[ip]');
    expect(scrubbed.error.message).not.toContain('192.168.1.100');
  });

  it('applies recursively to nested objects', () => {
    const event = makeEvent({
      error: {
        name: 'Error',
        message: 'nested test',
        handled: true,
        stack: 'at user@test.com line 1',
      },
      context: {
        url: 'https://example.com?email=user@test.com',
      },
    });
    const scrubbed = scrubEvent(event);
    expect(scrubbed.error.stack).toContain('[email]');
    expect(scrubbed.error.stack).not.toContain('user@test.com');
    expect(scrubbed.context.url).toContain('[email]');
    expect(scrubbed.context.url).not.toContain('user@test.com');
  });

  it('does not modify non-matching strings', () => {
    const event = makeEvent({
      error: {
        name: 'TypeError',
        message: 'Cannot read property of undefined',
        handled: false,
      },
    });
    const scrubbed = scrubEvent(event);
    expect(scrubbed.error.name).toBe('TypeError');
    expect(scrubbed.error.message).toBe('Cannot read property of undefined');
    expect(scrubbed.error.handled).toBe(false);
  });
});
