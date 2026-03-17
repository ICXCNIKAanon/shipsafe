import { describe, it, expect, beforeEach } from 'vitest';
import app from '../../src/index.js';
import { clearStore, getAllProjectErrors } from '../../src/services/error-store.js';
import { clearRateLimits } from '../../src/middleware/rate-limit.js';

function makeErrorEvent(overrides: Record<string, unknown> = {}) {
  return {
    type: 'error',
    timestamp: new Date().toISOString(),
    project_id: 'proj_123',
    environment: 'production',
    session_id: 'session_abc',
    error: {
      name: 'TypeError',
      message: 'Cannot read properties of undefined',
      stack: `TypeError: Cannot read properties of undefined
    at handleClick (/app/src/components/Button.tsx:15:10)
    at HTMLButtonElement.dispatch (/app/node_modules/react-dom/cjs/react-dom.development.js:3945:16)`,
      handled: false,
    },
    context: {
      url: 'https://example.com/dashboard',
      user_agent: 'Mozilla/5.0',
    },
    ...overrides,
  };
}

describe('POST /v1/events', () => {
  beforeEach(() => {
    clearStore();
    clearRateLimits();
  });

  it('returns 202 with valid error events', async () => {
    const res = await app.request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj_123',
        events: [makeErrorEvent()],
      }),
    });

    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body.accepted).toBe(1);
    expect(body.processed).toBe(1);
  });

  it('returns 401 without project ID', async () => {
    const res = await app.request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events: [makeErrorEvent()],
      }),
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toContain('Missing project ID');
  });

  it('processes and stores error events', async () => {
    await app.request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj_456',
        events: [makeErrorEvent({ project_id: 'proj_456' })],
      }),
    });

    const stored = getAllProjectErrors('proj_456');
    expect(stored).toHaveLength(1);
    expect(stored[0].title).toContain('TypeError');
    expect(stored[0].status).toBe('open');
  });

  it('handles batched events', async () => {
    const events = [
      makeErrorEvent(),
      makeErrorEvent({
        error: {
          name: 'ReferenceError',
          message: 'x is not defined',
          stack: `ReferenceError: x is not defined
    at render (/app/src/pages/Home.tsx:22:5)`,
          handled: false,
        },
      }),
      {
        type: 'performance',
        timestamp: new Date().toISOString(),
        project_id: 'proj_123',
        environment: 'production',
        session_id: 'session_abc',
        metrics: { page_load_ms: 1200 },
        url: 'https://example.com/',
      },
    ];

    const res = await app.request('/v1/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: 'proj_123',
        events,
      }),
    });

    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body.accepted).toBe(3);
    expect(body.processed).toBe(2); // Only error events are processed

    const stored = getAllProjectErrors('proj_123');
    expect(stored).toHaveLength(2);
  });

  it('accepts events with X-Project-ID header', async () => {
    const res = await app.request('/v1/events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Project-ID': 'proj_header',
      },
      body: JSON.stringify({
        project_id: 'proj_header',
        events: [makeErrorEvent({ project_id: 'proj_header' })],
      }),
    });

    expect(res.status).toBe(202);
  });

  it('returns 400 for missing events array', async () => {
    const res = await app.request('/v1/events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Project-ID': 'proj_123',
      },
      body: JSON.stringify({ project_id: 'proj_123' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('events');
  });
});
