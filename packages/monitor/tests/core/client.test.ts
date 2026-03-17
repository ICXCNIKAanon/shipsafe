import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ShipSafeClient } from '../../src/core/client.js';
import type { ShipSafeEvent } from '../../src/core/types.js';

describe('ShipSafeClient', () => {
  let client: ShipSafeClient;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
    });
    vi.stubGlobal('fetch', fetchSpy);
    vi.useFakeTimers();
  });

  afterEach(() => {
    client?.destroy();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  function createClient(overrides = {}) {
    client = new ShipSafeClient({
      projectId: 'test-project',
      endpoint: 'https://test.shipsafe.org/v1/events',
      environment: 'test',
      ...overrides,
    });
    return client;
  }

  it('generates a session ID', () => {
    createClient();
    expect(client.getSessionId()).toBeTruthy();
    expect(client.getSessionId().length).toBeGreaterThan(0);
  });

  it('queues events', () => {
    createClient();
    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);
    expect(client.getQueueLength()).toBe(1);
  });

  it('auto-flushes after 10 events', async () => {
    createClient();

    for (let i = 0; i < 10; i++) {
      client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);
    }

    // flush is called async, need to let microtasks resolve
    await vi.advanceTimersByTimeAsync(0);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body.events.length).toBe(10);
  });

  it('auto-flushes on timer (5s)', async () => {
    createClient();
    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);

    await vi.advanceTimersByTimeAsync(5000);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body.events.length).toBe(1);
  });

  it('retries failed flush with backoff', async () => {
    createClient({ debug: false });

    let callCount = 0;
    fetchSpy.mockImplementation(() => {
      callCount++;
      if (callCount < 3) {
        return Promise.reject(new Error('Network error'));
      }
      return Promise.resolve({ ok: true, status: 200 });
    });

    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);

    // Trigger flush
    const flushPromise = client.flush();

    // Advance through retries: 1s delay after 1st fail, 2s delay after 2nd fail
    await vi.advanceTimersByTimeAsync(1000);
    await vi.advanceTimersByTimeAsync(2000);
    await flushPromise;

    expect(callCount).toBe(3);
  });

  it('respects max queue size (100)', () => {
    createClient();

    // Override fetch to never resolve so flush doesn't drain the queue
    fetchSpy.mockImplementation(() => new Promise(() => {}));

    for (let i = 0; i < 150; i++) {
      client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);
    }

    // Queue should be capped - some events flushed at batch boundaries (10, 20, ...),
    // so what remains in queue should be <= 100
    expect(client.getQueueLength()).toBeLessThanOrEqual(100);
  });

  it('calls beforeSend hook', async () => {
    const beforeSend = vi.fn((event: ShipSafeEvent) => event);
    createClient({ beforeSend });

    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);

    expect(beforeSend).toHaveBeenCalledTimes(1);
    expect(beforeSend).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'error', project_id: 'test-project' }),
    );
  });

  it('drops events when beforeSend returns null', () => {
    const beforeSend = vi.fn(() => null);
    createClient({ beforeSend });

    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);

    expect(client.getQueueLength()).toBe(0);
  });

  it('respects sample rate for performance events', () => {
    createClient({ performanceSampleRate: 0 });

    client.capture({
      type: 'performance',
      metrics: {},
      url: 'https://example.com',
    } as any);

    expect(client.getQueueLength()).toBe(0);
  });

  it('applies PII scrubbing before send', () => {
    const beforeSend = vi.fn((event: ShipSafeEvent) => event);
    createClient({ beforeSend });

    client.capture({
      type: 'error',
      error: {
        name: 'Error',
        message: 'User email is test@example.com',
        handled: true,
      },
      context: {},
    } as any);

    const capturedEvent = beforeSend.mock.calls[0][0];
    expect((capturedEvent as any).error.message).toContain('[email]');
    expect((capturedEvent as any).error.message).not.toContain('test@example.com');
  });

  it('flush() sends batched events to endpoint', async () => {
    createClient();

    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);
    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);
    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);

    await client.flush();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://test.shipsafe.org/v1/events',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body.project_id).toBe('test-project');
    expect(body.events).toHaveLength(3);
  });

  it('does not capture events after destroy', () => {
    createClient();
    client.destroy();

    client.capture({ type: 'error' } as Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>);
    expect(client.getQueueLength()).toBe(0);
  });
});
