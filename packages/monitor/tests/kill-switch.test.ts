import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ShipSafeClient } from '../src/core/client.js';
import type { ShipSafeEvent } from '../src/core/types.js';

type CaptureArg = Omit<ShipSafeEvent, 'project_id' | 'session_id' | 'timestamp' | 'environment'>;

describe('ShipSafeClient kill switch', () => {
  let client: ShipSafeClient;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 });
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

  it('is not disabled initially', () => {
    createClient();
    expect(client.isDisabled()).toBe(false);
  });

  it('auto-disables after 3 flush errors', async () => {
    createClient();
    fetchSpy.mockRejectedValue(new Error('Network failure'));

    // Each flush() call exhausts all MAX_RETRIES internally before returning,
    // so we need to advance timers through the retry backoff for each call.
    // Retry delays: 1s, 2s (total 3s per flush call).
    const flush1 = client.flush();
    client.capture({ type: 'error' } as CaptureArg);
    await vi.advanceTimersByTimeAsync(10000);
    await flush1;

    expect(client.isDisabled()).toBe(false);

    const flush2 = client.flush();
    client.capture({ type: 'error' } as CaptureArg);
    await vi.advanceTimersByTimeAsync(10000);
    await flush2;

    expect(client.isDisabled()).toBe(false);

    const flush3 = client.flush();
    client.capture({ type: 'error' } as CaptureArg);
    await vi.advanceTimersByTimeAsync(10000);
    await flush3;

    expect(client.isDisabled()).toBe(true);
  });

  it('capture methods no-op when disabled', async () => {
    createClient();
    fetchSpy.mockRejectedValue(new Error('Network failure'));

    // Trigger 3 failed flushes to auto-disable
    for (let i = 0; i < 3; i++) {
      client.capture({ type: 'error' } as CaptureArg);
      const p = client.flush();
      await vi.advanceTimersByTimeAsync(10000);
      await p;
    }

    expect(client.isDisabled()).toBe(true);

    // Queue should be empty after flushes
    const queueBefore = client.getQueueLength();
    client.capture({ type: 'error' } as CaptureArg);
    expect(client.getQueueLength()).toBe(queueBefore);
  });

  it('logs console.warn on auto-disable', async () => {
    createClient();
    fetchSpy.mockRejectedValue(new Error('Network failure'));
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    for (let i = 0; i < 3; i++) {
      client.capture({ type: 'error' } as CaptureArg);
      const p = client.flush();
      await vi.advanceTimersByTimeAsync(10000);
      await p;
    }

    expect(warnSpy).toHaveBeenCalledWith(
      '[ShipSafe] Monitor auto-disabled after repeated errors. Events will not be captured.',
    );
  });

  it('manual disable() prevents capture', () => {
    createClient();
    client.disable();
    expect(client.isDisabled()).toBe(true);

    client.capture({ type: 'error' } as CaptureArg);
    expect(client.getQueueLength()).toBe(0);
  });

  it('manual enable() re-enables capture after disable', () => {
    createClient();
    client.disable();
    expect(client.isDisabled()).toBe(true);

    client.enable();
    expect(client.isDisabled()).toBe(false);

    client.capture({ type: 'error' } as CaptureArg);
    expect(client.getQueueLength()).toBe(1);
  });
});
