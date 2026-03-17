import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ShipSafeClient } from '../../src/core/client.js';
import { setupErrorCapture } from '../../src/capture/errors.js';

describe('setupErrorCapture (Node.js)', () => {
  let client: ShipSafeClient;
  let captureSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));
    vi.useFakeTimers();

    client = new ShipSafeClient({
      projectId: 'test-project',
      endpoint: 'https://test.shipsafe.org/v1/events',
      environment: 'test',
    });
    captureSpy = vi.spyOn(client, 'capture');
  });

  afterEach(() => {
    client.destroy();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('captures uncaught exceptions via process listener', () => {
    const cleanup = setupErrorCapture(client);

    const testError = new Error('test uncaught');
    // Emit the error on process (Node.js)
    // We need to emit it directly to the listeners
    process.emit('uncaughtException', testError);

    expect(captureSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'error',
        error: expect.objectContaining({
          name: 'Error',
          message: 'test uncaught',
          handled: false,
        }),
      }),
    );

    cleanup();
  });

  it('captures unhandled rejections via process listener', () => {
    const cleanup = setupErrorCapture(client);

    const testError = new Error('test rejection');
    process.emit('unhandledRejection', testError, Promise.resolve());

    expect(captureSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'error',
        error: expect.objectContaining({
          name: 'Error',
          message: 'test rejection',
          handled: false,
        }),
      }),
    );

    cleanup();
  });

  it('cleanup function removes listeners', () => {
    const initialUncaughtListenerCount = process.listenerCount('uncaughtException');
    const initialRejectionListenerCount = process.listenerCount('unhandledRejection');

    const cleanup = setupErrorCapture(client);

    expect(process.listenerCount('uncaughtException')).toBe(initialUncaughtListenerCount + 1);
    expect(process.listenerCount('unhandledRejection')).toBe(initialRejectionListenerCount + 1);

    cleanup();

    expect(process.listenerCount('uncaughtException')).toBe(initialUncaughtListenerCount);
    expect(process.listenerCount('unhandledRejection')).toBe(initialRejectionListenerCount);
  });
});
