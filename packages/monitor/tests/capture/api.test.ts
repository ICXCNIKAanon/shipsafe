import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ShipSafeClient } from '../../src/core/client.js';
import { setupApiCapture } from '../../src/capture/api.js';

describe('setupApiCapture', () => {
  let client: ShipSafeClient;
  let captureSpy: ReturnType<typeof vi.spyOn>;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    vi.useFakeTimers();
    originalFetch = globalThis.fetch;

    // Start with a working fetch for the client to use
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));

    client = new ShipSafeClient({
      projectId: 'test-project',
      endpoint: 'https://test.shipsafe.org/v1/events',
      environment: 'test',
    });
    captureSpy = vi.spyOn(client, 'capture');
  });

  afterEach(() => {
    client.destroy();
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('captures API errors for 4xx responses', async () => {
    // Set up fetch interception
    const cleanup = setupApiCapture(client);

    // Override the patched fetch to return a 404
    const patchedFetch = globalThis.fetch;
    const mockResponse = { ok: false, status: 404 };
    // We need to replace the underlying fetch that the interceptor calls
    // The interceptor saved a reference to the original fetch, so we mock
    // at the point where the interceptor was set up
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse);

    // Restore and re-setup to use the new mock
    cleanup();

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse));
    const cleanup2 = setupApiCapture(client);

    await globalThis.fetch('https://api.example.com/missing', { method: 'GET' });

    expect(captureSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'api_error',
        request: expect.objectContaining({
          method: 'GET',
          path: '/missing',
          status_code: 404,
        }),
      }),
    );

    cleanup2();
  });

  it('captures fetch network errors', async () => {
    const cleanup = setupApiCapture(client);

    // Re-setup with a failing fetch
    cleanup();
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new TypeError('Failed to fetch')),
    );
    const cleanup2 = setupApiCapture(client);

    await expect(
      globalThis.fetch('https://api.example.com/test'),
    ).rejects.toThrow('Failed to fetch');

    expect(captureSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'api_error',
        request: expect.objectContaining({
          method: 'GET',
          status_code: 0,
        }),
        error: expect.objectContaining({
          name: 'TypeError',
          message: 'Failed to fetch',
        }),
      }),
    );

    cleanup2();
  });

  it('does not capture successful responses', async () => {
    const cleanup = setupApiCapture(client);

    cleanup();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));
    const cleanup2 = setupApiCapture(client);

    await globalThis.fetch('https://api.example.com/ok');

    expect(captureSpy).not.toHaveBeenCalled();

    cleanup2();
  });

  it('cleanup restores original fetch', () => {
    const mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);

    const cleanup = setupApiCapture(client);
    expect(globalThis.fetch).not.toBe(mockFetch);

    cleanup();
    expect(globalThis.fetch).toBe(mockFetch);
  });
});
