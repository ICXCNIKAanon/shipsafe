import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ShipSafe, getClient } from '../../src/index.js';
import { errorHandler } from '../../src/adapters/express.js';

describe('Express errorHandler', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));
    vi.useFakeTimers();

    ShipSafe.init({
      projectId: 'test-project',
      endpoint: 'https://test.shipsafe.org/v1/events',
      environment: 'test',
    });
  });

  afterEach(() => {
    ShipSafe.destroy();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('calls next() with the error', () => {
    const handler = errorHandler();
    const err = new Error('test error');
    const req = { method: 'POST', originalUrl: '/api/users' };
    const res = { statusCode: 500 };
    const next = vi.fn();

    handler(err, req, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });

  it('captures error with request context', () => {
    const handler = errorHandler();
    const err = new Error('test error');
    const req = { method: 'POST', originalUrl: '/api/users' };
    const res = { statusCode: 500 };
    const next = vi.fn();

    const client = getClient()!;
    const captureSpy = vi.spyOn(client, 'capture');

    handler(err, req, res, next);

    expect(captureSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'error',
        error: expect.objectContaining({
          name: 'Error',
          message: 'test error',
          handled: true,
        }),
        context: expect.objectContaining({
          method: 'POST',
          url: '/api/users',
          status_code: 500,
        }),
      }),
    );
  });
});
