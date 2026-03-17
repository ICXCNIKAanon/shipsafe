import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import { rateLimiter, clearRateLimits } from '../../src/middleware/rate-limit.js';
import type { AppVariables } from '../../src/types.js';

function createTestApp(maxRequests: number, windowMs: number) {
  const app = new Hono<{ Variables: AppVariables }>();
  // Set a fake projectId for rate limiting key
  app.use('*', async (c, next) => {
    c.set('projectId', 'test-project');
    return next();
  });
  app.use('*', rateLimiter(maxRequests, windowMs));
  app.get('/test', (c) => c.json({ ok: true }));
  return app;
}

describe('rateLimiter middleware', () => {
  beforeEach(() => {
    clearRateLimits();
  });

  it('allows requests within limit', async () => {
    const app = createTestApp(3, 60000);
    const res = await app.request('/test');
    expect(res.status).toBe(200);
  });

  it('sets rate limit headers', async () => {
    const app = createTestApp(100, 60000);
    const res = await app.request('/test');
    expect(res.headers.get('X-RateLimit-Limit')).toBe('100');
    expect(res.headers.get('X-RateLimit-Remaining')).toBe('99');
    expect(res.headers.get('X-RateLimit-Reset')).toBeTruthy();
  });

  it('returns 429 when limit exceeded', async () => {
    const app = createTestApp(2, 60000);

    await app.request('/test'); // 1
    await app.request('/test'); // 2
    const res = await app.request('/test'); // 3 — over limit

    expect(res.status).toBe(429);
    const body = await res.json();
    expect(body.error).toContain('Rate limit exceeded');
  });

  it('decrements remaining count', async () => {
    const app = createTestApp(5, 60000);

    const res1 = await app.request('/test');
    expect(res1.headers.get('X-RateLimit-Remaining')).toBe('4');

    const res2 = await app.request('/test');
    expect(res2.headers.get('X-RateLimit-Remaining')).toBe('3');
  });

  it('resets after window expires', async () => {
    // Use a very short window (1ms) — requests should reset immediately
    const app = createTestApp(1, 1);

    await app.request('/test'); // 1 — allowed
    // Wait for window to expire
    await new Promise((r) => setTimeout(r, 5));
    const res = await app.request('/test'); // should be allowed after reset
    expect(res.status).toBe(200);
  });

  it('clearRateLimits resets all entries', async () => {
    const app = createTestApp(1, 60000);

    await app.request('/test'); // 1
    const blocked = await app.request('/test'); // 2 — blocked
    expect(blocked.status).toBe(429);

    clearRateLimits();

    const afterClear = await app.request('/test');
    expect(afterClear.status).toBe(200);
  });
});
