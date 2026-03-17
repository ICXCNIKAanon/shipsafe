import type { Context, Next } from 'hono';
import type { AppVariables } from '../types.js';

/**
 * Simple in-memory rate limiter per project.
 * Allows `maxRequests` requests per `windowMs` milliseconds.
 */

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const limits = new Map<string, RateLimitEntry>();

const DEFAULT_MAX_REQUESTS = 1000;
const DEFAULT_WINDOW_MS = 60_000; // 1 minute

export function rateLimiter(
  maxRequests: number = DEFAULT_MAX_REQUESTS,
  windowMs: number = DEFAULT_WINDOW_MS,
) {
  return async (
    c: Context<{ Variables: AppVariables }>,
    next: Next,
  ): Promise<Response | void> => {
    const projectId = c.get('projectId');
    const key = projectId ?? c.req.header('x-forwarded-for') ?? 'anonymous';
    const now = Date.now();

    let entry = limits.get(key);

    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      limits.set(key, entry);
    }

    entry.count++;

    c.header('X-RateLimit-Limit', String(maxRequests));
    c.header('X-RateLimit-Remaining', String(Math.max(0, maxRequests - entry.count)));
    c.header('X-RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)));

    if (entry.count > maxRequests) {
      return c.json({ error: 'Rate limit exceeded. Try again later.' }, 429);
    }

    return next();
  };
}

/**
 * Clear all rate limit entries (for testing).
 */
export function clearRateLimits(): void {
  limits.clear();
}
