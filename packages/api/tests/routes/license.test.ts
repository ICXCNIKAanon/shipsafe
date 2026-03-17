import { describe, it, expect } from 'vitest';
import app from '../../src/index.js';

describe('POST /v1/license/validate', () => {
  it('validates a PRO license key', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-PRO-abcdef12' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.valid).toBe(true);
    expect(body.tier).toBe('pro');
    expect(body.project_limit).toBe(5);
    expect(body.expires_at).toBeDefined();
  });

  it('validates a FREE license key', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-FREE-abcdefgh' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.valid).toBe(true);
    expect(body.tier).toBe('free');
    expect(body.project_limit).toBe(1);
  });

  it('validates a TEAM license key', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-TEAM-12345678' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.tier).toBe('team');
    expect(body.project_limit).toBe(20);
  });

  it('validates an AGENCY license key', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-AGENCY-xyzw1234' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.tier).toBe('agency');
    expect(body.project_limit).toBe(100);
  });

  it('rejects an invalid license key format', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'invalid-key' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.valid).toBe(false);
    expect(body.error).toContain('Invalid license key');
  });

  it('rejects a key with too-short random segment', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'SS-PRO-abc' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.valid).toBe(false);
  });

  it('returns 400 when license_key is missing', async () => {
    const res = await app.request('/v1/license/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('Missing license_key');
  });
});
