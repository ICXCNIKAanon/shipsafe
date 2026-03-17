import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateJwt, getInstallationToken, githubApi } from '../../src/github/api.js';
import { generateKeyPairSync } from 'node:crypto';

// Generate a test RSA key pair
const { privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

describe('generateJwt', () => {
  it('returns a JWT with 3 segments', () => {
    const jwt = generateJwt('12345', privateKey);
    const parts = jwt.split('.');
    expect(parts).toHaveLength(3);
  });

  it('header contains RS256 algorithm', () => {
    const jwt = generateJwt('12345', privateKey);
    const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString());
    expect(header.alg).toBe('RS256');
    expect(header.typ).toBe('JWT');
  });

  it('payload contains iss matching appId', () => {
    const jwt = generateJwt('99999', privateKey);
    const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    expect(payload.iss).toBe('99999');
  });

  it('payload has iat and exp fields', () => {
    const jwt = generateJwt('12345', privateKey);
    const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');
    expect(payload.exp).toBeGreaterThan(payload.iat);
  });
});

describe('getInstallationToken', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  it('throws when env vars are missing', async () => {
    delete process.env.SHIPSAFE_GITHUB_APP_ID;
    delete process.env.SHIPSAFE_GITHUB_PRIVATE_KEY;

    await expect(getInstallationToken(123)).rejects.toThrow(
      'Missing SHIPSAFE_GITHUB_APP_ID or SHIPSAFE_GITHUB_PRIVATE_KEY',
    );
  });

  it('returns token on successful API call', async () => {
    process.env.SHIPSAFE_GITHUB_APP_ID = '12345';
    process.env.SHIPSAFE_GITHUB_PRIVATE_KEY = privateKey;

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ token: 'ghs_test_token' }),
    } as Response);

    const token = await getInstallationToken(456);
    expect(token).toBe('ghs_test_token');
  });

  it('throws on non-OK response', async () => {
    process.env.SHIPSAFE_GITHUB_APP_ID = '12345';
    process.env.SHIPSAFE_GITHUB_PRIVATE_KEY = privateKey;

    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => 'Unauthorized',
    } as Response);

    await expect(getInstallationToken(456)).rejects.toThrow('Failed to get installation token');
  });
});

describe('githubApi', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('makes GET request with correct headers', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ data: 'test' }),
    } as Response);

    await githubApi('/repos/owner/repo', { token: 'ghs_abc' });

    expect(fetchSpy).toHaveBeenCalledOnce();
    const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.github.com/repos/owner/repo');
    expect(opts.method).toBe('GET');
    expect((opts.headers as Record<string, string>).Authorization).toBe('token ghs_abc');
  });

  it('makes POST request with body', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ id: 1 }),
    } as Response);

    await githubApi('/repos/owner/repo/issues', {
      token: 'ghs_abc',
      method: 'POST',
      body: { title: 'Test issue' },
    });

    const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(opts.method).toBe('POST');
    expect(JSON.parse(opts.body as string)).toEqual({ title: 'Test issue' });
  });

  it('passes through full URLs', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'text/plain' }),
      text: async () => 'ok',
    } as Response);

    await githubApi('https://api.github.com/custom/endpoint', { token: 'ghs_abc' });

    const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.github.com/custom/endpoint');
  });

  it('throws on non-OK response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 404,
      text: async () => 'Not Found',
    } as Response);

    await expect(
      githubApi('/repos/owner/repo', { token: 'ghs_abc' }),
    ).rejects.toThrow('GitHub API error: 404');
  });

  it('returns text for non-JSON responses', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'text/plain' }),
      text: async () => 'plain text response',
    } as Response);

    const result = await githubApi('/some/endpoint', { token: 'ghs_abc' });
    expect(result).toBe('plain text response');
  });
});
