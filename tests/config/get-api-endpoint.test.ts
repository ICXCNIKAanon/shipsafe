import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { getApiEndpoint } from '../../src/config/manager.js';
import { DEFAULT_API_URL } from '../../src/constants.js';

describe('getApiEndpoint', () => {
  const originalEnv = process.env.SHIPSAFE_API_URL;

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.SHIPSAFE_API_URL;
    } else {
      process.env.SHIPSAFE_API_URL = originalEnv;
    }
  });

  it('returns DEFAULT_API_URL when no env var and no config', () => {
    delete process.env.SHIPSAFE_API_URL;
    expect(getApiEndpoint()).toBe(DEFAULT_API_URL);
    expect(getApiEndpoint({})).toBe(DEFAULT_API_URL);
  });

  it('returns config apiEndpoint when no env var', () => {
    delete process.env.SHIPSAFE_API_URL;
    expect(getApiEndpoint({ apiEndpoint: 'https://api.shipsafe.org' })).toBe(
      'https://api.shipsafe.org',
    );
  });

  it('env var takes precedence over config', () => {
    process.env.SHIPSAFE_API_URL = 'https://custom.example.com';
    expect(getApiEndpoint({ apiEndpoint: 'https://api.shipsafe.org' })).toBe(
      'https://custom.example.com',
    );
  });

  it('env var takes precedence over default', () => {
    process.env.SHIPSAFE_API_URL = 'https://staging.shipsafe.org';
    expect(getApiEndpoint()).toBe('https://staging.shipsafe.org');
  });
});
