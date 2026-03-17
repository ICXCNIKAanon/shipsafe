import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock GitHub API dependencies before importing
vi.mock('../../src/github/api.js', () => ({
  getInstallationToken: vi.fn(),
  githubApi: vi.fn(),
}));

import {
  generateFix,
  generateAutoFixPr,
  parseStackTrace,
  type ProcessedError,
} from '../../src/autofix/pr-generator.js';
import { getInstallationToken, githubApi } from '../../src/github/api.js';

const mockedGetInstallationToken = vi.mocked(getInstallationToken);
const mockedGithubApi = vi.mocked(githubApi);

function makeError(overrides: Partial<ProcessedError> = {}): ProcessedError {
  return {
    id: 'err_001',
    message: "TypeError: Cannot read property 'name' of null",
    severity: 'critical',
    file: 'src/api/handler.ts',
    line: 10,
    ...overrides,
  };
}

describe('generateFix', () => {
  it('adds optional chaining for TypeError on null property access', () => {
    const error = makeError({
      message: "TypeError: Cannot read property 'name' of null",
      file: 'src/handler.ts',
      line: 3,
    });
    const content = [
      'function getUser(user) {',
      '  // some code',
      '  return user.name;',
      '}',
    ].join('\n');

    const result = generateFix(error, content);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('user?.name');
    expect(result!.description).toContain('optional chaining');
  });

  it('adds optional chaining for property access on undefined', () => {
    const error = makeError({
      message: "TypeError: Cannot read properties of undefined (reading 'email')",
      file: 'src/profile.ts',
      line: 2,
    });
    const content = ['const profile = getProfile();', 'const email = profile.email;', ''].join(
      '\n',
    );

    const result = generateFix(error, content);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('profile?.email');
  });

  it('wraps unhandled promise rejection in try/catch', () => {
    const error = makeError({
      message: 'UnhandledPromiseRejection: fetch failed',
      file: 'src/api.ts',
      line: 1,
    });
    const content = ['  await fetch(url);', ''].join('\n');

    const result = generateFix(error, content);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('try {');
    expect(result!.fixed).toContain('catch (err)');
    expect(result!.fixed).toContain('await fetch(url)');
  });

  it('adds typeof guard for "is not a function" TypeError', () => {
    const error = makeError({
      message: 'TypeError: callback is not a function',
      file: 'src/events.ts',
      line: 1,
    });
    const content = ['  callback(data);', ''].join('\n');

    const result = generateFix(error, content);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain("typeof callback === 'function'");
    expect(result!.fixed).toContain('callback(data)');
  });

  it('returns null for unfixable errors', () => {
    const error = makeError({
      message: 'SomeRandomError: something broke',
      file: 'src/unknown.ts',
      line: 1,
    });
    const content = ['const x = 42;', ''].join('\n');

    const result = generateFix(error, content);

    expect(result).toBeNull();
  });

  it('returns null when no file or line is provided', () => {
    const error = makeError({ file: undefined, line: undefined });
    const result = generateFix(error, 'const x = 1;');

    expect(result).toBeNull();
  });

  it('returns null when line number is out of range', () => {
    const error = makeError({ line: 999 });
    const result = generateFix(error, 'const x = 1;');

    expect(result).toBeNull();
  });

  it('adds declaration for ReferenceError: X is not defined', () => {
    const error = makeError({
      message: 'ReferenceError: config is not defined',
      file: 'src/app.ts',
      line: 1,
    });
    const content = ['  console.log(config);', ''].join('\n');

    const result = generateFix(error, content);

    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('const config = undefined');
    expect(result!.description).toContain('config');
  });
});

describe('parseStackTrace', () => {
  it('parses stack trace with function name and parens', () => {
    const result = parseStackTrace('at handler (/src/api/route.ts:42:10)');
    expect(result).toEqual({ file: '/src/api/route.ts', line: 42 });
  });

  it('parses stack trace without parens', () => {
    const result = parseStackTrace('at /src/api/route.ts:42');
    expect(result).toEqual({ file: '/src/api/route.ts', line: 42 });
  });

  it('returns null for unparseable stack traces', () => {
    const result = parseStackTrace('no stack trace here');
    expect(result).toBeNull();
  });
});

describe('generateAutoFixPr', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetInstallationToken.mockResolvedValue('ghs_test_token');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('creates branch, commits fix, and opens PR', async () => {
    const error = makeError({
      message: "TypeError: Cannot read property 'name' of null",
      file: 'src/handler.ts',
      line: 3,
    });

    const fileContent = [
      'function getUser(user) {',
      '  // some code',
      '  return user.name;',
      '}',
    ].join('\n');

    // Mock GitHub API calls in order
    mockedGithubApi
      // 1. Fetch file content
      .mockResolvedValueOnce({
        content: Buffer.from(fileContent).toString('base64'),
        sha: 'abc123',
        encoding: 'base64',
      })
      // 2. Get base branch ref
      .mockResolvedValueOnce({ object: { sha: 'base_sha_123' } })
      // 3. Create branch ref
      .mockResolvedValueOnce({})
      // 4. Commit file update
      .mockResolvedValueOnce({})
      // 5. Create PR
      .mockResolvedValueOnce({ html_url: 'https://github.com/owner/repo/pull/42' });

    const result = await generateAutoFixPr({
      error,
      repoFullName: 'owner/repo',
      installationId: 12345,
    });

    expect(result.status).toBe('pr_created');
    expect(result.prUrl).toBe('https://github.com/owner/repo/pull/42');
    expect(result.branchName).toBe('shipsafe/fix-err_001');
    expect(result.filesModified).toContain('src/handler.ts');

    // Verify correct API calls were made
    expect(mockedGetInstallationToken).toHaveBeenCalledWith(12345);
    expect(mockedGithubApi).toHaveBeenCalledTimes(5);

    // Verify branch creation
    const createBranchCall = mockedGithubApi.mock.calls[2];
    expect(createBranchCall[0]).toBe('/repos/owner/repo/git/refs');
    expect(createBranchCall[1]).toMatchObject({
      method: 'POST',
      body: { ref: 'refs/heads/shipsafe/fix-err_001', sha: 'base_sha_123' },
    });

    // Verify PR creation
    const createPrCall = mockedGithubApi.mock.calls[4];
    expect(createPrCall[0]).toBe('/repos/owner/repo/pulls');
    expect(createPrCall[1]).toMatchObject({ method: 'POST' });
  });

  it('returns cannot_fix when no file info available', async () => {
    const error = makeError({ file: undefined, line: undefined, stack_trace: undefined });

    const result = await generateAutoFixPr({
      error,
      repoFullName: 'owner/repo',
      installationId: 12345,
    });

    expect(result.status).toBe('cannot_fix');
    expect(result.description).toContain('Cannot determine');
  });

  it('returns fix_suggested when generateFix cannot fix the error', async () => {
    const error = makeError({
      message: 'SomeWeirdError: unknown issue',
      suggested_fix: 'Check the logs',
    });

    const fileContent = 'const x = 42;\n';

    mockedGithubApi.mockResolvedValueOnce({
      content: Buffer.from(fileContent).toString('base64'),
      sha: 'abc123',
      encoding: 'base64',
    });

    const result = await generateAutoFixPr({
      error,
      repoFullName: 'owner/repo',
      installationId: 12345,
    });

    expect(result.status).toBe('fix_suggested');
    expect(result.description).toBe('Check the logs');
  });

  it('uses stack trace to determine file when file is not set', async () => {
    const error = makeError({
      file: undefined,
      line: undefined,
      stack_trace: 'at handler (/src/api/route.ts:3:10)',
      message: "TypeError: Cannot read property 'name' of null",
    });

    const fileContent = [
      'function handler(data) {',
      '  // process',
      '  return data.name;',
      '}',
    ].join('\n');

    mockedGithubApi
      .mockResolvedValueOnce({
        content: Buffer.from(fileContent).toString('base64'),
        sha: 'abc123',
        encoding: 'base64',
      })
      .mockResolvedValueOnce({ object: { sha: 'base_sha_123' } })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ html_url: 'https://github.com/owner/repo/pull/99' });

    const result = await generateAutoFixPr({
      error,
      repoFullName: 'owner/repo',
      installationId: 12345,
    });

    expect(result.status).toBe('pr_created');
    expect(result.filesModified).toContain('src/api/route.ts');
  });

  it('returns cannot_fix when GitHub API throws', async () => {
    const error = makeError();
    mockedGetInstallationToken.mockRejectedValue(new Error('Auth failed'));

    const result = await generateAutoFixPr({
      error,
      repoFullName: 'owner/repo',
      installationId: 12345,
    });

    expect(result.status).toBe('cannot_fix');
    expect(result.description).toContain('Auth failed');
  });

  it('uses custom baseBranch when provided', async () => {
    const error = makeError({
      message: "TypeError: Cannot read property 'name' of null",
    });

    const fileContent = [
      'function getUser(user) {',
      '  // some code',
      '  return user.name;',
      '}',
    ].join('\n');

    // Set line to 3 so it matches 'return user.name;'
    error.line = 3;

    mockedGithubApi
      .mockResolvedValueOnce({
        content: Buffer.from(fileContent).toString('base64'),
        sha: 'abc123',
        encoding: 'base64',
      })
      .mockResolvedValueOnce({ object: { sha: 'dev_sha' } })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ html_url: 'https://github.com/owner/repo/pull/50' });

    await generateAutoFixPr({
      error,
      repoFullName: 'owner/repo',
      installationId: 12345,
      baseBranch: 'develop',
    });

    // Verify the base branch ref was fetched from 'develop'
    const getRefCall = mockedGithubApi.mock.calls[1];
    expect(getRefCall[0]).toBe('/repos/owner/repo/git/ref/heads/develop');

    // Verify PR was created against 'develop'
    const createPrCall = mockedGithubApi.mock.calls[4];
    expect((createPrCall[1] as { body: { base: string } }).body.base).toBe('develop');
  });
});
