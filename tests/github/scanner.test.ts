import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the GitHub API module
vi.mock('../../src/github/api.js', () => ({
  getInstallationToken: vi.fn(),
  githubApi: vi.fn(),
}));

// Mock the pattern engine
vi.mock('../../src/engines/pattern/index.js', () => ({
  runPatternEngine: vi.fn(),
}));

import { scanPullRequest, type PrScanOptions } from '../../src/github/scanner.js';
import { getInstallationToken, githubApi } from '../../src/github/api.js';
import { runPatternEngine } from '../../src/engines/pattern/index.js';

const mockedGetInstallationToken = vi.mocked(getInstallationToken);
const mockedGithubApi = vi.mocked(githubApi);
const mockedRunPatternEngine = vi.mocked(runPatternEngine);

const defaultOptions: PrScanOptions = {
  repoFullName: 'owner/repo',
  prNumber: 42,
  headSha: 'abc123',
  baseSha: 'def456',
  installationId: 12345,
};

describe('scanPullRequest', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetInstallationToken.mockResolvedValue('fake-token');
  });

  it('scans only changed files from the PR', async () => {
    // Mock: PR has 2 changed files
    mockedGithubApi.mockImplementation(async (path: string) => {
      if (path.includes('/pulls/42/files')) {
        return [
          { filename: 'src/app.ts', status: 'modified' },
          { filename: 'src/utils.ts', status: 'added' },
        ];
      }
      // File content requests return base64-encoded content
      if (path.includes('/contents/')) {
        return {
          content: Buffer.from('const x = 1;\n').toString('base64'),
          encoding: 'base64',
        };
      }
      return {};
    });

    mockedRunPatternEngine.mockResolvedValue({
      status: 'pass',
      score: 'A',
      findings: [],
      scan_duration_ms: 50,
    });

    const result = await scanPullRequest(defaultOptions);

    expect(result.status).toBe('pass');
    expect(result.findings).toEqual([]);

    // Pattern engine should have been called with the temp dir and file list
    expect(mockedRunPatternEngine).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: 'all',
        stagedFiles: ['src/app.ts', 'src/utils.ts'],
      }),
    );
  });

  it('returns scan result with findings when issues are detected', async () => {
    mockedGithubApi.mockImplementation(async (path: string) => {
      if (path.includes('/pulls/42/files')) {
        return [{ filename: 'config.ts', status: 'modified' }];
      }
      if (path.includes('/contents/')) {
        return {
          content: Buffer.from('const API_KEY = "sk-secret";\n').toString('base64'),
          encoding: 'base64',
        };
      }
      return {};
    });

    mockedRunPatternEngine.mockResolvedValue({
      status: 'fail',
      score: 'D',
      findings: [
        {
          id: 'finding-1',
          engine: 'pattern',
          severity: 'high',
          type: 'hardcoded-secret',
          file: 'config.ts',
          line: 1,
          description: 'Hardcoded API key',
          fix_suggestion: 'Use env vars',
          auto_fixable: false,
        },
      ],
      scan_duration_ms: 100,
    });

    const result = await scanPullRequest(defaultOptions);

    expect(result.status).toBe('fail');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].type).toBe('hardcoded-secret');
  });

  it('returns clean result when all files are removed', async () => {
    mockedGithubApi.mockImplementation(async (path: string) => {
      if (path.includes('/pulls/42/files')) {
        return [
          { filename: 'old-file.ts', status: 'removed' },
          { filename: 'another-old.ts', status: 'removed' },
        ];
      }
      return {};
    });

    const result = await scanPullRequest(defaultOptions);

    expect(result.status).toBe('pass');
    expect(result.score).toBe('A');
    expect(result.findings).toEqual([]);
    // Pattern engine should NOT have been called since all files were removed
    expect(mockedRunPatternEngine).not.toHaveBeenCalled();
  });

  it('filters out removed files and scans only remaining', async () => {
    mockedGithubApi.mockImplementation(async (path: string) => {
      if (path.includes('/pulls/42/files')) {
        return [
          { filename: 'deleted.ts', status: 'removed' },
          { filename: 'modified.ts', status: 'modified' },
        ];
      }
      if (path.includes('/contents/')) {
        return {
          content: Buffer.from('export const x = 1;\n').toString('base64'),
          encoding: 'base64',
        };
      }
      return {};
    });

    mockedRunPatternEngine.mockResolvedValue({
      status: 'pass',
      score: 'A',
      findings: [],
      scan_duration_ms: 30,
    });

    await scanPullRequest(defaultOptions);

    // Only the modified file should be passed to the engine
    expect(mockedRunPatternEngine).toHaveBeenCalledWith(
      expect.objectContaining({
        stagedFiles: ['modified.ts'],
      }),
    );
  });

  it('requests an installation token', async () => {
    mockedGithubApi.mockImplementation(async (path: string) => {
      if (path.includes('/pulls/42/files')) {
        return [];
      }
      return {};
    });

    // All files removed, so empty result
    await scanPullRequest(defaultOptions);

    expect(mockedGetInstallationToken).toHaveBeenCalledWith(12345);
  });
});
