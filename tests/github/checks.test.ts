import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Finding } from '../../src/types.js';

// Mock the GitHub API module
vi.mock('../../src/github/api.js', () => ({
  getInstallationToken: vi.fn(),
  githubApi: vi.fn(),
}));

import {
  createCheckRun,
  completeCheckRun,
  formatAnnotations,
  buildSummary,
} from '../../src/github/checks.js';
import { getInstallationToken, githubApi } from '../../src/github/api.js';

const mockedGetInstallationToken = vi.mocked(getInstallationToken);
const mockedGithubApi = vi.mocked(githubApi);

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'test-finding',
    engine: 'pattern',
    severity: 'high',
    type: 'hardcoded-secret',
    file: 'src/config.ts',
    line: 10,
    description: 'Hardcoded API key detected',
    fix_suggestion: 'Use environment variables instead',
    auto_fixable: false,
    ...overrides,
  };
}

describe('createCheckRun', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetInstallationToken.mockResolvedValue('fake-token');
  });

  it('sends correct API request to create a check run', async () => {
    mockedGithubApi.mockResolvedValue({ id: 777 });

    const checkRunId = await createCheckRun({
      repoFullName: 'owner/repo',
      headSha: 'abc123',
      installationId: 12345,
    });

    expect(checkRunId).toBe(777);

    expect(mockedGithubApi).toHaveBeenCalledWith(
      '/repos/owner/repo/check-runs',
      expect.objectContaining({
        method: 'POST',
        token: 'fake-token',
        body: expect.objectContaining({
          name: 'ShipSafe Security Scan',
          head_sha: 'abc123',
          status: 'in_progress',
        }),
      }),
    );
  });

  it('gets an installation token for the request', async () => {
    mockedGithubApi.mockResolvedValue({ id: 1 });

    await createCheckRun({
      repoFullName: 'owner/repo',
      headSha: 'abc123',
      installationId: 99999,
    });

    expect(mockedGetInstallationToken).toHaveBeenCalledWith(99999);
  });
});

describe('completeCheckRun', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetInstallationToken.mockResolvedValue('fake-token');
    mockedGithubApi.mockResolvedValue({});
  });

  it('formats findings as annotations in the check run output', async () => {
    const findings: Finding[] = [
      makeFinding({ file: 'src/app.ts', line: 5, severity: 'critical' }),
      makeFinding({ file: 'src/db.ts', line: 20, severity: 'medium' }),
    ];

    await completeCheckRun({
      repoFullName: 'owner/repo',
      checkRunId: 777,
      installationId: 12345,
      conclusion: 'failure',
      findings,
    });

    expect(mockedGithubApi).toHaveBeenCalledWith(
      '/repos/owner/repo/check-runs/777',
      expect.objectContaining({
        method: 'PATCH',
        body: expect.objectContaining({
          status: 'completed',
          conclusion: 'failure',
          output: expect.objectContaining({
            title: 'ShipSafe Security Scan',
            annotations: expect.arrayContaining([
              expect.objectContaining({
                path: 'src/app.ts',
                start_line: 5,
                annotation_level: 'failure',
              }),
              expect.objectContaining({
                path: 'src/db.ts',
                start_line: 20,
                annotation_level: 'warning',
              }),
            ]),
          }),
        }),
      }),
    );
  });

  it('sets conclusion to success when no findings', async () => {
    await completeCheckRun({
      repoFullName: 'owner/repo',
      checkRunId: 777,
      installationId: 12345,
      conclusion: 'success',
      findings: [],
    });

    expect(mockedGithubApi).toHaveBeenCalledWith(
      '/repos/owner/repo/check-runs/777',
      expect.objectContaining({
        body: expect.objectContaining({
          conclusion: 'success',
          output: expect.objectContaining({
            summary: expect.stringContaining('no security issues'),
          }),
        }),
      }),
    );
  });

  it('sets conclusion based on findings severity', async () => {
    await completeCheckRun({
      repoFullName: 'owner/repo',
      checkRunId: 777,
      installationId: 12345,
      conclusion: 'failure',
      findings: [makeFinding({ severity: 'critical' })],
    });

    expect(mockedGithubApi).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        body: expect.objectContaining({
          conclusion: 'failure',
        }),
      }),
    );
  });
});

describe('formatAnnotations', () => {
  it('maps critical severity to failure annotation level', () => {
    const annotations = formatAnnotations([makeFinding({ severity: 'critical' })]);
    expect(annotations[0].annotation_level).toBe('failure');
  });

  it('maps high severity to failure annotation level', () => {
    const annotations = formatAnnotations([makeFinding({ severity: 'high' })]);
    expect(annotations[0].annotation_level).toBe('failure');
  });

  it('maps medium severity to warning annotation level', () => {
    const annotations = formatAnnotations([makeFinding({ severity: 'medium' })]);
    expect(annotations[0].annotation_level).toBe('warning');
  });

  it('maps low severity to notice annotation level', () => {
    const annotations = formatAnnotations([makeFinding({ severity: 'low' })]);
    expect(annotations[0].annotation_level).toBe('notice');
  });

  it('maps info severity to notice annotation level', () => {
    const annotations = formatAnnotations([makeFinding({ severity: 'info' })]);
    expect(annotations[0].annotation_level).toBe('notice');
  });

  it('includes file path and line number', () => {
    const annotations = formatAnnotations([makeFinding({ file: 'src/index.ts', line: 42 })]);
    expect(annotations[0].path).toBe('src/index.ts');
    expect(annotations[0].start_line).toBe(42);
    expect(annotations[0].end_line).toBe(42);
  });

  it('includes description and fix suggestion in message', () => {
    const annotations = formatAnnotations([
      makeFinding({
        description: 'SQL injection vulnerability',
        fix_suggestion: 'Use parameterized queries',
      }),
    ]);
    expect(annotations[0].message).toContain('SQL injection vulnerability');
    expect(annotations[0].message).toContain('Use parameterized queries');
  });
});

describe('buildSummary', () => {
  it('returns "no security issues" message for empty findings', () => {
    const summary = buildSummary([]);
    expect(summary).toContain('no security issues');
  });

  it('includes count and severity breakdown', () => {
    const findings: Finding[] = [
      makeFinding({ severity: 'critical' }),
      makeFinding({ severity: 'high' }),
      makeFinding({ severity: 'high' }),
      makeFinding({ severity: 'medium' }),
    ];

    const summary = buildSummary(findings);

    expect(summary).toContain('4 issues');
    expect(summary).toContain('1 critical');
    expect(summary).toContain('2 high');
    expect(summary).toContain('1 medium');
  });

  it('omits severity categories with zero count', () => {
    const findings: Finding[] = [
      makeFinding({ severity: 'low' }),
    ];

    const summary = buildSummary(findings);

    expect(summary).toContain('1 issues');
    expect(summary).toContain('1 low');
    expect(summary).not.toContain('critical');
    expect(summary).not.toContain('high');
    expect(summary).not.toContain('medium');
  });
});
