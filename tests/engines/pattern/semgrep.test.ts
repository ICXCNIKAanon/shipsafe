import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Finding } from '../../../src/types.js';

// Mock child_process before importing the module under test
vi.mock('node:child_process', () => {
  const execFileFn = vi.fn();
  return {
    execFile: execFileFn,
  };
});

import { execFile } from 'node:child_process';
import { checkSemgrepInstalled, runSemgrep } from '../../../src/engines/pattern/semgrep.js';

// Cast to a mock so we can control behavior
const mockExecFile = vi.mocked(execFile);

// Helper: make execFile callback-based mock resolve with given stdout
function mockExecFileSuccess(stdout: string): void {
  mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
    // execFile can be called with (cmd, args, cb) or (cmd, args, opts, cb)
    const callback = cb ?? _opts;
    if (typeof callback === 'function') {
      callback(null, stdout, '');
    }
    return {} as any;
  });
}

function mockExecFileFailure(error: Error & { code?: number }, stdout = '', stderr = ''): void {
  mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
    const callback = cb ?? _opts;
    if (typeof callback === 'function') {
      (callback as any)(error, stdout, stderr);
    }
    return {} as any;
  });
}

const SAMPLE_SEMGREP_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: 'javascript.express.security.audit.xss.mustache-escape',
      path: 'src/app.ts',
      start: { line: 42, col: 5 },
      end: { line: 42, col: 50 },
      extra: {
        message: 'Untrusted user input in template without escaping',
        severity: 'WARNING',
        fix: 'escape(userInput)',
      },
    },
  ],
  errors: [],
});

const MULTI_RESULT_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: 'javascript.express.security.audit.xss.mustache-escape',
      path: 'src/app.ts',
      start: { line: 42, col: 5 },
      end: { line: 42, col: 50 },
      extra: {
        message: 'Untrusted user input in template without escaping',
        severity: 'WARNING',
        fix: 'escape(userInput)',
      },
    },
    {
      check_id: 'javascript.lang.security.detect-eval',
      path: 'src/utils.ts',
      start: { line: 10, col: 1 },
      end: { line: 10, col: 30 },
      extra: {
        message: 'Detected use of eval(). This is dangerous.',
        severity: 'ERROR',
      },
    },
    {
      check_id: 'javascript.lang.best-practice.no-console',
      path: 'src/index.ts',
      start: { line: 5, col: 1 },
      end: { line: 5, col: 20 },
      extra: {
        message: 'Avoid console.log in production code',
        severity: 'INFO',
      },
    },
  ],
  errors: [],
});

const CLEAN_OUTPUT = JSON.stringify({
  results: [],
  errors: [],
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkSemgrepInstalled', () => {
  it('returns true when which semgrep succeeds', async () => {
    mockExecFileSuccess('/usr/local/bin/semgrep\n');

    const result = await checkSemgrepInstalled();

    expect(result).toBe(true);
    expect(mockExecFile).toHaveBeenCalledWith(
      'which',
      ['semgrep'],
      expect.any(Function),
    );
  });

  it('returns false when which semgrep fails', async () => {
    const error = new Error('not found') as Error & { code?: number };
    error.code = 1;
    mockExecFileFailure(error);

    const result = await checkSemgrepInstalled();

    expect(result).toBe(false);
  });
});

describe('runSemgrep', () => {
  it('parses semgrep JSON output into Finding[]', async () => {
    // First call: which semgrep (success)
    // Second call: semgrep scan (returns JSON output)
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          // which semgrep
          callback(null, '/usr/local/bin/semgrep\n', '');
        } else {
          // semgrep scan
          callback(null, SAMPLE_SEMGREP_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runSemgrep('/project');

    expect(findings).toHaveLength(1);
    expect(findings[0]).toEqual({
      id: 'semgrep_javascript.express.security.audit.xss.mustache-escape_42',
      engine: 'pattern',
      severity: 'high',
      type: 'javascript.express.security.audit.xss.mustache-escape',
      file: 'src/app.ts',
      line: 42,
      description: 'Untrusted user input in template without escaping',
      fix_suggestion: 'escape(userInput)',
      auto_fixable: true,
    } satisfies Finding);
  });

  it('maps severity correctly (ERROR -> critical, WARNING -> high, INFO -> medium)', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/semgrep\n', '');
        } else {
          callback(null, MULTI_RESULT_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runSemgrep('/project');

    expect(findings).toHaveLength(3);
    // WARNING -> high
    expect(findings[0].severity).toBe('high');
    // ERROR -> critical
    expect(findings[1].severity).toBe('critical');
    // INFO -> medium
    expect(findings[2].severity).toBe('medium');
  });

  it('returns empty findings when scan is clean', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/semgrep\n', '');
        } else {
          callback(null, CLEAN_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runSemgrep('/project');

    expect(findings).toEqual([]);
  });

  it('handles semgrep not installed gracefully', async () => {
    const error = new Error('not found') as Error & { code?: number };
    error.code = 1;
    mockExecFileFailure(error);

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const findings = await runSemgrep('/project');

    expect(findings).toEqual([]);
    warnSpy.mockRestore();
  });

  it('passes staged files as arguments when provided', async () => {
    let callCount = 0;
    let capturedArgs: string[] = [];
    mockExecFile.mockImplementation((cmd: any, args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/semgrep\n', '');
        } else {
          capturedArgs = args as string[];
          callback(null, CLEAN_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const stagedFiles = ['src/app.ts', 'src/utils.ts'];
    await runSemgrep('/project', stagedFiles);

    // Should pass individual file paths instead of the target path
    expect(capturedArgs).toContain('src/app.ts');
    expect(capturedArgs).toContain('src/utils.ts');
    expect(capturedArgs).toContain('--json');
    expect(capturedArgs).toContain('--quiet');
  });

  it('sets auto_fixable to false when no fix is provided', async () => {
    const outputWithNoFix = JSON.stringify({
      results: [
        {
          check_id: 'javascript.lang.security.detect-eval',
          path: 'src/utils.ts',
          start: { line: 10, col: 1 },
          end: { line: 10, col: 30 },
          extra: {
            message: 'Detected use of eval(). This is dangerous.',
            severity: 'ERROR',
          },
        },
      ],
      errors: [],
    });

    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/semgrep\n', '');
        } else {
          callback(null, outputWithNoFix, '');
        }
      }
      return {} as any;
    });

    const findings = await runSemgrep('/project');

    expect(findings[0].auto_fixable).toBe(false);
    expect(findings[0].fix_suggestion).toBe('');
  });

  it('still parses findings when semgrep exits with non-zero but produces output', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          // which semgrep succeeds
          callback(null, '/usr/local/bin/semgrep\n', '');
        } else {
          // semgrep scan exits non-zero but has output
          const error = new Error('exit code 1') as any;
          error.code = 1;
          error.stdout = SAMPLE_SEMGREP_OUTPUT;
          callback(error, SAMPLE_SEMGREP_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const findings = await runSemgrep('/project');

    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('javascript.express.security.audit.xss.mustache-escape');

    warnSpy.mockRestore();
  });
});
