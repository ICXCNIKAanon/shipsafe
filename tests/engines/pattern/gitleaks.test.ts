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
import { checkGitleaksInstalled, runGitleaks } from '../../../src/engines/pattern/gitleaks.js';

// Cast to a mock so we can control behavior
const mockExecFile = vi.mocked(execFile);

// Helper: make execFile callback-based mock resolve with given stdout
function mockExecFileSuccess(stdout: string): void {
  mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
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

const SAMPLE_GITLEAKS_OUTPUT = JSON.stringify([
  {
    Description: 'AWS Access Key',
    File: 'src/config.ts',
    StartLine: 12,
    EndLine: 12,
    StartColumn: 1,
    EndColumn: 45,
    Match: 'AKIAIOSFODNN7EXAMPLE',
    Secret: 'AKIAIOSFODNN7EXAMPLE',
    RuleID: 'aws-access-key-id',
    Entropy: 3.5,
    Fingerprint: 'src/config.ts:aws-access-key-id:12',
  },
]);

const MULTI_RESULT_OUTPUT = JSON.stringify([
  {
    Description: 'AWS Access Key',
    File: 'src/config.ts',
    StartLine: 12,
    EndLine: 12,
    StartColumn: 1,
    EndColumn: 45,
    Match: 'AKIAIOSFODNN7EXAMPLE',
    Secret: 'AKIAIOSFODNN7EXAMPLE',
    RuleID: 'aws-access-key-id',
    Entropy: 3.5,
    Fingerprint: 'src/config.ts:aws-access-key-id:12',
  },
  {
    Description: 'Generic API Key',
    File: 'src/api.ts',
    StartLine: 5,
    EndLine: 5,
    StartColumn: 10,
    EndColumn: 60,
    Match: 'api_key = "sk-1234567890abcdef"',
    Secret: 'sk-1234567890abcdef',
    RuleID: 'generic-api-key',
    Entropy: 4.2,
    Fingerprint: 'src/api.ts:generic-api-key:5',
  },
]);

const CLEAN_OUTPUT = JSON.stringify([]);

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkGitleaksInstalled', () => {
  it('returns true when which gitleaks succeeds', async () => {
    mockExecFileSuccess('/usr/local/bin/gitleaks\n');

    const result = await checkGitleaksInstalled();

    expect(result).toBe(true);
    expect(mockExecFile).toHaveBeenCalledWith(
      'which',
      ['gitleaks'],
      expect.any(Function),
    );
  });

  it('returns false when which gitleaks fails', async () => {
    const error = new Error('not found') as Error & { code?: number };
    error.code = 1;
    mockExecFileFailure(error);

    const result = await checkGitleaksInstalled();

    expect(result).toBe(false);
  });
});

describe('runGitleaks', () => {
  it('parses gitleaks JSON array into Finding[]', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          // which gitleaks
          callback(null, '/usr/local/bin/gitleaks\n', '');
        } else {
          // gitleaks detect
          callback(null, SAMPLE_GITLEAKS_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runGitleaks('/project');

    expect(findings).toHaveLength(1);
    expect(findings[0]).toEqual({
      id: 'gitleaks_aws-access-key-id_12',
      engine: 'pattern',
      severity: 'critical',
      type: 'hardcoded_secret',
      file: 'src/config.ts',
      line: 12,
      description: 'AWS Access Key',
      fix_suggestion: 'Move this secret to a .env file or environment variable',
      auto_fixable: true,
    } satisfies Finding);
  });

  it('sets all findings to severity critical', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/gitleaks\n', '');
        } else {
          callback(null, MULTI_RESULT_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runGitleaks('/project');

    expect(findings).toHaveLength(2);
    expect(findings[0].severity).toBe('critical');
    expect(findings[1].severity).toBe('critical');
  });

  it('returns empty findings when no secrets found (empty array)', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/gitleaks\n', '');
        } else {
          callback(null, CLEAN_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runGitleaks('/project');

    expect(findings).toEqual([]);
  });

  it('handles tool not installed gracefully', async () => {
    const error = new Error('not found') as Error & { code?: number };
    error.code = 1;
    mockExecFileFailure(error);

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const findings = await runGitleaks('/project');

    expect(findings).toEqual([]);
    warnSpy.mockRestore();
  });

  it('maps Description to description, File to file, StartLine to line', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/gitleaks\n', '');
        } else {
          callback(null, MULTI_RESULT_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runGitleaks('/project');

    expect(findings[0].description).toBe('AWS Access Key');
    expect(findings[0].file).toBe('src/config.ts');
    expect(findings[0].line).toBe(12);

    expect(findings[1].description).toBe('Generic API Key');
    expect(findings[1].file).toBe('src/api.ts');
    expect(findings[1].line).toBe(5);
  });

  it('passes correct arguments for full scan', async () => {
    let callCount = 0;
    let capturedCmd = '';
    let capturedArgs: string[] = [];
    mockExecFile.mockImplementation((cmd: any, args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/gitleaks\n', '');
        } else {
          capturedCmd = cmd as string;
          capturedArgs = args as string[];
          callback(null, CLEAN_OUTPUT, '');
        }
      }
      return {} as any;
    });

    await runGitleaks('/project');

    expect(capturedCmd).toBe('gitleaks');
    expect(capturedArgs).toContain('detect');
    expect(capturedArgs).toContain('--source');
    expect(capturedArgs).toContain('/project');
    expect(capturedArgs).toContain('--report-format');
    expect(capturedArgs).toContain('json');
    expect(capturedArgs).toContain('--report-path');
    expect(capturedArgs).toContain('/dev/stdout');
    expect(capturedArgs).toContain('--no-git');
  });

  it('still parses findings when gitleaks exits with non-zero but produces output', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          // which gitleaks succeeds
          callback(null, '/usr/local/bin/gitleaks\n', '');
        } else {
          // gitleaks exits non-zero when it finds secrets
          const error = new Error('exit code 1') as any;
          error.code = 1;
          error.stdout = SAMPLE_GITLEAKS_OUTPUT;
          callback(error, SAMPLE_GITLEAKS_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const findings = await runGitleaks('/project');

    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe('hardcoded_secret');
    expect(findings[0].severity).toBe('critical');

    warnSpy.mockRestore();
  });

  it('generates correct finding IDs from ruleID and line', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/gitleaks\n', '');
        } else {
          callback(null, MULTI_RESULT_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runGitleaks('/project');

    expect(findings[0].id).toBe('gitleaks_aws-access-key-id_12');
    expect(findings[1].id).toBe('gitleaks_generic-api-key_5');
  });
});
