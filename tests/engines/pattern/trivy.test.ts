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
import { checkTrivyInstalled, runTrivy } from '../../../src/engines/pattern/trivy.js';

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

const SAMPLE_TRIVY_OUTPUT = JSON.stringify({
  SchemaVersion: 2,
  Results: [
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Type: 'npm',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2024-12345',
          PkgName: 'lodash',
          InstalledVersion: '4.17.20',
          FixedVersion: '4.17.21',
          Severity: 'HIGH',
          Title: 'Prototype Pollution in lodash',
          Description: 'lodash before 4.17.21 is vulnerable to prototype pollution',
        },
        {
          VulnerabilityID: 'CVE-2024-99999',
          PkgName: 'express',
          InstalledVersion: '4.18.0',
          FixedVersion: '',
          Severity: 'MEDIUM',
          Title: 'Open Redirect in Express',
          Description: 'Express before 4.19.0 allows open redirect',
        },
      ],
    },
  ],
});

const MULTI_SEVERITY_OUTPUT = JSON.stringify({
  SchemaVersion: 2,
  Results: [
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Type: 'npm',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2024-00001',
          PkgName: 'critical-pkg',
          InstalledVersion: '1.0.0',
          FixedVersion: '2.0.0',
          Severity: 'CRITICAL',
          Title: 'Critical vuln',
          Description: 'A critical vulnerability',
        },
        {
          VulnerabilityID: 'CVE-2024-00002',
          PkgName: 'high-pkg',
          InstalledVersion: '1.0.0',
          FixedVersion: '2.0.0',
          Severity: 'HIGH',
          Title: 'High vuln',
          Description: 'A high vulnerability',
        },
        {
          VulnerabilityID: 'CVE-2024-00003',
          PkgName: 'medium-pkg',
          InstalledVersion: '1.0.0',
          FixedVersion: '2.0.0',
          Severity: 'MEDIUM',
          Title: 'Medium vuln',
          Description: 'A medium vulnerability',
        },
        {
          VulnerabilityID: 'CVE-2024-00004',
          PkgName: 'low-pkg',
          InstalledVersion: '1.0.0',
          FixedVersion: '2.0.0',
          Severity: 'LOW',
          Title: 'Low vuln',
          Description: 'A low vulnerability',
        },
        {
          VulnerabilityID: 'CVE-2024-00005',
          PkgName: 'unknown-pkg',
          InstalledVersion: '1.0.0',
          FixedVersion: '',
          Severity: 'UNKNOWN',
          Title: 'Unknown vuln',
          Description: 'An unknown severity vulnerability',
        },
      ],
    },
  ],
});

const CLEAN_OUTPUT = JSON.stringify({
  SchemaVersion: 2,
  Results: [
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Type: 'npm',
      Vulnerabilities: null,
    },
  ],
});

const EMPTY_RESULTS_OUTPUT = JSON.stringify({
  SchemaVersion: 2,
  Results: [],
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkTrivyInstalled', () => {
  it('returns true when which trivy succeeds', async () => {
    mockExecFileSuccess('/usr/local/bin/trivy\n');

    const result = await checkTrivyInstalled();

    expect(result).toBe(true);
    expect(mockExecFile).toHaveBeenCalledWith(
      'which',
      ['trivy'],
      expect.any(Function),
    );
  });

  it('returns false when which trivy fails', async () => {
    const error = new Error('not found') as Error & { code?: number };
    error.code = 1;
    mockExecFileFailure(error);

    const result = await checkTrivyInstalled();

    expect(result).toBe(false);
  });
});

describe('runTrivy', () => {
  it('parses Trivy JSON output into Finding[]', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          // which trivy
          callback(null, '/usr/local/bin/trivy\n', '');
        } else {
          // trivy fs scan
          callback(null, SAMPLE_TRIVY_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runTrivy('/project');

    expect(findings).toHaveLength(2);
    expect(findings[0]).toEqual({
      id: 'trivy_CVE-2024-12345_lodash',
      engine: 'pattern',
      severity: 'high',
      type: 'dependency_vulnerability',
      file: 'package-lock.json',
      line: 0,
      description: 'CVE-2024-12345: Prototype Pollution in lodash (lodash@4.17.20)',
      fix_suggestion: 'Upgrade lodash to 4.17.21',
      auto_fixable: true,
    } satisfies Finding);

    expect(findings[1]).toEqual({
      id: 'trivy_CVE-2024-99999_express',
      engine: 'pattern',
      severity: 'medium',
      type: 'dependency_vulnerability',
      file: 'package-lock.json',
      line: 0,
      description: 'CVE-2024-99999: Open Redirect in Express (express@4.18.0)',
      fix_suggestion: 'No fix available yet',
      auto_fixable: false,
    } satisfies Finding);
  });

  it('maps CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN severity correctly', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/trivy\n', '');
        } else {
          callback(null, MULTI_SEVERITY_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runTrivy('/project');

    expect(findings).toHaveLength(5);
    expect(findings[0].severity).toBe('critical');
    expect(findings[1].severity).toBe('high');
    expect(findings[2].severity).toBe('medium');
    expect(findings[3].severity).toBe('low');
    expect(findings[4].severity).toBe('low');
  });

  it('sets auto_fixable based on FixedVersion presence', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/trivy\n', '');
        } else {
          callback(null, SAMPLE_TRIVY_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runTrivy('/project');

    // lodash has FixedVersion '4.17.21' -> auto_fixable true
    expect(findings[0].auto_fixable).toBe(true);
    expect(findings[0].fix_suggestion).toBe('Upgrade lodash to 4.17.21');

    // express has FixedVersion '' -> auto_fixable false
    expect(findings[1].auto_fixable).toBe(false);
    expect(findings[1].fix_suggestion).toBe('No fix available yet');
  });

  it('returns empty findings when no vulnerabilities found (null Vulnerabilities)', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/trivy\n', '');
        } else {
          callback(null, CLEAN_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runTrivy('/project');

    expect(findings).toEqual([]);
  });

  it('handles Results being empty array', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/trivy\n', '');
        } else {
          callback(null, EMPTY_RESULTS_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runTrivy('/project');

    expect(findings).toEqual([]);
  });

  it('handles tool not installed gracefully', async () => {
    const error = new Error('not found') as Error & { code?: number };
    error.code = 1;
    mockExecFileFailure(error);

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const findings = await runTrivy('/project');

    expect(findings).toEqual([]);
    warnSpy.mockRestore();
  });

  it('passes correct arguments for fs scan', async () => {
    let callCount = 0;
    let capturedCmd = '';
    let capturedArgs: string[] = [];
    mockExecFile.mockImplementation((cmd: any, args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/trivy\n', '');
        } else {
          capturedCmd = cmd as string;
          capturedArgs = args as string[];
          callback(null, CLEAN_OUTPUT, '');
        }
      }
      return {} as any;
    });

    await runTrivy('/project');

    expect(capturedCmd).toBe('trivy');
    expect(capturedArgs).toContain('fs');
    expect(capturedArgs).toContain('--format');
    expect(capturedArgs).toContain('json');
    expect(capturedArgs).toContain('--quiet');
    expect(capturedArgs).toContain('/project');
  });

  it('still parses findings when trivy exits with non-zero but produces output', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          // which trivy succeeds
          callback(null, '/usr/local/bin/trivy\n', '');
        } else {
          // trivy exits non-zero but has output
          const error = new Error('exit code 1') as any;
          error.code = 1;
          error.stdout = SAMPLE_TRIVY_OUTPUT;
          callback(error, SAMPLE_TRIVY_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const findings = await runTrivy('/project');

    expect(findings).toHaveLength(2);
    expect(findings[0].type).toBe('dependency_vulnerability');
    expect(findings[0].id).toBe('trivy_CVE-2024-12345_lodash');

    warnSpy.mockRestore();
  });

  it('generates correct finding IDs from VulnerabilityID and PkgName', async () => {
    let callCount = 0;
    mockExecFile.mockImplementation((_cmd: any, _args: any, _opts: any, cb?: any) => {
      const callback = cb ?? _opts;
      callCount++;
      if (typeof callback === 'function') {
        if (callCount === 1) {
          callback(null, '/usr/local/bin/trivy\n', '');
        } else {
          callback(null, SAMPLE_TRIVY_OUTPUT, '');
        }
      }
      return {} as any;
    });

    const findings = await runTrivy('/project');

    expect(findings[0].id).toBe('trivy_CVE-2024-12345_lodash');
    expect(findings[1].id).toBe('trivy_CVE-2024-99999_express');
  });
});
