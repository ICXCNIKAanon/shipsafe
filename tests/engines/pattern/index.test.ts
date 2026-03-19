import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Finding, ScanScope } from '../../../src/types.js';

// Mock the scanner modules before importing the orchestrator
vi.mock('../../../src/engines/pattern/semgrep.js', () => ({
  checkSemgrepInstalled: vi.fn(),
  runSemgrep: vi.fn(),
}));

vi.mock('../../../src/engines/pattern/gitleaks.js', () => ({
  checkGitleaksInstalled: vi.fn(),
  runGitleaks: vi.fn(),
}));

vi.mock('../../../src/engines/pattern/trivy.js', () => ({
  checkTrivyInstalled: vi.fn(),
  runTrivy: vi.fn(),
}));

// Also mock child_process for getStagedFiles
vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));

// Mock built-in engines
vi.mock('../../../src/engines/builtin/secrets.js', () => ({
  scanSecrets: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/engines/builtin/patterns.js', () => ({
  scanPatterns: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/engines/builtin/dependencies.js', () => ({
  scanDependencies: vi.fn().mockResolvedValue([]),
}));

// Mock graph engine
vi.mock('../../../src/engines/graph/index.js', () => ({
  isGraphEngineAvailable: vi.fn().mockReturnValue(false),
  runGraphEngine: vi.fn(),
}));

import {
  runPatternEngine,
  computeScore,
  getAvailableScanners,
  getStagedFiles,
} from '../../../src/engines/pattern/index.js';

import { checkSemgrepInstalled, runSemgrep } from '../../../src/engines/pattern/semgrep.js';
import { checkGitleaksInstalled, runGitleaks } from '../../../src/engines/pattern/gitleaks.js';
import { checkTrivyInstalled, runTrivy } from '../../../src/engines/pattern/trivy.js';
import { execFile } from 'node:child_process';

const mockedRunSemgrep = vi.mocked(runSemgrep);
const mockedRunGitleaks = vi.mocked(runGitleaks);
const mockedRunTrivy = vi.mocked(runTrivy);
const mockedCheckSemgrep = vi.mocked(checkSemgrepInstalled);
const mockedCheckGitleaks = vi.mocked(checkGitleaksInstalled);
const mockedCheckTrivy = vi.mocked(checkTrivyInstalled);
const mockedExecFile = vi.mocked(execFile);

function makeFinding(severity: Finding['severity'], id?: string): Finding {
  return {
    id: id ?? `test_${severity}_1`,
    engine: 'pattern',
    severity,
    type: 'test_rule',
    file: 'test.ts',
    line: 1,
    description: `Test ${severity} finding`,
    fix_suggestion: 'Fix it',
    auto_fixable: false,
  };
}

describe('computeScore', () => {
  it('returns A when no findings', () => {
    expect(computeScore([])).toBe('A');
  });

  it('returns A when only info findings (info excluded from scoring)', () => {
    expect(computeScore([makeFinding('info')])).toBe('A');
  });

  it('returns A when only env-example context findings', () => {
    const envExampleFinding: Finding = {
      ...makeFinding('critical'),
      context: 'env-example',
    };
    expect(computeScore([envExampleFinding])).toBe('A');
  });

  it('returns B when only low findings', () => {
    expect(computeScore([makeFinding('low')])).toBe('B');
  });

  it('returns C when medium findings present (no high/critical)', () => {
    expect(computeScore([makeFinding('medium')])).toBe('C');
  });

  it('returns C when medium + low findings (no high/critical)', () => {
    expect(computeScore([makeFinding('medium'), makeFinding('low')])).toBe('C');
  });

  it('returns D when high findings present (no critical)', () => {
    expect(computeScore([makeFinding('high')])).toBe('D');
  });

  it('returns D when high + medium findings (no critical)', () => {
    expect(computeScore([makeFinding('high'), makeFinding('medium')])).toBe('D');
  });

  it('returns F when critical findings present', () => {
    expect(computeScore([makeFinding('critical')])).toBe('F');
  });

  it('returns F when critical + other findings present', () => {
    expect(
      computeScore([
        makeFinding('critical'),
        makeFinding('high'),
        makeFinding('medium'),
        makeFinding('low'),
        makeFinding('info'),
      ]),
    ).toBe('F');
  });
});

describe('getAvailableScanners', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns availability of each scanner', async () => {
    mockedCheckSemgrep.mockResolvedValue(true);
    mockedCheckGitleaks.mockResolvedValue(false);
    mockedCheckTrivy.mockResolvedValue(true);

    const result = await getAvailableScanners();
    expect(result).toEqual({
      semgrep: true,
      gitleaks: false,
      trivy: true,
    });
  });

  it('returns all false when no scanners installed', async () => {
    mockedCheckSemgrep.mockResolvedValue(false);
    mockedCheckGitleaks.mockResolvedValue(false);
    mockedCheckTrivy.mockResolvedValue(false);

    const result = await getAvailableScanners();
    expect(result).toEqual({
      semgrep: false,
      gitleaks: false,
      trivy: false,
    });
  });

  it('returns all true when all scanners installed', async () => {
    mockedCheckSemgrep.mockResolvedValue(true);
    mockedCheckGitleaks.mockResolvedValue(true);
    mockedCheckTrivy.mockResolvedValue(true);

    const result = await getAvailableScanners();
    expect(result).toEqual({
      semgrep: true,
      gitleaks: true,
      trivy: true,
    });
  });
});

describe('getStagedFiles', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns array of staged file paths', async () => {
    mockedExecFile.mockImplementation((_cmd, _args, _opts, callback: any) => {
      callback(null, 'src/index.ts\nsrc/utils.ts\n', '');
      return {} as any;
    });

    const result = await getStagedFiles('/project');
    expect(result).toEqual(['src/index.ts', 'src/utils.ts']);
  });

  it('returns empty array when not in a git repo', async () => {
    mockedExecFile.mockImplementation((_cmd, _args, _opts, callback: any) => {
      callback(new Error('not a git repository'), '', '');
      return {} as any;
    });

    const result = await getStagedFiles('/not-a-repo');
    expect(result).toEqual([]);
  });

  it('returns empty array when no files are staged', async () => {
    mockedExecFile.mockImplementation((_cmd, _args, _opts, callback: any) => {
      callback(null, '', '');
      return {} as any;
    });

    const result = await getStagedFiles('/project');
    expect(result).toEqual([]);
  });
});

describe('runPatternEngine', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: all scanners installed, no findings
    mockedCheckSemgrep.mockResolvedValue(true);
    mockedCheckGitleaks.mockResolvedValue(true);
    mockedCheckTrivy.mockResolvedValue(true);
    mockedRunSemgrep.mockResolvedValue([]);
    mockedRunGitleaks.mockResolvedValue([]);
    mockedRunTrivy.mockResolvedValue([]);
  });

  it('runs available scanners in parallel', async () => {
    await runPatternEngine({ targetPath: '/project', scope: 'all' });

    expect(mockedRunSemgrep).toHaveBeenCalledOnce();
    expect(mockedRunGitleaks).toHaveBeenCalledOnce();
    expect(mockedRunTrivy).toHaveBeenCalledOnce();
  });

  it('aggregates findings from all scanners', async () => {
    const semgrepFinding = makeFinding('medium', 'semgrep_1');
    const gitleaksFinding = makeFinding('critical', 'gitleaks_1');
    const trivyFinding = makeFinding('high', 'trivy_1');

    mockedRunSemgrep.mockResolvedValue([semgrepFinding]);
    mockedRunGitleaks.mockResolvedValue([gitleaksFinding]);
    mockedRunTrivy.mockResolvedValue([trivyFinding]);

    const result = await runPatternEngine({ targetPath: '/project', scope: 'all' });

    expect(result.findings).toHaveLength(3);
    expect(result.findings).toEqual(
      expect.arrayContaining([semgrepFinding, gitleaksFinding, trivyFinding]),
    );
  });

  it('returns pass when no critical/high findings', async () => {
    mockedRunSemgrep.mockResolvedValue([makeFinding('low')]);
    mockedRunGitleaks.mockResolvedValue([]);
    mockedRunTrivy.mockResolvedValue([makeFinding('medium')]);

    const result = await runPatternEngine({ targetPath: '/project', scope: 'all' });

    expect(result.status).toBe('pass');
  });

  it('returns fail when critical findings exist', async () => {
    mockedRunSemgrep.mockResolvedValue([makeFinding('critical')]);

    const result = await runPatternEngine({ targetPath: '/project', scope: 'all' });

    expect(result.status).toBe('fail');
  });

  it('returns fail when high findings exist', async () => {
    mockedRunGitleaks.mockResolvedValue([makeFinding('high')]);

    const result = await runPatternEngine({ targetPath: '/project', scope: 'all' });

    expect(result.status).toBe('fail');
  });

  it('handles some scanners not being installed (skips gracefully)', async () => {
    mockedCheckSemgrep.mockResolvedValue(false);
    mockedCheckGitleaks.mockResolvedValue(true);
    mockedCheckTrivy.mockResolvedValue(false);

    mockedRunGitleaks.mockResolvedValue([makeFinding('low')]);

    const result = await runPatternEngine({ targetPath: '/project', scope: 'all' });

    expect(mockedRunSemgrep).not.toHaveBeenCalled();
    expect(mockedRunGitleaks).toHaveBeenCalledOnce();
    expect(mockedRunTrivy).not.toHaveBeenCalled();
    expect(result.findings).toHaveLength(1);
  });

  it('with scope staged gets staged files first', async () => {
    mockedExecFile.mockImplementation((_cmd, _args, _opts, callback: any) => {
      callback(null, 'src/app.ts\n', '');
      return {} as any;
    });

    await runPatternEngine({ targetPath: '/project', scope: 'staged' });

    expect(mockedRunSemgrep).toHaveBeenCalledWith('/project', ['src/app.ts']);
    expect(mockedRunGitleaks).toHaveBeenCalledWith('/project', ['src/app.ts']);
    expect(mockedRunTrivy).toHaveBeenCalledWith('/project');
  });

  it('returns clean result when no staged files and scope is staged', async () => {
    mockedExecFile.mockImplementation((_cmd, _args, _opts, callback: any) => {
      callback(null, '', '');
      return {} as any;
    });

    const result = await runPatternEngine({ targetPath: '/project', scope: 'staged' });

    expect(result.status).toBe('pass');
    expect(result.score).toBe('A');
    expect(result.findings).toEqual([]);
    // Scanners should not have been called
    expect(mockedRunSemgrep).not.toHaveBeenCalled();
    expect(mockedRunGitleaks).not.toHaveBeenCalled();
    expect(mockedRunTrivy).not.toHaveBeenCalled();
  });

  it('sorts findings by severity (critical first)', async () => {
    mockedRunSemgrep.mockResolvedValue([makeFinding('low', 'low_1')]);
    mockedRunGitleaks.mockResolvedValue([makeFinding('critical', 'crit_1')]);
    mockedRunTrivy.mockResolvedValue([
      makeFinding('medium', 'med_1'),
      makeFinding('high', 'high_1'),
      makeFinding('info', 'info_1'),
    ]);

    const result = await runPatternEngine({ targetPath: '/project', scope: 'all' });

    const severities = result.findings.map((f) => f.severity);
    expect(severities).toEqual(['critical', 'high', 'medium', 'low', 'info']);
  });

  it('populates scan_duration_ms with actual elapsed time', async () => {
    const result = await runPatternEngine({ targetPath: '/project', scope: 'all' });

    expect(result.scan_duration_ms).toBeTypeOf('number');
    expect(result.scan_duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('handles scanner promise rejection gracefully', async () => {
    mockedRunSemgrep.mockRejectedValue(new Error('semgrep crashed'));
    mockedRunGitleaks.mockResolvedValue([makeFinding('low')]);
    mockedRunTrivy.mockResolvedValue([]);

    const result = await runPatternEngine({ targetPath: '/project', scope: 'all' });

    // Should still return results from the scanners that succeeded
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe('test_low_1');
  });

  it('passes stagedFiles option through when provided', async () => {
    const stagedFiles = ['file1.ts', 'file2.ts'];

    await runPatternEngine({
      targetPath: '/project',
      scope: 'staged',
      stagedFiles,
    });

    expect(mockedRunSemgrep).toHaveBeenCalledWith('/project', stagedFiles);
    expect(mockedRunGitleaks).toHaveBeenCalledWith('/project', stagedFiles);
  });
});
