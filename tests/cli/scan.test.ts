import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanResult, Finding } from '../../src/types.js';

// Mock the pattern engine before importing
vi.mock('../../src/engines/pattern/index.js', () => ({
  runPatternEngine: vi.fn(),
}));

// Mock chalk to return plain strings for testability
vi.mock('chalk', () => {
  const passthrough = (str: string) => str;
  const chainable: any = new Proxy(passthrough, {
    get: () => chainable,
    apply: (_target: any, _thisArg: any, args: any[]) => args[0],
  });
  return { default: chainable };
});

import { handleScanAction } from '../../src/cli/scan.js';
import { runPatternEngine } from '../../src/engines/pattern/index.js';

const mockedRunPatternEngine = vi.mocked(runPatternEngine);

function makeFinding(
  severity: Finding['severity'],
  opts?: Partial<Finding>,
): Finding {
  return {
    id: opts?.id ?? `test_${severity}_1`,
    engine: 'pattern',
    severity,
    type: opts?.type ?? 'test_rule',
    file: opts?.file ?? 'src/config.ts',
    line: opts?.line ?? 12,
    description: opts?.description ?? `Test ${severity} finding`,
    fix_suggestion: opts?.fix_suggestion ?? 'Fix it',
    auto_fixable: opts?.auto_fixable ?? false,
  };
}

function makeCleanResult(): ScanResult {
  return {
    status: 'pass',
    score: 'A',
    findings: [],
    scan_duration_ms: 200,
  };
}

function makeResultWithFindings(findings: Finding[]): ScanResult {
  const hasCriticalOrHigh = findings.some(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );
  return {
    status: hasCriticalOrHigh ? 'fail' : 'pass',
    score: 'C',
    findings,
    scan_duration_ms: 8500,
  };
}

describe('handleScanAction', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {}) as any);
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it('prints "Score: A | 0 findings" for clean results', async () => {
    mockedRunPatternEngine.mockResolvedValue(makeCleanResult());

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Score: A');
    expect(output).toContain('0 findings');
  });

  it('formats findings with severity, file, and line', async () => {
    const finding = makeFinding('critical', {
      file: 'src/config.ts',
      line: 12,
      description: 'Hardcoded Supabase service role key detected',
      fix_suggestion: 'Move to .env and reference via process.env.SUPABASE_SERVICE_KEY',
    });
    mockedRunPatternEngine.mockResolvedValue(makeResultWithFindings([finding]));

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('CRITICAL');
    expect(output).toContain('src/config.ts:12');
    expect(output).toContain('Hardcoded Supabase service role key detected');
    expect(output).toContain('Move to .env and reference via process.env.SUPABASE_SERVICE_KEY');
  });

  it('outputs JSON to stdout when --json flag is set', async () => {
    const result = makeCleanResult();
    mockedRunPatternEngine.mockResolvedValue(result);

    await handleScanAction({ scope: 'staged', fix: false, json: true });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    const parsed = JSON.parse(output);
    expect(parsed.status).toBe('pass');
    expect(parsed.score).toBe('A');
    expect(parsed.findings).toEqual([]);
  });

  it('exits with code 1 when critical findings exist', async () => {
    const finding = makeFinding('critical');
    mockedRunPatternEngine.mockResolvedValue(makeResultWithFindings([finding]));

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it('exits with code 1 when high findings exist', async () => {
    const finding = makeFinding('high');
    mockedRunPatternEngine.mockResolvedValue(makeResultWithFindings([finding]));

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it('exits with code 0 when clean', async () => {
    mockedRunPatternEngine.mockResolvedValue(makeCleanResult());

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    expect(exitSpy).not.toHaveBeenCalled();
  });

  it('exits with code 0 when only medium/low findings', async () => {
    const findings = [makeFinding('medium'), makeFinding('low')];
    mockedRunPatternEngine.mockResolvedValue(makeResultWithFindings(findings));

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    expect(exitSpy).not.toHaveBeenCalled();
  });

  it('uses default scope of staged', async () => {
    mockedRunPatternEngine.mockResolvedValue(makeCleanResult());

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    expect(mockedRunPatternEngine).toHaveBeenCalledWith(
      expect.objectContaining({ scope: 'staged' }),
    );
  });

  it('passes scope "all" through to pattern engine', async () => {
    mockedRunPatternEngine.mockResolvedValue(makeCleanResult());

    await handleScanAction({ scope: 'all', fix: false, json: false });

    expect(mockedRunPatternEngine).toHaveBeenCalledWith(
      expect.objectContaining({ scope: 'all' }),
    );
  });

  it('passes file scope through to pattern engine', async () => {
    mockedRunPatternEngine.mockResolvedValue(makeCleanResult());

    await handleScanAction({ scope: 'file:src/main.ts', fix: false, json: false });

    expect(mockedRunPatternEngine).toHaveBeenCalledWith(
      expect.objectContaining({ scope: 'file:src/main.ts' }),
    );
  });

  it('includes scan duration in output', async () => {
    mockedRunPatternEngine.mockResolvedValue(makeCleanResult());

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('0.2s');
  });

  it('shows header in formatted output', async () => {
    mockedRunPatternEngine.mockResolvedValue(makeCleanResult());

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('ShipSafe Scan Results');
  });
});
