import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanResult, Finding } from '../../src/types.js';

// Mock modules before importing the module under test
vi.mock('../../src/engines/pattern/index.js', () => ({
  runPatternEngine: vi.fn(),
  getAvailableScanners: vi.fn().mockResolvedValue({ semgrep: false, gitleaks: false, trivy: false }),
}));

vi.mock('../../src/autofix/secret-fixer.js', () => ({
  fixHardcodedSecret: vi.fn(),
}));

vi.mock('../../src/cli/license-gate.js', () => ({
  gateFeature: vi.fn().mockResolvedValue({ allowed: true, tier: 'pro' }),
}));

vi.mock('../../src/engines/graph/index.js', () => ({
  isGraphEngineAvailable: vi.fn().mockReturnValue(false),
}));

vi.mock('../../src/cli/license-check.js', () => ({
  checkLicense: vi.fn().mockResolvedValue({ valid: true, tier: 'pro' }),
}));

vi.mock('../../src/engines/builtin/secrets.js', () => ({
  getSecretPatternCount: vi.fn().mockReturnValue(174),
}));

vi.mock('../../src/engines/builtin/patterns.js', () => ({
  getPatternRuleCount: vi.fn().mockReturnValue(44),
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
import { fixHardcodedSecret } from '../../src/autofix/secret-fixer.js';

const mockedRunPatternEngine = vi.mocked(runPatternEngine);
const mockedFixHardcodedSecret = vi.mocked(fixHardcodedSecret);

function makeSecretFinding(opts?: Partial<Finding>): Finding {
  return {
    id: 'sec_001',
    engine: 'pattern',
    severity: 'critical',
    type: 'hardcoded_secret',
    file: 'src/config.ts',
    line: 5,
    description: 'Hardcoded API key detected',
    fix_suggestion: 'Move to .env',
    auto_fixable: true,
    ...opts,
  };
}

function makeResult(findings: Finding[]): ScanResult {
  return {
    status: 'fail',
    score: 'F',
    findings,
    scan_duration_ms: 300,
  };
}

describe('handleScanAction --fix flag wiring', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {}) as any);

    // Default: fixHardcodedSecret resolves successfully
    mockedFixHardcodedSecret.mockResolvedValue({
      file: 'src/config.ts',
      line: 5,
      secretType: 'api_key',
      envVarName: 'API_KEY',
      filesModified: ['src/config.ts', '.env', '.gitignore'],
    });
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it('calls fixHardcodedSecret when --fix is passed and finding is hardcoded_secret and auto_fixable', async () => {
    const finding = makeSecretFinding();
    mockedRunPatternEngine.mockResolvedValue(makeResult([finding]));

    await handleScanAction({ scope: 'staged', fix: true, json: false });

    expect(mockedFixHardcodedSecret).toHaveBeenCalledOnce();
    expect(mockedFixHardcodedSecret).toHaveBeenCalledWith(finding);
  });

  it('calls fixHardcodedSecret for each eligible finding when multiple exist', async () => {
    const finding1 = makeSecretFinding({ id: 'sec_001', file: 'src/config.ts', line: 5 });
    const finding2 = makeSecretFinding({ id: 'sec_002', file: 'src/db.ts', line: 10 });
    mockedRunPatternEngine.mockResolvedValue(makeResult([finding1, finding2]));

    await handleScanAction({ scope: 'staged', fix: true, json: false });

    expect(mockedFixHardcodedSecret).toHaveBeenCalledTimes(2);
    expect(mockedFixHardcodedSecret).toHaveBeenCalledWith(finding1);
    expect(mockedFixHardcodedSecret).toHaveBeenCalledWith(finding2);
  });

  it('does NOT call fixHardcodedSecret when --fix is NOT passed', async () => {
    const finding = makeSecretFinding();
    mockedRunPatternEngine.mockResolvedValue(makeResult([finding]));

    await handleScanAction({ scope: 'staged', fix: false, json: false });

    expect(mockedFixHardcodedSecret).not.toHaveBeenCalled();
  });

  it('does NOT call fixHardcodedSecret for findings with auto_fixable: false even when --fix is passed', async () => {
    const finding = makeSecretFinding({ auto_fixable: false });
    mockedRunPatternEngine.mockResolvedValue(makeResult([finding]));

    await handleScanAction({ scope: 'staged', fix: true, json: false });

    expect(mockedFixHardcodedSecret).not.toHaveBeenCalled();
  });

  it('does NOT call fixHardcodedSecret for non-secret finding types even when --fix is passed', async () => {
    const finding = makeSecretFinding({ type: 'sql_injection', auto_fixable: true });
    mockedRunPatternEngine.mockResolvedValue(makeResult([finding]));

    await handleScanAction({ scope: 'staged', fix: true, json: false });

    expect(mockedFixHardcodedSecret).not.toHaveBeenCalled();
  });

  it('skips non-eligible findings but still fixes eligible ones in a mixed list', async () => {
    const secretFinding = makeSecretFinding({ id: 'sec_001' });
    const nonFixable = makeSecretFinding({ id: 'sec_002', auto_fixable: false });
    const wrongType = makeSecretFinding({ id: 'sec_003', type: 'xss_vulnerability' });
    mockedRunPatternEngine.mockResolvedValue(
      makeResult([secretFinding, nonFixable, wrongType]),
    );

    await handleScanAction({ scope: 'staged', fix: true, json: false });

    expect(mockedFixHardcodedSecret).toHaveBeenCalledOnce();
    expect(mockedFixHardcodedSecret).toHaveBeenCalledWith(secretFinding);
  });

  it('logs a green confirmation message after each fix', async () => {
    const finding = makeSecretFinding();
    mockedRunPatternEngine.mockResolvedValue(makeResult([finding]));

    await handleScanAction({ scope: 'staged', fix: true, json: false });

    const output = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(output).toContain('Fixed');
  });

  it('does NOT call fixHardcodedSecret when there are no findings', async () => {
    mockedRunPatternEngine.mockResolvedValue({
      status: 'pass',
      score: 'A',
      findings: [],
      scan_duration_ms: 100,
    });

    await handleScanAction({ scope: 'staged', fix: true, json: false });

    expect(mockedFixHardcodedSecret).not.toHaveBeenCalled();
  });
});
