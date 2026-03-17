import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/engines/pattern/index.js', () => ({
  runPatternEngine: vi.fn(),
}));

import { handleScan } from '../../src/mcp/tools/scan.js';
import { runPatternEngine } from '../../src/engines/pattern/index.js';

const mockedRunPatternEngine = vi.mocked(runPatternEngine);

describe('handleScan (MCP tool)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls runPatternEngine with defaults', async () => {
    mockedRunPatternEngine.mockResolvedValue({
      status: 'pass',
      score: 'A',
      findings: [],
      scan_duration_ms: 100,
    });

    const result = await handleScan({});

    expect(mockedRunPatternEngine).toHaveBeenCalledWith({
      targetPath: process.cwd(),
      scope: 'staged',
    });
    expect(result.status).toBe('pass');
  });

  it('passes scope parameter through', async () => {
    mockedRunPatternEngine.mockResolvedValue({
      status: 'fail',
      score: 'F',
      findings: [],
      scan_duration_ms: 200,
    });

    await handleScan({ scope: 'all' });

    expect(mockedRunPatternEngine).toHaveBeenCalledWith({
      targetPath: process.cwd(),
      scope: 'all',
    });
  });

  it('returns findings from engine', async () => {
    const findings = [
      {
        id: 'f1',
        engine: 'pattern' as const,
        severity: 'high' as const,
        type: 'secret',
        file: 'src/app.ts',
        line: 10,
        description: 'Hardcoded secret',
        fix_suggestion: 'Move to .env',
        auto_fixable: true,
      },
    ];
    mockedRunPatternEngine.mockResolvedValue({
      status: 'fail',
      score: 'D',
      findings,
      scan_duration_ms: 300,
    });

    const result = await handleScan({});

    expect(result.findings).toEqual(findings);
    expect(result.score).toBe('D');
  });
});
