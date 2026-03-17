import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/autofix/secret-fixer.js', () => ({
  fixHardcodedSecret: vi.fn(),
}));

vi.mock('../../src/autofix/pr-generator.js', () => ({
  generateFix: vi.fn(),
  parseStackTrace: vi.fn(),
  generateAutoFixPr: vi.fn(),
}));

vi.mock('node:fs/promises', async () => {
  const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
  return {
    ...actual,
    readFile: vi.fn(),
    writeFile: vi.fn(),
  };
});

import {
  handleFix,
  cacheFindings,
  clearFindingsCache,
  getCachedFindings,
} from '../../src/mcp/tools/fix.js';
import { fixHardcodedSecret } from '../../src/autofix/secret-fixer.js';
import { generateFix } from '../../src/autofix/pr-generator.js';
import { readFile, writeFile } from 'node:fs/promises';

const mockedFixHardcodedSecret = vi.mocked(fixHardcodedSecret);
const mockedGenerateFix = vi.mocked(generateFix);
const mockedReadFile = vi.mocked(readFile);
const mockedWriteFile = vi.mocked(writeFile);

const SAMPLE_FINDING = {
  id: 'sec_001',
  type: 'hardcoded-secret',
  file: 'src/config.ts',
  line: 5,
  description: 'Hardcoded API key',
  fix_suggestion: 'Move to .env',
  auto_fixable: true,
};

describe('cacheFindings / getCachedFindings / clearFindingsCache', () => {
  beforeEach(() => {
    clearFindingsCache();
  });

  it('caches and retrieves findings', () => {
    cacheFindings([SAMPLE_FINDING]);
    expect(getCachedFindings()).toEqual([SAMPLE_FINDING]);
  });

  it('clears cached findings', () => {
    cacheFindings([SAMPLE_FINDING]);
    clearFindingsCache();
    expect(getCachedFindings()).toEqual([]);
  });

  it('caches a copy, not a reference', () => {
    const findings = [SAMPLE_FINDING];
    cacheFindings(findings);
    findings.push({ ...SAMPLE_FINDING, id: 'sec_002' });
    expect(getCachedFindings()).toHaveLength(1);
  });
});

describe('handleFix', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearFindingsCache();
  });

  it('returns suggestion_only when finding not found', async () => {
    const result = await handleFix({ finding_id: 'nonexistent' });
    expect(result.status).toBe('suggestion_only');
    expect(result.description).toContain('not found');
  });

  it('fixes hardcoded secret with secret-fixer', async () => {
    cacheFindings([SAMPLE_FINDING]);
    mockedFixHardcodedSecret.mockResolvedValue({
      file: 'src/config.ts',
      line: 5,
      secretType: 'api_key',
      envVarName: 'API_KEY',
      filesModified: ['src/config.ts', '.env', '.gitignore'],
    });

    const result = await handleFix({ finding_id: 'sec_001' });

    expect(result.status).toBe('fixed');
    expect(result.files_modified).toEqual(['src/config.ts', '.env', '.gitignore']);
    expect(result.description).toContain('API_KEY');
  });

  it('returns suggestion_only when secret-fixer fails', async () => {
    cacheFindings([SAMPLE_FINDING]);
    mockedFixHardcodedSecret.mockRejectedValue(new Error('File not found'));

    const result = await handleFix({ finding_id: 'sec_001' });

    expect(result.status).toBe('suggestion_only');
    expect(result.description).toContain('Auto-fix failed');
  });

  it('uses generateFix for non-secret auto-fixable findings', async () => {
    const finding = { ...SAMPLE_FINDING, id: 'fix_001', type: 'missing-await' };
    cacheFindings([finding]);
    mockedReadFile.mockResolvedValue('const x = fetch()' as any);
    mockedGenerateFix.mockReturnValue({
      description: 'Added await keyword',
      fixed: 'const x = await fetch()',
    });

    const result = await handleFix({ finding_id: 'fix_001' });

    expect(result.status).toBe('fixed');
    expect(result.files_modified).toEqual(['src/config.ts']);
  });

  it('returns fix_suggestion when not auto-fixable', async () => {
    const finding = { ...SAMPLE_FINDING, id: 'info_001', type: 'info', auto_fixable: false };
    cacheFindings([finding]);

    const result = await handleFix({ finding_id: 'info_001' });

    expect(result.status).toBe('suggestion_only');
    expect(result.description).toBe('Move to .env');
  });
});
