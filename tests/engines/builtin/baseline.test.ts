import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import type { Finding } from '../../../src/types.js';
import {
  computeFindingHash,
  loadBaseline,
  saveBaseline,
  filterNewFindings,
  BASELINE_FILENAME,
  type BaselineFile,
} from '../../../src/engines/builtin/baseline.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'hardcoded_secret',
    engine: 'pattern',
    severity: 'high',
    type: 'secret',
    file: 'src/config.ts',
    line: 42,
    description: 'Hardcoded API key detected',
    fix_suggestion: 'Move to environment variable',
    auto_fixable: true,
    ...overrides,
  };
}

describe('computeFindingHash', () => {
  it('returns a 16-char hex string', () => {
    const hash = computeFindingHash(makeFinding());
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });

  it('produces stable hashes for identical findings', () => {
    const f = makeFinding();
    expect(computeFindingHash(f)).toBe(computeFindingHash(f));
  });

  it('produces different hashes for different descriptions', () => {
    const f1 = makeFinding({ description: 'Hardcoded API key detected' });
    const f2 = makeFinding({ description: 'Hardcoded password detected' });
    expect(computeFindingHash(f1)).not.toBe(computeFindingHash(f2));
  });

  it('produces different hashes for different file paths', () => {
    const f1 = makeFinding({ file: 'src/config.ts' });
    const f2 = makeFinding({ file: 'src/utils.ts' });
    expect(computeFindingHash(f1)).not.toBe(computeFindingHash(f2));
  });

  it('produces different hashes for different IDs', () => {
    const f1 = makeFinding({ id: 'hardcoded_secret' });
    const f2 = makeFinding({ id: 'weak_crypto' });
    expect(computeFindingHash(f1)).not.toBe(computeFindingHash(f2));
  });

  it('produces the SAME hash regardless of line number changes', () => {
    const f1 = makeFinding({ line: 42 });
    const f2 = makeFinding({ line: 100 });
    expect(computeFindingHash(f1)).toBe(computeFindingHash(f2));
  });

  it('normalizes absolute paths relative to projectDir', () => {
    const f1 = makeFinding({ file: '/project/src/config.ts' });
    const f2 = makeFinding({ file: 'src/config.ts' });
    expect(computeFindingHash(f1, '/project')).toBe(computeFindingHash(f2));
  });
});

describe('loadBaseline', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-baseline-test-'));
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('returns empty baseline when file does not exist', async () => {
    const baseline = await loadBaseline(tmpDir);
    expect(baseline.version).toBe(1);
    expect(baseline.findings).toEqual([]);
  });

  it('returns empty baseline when file contains invalid JSON', async () => {
    await writeFile(join(tmpDir, BASELINE_FILENAME), 'not json', 'utf-8');
    const baseline = await loadBaseline(tmpDir);
    expect(baseline.version).toBe(1);
    expect(baseline.findings).toEqual([]);
  });

  it('returns empty baseline when JSON has wrong shape', async () => {
    await writeFile(join(tmpDir, BASELINE_FILENAME), JSON.stringify({ foo: 'bar' }), 'utf-8');
    const baseline = await loadBaseline(tmpDir);
    expect(baseline.version).toBe(1);
    expect(baseline.findings).toEqual([]);
  });

  it('loads a valid baseline file', async () => {
    const data: BaselineFile = {
      version: 1,
      created: '2026-01-01T00:00:00.000Z',
      findings: [
        { id: 'hardcoded_secret', file: 'src/config.ts', line: 42, type: 'secret', hash: 'abc123def456abcd' },
      ],
    };
    await writeFile(join(tmpDir, BASELINE_FILENAME), JSON.stringify(data), 'utf-8');

    const baseline = await loadBaseline(tmpDir);
    expect(baseline.version).toBe(1);
    expect(baseline.created).toBe('2026-01-01T00:00:00.000Z');
    expect(baseline.findings).toHaveLength(1);
    expect(baseline.findings[0].hash).toBe('abc123def456abcd');
  });
});

describe('saveBaseline', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-baseline-test-'));
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('writes a valid baseline file', async () => {
    const findings: Finding[] = [
      makeFinding({ id: 'secret_1', file: 'src/a.ts', line: 10, description: 'Secret A' }),
      makeFinding({ id: 'vuln_1', file: 'src/b.ts', line: 20, description: 'Vuln B' }),
    ];

    await saveBaseline(tmpDir, findings);

    const raw = await readFile(join(tmpDir, BASELINE_FILENAME), 'utf-8');
    const parsed: BaselineFile = JSON.parse(raw);

    expect(parsed.version).toBe(1);
    expect(parsed.created).toBeTruthy();
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings[0].id).toBe('secret_1');
    expect(parsed.findings[0].hash).toMatch(/^[0-9a-f]{16}$/);
    expect(parsed.findings[1].id).toBe('vuln_1');
  });

  it('overwrites existing baseline file', async () => {
    await saveBaseline(tmpDir, [makeFinding()]);
    await saveBaseline(tmpDir, []);

    const raw = await readFile(join(tmpDir, BASELINE_FILENAME), 'utf-8');
    const parsed: BaselineFile = JSON.parse(raw);
    expect(parsed.findings).toHaveLength(0);
  });
});

describe('filterNewFindings', () => {
  it('returns all findings when baseline is empty', () => {
    const findings = [makeFinding(), makeFinding({ id: 'other', description: 'Other finding' })];
    const baseline: BaselineFile = { version: 1, created: '', findings: [] };

    const result = filterNewFindings(findings, baseline);
    expect(result).toHaveLength(2);
  });

  it('filters out findings that match the baseline by hash', () => {
    const existingFinding = makeFinding();
    const existingHash = computeFindingHash(existingFinding);
    const newFinding = makeFinding({ id: 'new_issue', description: 'Brand new issue' });

    const baseline: BaselineFile = {
      version: 1,
      created: '',
      findings: [
        { id: existingFinding.id, file: existingFinding.file, line: existingFinding.line, type: existingFinding.type, hash: existingHash },
      ],
    };

    const result = filterNewFindings([existingFinding, newFinding], baseline);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('new_issue');
  });

  it('keeps findings even if line number changed (hash ignores line)', () => {
    const original = makeFinding({ line: 42 });
    const shifted = makeFinding({ line: 99 }); // same id/file/description, different line

    const baseline: BaselineFile = {
      version: 1,
      created: '',
      findings: [
        { id: original.id, file: original.file, line: original.line, type: original.type, hash: computeFindingHash(original) },
      ],
    };

    // The shifted finding should be filtered because its hash matches (line is excluded)
    const result = filterNewFindings([shifted], baseline);
    expect(result).toHaveLength(0);
  });

  it('returns empty array when all findings are baselined', () => {
    const f1 = makeFinding({ id: 'a', description: 'Desc A' });
    const f2 = makeFinding({ id: 'b', description: 'Desc B' });

    const baseline: BaselineFile = {
      version: 1,
      created: '',
      findings: [
        { id: f1.id, file: f1.file, line: f1.line, type: f1.type, hash: computeFindingHash(f1) },
        { id: f2.id, file: f2.file, line: f2.line, type: f2.type, hash: computeFindingHash(f2) },
      ],
    };

    const result = filterNewFindings([f1, f2], baseline);
    expect(result).toHaveLength(0);
  });

  it('handles projectDir normalization for absolute paths', () => {
    const finding = makeFinding({ file: '/project/src/config.ts' });
    const hash = computeFindingHash(finding, '/project');

    const baseline: BaselineFile = {
      version: 1,
      created: '',
      findings: [
        { id: finding.id, file: finding.file, line: finding.line, type: finding.type, hash },
      ],
    };

    const result = filterNewFindings([finding], baseline, '/project');
    expect(result).toHaveLength(0);
  });
});
