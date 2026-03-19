/**
 * ShipSafe Baseline Manager
 *
 * Manages a `.shipsafe-baseline.json` file in the project root.
 * When scanning staged files, findings that already exist in the baseline
 * are suppressed — only NEW findings are reported. This prevents
 * re-flagging the same known issues on every commit.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { join, relative, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import type { Finding } from '../../types.js';

// ── Types ──────────────────────────────────────────────────────────────────────

export const BASELINE_FILENAME = '.shipsafe-baseline.json';

export interface BaselineFinding {
  id: string;
  file: string;
  line: number;
  type: string;
  hash: string;
}

export interface BaselineFile {
  version: 1;
  created: string;
  findings: BaselineFinding[];
}

// ── Hash ───────────────────────────────────────────────────────────────────────

/**
 * Computes a stable fingerprint for a finding.
 * Uses id + relative file path + description (NOT line number, since lines shift).
 */
export function computeFindingHash(finding: Finding, projectDir?: string): string {
  const filePath = projectDir && isAbsolute(finding.file)
    ? relative(projectDir, finding.file)
    : finding.file;

  const input = `${finding.id}::${filePath}::${finding.description}`;
  return createHash('sha256').update(input).digest('hex').slice(0, 16);
}

// ── Load / Save ────────────────────────────────────────────────────────────────

/**
 * Reads `.shipsafe-baseline.json` from the project root.
 * Returns an empty baseline if the file doesn't exist or is malformed.
 */
export async function loadBaseline(projectDir: string): Promise<BaselineFile> {
  const filePath = join(projectDir, BASELINE_FILENAME);
  try {
    const raw = await readFile(filePath, 'utf-8');
    const parsed = JSON.parse(raw) as BaselineFile;

    // Basic shape validation
    if (
      parsed.version === 1 &&
      typeof parsed.created === 'string' &&
      Array.isArray(parsed.findings)
    ) {
      return parsed;
    }

    // Invalid shape — treat as empty
    return { version: 1, created: new Date().toISOString(), findings: [] };
  } catch {
    // File not found or JSON parse error — return empty baseline
    return { version: 1, created: new Date().toISOString(), findings: [] };
  }
}

/**
 * Writes findings to `.shipsafe-baseline.json` in the project root.
 */
export async function saveBaseline(projectDir: string, findings: Finding[]): Promise<void> {
  const filePath = join(projectDir, BASELINE_FILENAME);

  const baselineFindings: BaselineFinding[] = findings.map((f) => ({
    id: f.id,
    file: f.file,
    line: f.line,
    type: f.type,
    hash: computeFindingHash(f, projectDir),
  }));

  const baseline: BaselineFile = {
    version: 1,
    created: new Date().toISOString(),
    findings: baselineFindings,
  };

  await writeFile(filePath, JSON.stringify(baseline, null, 2) + '\n', 'utf-8');
}

// ── Filtering ──────────────────────────────────────────────────────────────────

/**
 * Returns only findings that do NOT exist in the baseline (compare by hash).
 */
export function filterNewFindings(
  findings: Finding[],
  baseline: BaselineFile,
  projectDir?: string,
): Finding[] {
  if (baseline.findings.length === 0) {
    return findings;
  }

  const baselineHashes = new Set(baseline.findings.map((bf) => bf.hash));

  return findings.filter((f) => {
    const hash = computeFindingHash(f, projectDir);
    return !baselineHashes.has(hash);
  });
}
