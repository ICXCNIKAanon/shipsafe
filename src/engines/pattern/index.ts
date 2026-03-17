import { execFile } from 'node:child_process';
import type { Finding, ScanResult, ScanScope, SecurityScore, ScannerAvailability } from '../../types.js';
import { SEVERITY_ORDER } from '../../constants.js';
import { checkSemgrepInstalled, runSemgrep } from './semgrep.js';
import { checkGitleaksInstalled, runGitleaks } from './gitleaks.js';
import { checkTrivyInstalled, runTrivy } from './trivy.js';

export interface PatternEngineOptions {
  targetPath: string;
  scope: ScanScope;
  stagedFiles?: string[];
}

export function computeScore(findings: Finding[]): SecurityScore {
  if (findings.length === 0) return 'A';

  const severities = new Set(findings.map((f) => f.severity));

  if (severities.has('critical')) return 'F';
  if (severities.has('high')) return 'D';
  if (severities.has('medium')) return 'C';

  // Only info and/or low remain
  return 'B';
}

export async function getAvailableScanners(): Promise<ScannerAvailability> {
  const [semgrep, gitleaks, trivy] = await Promise.all([
    checkSemgrepInstalled(),
    checkGitleaksInstalled(),
    checkTrivyInstalled(),
  ]);

  return { semgrep, gitleaks, trivy };
}

export async function getStagedFiles(projectDir: string): Promise<string[]> {
  return new Promise((resolve) => {
    execFile('git', ['diff', '--cached', '--name-only'], { cwd: projectDir }, (error, stdout) => {
      if (error) {
        resolve([]);
        return;
      }

      const files = (typeof stdout === 'string' ? stdout : '')
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0);

      resolve(files);
    });
  });
}

export async function runPatternEngine(options: PatternEngineOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const { targetPath, scope, stagedFiles: providedStagedFiles } = options;

  // 1. Check which scanners are installed
  const availability = await getAvailableScanners();

  // 2. If scope is 'staged', get staged files
  let stagedFiles: string[] | undefined = providedStagedFiles;
  if (scope === 'staged' && !stagedFiles) {
    stagedFiles = await getStagedFiles(targetPath);
  }

  // 3. If scope is 'staged' and no staged files, return clean result immediately
  if (scope === 'staged' && (!stagedFiles || stagedFiles.length === 0)) {
    return {
      status: 'pass',
      score: 'A',
      findings: [],
      scan_duration_ms: Date.now() - startTime,
    };
  }

  // 4. Run all available scanners in parallel with Promise.allSettled()
  const scannerPromises: Promise<Finding[]>[] = [];

  if (availability.semgrep) {
    scannerPromises.push(runSemgrep(targetPath, stagedFiles));
  }
  if (availability.gitleaks) {
    scannerPromises.push(runGitleaks(targetPath, stagedFiles));
  }
  if (availability.trivy) {
    scannerPromises.push(runTrivy(targetPath));
  }

  const results = await Promise.allSettled(scannerPromises);

  // 5. Merge all findings into single array
  const findings: Finding[] = [];
  for (const result of results) {
    if (result.status === 'fulfilled') {
      findings.push(...result.value);
    }
    // Rejected promises are silently skipped (scanner failure is non-fatal)
  }

  // 6. Sort findings by severity (critical first)
  findings.sort((a, b) => {
    const orderA = SEVERITY_ORDER[a.severity] ?? 999;
    const orderB = SEVERITY_ORDER[b.severity] ?? 999;
    return orderA - orderB;
  });

  // 7. Compute score
  const score = computeScore(findings);

  // 8. Determine status
  const hasCriticalOrHigh = findings.some(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );
  const status = hasCriticalOrHigh ? 'fail' : 'pass';

  // 9. Return ScanResult with timing info
  return {
    status,
    score,
    findings,
    scan_duration_ms: Date.now() - startTime,
  };
}
