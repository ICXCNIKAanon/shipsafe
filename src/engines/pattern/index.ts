import { execFile } from 'node:child_process';
import type { Finding, ScanResult, ScanScope, SecurityScore, ScannerAvailability } from '../../types.js';
import { SEVERITY_ORDER } from '../../constants.js';
import { checkSemgrepInstalled, runSemgrep } from './semgrep.js';
import { checkGitleaksInstalled, runGitleaks } from './gitleaks.js';
import { checkTrivyInstalled, runTrivy } from './trivy.js';
import { runGraphEngine, isGraphEngineAvailable } from '../graph/index.js';
import { loadBaseline, filterNewFindings } from '../builtin/baseline.js';

export interface PatternEngineOptions {
  targetPath: string;
  scope: ScanScope;
  stagedFiles?: string[];
}

export function computeScore(findings: Finding[]): SecurityScore {
  // Filter out info-level and env-example findings for scoring
  const scorable = findings.filter(f =>
    f.severity !== 'info' && f.context !== 'env-example'
  );

  if (scorable.length === 0) return 'A';

  const severities = new Set(scorable.map((f) => f.severity));

  if (severities.has('critical')) return 'F';
  if (severities.has('high')) return 'D';
  if (severities.has('medium')) return 'C';

  // Only low remain
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

  // 3.5. Strip metadata from staged images before scanning (privacy protection)
  if (scope === 'staged' && stagedFiles && stagedFiles.length > 0) {
    try {
      const { stripStagedImages, isSupported } = await import('@metastrip/hooks');
      const imageFiles = stagedFiles.filter((f: string) => isSupported(f));
      if (imageFiles.length > 0) {
        const result = await stripStagedImages(imageFiles);
        if (result && result.stripped > 0) {
          console.log(`  MetaStrip: Stripped metadata from ${result.stripped} image${result.stripped === 1 ? '' : 's'} (zero quality loss)`);
        }
      }
    } catch {
      // @metastrip/hooks not available or failed — skip silently
    }
  }

  // 4. Run built-in scanners (always available — no external deps)
  const { scanSecrets } = await import('../builtin/secrets.js');
  const { scanPatterns } = await import('../builtin/patterns.js');
  const { scanDependencies } = await import('../builtin/dependencies.js');

  const scannerPromises: Promise<Finding[]>[] = [
    scanSecrets(targetPath, stagedFiles),
    scanPatterns(targetPath, stagedFiles),
    scanDependencies(targetPath),
  ];

  // 4b. Also run external scanners if installed (additive — more coverage)
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
  }

  // 5b. Deduplicate findings (built-in + external may find same issue)
  const seen = new Set<string>();
  const deduped: Finding[] = [];
  for (const f of findings) {
    const key = `${f.file}:${f.line}:${f.type}:${f.description}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(f);
    }
  }
  findings.length = 0;
  findings.push(...deduped);

  // 5c. Run graph engine (optional — failures are non-fatal)
  if (isGraphEngineAvailable()) {
    try {
      const graphResult = await runGraphEngine({ targetPath, scope });
      findings.push(...graphResult.findings);
    } catch {
      // Graph engine failure is non-fatal
    }
  }

  // 5d. Call map post-filter (only for full scans — too slow for staged)
  if (scope === 'all') {
    try {
      const { buildCallMapWithTimeout, findClosestFunctionKey } = await import('../builtin/call-map.js');
      const callMap = await buildCallMapWithTimeout(targetPath, undefined, 5000);

      if (callMap) {
        // Rule IDs to check with call map
        const AUTH_RULES = new Set([
          'AUTH_MISSING_AUTH_MIDDLEWARE',
          'NEXT_API_NO_AUTH',
          'NEXT_SERVER_ACTION_NO_AUTH',
        ]);
        const SQL_RULES = new Set([
          'SQL_INJECTION_CONCAT',
          'SQL_INJECTION_TEMPLATE',
          'SQL_INJECTION_FSTRING',
          'SQL_INJECTION_FORMAT',
        ]);
        const XSS_RULES = new Set([
          'XSS_DANGEROUSLY_SET_INNERHTML',
          'XSS_EVAL',
          'XSS_UNESCAPED_TEMPLATE',
          'REACT_DANGEROUSLYSETINNERHTML_VARIABLE',
          'DOM_XSS_INNERHTML_ASSIGN',
        ]);

        // Filter findings in-place
        const filteredFindings: Finding[] = [];
        for (const finding of findings) {
          const funcKey = findClosestFunctionKey(callMap, finding.file, finding.line);

          if (funcKey) {
            // AUTH rules: suppress if called from auth context
            if (AUTH_RULES.has(finding.id) && callMap.isCalledFromAuthContext(funcKey)) {
              continue; // Suppress — auth is in the call chain
            }

            // SQL rules: downgrade to info if validation is in call chain
            if (SQL_RULES.has(finding.id) && callMap.hasValidationInCallChain(funcKey)) {
              finding.severity = 'info';
            }

            // XSS rules: suppress if validation is in call chain
            if (XSS_RULES.has(finding.id) && callMap.hasValidationInCallChain(funcKey)) {
              continue; // Suppress — validation/sanitization is in the call chain
            }
          }

          filteredFindings.push(finding);
        }

        // Replace findings array
        findings.length = 0;
        findings.push(...filteredFindings);
      }
    } catch {
      // Call map failure is non-fatal — fall back to pattern-only results
    }
  }

  // 6. Sort findings by severity (critical first)
  findings.sort((a, b) => {
    const orderA = SEVERITY_ORDER[a.severity] ?? 999;
    const orderB = SEVERITY_ORDER[b.severity] ?? 999;
    return orderA - orderB;
  });

  // 7. Delta mode: for staged scans, filter against baseline
  let reportedFindings = findings;
  let newFindingsCount: number | undefined;
  let baselineSuppressedCount: number | undefined;

  if (scope === 'staged') {
    const baseline = await loadBaseline(targetPath);
    if (baseline.findings.length > 0) {
      reportedFindings = filterNewFindings(findings, baseline, targetPath);
      newFindingsCount = reportedFindings.length;
      baselineSuppressedCount = findings.length - reportedFindings.length;
    }
  }

  // 8. Compute score (based on reported findings only)
  const score = computeScore(reportedFindings);

  // 9. Determine status
  const hasCriticalOrHigh = reportedFindings.some(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );
  const status = hasCriticalOrHigh ? 'fail' : 'pass';

  // 10. Write scan cache for HUD integrations (claude-vitals, etc.)
  const result: ScanResult = {
    status,
    score,
    findings: reportedFindings,
    scan_duration_ms: Date.now() - startTime,
    ...(newFindingsCount !== undefined && { new_findings_count: newFindingsCount }),
    ...(baselineSuppressedCount !== undefined && { baseline_suppressed_count: baselineSuppressedCount }),
  };

  try {
    const { mkdir, writeFile } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const cacheDir = join(targetPath, '.shipsafe');
    await mkdir(cacheDir, { recursive: true });
    await writeFile(join(cacheDir, 'last-scan.json'), JSON.stringify({
      score,
      status,
      findings_count: reportedFindings.length,
      critical: reportedFindings.filter(f => f.severity === 'critical').length,
      high: reportedFindings.filter(f => f.severity === 'high').length,
      medium: reportedFindings.filter(f => f.severity === 'medium').length,
      low: reportedFindings.filter(f => f.severity === 'low').length,
      info: reportedFindings.filter(f => f.severity === 'info').length,
      auto_fixable: reportedFindings.filter(f => f.auto_fixable).length,
      scan_duration_ms: result.scan_duration_ms,
      timestamp: new Date().toISOString(),
      version: '1.4.0',
    }, null, 2) + '\n', 'utf-8');
  } catch {
    // Cache write is best-effort — never block the scan
  }

  return result;
}
