import { execFile } from 'node:child_process';
import type { Finding, Severity } from '../../types.js';

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion: string;
  Severity: string;
  Title: string;
  Description: string;
}

interface TrivyResult {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities: TrivyVulnerability[] | null;
}

interface TrivyOutput {
  SchemaVersion: number;
  Results: TrivyResult[];
}

function execFilePromise(
  cmd: string,
  args: string[],
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, (error, stdout, stderr) => {
      if (error) {
        // Attach stdout/stderr to the error so callers can still read output
        const enrichedError = error as Error & {
          stdout?: string;
          stderr?: string;
        };
        enrichedError.stdout = typeof stdout === 'string' ? stdout : '';
        enrichedError.stderr = typeof stderr === 'string' ? stderr : '';
        reject(enrichedError);
        return;
      }
      resolve({
        stdout: typeof stdout === 'string' ? stdout : '',
        stderr: typeof stderr === 'string' ? stderr : '',
      });
    });
  });
}

const SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

function mapSeverity(trivySeverity: string): Severity {
  return SEVERITY_MAP[trivySeverity] ?? 'low';
}

function parseTrivyOutput(jsonString: string): Finding[] {
  const output: TrivyOutput = JSON.parse(jsonString);
  const findings: Finding[] = [];

  for (const result of output.Results) {
    if (!result.Vulnerabilities) {
      continue;
    }

    for (const vuln of result.Vulnerabilities) {
      const hasFixedVersion = vuln.FixedVersion !== '' && vuln.FixedVersion != null;

      findings.push({
        id: `trivy_${vuln.VulnerabilityID}_${vuln.PkgName}`,
        engine: 'pattern' as const,
        severity: mapSeverity(vuln.Severity),
        type: 'dependency_vulnerability',
        file: result.Target,
        line: 0,
        description: `${vuln.VulnerabilityID}: ${vuln.Title} (${vuln.PkgName}@${vuln.InstalledVersion})`,
        fix_suggestion: hasFixedVersion
          ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion}`
          : 'No fix available yet',
        auto_fixable: hasFixedVersion,
      });
    }
  }

  return findings;
}

export async function checkTrivyInstalled(): Promise<boolean> {
  try {
    await execFilePromise('which', ['trivy']);
    return true;
  } catch {
    return false;
  }
}

export async function runTrivy(targetPath: string): Promise<Finding[]> {
  const installed = await checkTrivyInstalled();
  if (!installed) {
    console.warn('ShipSafe: trivy is not installed, skipping dependency vulnerability scan');
    return [];
  }

  try {
    const args = ['fs', '--format', 'json', '--quiet', targetPath];

    const { stdout } = await execFilePromise('trivy', args);
    return parseTrivyOutput(stdout);
  } catch (error: unknown) {
    // If trivy exits non-zero but produced output, still try to parse it
    const execError = error as Error & { stdout?: string };
    if (execError.stdout) {
      try {
        return parseTrivyOutput(execError.stdout);
      } catch {
        // JSON parse failed on the output — fall through to warn
      }
    }

    console.warn('ShipSafe: trivy scan failed', execError.message);
    return [];
  }
}
