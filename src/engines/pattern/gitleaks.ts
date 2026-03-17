import { execFile } from 'node:child_process';
import type { Finding } from '../../types.js';

interface GitleaksResult {
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  RuleID: string;
  Entropy: number;
  Fingerprint: string;
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

function parseGitleaksOutput(jsonString: string): Finding[] {
  const results: GitleaksResult[] = JSON.parse(jsonString);

  return results.map((result) => ({
    id: `gitleaks_${result.RuleID}_${result.StartLine}`,
    engine: 'pattern' as const,
    severity: 'critical' as const,
    type: 'hardcoded_secret',
    file: result.File,
    line: result.StartLine,
    description: result.Description,
    fix_suggestion: 'Move this secret to a .env file or environment variable',
    auto_fixable: true,
  }));
}

export async function checkGitleaksInstalled(): Promise<boolean> {
  try {
    await execFilePromise('which', ['gitleaks']);
    return true;
  } catch {
    return false;
  }
}

export async function runGitleaks(
  targetPath: string,
  _stagedFiles?: string[],
): Promise<Finding[]> {
  const installed = await checkGitleaksInstalled();
  if (!installed) {
    console.warn('ShipSafe: gitleaks is not installed, skipping secret scan');
    return [];
  }

  try {
    const args = [
      'detect',
      '--source',
      targetPath,
      '--report-format',
      'json',
      '--report-path',
      '/dev/stdout',
      '--no-git',
    ];

    const { stdout } = await execFilePromise('gitleaks', args);
    return parseGitleaksOutput(stdout);
  } catch (error: unknown) {
    // gitleaks exits non-zero when it finds secrets — still try to parse output
    const execError = error as Error & { stdout?: string };
    if (execError.stdout) {
      try {
        return parseGitleaksOutput(execError.stdout);
      } catch {
        // JSON parse failed on the output — fall through to warn
      }
    }

    console.warn('ShipSafe: gitleaks scan failed', execError.message);
    return [];
  }
}
