import { execFile } from 'node:child_process';
import type { Finding, Severity } from '../../types.js';

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: string;
    fix?: string;
  };
}

interface SemgrepOutput {
  results: SemgrepResult[];
  errors: unknown[];
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
  ERROR: 'critical',
  WARNING: 'high',
  INFO: 'medium',
};

function mapSeverity(semgrepSeverity: string): Severity {
  return SEVERITY_MAP[semgrepSeverity] ?? 'low';
}

function parseSemgrepOutput(jsonString: string): Finding[] {
  const output: SemgrepOutput = JSON.parse(jsonString);

  return output.results.map((result) => ({
    id: `semgrep_${result.check_id}_${result.start.line}`,
    engine: 'pattern' as const,
    severity: mapSeverity(result.extra.severity),
    type: result.check_id,
    file: result.path,
    line: result.start.line,
    description: result.extra.message,
    fix_suggestion: result.extra.fix ?? '',
    auto_fixable: result.extra.fix != null,
  }));
}

export async function checkSemgrepInstalled(): Promise<boolean> {
  try {
    await execFilePromise('which', ['semgrep']);
    return true;
  } catch {
    return false;
  }
}

export async function runSemgrep(
  targetPath: string,
  stagedFiles?: string[],
): Promise<Finding[]> {
  const installed = await checkSemgrepInstalled();
  if (!installed) {
    console.warn('ShipSafe: semgrep is not installed, skipping pattern scan');
    return [];
  }

  try {
    const args = ['scan', '--json', '--quiet'];

    if (stagedFiles && stagedFiles.length > 0) {
      args.push(...stagedFiles);
    } else {
      args.push(targetPath);
    }

    const { stdout } = await execFilePromise('semgrep', args);
    return parseSemgrepOutput(stdout);
  } catch (error: unknown) {
    // If semgrep exits non-zero but produced output, still try to parse it
    const execError = error as Error & { stdout?: string };
    if (execError.stdout) {
      try {
        return parseSemgrepOutput(execError.stdout);
      } catch {
        // JSON parse failed on the output — fall through to warn
      }
    }

    console.warn('ShipSafe: semgrep scan failed', execError.message);
    return [];
  }
}
