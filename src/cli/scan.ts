import { Command } from 'commander';
import chalk from 'chalk';
import type { ScanResult, ScanScope, Severity } from '../types.js';
import { runPatternEngine } from '../engines/pattern/index.js';

export interface ScanOptions {
  scope: string;
  fix: boolean;
  json: boolean;
}

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.red,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

function formatDuration(ms: number): string {
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatResults(result: ScanResult): void {
  console.log(chalk.bold('\nShipSafe Scan Results'));
  console.log(chalk.bold('─'.repeat(40)));

  const duration = formatDuration(result.scan_duration_ms);
  const scoreLine = `Score: ${result.score} | ${result.findings.length} findings | ${duration}`;
  console.log(scoreLine);

  if (result.findings.length > 0) {
    console.log('');
    for (const finding of result.findings) {
      const colorFn = SEVERITY_COLORS[finding.severity];
      const severityLabel = colorFn(finding.severity.toUpperCase());
      console.log(`${severityLabel}  ${finding.file}:${finding.line}`);
      console.log(`  ${finding.description}`);
      console.log(`  Fix: ${finding.fix_suggestion}`);
    }
  }

  console.log('');
}

export async function handleScanAction(options: ScanOptions): Promise<void> {
  const scope = options.scope as ScanScope;

  const result = await runPatternEngine({
    targetPath: process.cwd(),
    scope,
  });

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    formatResults(result);
  }

  const hasCriticalOrHigh = result.findings.some(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );

  if (hasCriticalOrHigh) {
    process.exit(1);
  }
}

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan project for security vulnerabilities')
    .option('--scope <scope>', 'Scan scope: staged, all, or file:<path>', 'staged')
    .option('--fix', 'Attempt to auto-fix findings', false)
    .option('--json', 'Output results as JSON', false)
    .action(async (options: ScanOptions) => {
      await handleScanAction(options);
    });
}
