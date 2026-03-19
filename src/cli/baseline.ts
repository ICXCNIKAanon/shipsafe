import { Command } from 'commander';
import chalk from 'chalk';
import { runPatternEngine } from '../engines/pattern/index.js';
import { loadBaseline, saveBaseline, BASELINE_FILENAME } from '../engines/builtin/baseline.js';

export function registerBaselineCommand(program: Command): void {
  program
    .command('baseline')
    .description('Create or update the baseline from current scan findings')
    .option('--show', 'Show current baseline contents without updating', false)
    .option('--clear', 'Remove the baseline (all findings will be reported again)', false)
    .action(async (options: { show: boolean; clear: boolean }) => {
      await handleBaselineAction(options);
    });
}

async function handleBaselineAction(options: { show: boolean; clear: boolean }): Promise<void> {
  const projectDir = process.cwd();

  if (options.show) {
    const baseline = await loadBaseline(projectDir);
    if (baseline.findings.length === 0) {
      console.log(chalk.dim('\n  No baseline found. Run `shipsafe baseline` to create one.\n'));
      return;
    }

    console.log('');
    console.log(chalk.bold('  ShipSafe Baseline'));
    console.log(chalk.dim('  ' + '─'.repeat(44)));
    console.log(`  Created: ${chalk.dim(baseline.created)}`);
    console.log(`  Findings: ${chalk.yellow(String(baseline.findings.length))}`);
    console.log('');

    for (const finding of baseline.findings) {
      console.log(`  ${chalk.dim(finding.hash.slice(0, 8))}  ${finding.id}  ${chalk.dim(finding.file + ':' + finding.line)}`);
    }
    console.log('');
    return;
  }

  if (options.clear) {
    const { unlink } = await import('node:fs/promises');
    const { join } = await import('node:path');
    try {
      await unlink(join(projectDir, BASELINE_FILENAME));
      console.log(chalk.green(`\n  Baseline cleared. All findings will be reported on next scan.\n`));
    } catch {
      console.log(chalk.dim(`\n  No baseline file found — nothing to clear.\n`));
    }
    return;
  }

  // Default: run a full scan and save the findings as the baseline
  console.log(chalk.dim('\n  Running full scan to establish baseline...'));

  const result = await runPatternEngine({
    targetPath: projectDir,
    scope: 'all',
  });

  await saveBaseline(projectDir, result.findings);

  console.log('');
  console.log(chalk.bold('  Baseline Updated'));
  console.log(chalk.dim('  ' + '─'.repeat(44)));
  console.log(`  Findings baselined: ${chalk.yellow(String(result.findings.length))}`);
  console.log(`  File: ${chalk.dim(BASELINE_FILENAME)}`);
  console.log('');

  if (result.findings.length > 0) {
    console.log(chalk.dim('  These findings will be suppressed in future staged scans.'));
    console.log(chalk.dim('  Only NEW findings will be reported.\n'));
  } else {
    console.log(chalk.dim('  No findings to baseline — your project is clean!\n'));
  }
}
