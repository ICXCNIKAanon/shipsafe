import { Command } from 'commander';
import chalk from 'chalk';
import {
  scanEnvironment,
  type EnvironmentScanResult,
  type EnvironmentThreat,
} from '../engines/builtin/environment-scan.js';

const SEVERITY_COLORS: Record<string, (text: string) => string> = {
  critical: chalk.red,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
};

const CATEGORY_LABELS: Record<string, string> = {
  mcp_server: 'MCP Server',
  hook: 'Hook',
  prompt_injection: 'Prompt Injection',
  skill: 'Skill',
};

function formatThreat(threat: EnvironmentThreat): void {
  const colorFn = SEVERITY_COLORS[threat.severity] ?? chalk.white;
  const severityLabel = colorFn(threat.severity.toUpperCase().padEnd(8));
  const categoryLabel = chalk.dim(`[${CATEGORY_LABELS[threat.category] ?? threat.category}]`);

  console.log(`  ${severityLabel} ${categoryLabel} ${threat.id}`);
  console.log(`  ${threat.description}`);
  console.log(`  ${chalk.dim('Location:')} ${threat.location}`);
  if (threat.evidence) {
    console.log(`  ${chalk.dim('Evidence:')} ${threat.evidence}`);
  }
  console.log('');
}

function formatResults(result: EnvironmentScanResult): void {
  console.log('');
  console.log(chalk.bold('  ShipSafe Environment Scan'));
  console.log(chalk.dim('  ' + '\u2500'.repeat(44)));
  console.log('');

  const check = chalk.green('\u2713');

  // Show what was scanned
  console.log(chalk.dim('  Scanned:'));
  console.log(`    ${check} MCP configs: ${result.scanned.mcp_configs.length > 0 ? result.scanned.mcp_configs.join(', ') : chalk.dim('none found')}`);
  console.log(`    ${check} Hooks file: ${result.scanned.hooks_file ?? chalk.dim('none found')}`);
  console.log(`    ${check} CLAUDE.md files: ${result.scanned.claude_md_files.length > 0 ? result.scanned.claude_md_files.join(', ') : chalk.dim('none found')}`);
  console.log(`    ${check} Skill files: ${result.scanned.skill_files.length > 0 ? String(result.scanned.skill_files.length) + ' files' : chalk.dim('none found')}`);
  console.log('');

  // Status
  if (result.status === 'pass') {
    console.log(chalk.green('  \u2713 No threats detected. Environment looks clean.'));
    console.log('');
    return;
  }

  console.log(chalk.red(`  \u2717 ${result.threats_found} threat${result.threats_found === 1 ? '' : 's'} detected`));
  console.log('');
  console.log(chalk.dim('  ' + '\u2500'.repeat(44)));
  console.log('');

  for (const threat of result.threats) {
    formatThreat(threat);
  }
}

export async function handleScanEnvironmentAction(options: { json: boolean }): Promise<void> {
  if (!options.json) {
    console.log(chalk.dim('\n  Scanning Claude Code environment...'));
  }

  const result = await scanEnvironment();

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    formatResults(result);
  }

  if (result.status === 'fail') {
    const hasCritical = result.threats.some((t) => t.severity === 'critical');
    if (hasCritical) {
      process.exit(1);
    }
  }
}

export function registerScanEnvironmentCommand(program: Command): void {
  program
    .command('scan-environment')
    .description('Scan Claude Code environment for malicious MCP servers, hooks, skills, and prompt injection')
    .option('--json', 'Output results as JSON', false)
    .action(async (options: { json: boolean }) => {
      await handleScanEnvironmentAction(options);
    });
}
