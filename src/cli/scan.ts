import { Command } from 'commander';
import chalk from 'chalk';
import type { ScanResult, ScanScope, Severity } from '../types.js';
import { runPatternEngine, getAvailableScanners } from '../engines/pattern/index.js';
import { isGraphEngineAvailable } from '../engines/graph/index.js';
import { fixHardcodedSecret } from '../autofix/secret-fixer.js';
import { fixSqlInjectionInFile } from '../autofix/sql-fixer.js';
import { fixMissingHelmet, fixMissingRateLimit } from '../autofix/middleware-fixer.js';
import { gateFeature } from './license-gate.js';
import { checkLicense } from './license-check.js';
import { checkHooksInstalled, installHooks } from '../hooks/installer.js';

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

async function formatResults(result: ScanResult): Promise<void> {
  const scanners = await getAvailableScanners();
  const graphAvailable = isGraphEngineAvailable();
  const license = await checkLicense();

  // Get built-in engine stats
  const { getSecretPatternCount } = await import('../engines/builtin/secrets.js');
  const { getPatternRuleCount } = await import('../engines/builtin/patterns.js');

  // Pre-compute counts to keep log lines free of sensitive-looking identifiers
  const credentialPatternCount = getSecretPatternCount();
  const vulnRuleCount = getPatternRuleCount();

  console.log('');
  console.log(chalk.bold('  ShipSafe Scan Results'));
  console.log(chalk.dim('  ' + '─'.repeat(44)));
  console.log('');

  const check = chalk.green('✓');
  const cross = chalk.dim('✗');

  console.log(chalk.dim('  Built-in Engines:'));
  console.log(`    ${check} Credential Scanner ${chalk.dim(`(${credentialPatternCount} patterns)`)}`);
  console.log(`    ${check} Vulnerability Scanner ${chalk.dim(`(${vulnRuleCount} rules)`)}`);
  console.log(`    ${check} Dependency Auditor`);
  console.log(`    ${graphAvailable ? check : cross} Knowledge Graph`);

  if (scanners.semgrep || scanners.gitleaks || scanners.trivy) {
    console.log(chalk.dim('  External (bonus):'));
    if (scanners.semgrep) console.log(`    ${check} Semgrep`);
    if (scanners.gitleaks) console.log(`    ${check} Gitleaks`);
    if (scanners.trivy) console.log(`    ${check} Trivy`);
  }
  console.log('');

  // Score
  const duration = formatDuration(result.scan_duration_ms);
  const scoreColor = result.score === 'A' ? chalk.green : result.score === 'B' ? chalk.yellow : chalk.red;
  const actionableFindings = result.findings.filter(f => f.severity !== 'info');
  const infoFindings = result.findings.filter(f => f.severity === 'info');
  let findingsSummary = `${actionableFindings.length} findings`;
  if (infoFindings.length > 0) {
    findingsSummary += chalk.dim(` + ${infoFindings.length} info`);
  }
  if (result.baseline_suppressed_count !== undefined && result.baseline_suppressed_count > 0) {
    findingsSummary += chalk.dim(` (${result.baseline_suppressed_count} baselined)`);
  }
  console.log(`  Score: ${scoreColor(chalk.bold(result.score))}  |  ${findingsSummary}  |  ${chalk.dim(duration)}`);
  console.log(`  Tier:  ${chalk.dim(license.tier)}`);
  console.log('');

  // Findings
  if (result.findings.length > 0) {
    console.log(chalk.dim('  ' + '─'.repeat(44)));
    console.log('');
    for (const finding of result.findings) {
      const colorFn = SEVERITY_COLORS[finding.severity];
      const severityLabel = colorFn(finding.severity.toUpperCase().padEnd(8));
      console.log(`  ${severityLabel} ${chalk.dim(finding.file + ':' + finding.line)}`);
      console.log(`  ${finding.description}`);
      console.log(`  ${chalk.dim('Fix:')} ${finding.fix_suggestion}`);
      console.log('');
    }
  } else {
    console.log(chalk.green('  ✓ No vulnerabilities found. Smooth sailing.'));
    console.log('');
  }
}

export async function handleScanAction(options: ScanOptions): Promise<void> {
  const scope = options.scope as ScanScope;

  // Auto-install git hooks if not already present (silent, best-effort)
  try {
    const hasHooks = await checkHooksInstalled();
    if (!hasHooks) {
      await installHooks();
    }
  } catch {
    // Not a git repo or can't write hooks — skip silently
  }

  if (!options.json) {
    console.log(chalk.dim(`\n  Scanning ${scope === 'staged' ? 'staged files' : 'all files'}...`));
  }

  const result = await runPatternEngine({
    targetPath: process.cwd(),
    scope,
  });

  if (options.fix) {
    const gate = await gateFeature('autofix');
    if (!gate.allowed) {
      console.log(chalk.yellow(`\n${gate.reason}`));
    } else {
      const sqlInjectionTypes = [
        'SQL_INJECTION_CONCAT',
        'SQL_INJECTION_TEMPLATE',
        'SQL_INJECTION_INLINE_VAR',
        'SQL_INJECTION_TEMPLATE_STRING',
        'TEMPLATE_LITERAL_SQL_VARIABLE',
      ];
      for (const finding of result.findings) {
        if (finding.type === 'hardcoded_secret' && finding.auto_fixable) {
          const fix = await fixHardcodedSecret(finding);
          console.log(chalk.green(`Fixed: moved ${fix.envVarName} to .env in ${finding.file}:${finding.line}`));
        } else if (sqlInjectionTypes.includes(finding.type) && finding.auto_fixable) {
          try {
            const fix = await fixSqlInjectionInFile(finding);
            console.log(chalk.green(`Fixed: converted SQL injection to parameterized query (${fix.paramStyle}) in ${finding.file}:${finding.line}`));
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            console.log(chalk.yellow(`Could not auto-fix SQL injection in ${finding.file}:${finding.line}: ${message}`));
          }
        } else if (finding.id === 'CONFIG_NO_SECURITY_HEADERS' && finding.auto_fixable) {
          try {
            const { readFile, writeFile } = await import('node:fs/promises');
            const filePath = (await import('node:path')).resolve(process.cwd(), finding.file);
            const content = await readFile(filePath, 'utf-8');
            const result = fixMissingHelmet(content, finding);
            if (result) {
              await writeFile(filePath, result.fixed, 'utf-8');
              console.log(chalk.green(`Fixed: ${result.description} in ${finding.file}`));
            }
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            console.log(chalk.yellow(`Could not auto-fix missing helmet in ${finding.file}: ${message}`));
          }
        } else if (finding.id === 'RATE_LIMIT_AUTH_ENDPOINT' && finding.auto_fixable) {
          try {
            const { readFile, writeFile } = await import('node:fs/promises');
            const filePath = (await import('node:path')).resolve(process.cwd(), finding.file);
            const content = await readFile(filePath, 'utf-8');
            const result = fixMissingRateLimit(content, finding);
            if (result) {
              await writeFile(filePath, result.fixed, 'utf-8');
              console.log(chalk.green(`Fixed: ${result.description} in ${finding.file}`));
            }
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            console.log(chalk.yellow(`Could not auto-fix missing rate limit in ${finding.file}: ${message}`));
          }
        }
      }
    }
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    await formatResults(result);
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
