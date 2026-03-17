import * as fs from 'node:fs/promises';
import * as path from 'node:path';

export interface FixParams {
  finding_id: string;
  strategy?: 'suggested' | 'custom';
}

export interface FixResult {
  status: 'fixed' | 'suggestion_only';
  files_modified: string[];
  description: string;
}

// In-memory cache of findings from the last scan
let lastScanFindings: Array<{
  id: string;
  type: string;
  file: string;
  line: number;
  description: string;
  fix_suggestion: string;
  auto_fixable: boolean;
}> = [];

/**
 * Store findings from the most recent scan for lookup by the fix tool.
 */
export function cacheFindings(
  findings: Array<{
    id: string;
    type: string;
    file: string;
    line: number;
    description: string;
    fix_suggestion: string;
    auto_fixable: boolean;
  }>,
): void {
  lastScanFindings = [...findings];
}

/**
 * Clear the findings cache (useful for tests).
 */
export function clearFindingsCache(): void {
  lastScanFindings = [];
}

/**
 * Get cached findings (useful for tests).
 */
export function getCachedFindings(): typeof lastScanFindings {
  return lastScanFindings;
}

export async function handleFix(params: FixParams): Promise<FixResult> {
  const { finding_id, strategy = 'suggested' } = params;

  // Look up the finding
  const finding = lastScanFindings.find((f) => f.id === finding_id);
  if (!finding) {
    return {
      status: 'suggestion_only',
      files_modified: [],
      description: `Finding ${finding_id} not found in last scan results. Run shipsafe_scan first.`,
    };
  }

  // For hardcoded secrets with suggested strategy, attempt auto-fix
  if (strategy === 'suggested' && finding.type === 'hardcoded-secret') {
    return await fixHardcodedSecret(finding);
  }

  // For all other findings, return the suggestion for manual implementation
  return {
    status: 'suggestion_only',
    files_modified: [],
    description: finding.fix_suggestion,
  };
}

async function fixHardcodedSecret(finding: {
  id: string;
  file: string;
  line: number;
  description: string;
}): Promise<FixResult> {
  const projectDir = process.cwd();
  const filePath = path.resolve(projectDir, finding.file);
  const filesModified: string[] = [];

  try {
    // Read the source file
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    const targetLine = lines[finding.line - 1];

    if (!targetLine) {
      return {
        status: 'suggestion_only',
        files_modified: [],
        description: `Could not read line ${finding.line} from ${finding.file}. Apply fix manually: ${finding.description}`,
      };
    }

    // Extract secret value — look for common patterns
    const secretMatch = targetLine.match(
      /['"`]([A-Za-z0-9_\-./+=]{8,})['"`]/,
    );
    if (!secretMatch) {
      return {
        status: 'suggestion_only',
        files_modified: [],
        description: `Could not extract secret value from line ${finding.line}. Apply fix manually.`,
      };
    }

    const secretValue = secretMatch[1];

    // Derive an env var name from context
    const varNameMatch = targetLine.match(
      /(?:const|let|var)\s+(\w+)|(\w+)\s*[:=]/,
    );
    const rawName = varNameMatch?.[1] ?? varNameMatch?.[2] ?? 'SECRET';
    const envVarName = rawName
      .replace(/([a-z])([A-Z])/g, '$1_$2')
      .toUpperCase();

    // Replace the hardcoded value with process.env reference
    const newLine = targetLine.replace(
      secretMatch[0],
      `process.env.${envVarName}`,
    );
    lines[finding.line - 1] = newLine;
    await fs.writeFile(filePath, lines.join('\n'), 'utf-8');
    filesModified.push(finding.file);

    // Add to .env file
    const envPath = path.join(projectDir, '.env');
    let envContent = '';
    try {
      envContent = await fs.readFile(envPath, 'utf-8');
    } catch {
      // .env doesn't exist yet
    }
    if (!envContent.includes(`${envVarName}=`)) {
      const newEntry = `${envVarName}=${secretValue}\n`;
      await fs.writeFile(envPath, envContent + newEntry, 'utf-8');
      filesModified.push('.env');
    }

    // Add .env to .gitignore if not already there
    const gitignorePath = path.join(projectDir, '.gitignore');
    let gitignoreContent = '';
    try {
      gitignoreContent = await fs.readFile(gitignorePath, 'utf-8');
    } catch {
      // .gitignore doesn't exist yet
    }
    if (!gitignoreContent.includes('.env')) {
      const separator = gitignoreContent.endsWith('\n') || gitignoreContent === '' ? '' : '\n';
      await fs.writeFile(
        gitignorePath,
        gitignoreContent + separator + '.env\n',
        'utf-8',
      );
      filesModified.push('.gitignore');
    }

    return {
      status: 'fixed',
      files_modified: filesModified,
      description: `Moved hardcoded secret to .env as ${envVarName} and replaced with process.env.${envVarName}`,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: 'suggestion_only',
      files_modified: [],
      description: `Auto-fix failed: ${message}. Apply fix manually: move secret to .env and use process.env reference.`,
    };
  }
}
