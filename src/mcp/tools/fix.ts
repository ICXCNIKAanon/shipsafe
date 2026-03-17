import { fixHardcodedSecret } from '../../autofix/secret-fixer.js';
import { generateFix, type ProcessedError } from '../../autofix/pr-generator.js';
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

  // For hardcoded secrets with suggested strategy, use the autofix secret-fixer
  if (strategy === 'suggested' && finding.type === 'hardcoded-secret') {
    try {
      const result = await fixHardcodedSecret({
        id: finding.id,
        engine: 'pattern',
        severity: 'high',
        type: finding.type,
        file: finding.file,
        line: finding.line,
        description: finding.description,
        fix_suggestion: finding.fix_suggestion,
        auto_fixable: finding.auto_fixable,
      });
      return {
        status: 'fixed',
        files_modified: result.filesModified,
        description: `Moved hardcoded secret to .env as ${result.envVarName} and replaced with process.env.${result.envVarName}`,
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

  // For other auto-fixable findings, try the generateFix engine
  if (strategy === 'suggested' && finding.auto_fixable) {
    try {
      const filePath = path.resolve(process.cwd(), finding.file);
      const content = await fs.readFile(filePath, 'utf-8');

      const error: ProcessedError = {
        id: finding.id,
        message: finding.description,
        severity: 'high',
        file: finding.file,
        line: finding.line,
      };

      const patch = generateFix(error, content);
      if (patch) {
        await fs.writeFile(filePath, patch.fixed, 'utf-8');
        return {
          status: 'fixed',
          files_modified: [finding.file],
          description: patch.description,
        };
      }
    } catch {
      // Fall through to suggestion_only
    }
  }

  // For all other findings, return the suggestion for manual implementation
  return {
    status: 'suggestion_only',
    files_modified: [],
    description: finding.fix_suggestion,
  };
}
