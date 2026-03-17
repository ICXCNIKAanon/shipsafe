import { getInstallationToken, githubApi } from '../github/api.js';

/**
 * A production error enriched by the cloud API pipeline.
 */
export interface ProcessedError {
  id: string;
  message: string;
  severity: string;
  stack_trace?: string;
  root_cause?: string;
  suggested_fix?: string;
  file?: string;
  line?: number;
}

export interface AutoFixPrOptions {
  error: ProcessedError;
  repoFullName: string;
  installationId: number;
  baseBranch?: string; // default: 'main'
}

export interface AutoFixResult {
  status: 'pr_created' | 'fix_suggested' | 'cannot_fix';
  prUrl?: string;
  branchName?: string;
  description: string;
  filesModified: string[];
}

export interface FixPatch {
  filePath: string;
  original: string;
  fixed: string;
  description: string;
}

// ── Fix pattern matchers ──

interface FixPattern {
  test: (message: string) => boolean;
  apply: (line: string, message: string) => string | null;
  describe: (message: string) => string;
}

/**
 * Extract the property name from a TypeError message like
 * "Cannot read property 'foo' of null" or "Cannot read properties of undefined (reading 'bar')"
 */
function extractPropertyName(message: string): string | null {
  // "Cannot read property 'X' of null/undefined"
  const match1 = message.match(/Cannot read propert(?:y|ies) (?:of \w+ \(reading )?'(\w+)'/);
  if (match1) return match1[1];
  // "Cannot read properties of undefined (reading 'X')"
  const match2 = message.match(/reading '(\w+)'/);
  if (match2) return match2[1];
  return null;
}

const FIX_PATTERNS: FixPattern[] = [
  // 1. TypeError: Cannot read property 'X' of null/undefined → optional chaining
  {
    test: (msg) =>
      /Cannot read propert(?:y|ies)/.test(msg) &&
      /(?:null|undefined)/.test(msg),
    apply: (line, message) => {
      const prop = extractPropertyName(message);
      if (!prop) return null;
      // Replace `.prop` with `?.prop` if not already optional-chained
      const pattern = new RegExp(`(?<!\\?)\\.(${prop})\\b`);
      if (!pattern.test(line)) return null;
      return line.replace(pattern, `?.${prop}`);
    },
    describe: (msg) => {
      const prop = extractPropertyName(msg);
      return `Add optional chaining for property '${prop ?? 'unknown'}' to prevent TypeError on null/undefined`;
    },
  },

  // 2. TypeError: X is not a function → guard with typeof check
  {
    test: (msg) => /is not a function/.test(msg),
    apply: (line, message) => {
      const match = message.match(/(\w+) is not a function/);
      if (!match) return null;
      const fnName = match[1];
      // Add typeof guard: `if (typeof fn === 'function') { fn(...) }`
      const callPattern = new RegExp(`(${fnName})\\s*\\(`);
      if (!callPattern.test(line)) return null;
      const trimmed = line.trimStart();
      const indent = line.slice(0, line.length - trimmed.length);
      return `${indent}if (typeof ${fnName} === 'function') { ${trimmed} }`;
    },
    describe: (msg) => {
      const match = msg.match(/(\w+) is not a function/);
      return `Add typeof guard before calling '${match?.[1] ?? 'unknown'}' to prevent TypeError`;
    },
  },

  // 3. ReferenceError: X is not defined → declare as undefined
  {
    test: (msg) => /is not defined/.test(msg) && msg.includes('ReferenceError'),
    apply: (line, message) => {
      const match = message.match(/(\w+) is not defined/);
      if (!match) return null;
      const varName = match[1];
      const trimmed = line.trimStart();
      const indent = line.slice(0, line.length - trimmed.length);
      return `${indent}const ${varName} = undefined; // TODO: provide correct value\n${line}`;
    },
    describe: (msg) => {
      const match = msg.match(/(\w+) is not defined/);
      return `Declare missing variable '${match?.[1] ?? 'unknown'}' — requires manual review`;
    },
  },

  // 4. Unhandled promise rejection → wrap in try/catch
  {
    test: (msg) =>
      /[Uu]nhandled.*(?:promise|rejection)/i.test(msg) ||
      /UnhandledPromiseRejection/i.test(msg),
    apply: (line) => {
      const trimmed = line.trimStart();
      const indent = line.slice(0, line.length - trimmed.length);
      // Wrap the line in a try/catch
      return [
        `${indent}try {`,
        `${indent}  ${trimmed}`,
        `${indent}} catch (err) {`,
        `${indent}  console.error('Caught previously unhandled rejection:', err);`,
        `${indent}}`,
      ].join('\n');
    },
    describe: () => 'Wrap unhandled async call in try/catch block',
  },

  // 5. SQL injection → parameterize
  {
    test: (msg) => /sql.*injection/i.test(msg),
    apply: (line) => {
      // Match template literal or string concatenation in SQL-like context
      const templateMatch = line.match(/`([^`]*\$\{(\w+)\}[^`]*)`/);
      if (templateMatch) {
        const param = templateMatch[2];
        const trimmed = line.trimStart();
        const indent = line.slice(0, line.length - trimmed.length);
        // Replace template literal with parameterized query
        const safeSql = templateMatch[1].replace(`\${${param}}`, '?');
        return `${indent}// FIXED: parameterized query to prevent SQL injection\n${indent}${line.replace(templateMatch[0], `'${safeSql}', [${param}]`)}`;
      }
      return null;
    },
    describe: () => 'Parameterize SQL query to prevent SQL injection',
  },
];

/**
 * Analyze an error and generate a code fix (without creating a PR).
 */
export function generateFix(error: ProcessedError, fileContent: string): FixPatch | null {
  if (!error.file || !error.line) return null;

  const lines = fileContent.split('\n');
  const lineIndex = error.line - 1;
  if (lineIndex < 0 || lineIndex >= lines.length) return null;

  const targetLine = lines[lineIndex];

  for (const pattern of FIX_PATTERNS) {
    if (pattern.test(error.message)) {
      const fixedLine = pattern.apply(targetLine, error.message);
      if (fixedLine !== null && fixedLine !== targetLine) {
        const fixedLines = [...lines];
        fixedLines[lineIndex] = fixedLine;
        return {
          filePath: error.file,
          original: fileContent,
          fixed: fixedLines.join('\n'),
          description: pattern.describe(error.message),
        };
      }
    }
  }

  return null;
}

/**
 * Parse a stack trace to extract file and line number.
 */
export function parseStackTrace(stackTrace: string): { file: string; line: number } | null {
  // Match patterns like "at handler (/src/api/route.ts:42:10)" or "at /src/api/route.ts:42"
  const match = stackTrace.match(/at\s+(?:\S+\s+)?(?:\()?([^:]+):(\d+)/);
  if (!match) return null;
  return { file: match[1], line: parseInt(match[2], 10) };
}

/**
 * Generate a fix based on error analysis and create a PR via GitHub API.
 */
export async function generateAutoFixPr(options: AutoFixPrOptions): Promise<AutoFixResult> {
  const { error, repoFullName, installationId, baseBranch = 'main' } = options;

  // 1. Determine the file and line from the error or its stack trace
  let file = error.file;
  let line = error.line;

  if (!file && error.stack_trace) {
    const parsed = parseStackTrace(error.stack_trace);
    if (parsed) {
      file = parsed.file;
      line = parsed.line;
    }
  }

  if (!file || !line) {
    return {
      status: 'cannot_fix',
      description: 'Cannot determine the source file from this error. No stack trace or file info available.',
      filesModified: [],
    };
  }

  // Normalize file path (remove leading /)
  const filePath = file.startsWith('/') ? file.slice(1) : file;

  try {
    // 2. Get an installation token
    const token = await getInstallationToken(installationId);

    // 3. Fetch file content from GitHub
    const fileResponse = (await githubApi(`/repos/${repoFullName}/contents/${filePath}`, {
      token,
      method: 'GET',
    })) as { content: string; sha: string; encoding: string };

    if (!fileResponse.content) {
      return {
        status: 'cannot_fix',
        description: `File ${filePath} not found in repository.`,
        filesModified: [],
      };
    }

    const fileContent = Buffer.from(fileResponse.content, 'base64').toString('utf-8');

    // 4. Generate the fix
    const patch = generateFix({ ...error, file: filePath, line }, fileContent);

    if (!patch) {
      return {
        status: 'fix_suggested',
        description: error.suggested_fix ?? `Unable to auto-fix: ${error.message}`,
        filesModified: [],
      };
    }

    // 5. Create a new branch
    const branchName = `shipsafe/fix-${error.id}`;

    // Get the base branch SHA
    const baseBranchRef = (await githubApi(`/repos/${repoFullName}/git/ref/heads/${baseBranch}`, {
      token,
    })) as { object: { sha: string } };

    const baseSha = baseBranchRef.object.sha;

    // Create the new branch
    await githubApi(`/repos/${repoFullName}/git/refs`, {
      method: 'POST',
      token,
      body: {
        ref: `refs/heads/${branchName}`,
        sha: baseSha,
      },
    });

    // 6. Commit the fix
    await githubApi(`/repos/${repoFullName}/contents/${filePath}`, {
      method: 'PUT',
      token,
      body: {
        message: `fix: ${patch.description}`,
        content: Buffer.from(patch.fixed).toString('base64'),
        sha: fileResponse.sha,
        branch: branchName,
      },
    });

    // 7. Create the PR
    const pr = (await githubApi(`/repos/${repoFullName}/pulls`, {
      method: 'POST',
      token,
      body: {
        title: `fix: ${truncate(error.message, 60)}`,
        head: branchName,
        base: baseBranch,
        body: [
          '## Auto-Fix by ShipSafe',
          '',
          `**Error:** ${error.message}`,
          '',
          `**Root cause:** ${error.root_cause ?? 'See error details'}`,
          '',
          `**Fix applied:** ${patch.description}`,
          '',
          `**File:** \`${filePath}\` (line ${line})`,
          '',
          '---',
          '_This PR was automatically generated by ShipSafe. Please review before merging._',
        ].join('\n'),
      },
    })) as { html_url: string };

    return {
      status: 'pr_created',
      prUrl: pr.html_url,
      branchName,
      description: patch.description,
      filesModified: [filePath],
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: 'cannot_fix',
      description: `Auto-fix PR failed: ${message}`,
      filesModified: [],
    };
  }
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}
