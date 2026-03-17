import type { Finding } from '../types.js';
import { getInstallationToken, githubApi } from './api.js';

/**
 * Create a check run in 'in_progress' state.
 * Returns the check run ID.
 */
export async function createCheckRun(options: {
  repoFullName: string;
  headSha: string;
  installationId: number;
}): Promise<number> {
  const token = await getInstallationToken(options.installationId);

  const result = (await githubApi(`/repos/${options.repoFullName}/check-runs`, {
    method: 'POST',
    token,
    body: {
      name: 'ShipSafe Security Scan',
      head_sha: options.headSha,
      status: 'in_progress',
      started_at: new Date().toISOString(),
    },
  })) as { id: number };

  return result.id;
}

/**
 * Format findings as GitHub check run annotations.
 */
export function formatAnnotations(
  findings: Finding[],
): Array<{
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: 'failure' | 'warning' | 'notice';
  message: string;
  title: string;
}> {
  return findings.map((finding) => ({
    path: finding.file,
    start_line: finding.line,
    end_line: finding.line,
    annotation_level: severityToAnnotationLevel(finding.severity),
    message: `${finding.description}\n\nFix: ${finding.fix_suggestion}`,
    title: `[${finding.severity.toUpperCase()}] ${finding.type}`,
  }));
}

function severityToAnnotationLevel(
  severity: string,
): 'failure' | 'warning' | 'notice' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'failure';
    case 'medium':
      return 'warning';
    default:
      return 'notice';
  }
}

/**
 * Build a summary string for the check run output.
 */
export function buildSummary(findings: Finding[]): string {
  if (findings.length === 0) {
    return 'ShipSafe found no security issues. Ship it!';
  }

  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const low = findings.filter((f) => f.severity === 'low').length;

  const parts: string[] = [];
  if (critical > 0) parts.push(`${critical} critical`);
  if (high > 0) parts.push(`${high} high`);
  if (medium > 0) parts.push(`${medium} medium`);
  if (low > 0) parts.push(`${low} low`);

  return `ShipSafe found ${findings.length} issues (${parts.join(', ')})`;
}

/**
 * Complete a check run with results.
 */
export async function completeCheckRun(options: {
  repoFullName: string;
  checkRunId: number;
  installationId: number;
  conclusion: 'success' | 'failure' | 'neutral';
  findings: Finding[];
}): Promise<void> {
  const token = await getInstallationToken(options.installationId);

  const annotations = formatAnnotations(options.findings);
  const summary = buildSummary(options.findings);

  // GitHub API limits annotations to 50 per request
  const annotationBatch = annotations.slice(0, 50);

  await githubApi(`/repos/${options.repoFullName}/check-runs/${options.checkRunId}`, {
    method: 'PATCH',
    token,
    body: {
      status: 'completed',
      conclusion: options.conclusion,
      completed_at: new Date().toISOString(),
      output: {
        title: 'ShipSafe Security Scan',
        summary,
        annotations: annotationBatch,
      },
    },
  });
}
