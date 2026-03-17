import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanResult } from '../types.js';
import { getInstallationToken, githubApi } from './api.js';
import { runPatternEngine } from '../engines/pattern/index.js';

export interface PrScanOptions {
  repoFullName: string;
  prNumber: number;
  headSha: string;
  baseSha: string;
  installationId: number;
}

interface PrFile {
  filename: string;
  status: string;
  raw_url?: string;
  contents_url?: string;
}

/**
 * Get changed files in a PR and scan them.
 *
 * 1. Fetches list of changed files via GitHub API
 * 2. Downloads content of each changed file
 * 3. Writes them to a temp directory
 * 4. Runs pattern engine scan
 * 5. Cleans up temp directory
 * 6. Returns scan result
 */
export async function scanPullRequest(options: PrScanOptions): Promise<ScanResult> {
  const token = await getInstallationToken(options.installationId);

  // 1. Fetch changed files
  const files = await fetchChangedFiles(options.repoFullName, options.prNumber, token);

  // Filter out deleted files — nothing to scan
  const filesToScan = files.filter((f) => f.status !== 'removed');

  if (filesToScan.length === 0) {
    return {
      status: 'pass',
      score: 'A',
      findings: [],
      scan_duration_ms: 0,
    };
  }

  // 2. Create temp directory
  const tmpDir = await fs.mkdtemp(path.join(tmpdir(), 'shipsafe-pr-'));

  try {
    // 3. Download and write each file
    const filePaths: string[] = [];
    for (const file of filesToScan) {
      const content = await fetchFileContent(
        options.repoFullName,
        file.filename,
        options.headSha,
        token,
      );

      const filePath = path.join(tmpDir, file.filename);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, content, 'utf-8');
      filePaths.push(file.filename);
    }

    // 4. Run pattern engine scan on the temp directory
    const result = await runPatternEngine({
      targetPath: tmpDir,
      scope: 'all',
      stagedFiles: filePaths,
    });

    return result;
  } finally {
    // 5. Clean up temp directory
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

/**
 * Fetch the list of files changed in a PR.
 */
async function fetchChangedFiles(
  repoFullName: string,
  prNumber: number,
  token: string,
): Promise<PrFile[]> {
  const result = (await githubApi(`/repos/${repoFullName}/pulls/${prNumber}/files`, {
    token,
  })) as PrFile[];

  return result;
}

/**
 * Fetch the raw content of a file at a specific commit SHA.
 */
async function fetchFileContent(
  repoFullName: string,
  filePath: string,
  sha: string,
  token: string,
): Promise<string> {
  const result = (await githubApi(
    `/repos/${repoFullName}/contents/${filePath}?ref=${sha}`,
    {
      token,
    },
  )) as { content?: string; encoding?: string };

  if (result.content && result.encoding === 'base64') {
    return Buffer.from(result.content, 'base64').toString('utf-8');
  }

  // Fallback: try raw download
  const rawResult = (await githubApi(
    `https://raw.githubusercontent.com/${repoFullName}/${sha}/${filePath}`,
    { token },
  )) as string;

  return rawResult;
}
