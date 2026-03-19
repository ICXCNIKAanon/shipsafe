/**
 * .gitignore-aware file filtering for ShipSafe.
 *
 * Uses `git ls-files` for accuracy — handles nested .gitignore files,
 * negation rules, and global git excludes without manual parsing.
 *
 * Key insight: .env.local is typically in .gitignore. By filtering
 * gitignored files, we automatically stop flagging .env.local secrets —
 * which is the #1 noise complaint.
 */

import { execFile } from 'node:child_process';
import { resolve } from 'node:path';

// ── Types ──

export interface GitIgnoreFilter {
  /** Returns true if the file is gitignored (should be skipped). */
  isGitIgnored(filePath: string): boolean;
  /** Returns true if the file is untracked (not yet git-added, but not ignored). */
  isUntracked(filePath: string): boolean;
}

// ── Cache ──

const filterCache = new Map<string, GitIgnoreFilter>();

// ── Helpers ──

/**
 * Run a git command and return stdout lines.
 * Resolves to an empty array on any error (not a git repo, git not installed, etc.).
 */
function gitLsFiles(cwd: string, args: string[]): Promise<string[]> {
  return new Promise((res) => {
    execFile(
      'git',
      ['ls-files', ...args],
      { cwd, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout) => {
        if (error) {
          // Not a git repo, git not installed, or other error — silent fallback
          res([]);
          return;
        }
        const lines = stdout
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l.length > 0);
        res(lines);
      },
    );
  });
}

// ── Public API ──

/**
 * Load gitignore filter for a project directory.
 *
 * Runs two git commands to determine:
 * 1. Which files are gitignored (ignored + untracked)
 * 2. Which files are simply untracked (not ignored, just not `git add`ed)
 *
 * Results are cached for the duration of a scan (keyed by resolved path).
 * Returns a no-op filter for non-git directories.
 */
export async function loadGitIgnoreFilter(projectDir: string): Promise<GitIgnoreFilter> {
  const resolvedDir = resolve(projectDir);

  // Check cache first — avoids running git twice for patterns + secrets scans
  const cached = filterCache.get(resolvedDir);
  if (cached) return cached;

  // Run both git commands in parallel
  const [ignoredFiles, untrackedFiles] = await Promise.all([
    // --others: only untracked files; --ignored: only ignored ones; --exclude-standard: use .gitignore + global excludes
    gitLsFiles(resolvedDir, ['--others', '--ignored', '--exclude-standard']),
    // --others: untracked files; --exclude-standard: respect .gitignore
    // This returns files that are untracked AND not ignored
    gitLsFiles(resolvedDir, ['--others', '--exclude-standard']),
  ]);

  // Build Sets of resolved absolute paths for O(1) lookups
  const ignoredSet = new Set<string>(
    ignoredFiles.map((f) => resolve(resolvedDir, f)),
  );
  const untrackedSet = new Set<string>(
    untrackedFiles.map((f) => resolve(resolvedDir, f)),
  );

  const filter: GitIgnoreFilter = {
    isGitIgnored(filePath: string): boolean {
      return ignoredSet.has(resolve(filePath));
    },
    isUntracked(filePath: string): boolean {
      return untrackedSet.has(resolve(filePath));
    },
  };

  // Cache for this scan session
  filterCache.set(resolvedDir, filter);

  return filter;
}

/**
 * Clear the gitignore filter cache.
 * Call between scans if needed, or let it persist for the CLI lifetime.
 */
export function clearGitIgnoreCache(): void {
  filterCache.clear();
}
