import { dbGetSourceMap } from '../db/sourcemap-repo.js';

/**
 * Attempt to resolve a minified stack frame back to its original source file.
 *
 * Strategy (Phase 4 — no VLQ decoding yet):
 *  1. Look for a source map at `file + '.map'`, then at `file` directly.
 *  2. If not found, return the frame unchanged.
 *  3. Parse the source map JSON; on failure, return unchanged (graceful degradation).
 *  4. Pick the first source that is NOT from node_modules.
 *  5. Strip leading relative-path prefixes (e.g. `../../`) from the source path.
 *  6. Return `{ file: cleanPath, line }` — line is preserved as-is (VLQ mapping deferred).
 */
export function resolveStackFrame(
  projectId: string,
  release: string,
  file: string,
  line: number,
  _column?: number,
): { file: string; line: number } {
  const fallback = { file, line };

  // 1. Locate the source map content.
  const rawMap =
    dbGetSourceMap(projectId, release, `${file}.map`) ?? dbGetSourceMap(projectId, release, file);

  if (rawMap === undefined) {
    return fallback;
  }

  // 2. Parse JSON; degrade gracefully on failure.
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawMap);
  } catch {
    return fallback;
  }

  // 3. Extract sources array.
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !Array.isArray((parsed as Record<string, unknown>)['sources'])
  ) {
    return fallback;
  }

  const sources = (parsed as Record<string, unknown>)['sources'] as unknown[];

  // 4. Find first source not from node_modules.
  const source = sources.find(
    (s): s is string => typeof s === 'string' && !s.includes('node_modules'),
  );

  if (source === undefined) {
    return fallback;
  }

  // 5. Strip leading relative path prefixes (../../ etc.).
  const cleanPath = source.replace(/^(\.\.\/)+/, '');

  return { file: cleanPath, line };
}
