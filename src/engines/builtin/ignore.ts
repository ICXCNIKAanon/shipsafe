/**
 * .shipsafeignore support — gitignore-style file exclusion.
 * Reads .shipsafeignore from the project root and filters file paths.
 */

import { readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

export interface IgnoreFilter {
  /** Returns true if the file should be ignored (skipped). */
  isIgnored(filePath: string): boolean;
}

/**
 * Parse a .shipsafeignore file into glob patterns.
 * Supports: file paths, directory paths, glob patterns, comments (#), negation (!).
 */
function parseIgnorePatterns(content: string): Array<{ pattern: RegExp; negated: boolean }> {
  const rules: Array<{ pattern: RegExp; negated: boolean }> = [];

  for (let line of content.split('\n')) {
    line = line.trim();
    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;

    let negated = false;
    if (line.startsWith('!')) {
      negated = true;
      line = line.slice(1);
    }

    // Convert glob pattern to regex
    const regex = globToRegex(line);
    rules.push({ pattern: regex, negated });
  }

  return rules;
}

function globToRegex(glob: string): RegExp {
  let regex = '';
  let i = 0;

  // If pattern starts with /, anchor to root
  const anchored = glob.startsWith('/');
  if (anchored) glob = glob.slice(1);

  // If pattern ends with /, match directory (and everything inside)
  const dirOnly = glob.endsWith('/');
  if (dirOnly) glob = glob.slice(0, -1);

  while (i < glob.length) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        // ** matches any number of directories
        if (glob[i + 2] === '/') {
          regex += '(?:.*/)?';
          i += 3;
        } else {
          regex += '.*';
          i += 2;
        }
      } else {
        // * matches anything except /
        regex += '[^/]*';
        i++;
      }
    } else if (ch === '?') {
      regex += '[^/]';
      i++;
    } else if (ch === '.') {
      regex += '\\.';
      i++;
    } else {
      regex += ch;
      i++;
    }
  }

  if (dirOnly) {
    regex += '(?:/.*)?';
  }

  // If not anchored and doesn't contain /, match basename anywhere
  if (!anchored && !glob.includes('/')) {
    return new RegExp(`(?:^|/)${regex}(?:$|/)`, 'i');
  }

  return new RegExp(`^${regex}(?:$|/)`, 'i');
}

/**
 * Load .shipsafeignore from a project directory and return a filter function.
 * Returns a no-op filter if the file doesn't exist.
 */
export async function loadIgnoreFilter(projectDir: string): Promise<IgnoreFilter> {
  const ignorePath = join(projectDir, '.shipsafeignore');

  let content: string;
  try {
    content = await readFile(ignorePath, 'utf-8');
  } catch {
    // No .shipsafeignore — nothing is ignored
    return { isIgnored: () => false };
  }

  const rules = parseIgnorePatterns(content);
  if (rules.length === 0) {
    return { isIgnored: () => false };
  }

  return {
    isIgnored(filePath: string): boolean {
      // Normalize to relative path
      const rel = relative(projectDir, filePath) || filePath;

      let ignored = false;
      for (const rule of rules) {
        if (rule.pattern.test(rel)) {
          ignored = !rule.negated;
        }
      }
      return ignored;
    },
  };
}
