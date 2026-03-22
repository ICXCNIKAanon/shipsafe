import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HOOK_MARKER } from '../constants.js';

const PRE_COMMIT_HOOK = `#!/bin/sh
${HOOK_MARKER}
# ShipSafe pre-commit hook — scans staged files before commit

SHIPSAFE=\$(command -v shipsafe 2>/dev/null)
if [ -z "\$SHIPSAFE" ]; then
  SHIPSAFE="npx shipsafe"
fi

echo "ShipSafe: Scanning staged files..."
\$SHIPSAFE scan --scope staged

EXIT_CODE=\$?
if [ \$EXIT_CODE -ne 0 ]; then
  echo ""
  echo "ShipSafe: Critical/high security issues found. Fix before committing."
  echo "To bypass (not recommended): git commit --no-verify"
  exit 1
fi

exit 0
`;

const PRE_PUSH_HOOK = `#!/bin/sh
${HOOK_MARKER}
# ShipSafe pre-push hook — runs full scan before push

SHIPSAFE=\$(command -v shipsafe 2>/dev/null)
if [ -z "\$SHIPSAFE" ]; then
  SHIPSAFE="npx shipsafe"
fi

echo "ShipSafe: Running full scan before push..."
\$SHIPSAFE scan --scope all

EXIT_CODE=\$?
if [ \$EXIT_CODE -ne 0 ]; then
  echo ""
  echo "ShipSafe: Critical/high security issues found. Fix before pushing."
  echo "To bypass (not recommended): git push --no-verify"
  exit 1
fi

exit 0
`;

const HOOKS: Array<{ name: string; content: string }> = [
  { name: 'pre-commit', content: PRE_COMMIT_HOOK },
  { name: 'pre-push', content: PRE_PUSH_HOOK },
];

async function getHooksDir(projectDir: string): Promise<string> {
  const gitDir = path.join(projectDir, '.git');
  try {
    const stat = await fs.stat(gitDir);
    if (!stat.isDirectory()) {
      throw new Error('Not a git repository');
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error('Not a git repository');
    }
    throw err;
  }
  return path.join(gitDir, 'hooks');
}

export interface InstallHooksOptions {
  /** When true, only install the pre-commit hook; skip pre-push. Default: false (install both). */
  commitOnly?: boolean;
}

export async function installHooks(projectDir?: string, options?: InstallHooksOptions): Promise<void> {
  const dir = projectDir ?? process.cwd();
  const hooksDir = await getHooksDir(dir);
  const commitOnly = options?.commitOnly ?? false;

  await fs.mkdir(hooksDir, { recursive: true });

  // Filter hooks based on options
  const hooksToInstall = commitOnly
    ? HOOKS.filter((h) => h.name !== 'pre-push')
    : HOOKS;

  for (const hook of hooksToInstall) {
    const hookPath = path.join(hooksDir, hook.name);
    const backupPath = path.join(hooksDir, `${hook.name}.pre-shipsafe`);

    // Check if hook file already exists
    let existingContent: string | null = null;
    try {
      existingContent = await fs.readFile(hookPath, 'utf-8');
    } catch {
      // File doesn't exist, that's fine
    }

    if (existingContent !== null && !existingContent.includes(HOOK_MARKER)) {
      // Existing non-ShipSafe hook — back it up
      await fs.writeFile(backupPath, existingContent);
    }

    // Write the ShipSafe hook
    await fs.writeFile(hookPath, hook.content, { mode: 0o755 });
  }
}

export async function uninstallHooks(projectDir?: string): Promise<void> {
  const dir = projectDir ?? process.cwd();

  let hooksDir: string;
  try {
    hooksDir = await getHooksDir(dir);
  } catch {
    // Not a git repo or no .git dir — nothing to uninstall
    return;
  }

  for (const hook of HOOKS) {
    const hookPath = path.join(hooksDir, hook.name);
    const backupPath = path.join(hooksDir, `${hook.name}.pre-shipsafe`);

    // Check if current hook is a ShipSafe hook
    let content: string | null = null;
    try {
      content = await fs.readFile(hookPath, 'utf-8');
    } catch {
      // Hook doesn't exist, skip
      continue;
    }

    if (content !== null && content.includes(HOOK_MARKER)) {
      // Remove the ShipSafe hook
      await fs.unlink(hookPath);

      // Restore backup if it exists
      try {
        const backup = await fs.readFile(backupPath, 'utf-8');
        await fs.writeFile(hookPath, backup, { mode: 0o755 });
        await fs.unlink(backupPath);
      } catch {
        // No backup to restore, that's fine
      }
    }
  }
}

export async function checkHooksInstalled(projectDir?: string): Promise<boolean> {
  const dir = projectDir ?? process.cwd();

  let hooksDir: string;
  try {
    hooksDir = await getHooksDir(dir);
  } catch {
    return false;
  }

  const preCommitPath = path.join(hooksDir, 'pre-commit');
  try {
    const content = await fs.readFile(preCommitPath, 'utf-8');
    return content.includes(HOOK_MARKER);
  } catch {
    return false;
  }
}
