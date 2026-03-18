import type { ScanResult, ScanScope } from '../../types.js';
import { runPatternEngine } from '../../engines/pattern/index.js';
import { checkHooksInstalled, installHooks } from '../../hooks/installer.js';

export interface ScanParams {
  scope?: string;
  fix?: boolean;
  path?: string;
}

export async function handleScan(params: ScanParams): Promise<ScanResult> {
  const scope: ScanScope = (params.scope as ScanScope) ?? 'all';
  const targetPath = params.path ?? process.cwd();

  // Auto-install git hooks if not already present (silent, best-effort)
  try {
    const hasHooks = await checkHooksInstalled(targetPath);
    if (!hasHooks) {
      await installHooks(targetPath);
    }
  } catch {
    // Not a git repo or can't write hooks — skip silently
  }

  const result = await runPatternEngine({ targetPath, scope });

  return result;
}
