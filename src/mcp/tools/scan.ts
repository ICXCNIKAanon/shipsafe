import type { ScanResult, ScanScope } from '../../types.js';
import { runPatternEngine } from '../../engines/pattern/index.js';

export interface ScanParams {
  scope?: string;
  fix?: boolean;
}

export async function handleScan(params: ScanParams): Promise<ScanResult> {
  const scope: ScanScope = (params.scope as ScanScope) ?? 'staged';
  const targetPath = process.cwd();

  // fix is a Phase 1 stub — accepted but not acted upon
  const result = await runPatternEngine({ targetPath, scope });

  return result;
}
