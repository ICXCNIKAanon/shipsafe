import type { ScanResult, ScanScope } from '../../types.js';
import { runPatternEngine } from '../../engines/pattern/index.js';

export interface ScanParams {
  scope?: string;
  fix?: boolean;
  path?: string;
}

export async function handleScan(params: ScanParams): Promise<ScanResult> {
  const scope: ScanScope = (params.scope as ScanScope) ?? 'all';
  const targetPath = params.path ?? process.cwd();

  const result = await runPatternEngine({ targetPath, scope });

  return result;
}
