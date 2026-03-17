import type { ScannerAvailability } from '../../types.js';
import { getProjectName, loadConfig } from '../../config/manager.js';
import { checkHooksInstalled } from '../../hooks/installer.js';
import { getAvailableScanners } from '../../engines/pattern/index.js';

export interface McpProjectStatus {
  project: string;
  hooks_installed: boolean;
  scanners: ScannerAvailability;
  license: string;
}

export async function handleStatus(): Promise<McpProjectStatus> {
  const projectDir = process.cwd();
  const projectName = getProjectName(projectDir);
  const hooksInstalled = await checkHooksInstalled(projectDir);
  const scanners = await getAvailableScanners();
  const config = await loadConfig(projectDir);

  const license = config.licenseKey ? 'pro' : 'free';

  return {
    project: projectName,
    hooks_installed: hooksInstalled,
    scanners,
    license,
  };
}
