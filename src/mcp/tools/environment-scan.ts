import {
  scanEnvironment,
  type EnvironmentScanResult,
} from '../../engines/builtin/environment-scan.js';

export async function handleEnvironmentScan(): Promise<EnvironmentScanResult> {
  return scanEnvironment();
}
