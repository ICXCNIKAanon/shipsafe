import * as fs from 'node:fs/promises';
import { readFileSync, existsSync } from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { ShipSafeConfig } from '../types.js';
import { GLOBAL_DIR_NAME, CONFIG_FILE, DEFAULT_CONFIG, DEFAULT_API_URL } from '../constants.js';

/**
 * Deep merge two objects. Source values override target values.
 * Arrays are replaced, not concatenated.
 */
function deepMerge(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...target };

  for (const key of Object.keys(source)) {
    const sourceVal = source[key];
    const targetVal = result[key];

    if (
      sourceVal !== null &&
      sourceVal !== undefined &&
      typeof sourceVal === 'object' &&
      !Array.isArray(sourceVal) &&
      targetVal !== null &&
      targetVal !== undefined &&
      typeof targetVal === 'object' &&
      !Array.isArray(targetVal)
    ) {
      result[key] = deepMerge(
        targetVal as Record<string, unknown>,
        sourceVal as Record<string, unknown>,
      );
    } else {
      result[key] = sourceVal;
    }
  }

  return result;
}

/**
 * Returns the path to the global ShipSafe config directory (~/.shipsafe).
 */
export function getGlobalConfigDir(): string {
  return path.join(os.homedir(), GLOBAL_DIR_NAME);
}

/**
 * Reads a JSON config file and returns the parsed contents, or an empty
 * object if the file does not exist or cannot be parsed.
 */
async function readConfigFile(filePath: string): Promise<Partial<ShipSafeConfig>> {
  try {
    const raw = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(raw) as Partial<ShipSafeConfig>;
  } catch {
    return {};
  }
}

/**
 * Reads the global config from ~/.shipsafe/config.json.
 * Returns defaults if the file is missing.
 */
export async function loadGlobalConfig(): Promise<ShipSafeConfig> {
  const configPath = path.join(getGlobalConfigDir(), 'config.json');
  const raw = await readConfigFile(configPath);
  return deepMerge(
    { ...DEFAULT_CONFIG } as Record<string, unknown>,
    raw as Record<string, unknown>,
  ) as ShipSafeConfig;
}

/**
 * Reads the project config from <projectDir>/shipsafe.config.json.
 * Returns defaults if the file is missing.
 */
export async function loadProjectConfig(projectDir?: string): Promise<ShipSafeConfig> {
  const dir = projectDir ?? process.cwd();
  const configPath = path.join(dir, CONFIG_FILE);
  const raw = await readConfigFile(configPath);
  return deepMerge(
    { ...DEFAULT_CONFIG } as Record<string, unknown>,
    raw as Record<string, unknown>,
  ) as ShipSafeConfig;
}

/**
 * Merges global and project configs. Project config overrides global config.
 * Merge order: defaults < global < project.
 */
export async function loadConfig(projectDir?: string): Promise<ShipSafeConfig> {
  const globalConfigPath = path.join(getGlobalConfigDir(), 'config.json');
  const dir = projectDir ?? process.cwd();
  const projectConfigPath = path.join(dir, CONFIG_FILE);

  const globalRaw = await readConfigFile(globalConfigPath);
  const projectRaw = await readConfigFile(projectConfigPath);

  // Three-way merge: defaults < global raw < project raw
  const withGlobal = deepMerge(
    { ...DEFAULT_CONFIG } as Record<string, unknown>,
    globalRaw as Record<string, unknown>,
  );
  return deepMerge(
    withGlobal,
    projectRaw as Record<string, unknown>,
  ) as ShipSafeConfig;
}

/**
 * Returns the API endpoint. Priority: SHIPSAFE_API_URL env var > config value > default.
 */
export function getApiEndpoint(config?: Pick<ShipSafeConfig, 'apiEndpoint'>): string {
  return process.env.SHIPSAFE_API_URL ?? config?.apiEndpoint ?? DEFAULT_API_URL;
}

/**
 * Writes config to ~/.shipsafe/config.json, creating the directory if needed.
 */
export async function saveGlobalConfig(config: Partial<ShipSafeConfig>): Promise<void> {
  const dir = getGlobalConfigDir();
  await fs.mkdir(dir, { recursive: true });
  const configPath = path.join(dir, 'config.json');
  await fs.writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
}

/**
 * Writes config to <projectDir>/shipsafe.config.json.
 */
export async function saveProjectConfig(
  config: Partial<ShipSafeConfig>,
  projectDir?: string,
): Promise<void> {
  const dir = projectDir ?? process.cwd();
  const configPath = path.join(dir, CONFIG_FILE);
  await fs.writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
}

/**
 * Derives project name from package.json name field or falls back to directory name.
 */
export function getProjectName(projectDir?: string): string {
  const dir = projectDir ?? process.cwd();
  const pkgPath = path.join(dir, 'package.json');

  try {
    if (existsSync(pkgPath)) {
      const raw = readFileSync(pkgPath, 'utf-8');
      const pkg = JSON.parse(raw) as { name?: string };
      if (pkg.name) {
        return pkg.name;
      }
    }
  } catch {
    // fall through to directory name
  }

  return path.basename(dir);
}
