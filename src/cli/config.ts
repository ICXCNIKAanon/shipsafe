import { Command } from 'commander';
import {
  loadConfig,
  loadGlobalConfig,
  saveGlobalConfig,
  saveProjectConfig,
} from '../config/manager.js';
import type { ShipSafeConfig } from '../types.js';

export interface ConfigSetOptions {
  global: boolean;
}

/**
 * Traverses a nested object using dot-separated key path.
 * Returns the value at the path, or undefined if any segment is missing.
 */
function getNestedValue(obj: Record<string, unknown>, keyPath: string): unknown {
  const segments = keyPath.split('.');
  let current: unknown = obj;

  for (const segment of segments) {
    if (current === null || current === undefined || typeof current !== 'object' || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }

  return current;
}

/**
 * Sets a value on a nested object using dot-separated key path.
 * Creates intermediate objects as needed.
 */
function setNestedValue(obj: Record<string, unknown>, keyPath: string, value: unknown): void {
  const segments = keyPath.split('.');
  let current = obj;

  for (let i = 0; i < segments.length - 1; i++) {
    const segment = segments[i];
    if (current[segment] === null || current[segment] === undefined || typeof current[segment] !== 'object' || Array.isArray(current[segment])) {
      current[segment] = {};
    }
    current = current[segment] as Record<string, unknown>;
  }

  current[segments[segments.length - 1]] = value;
}

/**
 * Parses a string value into the appropriate type:
 * "true" → true, "false" → false, numeric strings → numbers, otherwise string.
 */
function parseValue(raw: string): unknown {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  const num = Number(raw);
  if (!isNaN(num) && raw.trim() !== '') return num;
  return raw;
}

/**
 * Formats a value for console output:
 * Objects/arrays → JSON.stringify, primitives → String().
 */
function formatValue(value: unknown): string {
  if (value !== null && value !== undefined && typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

/**
 * Shows the full merged config (defaults < global < project).
 */
export async function handleConfigList(): Promise<void> {
  const config = await loadConfig();
  console.log(JSON.stringify(config, null, 2));
}

/**
 * Gets a specific config value by dot-notation key.
 * Exits with code 1 if the key is not found.
 */
export async function handleConfigGet(key: string): Promise<void> {
  const config = await loadConfig();
  const value = getNestedValue(config as Record<string, unknown>, key);

  if (value === undefined) {
    console.log(`Key not found: ${key}`);
    process.exit(1);
    return;
  }

  console.log(formatValue(value));
}

/**
 * Sets a config value by dot-notation key.
 * Reads the existing config, merges the new value, and saves.
 * Saves to global config if --global flag is set, otherwise project config.
 */
export async function handleConfigSet(
  key: string,
  rawValue: string,
  options: ConfigSetOptions,
): Promise<void> {
  const parsedValue = parseValue(rawValue);
  const location = options.global ? 'global' : 'project';

  let existing: ShipSafeConfig;
  if (options.global) {
    existing = await loadGlobalConfig();
  } else {
    existing = await loadConfig();
  }

  // Deep-clone to avoid mutating the returned config object
  const config = JSON.parse(JSON.stringify(existing)) as Record<string, unknown>;
  setNestedValue(config, key, parsedValue);

  if (options.global) {
    await saveGlobalConfig(config as Partial<ShipSafeConfig>);
  } else {
    await saveProjectConfig(config as Partial<ShipSafeConfig>);
  }

  console.log(`Set ${key} = ${formatValue(parsedValue)} in ${location} config`);
}

export function registerConfigCommand(program: Command): void {
  const configCmd = program
    .command('config')
    .description('View and set ShipSafe configuration');

  configCmd
    .command('list')
    .description('Show merged config (all values)')
    .action(async () => {
      await handleConfigList();
    });

  configCmd
    .command('get <key>')
    .description('Get a specific config value (supports dot notation: monitoring.enabled)')
    .action(async (key: string) => {
      await handleConfigGet(key);
    });

  configCmd
    .command('set <key> <value>')
    .description('Set a config value (supports dot notation; use --global for global config)')
    .option('--global', 'Save to global config (~/.shipsafe/config.json)', false)
    .action(async (key: string, value: string, options: ConfigSetOptions) => {
      await handleConfigSet(key, value, options);
    });
}
