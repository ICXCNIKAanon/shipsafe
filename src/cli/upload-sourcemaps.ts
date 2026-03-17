import * as fs from 'node:fs/promises';
import { readFileSync, existsSync } from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig } from '../../src/config/manager.js';

/**
 * Recursively find all .map files in a directory.
 */
async function findSourceMaps(dir: string): Promise<string[]> {
  const results: string[] = [];

  let names: string[];
  try {
    names = await fs.readdir(dir);
  } catch {
    return results;
  }

  for (const name of names) {
    const fullPath = path.join(dir, name);
    try {
      const stat = await fs.stat(fullPath);
      if (stat.isDirectory()) {
        // Skip node_modules
        if (name === 'node_modules') continue;
        const nested = await findSourceMaps(fullPath);
        results.push(...nested);
      } else if (name.endsWith('.map')) {
        results.push(fullPath);
      }
    } catch {
      // Skip files we can't stat
    }
  }

  return results;
}

/**
 * Reads the version field from package.json in the current working directory.
 * Returns undefined if package.json is absent or has no version field.
 */
function readVersionFromPackageJson(): string | undefined {
  const pkgPath = path.join(process.cwd(), 'package.json');
  try {
    if (existsSync(pkgPath)) {
      const raw = readFileSync(pkgPath, 'utf-8');
      const pkg = JSON.parse(raw) as { version?: string };
      return pkg.version ?? undefined;
    }
  } catch {
    // ignore
  }
  return undefined;
}

/**
 * Upload source maps action — finds .map files and uploads them to the ShipSafe API.
 */
export async function handleUploadSourcemaps(options: {
  dir: string;
  release?: string;
}): Promise<void> {
  const targetDir = path.resolve(process.cwd(), options.dir);

  // Verify directory exists
  try {
    const stat = await fs.stat(targetDir);
    if (!stat.isDirectory()) {
      console.error(chalk.red(`Error: ${options.dir} is not a directory`));
      return;
    }
  } catch {
    console.error(chalk.red(`Error: Directory ${options.dir} does not exist`));
    console.log(`Run your build first, then try again.`);
    return;
  }

  console.log(chalk.bold(`Scanning ${options.dir} for source maps...\n`));

  const mapFiles = await findSourceMaps(targetDir);

  if (mapFiles.length === 0) {
    console.log(chalk.yellow('No source map files (.map) found.'));
    console.log(`Ensure your build is configured to emit source maps.`);
    return;
  }

  // List found files
  for (const file of mapFiles) {
    const relative = path.relative(process.cwd(), file);
    console.log(`  ${chalk.cyan(relative)}`);
  }

  console.log('');

  // Load config
  const config = await loadConfig();

  if (!config.apiEndpoint || !config.projectId) {
    console.log(
      chalk.yellow(
        'Warning: No API endpoint or project ID configured. Run `shipsafe setup` to connect.',
      ),
    );
    return;
  }

  // Determine release version
  const release = options.release ?? readVersionFromPackageJson() ?? 'unknown';

  // Read all .map file contents
  const sourceMaps: Array<{ file_path: string; source_map: string }> = [];
  for (const file of mapFiles) {
    const relativePath = path.relative(process.cwd(), file);
    const content = await fs.readFile(file, 'utf-8');
    sourceMaps.push({ file_path: relativePath, source_map: content });
  }

  // Build request headers
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (config.licenseKey) {
    headers['Authorization'] = `Bearer ${config.licenseKey}`;
  }

  // POST to API
  const url = `${config.apiEndpoint}/v1/sourcemaps/batch`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        project_id: config.projectId,
        release,
        source_maps: sourceMaps,
      }),
    });
  } catch (err) {
    console.error(chalk.red(`Upload failed: ${(err as Error).message}`));
    return;
  }

  if (!response.ok) {
    const text = await response.text();
    console.error(chalk.red(`Upload failed (${response.status}): ${text}`));
    return;
  }

  console.log(
    chalk.green(
      `Found ${mapFiles.length} source map${mapFiles.length === 1 ? '' : 's'}, uploaded to ShipSafe.`,
    ),
  );
}

/**
 * Register the 'upload-sourcemaps' command with the CLI program.
 */
export function registerUploadSourcemapsCommand(program: Command): void {
  program
    .command('upload-sourcemaps')
    .description('Upload source maps for production stack trace resolution')
    .option('--dir <dir>', 'Directory containing source maps', './dist')
    .option('--release <version>', 'Release version tag for the source maps')
    .action(async (options: { dir: string; release?: string }) => {
      // Default release to package.json version if not specified
      const release = options.release ?? readVersionFromPackageJson() ?? 'unknown';
      await handleUploadSourcemaps({ dir: options.dir, release });
    });
}
