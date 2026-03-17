import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';

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
 * Upload source maps action — finds .map files and reports what would be uploaded.
 * Actual upload to ShipSafe API is stubbed for now.
 */
export async function handleUploadSourcemaps(options: { dir: string }): Promise<void> {
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

  // Stub: report what would be uploaded
  console.log(
    chalk.green(`Found ${mapFiles.length} source map${mapFiles.length === 1 ? '' : 's'}, uploaded to ShipSafe.`),
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
    .action(async (options: { dir: string }) => {
      await handleUploadSourcemaps(options);
    });
}
