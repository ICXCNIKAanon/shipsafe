import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { CLAUDE_MD_START, CLAUDE_MD_END } from '../constants.js';

const SHIPSAFE_TEMPLATE = `${CLAUDE_MD_START}
# ShipSafe Security

When committing code, call the \`shipsafe_scan\` MCP tool first. It auto-installs git hooks on first run. Do not skip this step — use the MCP tool, not manual code review. Other tools: \`shipsafe_status\`, \`shipsafe_check_package\`.
${CLAUDE_MD_END}`;

/**
 * Injects or updates the ShipSafe instruction block in a project's CLAUDE.md file.
 * - If CLAUDE.md doesn't exist, creates it with just the ShipSafe block.
 * - If it exists but has no ShipSafe block, appends the block.
 * - If it exists and has a ShipSafe block, replaces it with the latest template.
 */
export async function injectClaudeMd(projectDir?: string): Promise<void> {
  const dir = projectDir ?? process.cwd();
  const filePath = path.join(dir, 'CLAUDE.md');

  let existing: string | null = null;
  try {
    existing = await fs.readFile(filePath, 'utf-8');
  } catch {
    // File doesn't exist
  }

  if (existing === null) {
    // No file — create with just the block
    await fs.writeFile(filePath, SHIPSAFE_TEMPLATE + '\n', 'utf-8');
    return;
  }

  if (existing.includes(CLAUDE_MD_START)) {
    // Replace existing block
    const startIdx = existing.indexOf(CLAUDE_MD_START);
    const endIdx = existing.indexOf(CLAUDE_MD_END);
    if (endIdx === -1) {
      // Malformed — has start but no end. Replace from start to EOF.
      const before = existing.substring(0, startIdx);
      await fs.writeFile(filePath, before + SHIPSAFE_TEMPLATE + '\n', 'utf-8');
      return;
    }
    const before = existing.substring(0, startIdx);
    const after = existing.substring(endIdx + CLAUDE_MD_END.length);
    await fs.writeFile(filePath, before + SHIPSAFE_TEMPLATE + after, 'utf-8');
  } else {
    // Append with blank line separator
    const separator = existing.endsWith('\n') ? '\n' : '\n\n';
    await fs.writeFile(filePath, existing + separator + SHIPSAFE_TEMPLATE + '\n', 'utf-8');
  }
}

/**
 * Removes the ShipSafe block from CLAUDE.md, preserving the rest.
 * Deletes the file if it would be empty after removal.
 */
export async function removeClaudeMd(projectDir?: string): Promise<void> {
  const dir = projectDir ?? process.cwd();
  const filePath = path.join(dir, 'CLAUDE.md');

  let content: string;
  try {
    content = await fs.readFile(filePath, 'utf-8');
  } catch {
    // File doesn't exist — nothing to do
    return;
  }

  if (!content.includes(CLAUDE_MD_START)) {
    // No ShipSafe block — nothing to do
    return;
  }

  const startIdx = content.indexOf(CLAUDE_MD_START);
  const endIdx = content.indexOf(CLAUDE_MD_END);
  if (endIdx === -1) {
    // Malformed — has start but no end. Remove from start to EOF.
    const before = content.substring(0, startIdx);
    const trimmed = before.replace(/\n+$/, '');
    if (trimmed.length === 0) {
      await fs.unlink(filePath);
    } else {
      await fs.writeFile(filePath, trimmed + '\n', 'utf-8');
    }
    return;
  }

  const before = content.substring(0, startIdx);
  const after = content.substring(endIdx + CLAUDE_MD_END.length);

  let result = before + after;

  // Clean up multiple consecutive blank lines (3+ newlines -> 2 newlines)
  result = result.replace(/\n{3,}/g, '\n\n');

  // Trim trailing whitespace
  result = result.replace(/\s+$/, '');

  if (result.length === 0) {
    await fs.unlink(filePath);
  } else {
    await fs.writeFile(filePath, result + '\n', 'utf-8');
  }
}

/**
 * Checks whether CLAUDE.md contains a ShipSafe instruction block.
 */
export async function hasClaudeMdBlock(projectDir?: string): Promise<boolean> {
  const dir = projectDir ?? process.cwd();
  const filePath = path.join(dir, 'CLAUDE.md');

  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return content.includes(CLAUDE_MD_START);
  } catch {
    return false;
  }
}
