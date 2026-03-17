import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { CLAUDE_MD_START, CLAUDE_MD_END } from '../constants.js';

const SHIPSAFE_TEMPLATE = `${CLAUDE_MD_START}
# ShipSafe Security & Monitoring Agent

## Session Start (MANDATORY)
At the start of EVERY session, do the following:
1. Ask the user: "ShipSafe is active on this project. Keep security protection enabled? (yes/no)"
2. If yes: call the \`shipsafe_status\` tool to check project state and queued production errors
3. If there are queued production errors, present them to the user and offer to fix them BEFORE starting new work
4. Print the one-line status: "ShipSafe: [score] | [issue count] issues | [error count] production errors"

## Rules (Active Copilot Mode - user said yes)

### Pre-Commit
- Before EVERY git commit, call \`shipsafe_scan\` and wait for results
- If critical or high issues are found, fix them before committing. Do NOT commit with unresolved critical/high findings.
- If medium/low issues are found, inform the user and let them decide

### Security Practices
- NEVER hardcode API keys, tokens, secrets, or credentials. Always use environment variables.
- If you detect a hardcoded secret, move it to .env, add .env to .gitignore, and replace with process.env reference
- When installing packages, call \`shipsafe_check_package\` to verify safety before installing
- Use parameterized queries. Never concatenate user input into SQL strings.

### Monitoring
- If this project does not have the ShipSafe monitoring snippet installed and it is a deployable web application, add it
- Do NOT remove or modify the ShipSafe monitoring snippet or git hooks

### Production Errors
- When production errors are delivered at session start, address them BEFORE working on new features
- Use the full context provided (stack trace, root cause, suggested fix)
- After fixing a production error, inform the user what was fixed and why

## Rules (Silent Guardian Mode - user said no)
- ShipSafe tools are available but do not proactively use them
- Git hooks will still run on commit/push
- Do NOT ask the user about ShipSafe again during this session
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
