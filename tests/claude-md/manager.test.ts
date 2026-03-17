import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { injectClaudeMd, removeClaudeMd, hasClaudeMdBlock } from '../../src/claude-md/manager.js';
import { CLAUDE_MD_START, CLAUDE_MD_END } from '../../src/constants.js';

async function makeTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(tmpdir(), 'shipsafe-claudemd-test-'));
}

async function rmDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe('injectClaudeMd', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('creates CLAUDE.md if it does not exist', async () => {
    await injectClaudeMd(tmpProject);

    const filePath = path.join(tmpProject, 'CLAUDE.md');
    const stat = await fs.stat(filePath);
    expect(stat.isFile()).toBe(true);
  });

  it('created file contains the ShipSafe template between sentinels', async () => {
    await injectClaudeMd(tmpProject);

    const content = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');
    expect(content).toContain(CLAUDE_MD_START);
    expect(content).toContain(CLAUDE_MD_END);
    expect(content).toContain('# ShipSafe Security & Monitoring Agent');
    expect(content).toContain('shipsafe_scan');
    expect(content).toContain('shipsafe_status');
    expect(content).toContain('shipsafe_check_package');
  });

  it('template is under 50 lines including sentinels', async () => {
    await injectClaudeMd(tmpProject);

    const content = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');
    const startIdx = content.indexOf(CLAUDE_MD_START);
    const endIdx = content.indexOf(CLAUDE_MD_END) + CLAUDE_MD_END.length;
    const block = content.substring(startIdx, endIdx);
    const lineCount = block.split('\n').length;
    expect(lineCount).toBeLessThanOrEqual(50);
  });

  it('appends to existing CLAUDE.md without modifying existing content', async () => {
    const existingContent = '# My Project\n\nSome existing instructions.\n';
    await fs.writeFile(path.join(tmpProject, 'CLAUDE.md'), existingContent);

    await injectClaudeMd(tmpProject);

    const content = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');
    // Existing content is preserved at the top
    expect(content).toContain('# My Project');
    expect(content).toContain('Some existing instructions.');
    // ShipSafe block is appended
    expect(content).toContain(CLAUDE_MD_START);
    expect(content).toContain(CLAUDE_MD_END);
    // There should be a blank line separating existing content from the ShipSafe block
    expect(content).toContain('Some existing instructions.\n\n' + CLAUDE_MD_START);
  });

  it('replaces existing ShipSafe block (update scenario)', async () => {
    // Write file with an outdated ShipSafe block
    const oldBlock = `${CLAUDE_MD_START}\n# Old ShipSafe content\nThis is outdated.\n${CLAUDE_MD_END}`;
    const existingContent = `# My Project\n\n${oldBlock}\n`;
    await fs.writeFile(path.join(tmpProject, 'CLAUDE.md'), existingContent);

    await injectClaudeMd(tmpProject);

    const content = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');
    // Old content should be gone
    expect(content).not.toContain('Old ShipSafe content');
    expect(content).not.toContain('This is outdated.');
    // New template should be present
    expect(content).toContain('# ShipSafe Security & Monitoring Agent');
    // Existing project content preserved
    expect(content).toContain('# My Project');
    // Only one start sentinel
    const startCount = content.split(CLAUDE_MD_START).length - 1;
    expect(startCount).toBe(1);
  });

  it('is idempotent — running twice produces same result', async () => {
    await injectClaudeMd(tmpProject);
    const firstContent = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');

    await injectClaudeMd(tmpProject);
    const secondContent = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');

    expect(firstContent).toBe(secondContent);
  });
});

describe('removeClaudeMd', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('removes ShipSafe block and preserves the rest', async () => {
    const existingContent = '# My Project\n\nSome instructions.\n';
    await fs.writeFile(path.join(tmpProject, 'CLAUDE.md'), existingContent);

    // Inject then remove
    await injectClaudeMd(tmpProject);
    await removeClaudeMd(tmpProject);

    const content = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');
    expect(content).toContain('# My Project');
    expect(content).toContain('Some instructions.');
    expect(content).not.toContain(CLAUDE_MD_START);
    expect(content).not.toContain(CLAUDE_MD_END);
    expect(content).not.toContain('ShipSafe');
  });

  it('deletes empty CLAUDE.md after removal', async () => {
    // Create CLAUDE.md with only the ShipSafe block
    await injectClaudeMd(tmpProject);
    await removeClaudeMd(tmpProject);

    const filePath = path.join(tmpProject, 'CLAUDE.md');
    await expect(fs.access(filePath)).rejects.toThrow();
  });

  it('cleans up double blank lines left behind', async () => {
    const existingContent = '# My Project\n\nSome instructions.\n';
    await fs.writeFile(path.join(tmpProject, 'CLAUDE.md'), existingContent);

    await injectClaudeMd(tmpProject);
    await removeClaudeMd(tmpProject);

    const content = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');
    // Should not have triple+ newlines (double blank lines)
    expect(content).not.toMatch(/\n{3,}/);
  });

  it('does nothing when CLAUDE.md does not exist', async () => {
    // Should not throw
    await expect(removeClaudeMd(tmpProject)).resolves.toBeUndefined();
  });

  it('does nothing when CLAUDE.md has no ShipSafe block', async () => {
    const content = '# My Project\n\nNo ShipSafe here.\n';
    await fs.writeFile(path.join(tmpProject, 'CLAUDE.md'), content);

    await removeClaudeMd(tmpProject);

    const after = await fs.readFile(path.join(tmpProject, 'CLAUDE.md'), 'utf-8');
    expect(after).toBe(content);
  });
});

describe('hasClaudeMdBlock', () => {
  let tmpProject: string;

  beforeEach(async () => {
    tmpProject = await makeTmpDir();
  });

  afterEach(async () => {
    await rmDir(tmpProject);
  });

  it('returns true when ShipSafe block exists', async () => {
    await injectClaudeMd(tmpProject);
    const result = await hasClaudeMdBlock(tmpProject);
    expect(result).toBe(true);
  });

  it('returns false when no ShipSafe block exists', async () => {
    const content = '# My Project\n\nNo ShipSafe here.\n';
    await fs.writeFile(path.join(tmpProject, 'CLAUDE.md'), content);

    const result = await hasClaudeMdBlock(tmpProject);
    expect(result).toBe(false);
  });

  it('returns false when CLAUDE.md does not exist', async () => {
    const result = await hasClaudeMdBlock(tmpProject);
    expect(result).toBe(false);
  });
});
