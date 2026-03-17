import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { detectAndRecommend, detectFramework } from '../../src/autofix/scaffolding.js';

let tmpDir: string;

async function createTmpDir(): Promise<string> {
  return await fs.mkdtemp(path.join(os.tmpdir(), 'shipsafe-scaffold-test-'));
}

async function writePackageJson(
  dir: string,
  deps: Record<string, string> = {},
  devDeps: Record<string, string> = {},
): Promise<void> {
  await fs.writeFile(
    path.join(dir, 'package.json'),
    JSON.stringify({
      name: 'test-project',
      dependencies: deps,
      devDependencies: devDeps,
    }),
    'utf-8',
  );
}

describe('detectFramework', () => {
  it('detects Express', () => {
    expect(detectFramework({ dependencies: { express: '^4.18.0' } })).toBe('express');
  });

  it('detects Next.js', () => {
    expect(detectFramework({ dependencies: { next: '^14.0.0', react: '^18.0.0' } })).toBe(
      'nextjs',
    );
  });

  it('detects Fastify', () => {
    expect(detectFramework({ dependencies: { fastify: '^4.0.0' } })).toBe('fastify');
  });

  it('detects Hono', () => {
    expect(detectFramework({ dependencies: { hono: '^3.0.0' } })).toBe('hono');
  });

  it('returns null for unknown frameworks', () => {
    expect(detectFramework({ dependencies: { lodash: '^4.0.0' } })).toBeNull();
  });

  it('returns null for empty dependencies', () => {
    expect(detectFramework({})).toBeNull();
  });

  it('prefers Next.js over Express when both present', () => {
    expect(
      detectFramework({ dependencies: { next: '^14.0.0', express: '^4.18.0' } }),
    ).toBe('nextjs');
  });
});

describe('detectAndRecommend', () => {
  beforeEach(async () => {
    tmpDir = await createTmpDir();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('detects Express project and recommends helmet', async () => {
    await writePackageJson(tmpDir, { express: '^4.18.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    expect(result!.framework).toBe('express');
    const helmetRec = result!.recommendations.find((r) => r.type === 'missing_helmet');
    expect(helmetRec).toBeDefined();
    expect(helmetRec!.priority).toBe('high');
    expect(helmetRec!.fix).toContain('helmet');
  });

  it('detects Next.js project and recommends CSP', async () => {
    await writePackageJson(tmpDir, { next: '^14.0.0', react: '^18.0.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    expect(result!.framework).toBe('nextjs');
    const cspRec = result!.recommendations.find((r) => r.type === 'missing_csp');
    expect(cspRec).toBeDefined();
    expect(cspRec!.priority).toBe('high');
    expect(cspRec!.fix).toContain('Content-Security-Policy');
  });

  it('detects missing .env in .gitignore', async () => {
    await writePackageJson(tmpDir, { express: '^4.18.0' });
    // No .gitignore file — .env is definitely not covered

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    const envRec = result!.recommendations.find((r) => r.type === 'missing_env_config');
    expect(envRec).toBeDefined();
    expect(envRec!.priority).toBe('high');
  });

  it('does not recommend missing_env_config when .env is in .gitignore', async () => {
    await writePackageJson(tmpDir, { express: '^4.18.0' });
    await fs.writeFile(path.join(tmpDir, '.gitignore'), '.env\nnode_modules\n', 'utf-8');

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    const envRec = result!.recommendations.find((r) => r.type === 'missing_env_config');
    expect(envRec).toBeUndefined();
  });

  it('returns null for unknown frameworks', async () => {
    await writePackageJson(tmpDir, { lodash: '^4.0.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).toBeNull();
  });

  it('returns null when no package.json exists', async () => {
    const result = await detectAndRecommend(tmpDir);

    expect(result).toBeNull();
  });

  it('does not recommend helmet when it is already installed', async () => {
    await writePackageJson(tmpDir, { express: '^4.18.0', helmet: '^7.0.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    const helmetRec = result!.recommendations.find((r) => r.type === 'missing_helmet');
    expect(helmetRec).toBeUndefined();
  });

  it('does not recommend cors when it is already installed', async () => {
    await writePackageJson(tmpDir, { express: '^4.18.0', cors: '^2.8.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    const corsRec = result!.recommendations.find((r) => r.type === 'missing_cors');
    expect(corsRec).toBeUndefined();
  });

  it('does not recommend rate-limit when express-rate-limit is installed', async () => {
    await writePackageJson(tmpDir, { express: '^4.18.0', 'express-rate-limit': '^7.0.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    const rateLimitRec = result!.recommendations.find((r) => r.type === 'missing_rate_limit');
    expect(rateLimitRec).toBeUndefined();
  });

  it('detects Fastify project and recommends @fastify/helmet', async () => {
    await writePackageJson(tmpDir, { fastify: '^4.0.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    expect(result!.framework).toBe('fastify');
    const helmetRec = result!.recommendations.find((r) => r.type === 'missing_helmet');
    expect(helmetRec).toBeDefined();
    expect(helmetRec!.fix).toContain('@fastify/helmet');
  });

  it('detects Hono project and recommends secure headers', async () => {
    await writePackageJson(tmpDir, { hono: '^3.0.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    expect(result!.framework).toBe('hono');
    const cspRec = result!.recommendations.find((r) => r.type === 'missing_csp');
    expect(cspRec).toBeDefined();
    expect(cspRec!.fix).toContain('secureHeaders');
  });

  it('returns recommendations with all required fields', async () => {
    await writePackageJson(tmpDir, { express: '^4.18.0' });

    const result = await detectAndRecommend(tmpDir);

    expect(result).not.toBeNull();
    for (const rec of result!.recommendations) {
      expect(rec).toHaveProperty('type');
      expect(rec).toHaveProperty('description');
      expect(rec).toHaveProperty('fix');
      expect(rec).toHaveProperty('file');
      expect(rec).toHaveProperty('priority');
      expect(['high', 'medium', 'low']).toContain(rec.priority);
    }
  });
});
