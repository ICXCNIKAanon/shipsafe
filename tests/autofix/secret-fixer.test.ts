import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import type { Finding } from '../../src/types.js';
import {
  fixHardcodedSecret,
  generateEnvVarName,
  ensureGitignoreHasEnv,
} from '../../src/autofix/secret-fixer.js';

let tmpDir: string;

async function createTmpDir(): Promise<string> {
  return await fs.mkdtemp(path.join(os.tmpdir(), 'shipsafe-secret-test-'));
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'sec_001',
    engine: 'pattern',
    severity: 'critical',
    type: 'hardcoded-secret',
    file: 'src/config.ts',
    line: 2,
    description: 'Hardcoded API key detected',
    fix_suggestion: 'Move secret to environment variable',
    auto_fixable: true,
    ...overrides,
  };
}

describe('generateEnvVarName', () => {
  it('converts camelCase context to UPPER_SNAKE_CASE', () => {
    expect(generateEnvVarName('api_key', 'supabaseKey')).toBe('SUPABASE_KEY');
  });

  it('handles hyphenated input', () => {
    expect(generateEnvVarName('api_key', 'aws-access-key')).toBe('AWS_ACCESS_KEY');
  });

  it('strips const/let/var prefixes', () => {
    expect(generateEnvVarName('api_key', 'const myApiKey')).toBe('MY_API_KEY');
  });

  it('returns SECRET_VALUE for empty context', () => {
    expect(generateEnvVarName('', '')).toBe('SECRET_VALUE');
  });

  it('handles PascalCase names', () => {
    expect(generateEnvVarName('token', 'DatabaseUrl')).toBe('DATABASE_URL');
  });

  it('takes the first identifier from an assignment', () => {
    expect(generateEnvVarName('api_key', 'apiKey = "abc"')).toBe('API_KEY');
  });
});

describe('ensureGitignoreHasEnv', () => {
  beforeEach(async () => {
    tmpDir = await createTmpDir();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('creates .gitignore with .env if it does not exist', async () => {
    const modified = await ensureGitignoreHasEnv(tmpDir);

    expect(modified).toBe(true);
    const content = await fs.readFile(path.join(tmpDir, '.gitignore'), 'utf-8');
    expect(content).toContain('.env');
  });

  it('appends .env to existing .gitignore', async () => {
    await fs.writeFile(path.join(tmpDir, '.gitignore'), 'node_modules\n', 'utf-8');

    const modified = await ensureGitignoreHasEnv(tmpDir);

    expect(modified).toBe(true);
    const content = await fs.readFile(path.join(tmpDir, '.gitignore'), 'utf-8');
    expect(content).toContain('node_modules');
    expect(content).toContain('.env');
  });

  it('does not duplicate .env entry', async () => {
    await fs.writeFile(path.join(tmpDir, '.gitignore'), '.env\nnode_modules\n', 'utf-8');

    const modified = await ensureGitignoreHasEnv(tmpDir);

    expect(modified).toBe(false);
    const content = await fs.readFile(path.join(tmpDir, '.gitignore'), 'utf-8');
    const envCount = content.split('\n').filter((l) => l.trim() === '.env').length;
    expect(envCount).toBe(1);
  });

  it('recognizes .env* pattern as already covered', async () => {
    await fs.writeFile(path.join(tmpDir, '.gitignore'), '.env*\n', 'utf-8');

    const modified = await ensureGitignoreHasEnv(tmpDir);

    expect(modified).toBe(false);
  });
});

describe('fixHardcodedSecret', () => {
  beforeEach(async () => {
    tmpDir = await createTmpDir();
    // Create src directory
    await fs.mkdir(path.join(tmpDir, 'src'), { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('moves a hardcoded secret to .env file', async () => {
    const sourceFile = path.join(tmpDir, 'src/config.ts');
    await fs.writeFile(
      sourceFile,
      `const config = {\n  apiKey: "AKIAIOSFODNN7EXAMPLE",\n};\n`,
      'utf-8',
    );

    const finding = makeFinding({ file: 'src/config.ts', line: 2 });
    const result = await fixHardcodedSecret(finding, tmpDir);

    // Check .env was created with the secret
    const envContent = await fs.readFile(path.join(tmpDir, '.env'), 'utf-8');
    expect(envContent).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(result.filesModified).toContain('.env');
    expect(result.envVarName).toBeTruthy();
  });

  it('replaces hardcoded value with process.env reference', async () => {
    const sourceFile = path.join(tmpDir, 'src/config.ts');
    await fs.writeFile(
      sourceFile,
      `const db = "init";\nconst apiKey = "sk_test_abc123xyz789";\nmodule.exports = apiKey;\n`,
      'utf-8',
    );

    const finding = makeFinding({ file: 'src/config.ts', line: 2 });
    const result = await fixHardcodedSecret(finding, tmpDir);

    const updated = await fs.readFile(sourceFile, 'utf-8');
    expect(updated).toContain('process.env.');
    expect(updated).not.toContain('"sk_test_abc123xyz789"');
    expect(result.filesModified).toContain('src/config.ts');
  });

  it('adds .env to .gitignore', async () => {
    const sourceFile = path.join(tmpDir, 'src/config.ts');
    await fs.writeFile(
      sourceFile,
      `const x = 1;\nconst token = "ghp_1234567890abcdef";\n`,
      'utf-8',
    );

    const finding = makeFinding({ file: 'src/config.ts', line: 2 });
    const result = await fixHardcodedSecret(finding, tmpDir);

    const gitignore = await fs.readFile(path.join(tmpDir, '.gitignore'), 'utf-8');
    expect(gitignore).toContain('.env');
    expect(result.filesModified).toContain('.gitignore');
  });

  it('does not duplicate .env in .gitignore when it already exists', async () => {
    const sourceFile = path.join(tmpDir, 'src/config.ts');
    await fs.writeFile(
      sourceFile,
      `const x = 1;\nconst secret = "mysupersecretvalue123";\n`,
      'utf-8',
    );
    await fs.writeFile(path.join(tmpDir, '.gitignore'), '.env\nnode_modules\n', 'utf-8');

    const finding = makeFinding({ file: 'src/config.ts', line: 2 });
    const result = await fixHardcodedSecret(finding, tmpDir);

    // .gitignore should NOT be in filesModified since it wasn't changed
    expect(result.filesModified).not.toContain('.gitignore');

    const gitignore = await fs.readFile(path.join(tmpDir, '.gitignore'), 'utf-8');
    const envCount = gitignore.split('\n').filter((l) => l.trim() === '.env').length;
    expect(envCount).toBe(1);
  });

  it('throws when target line does not exist', async () => {
    const sourceFile = path.join(tmpDir, 'src/config.ts');
    await fs.writeFile(sourceFile, 'const x = 1;\n', 'utf-8');

    const finding = makeFinding({ file: 'src/config.ts', line: 999 });

    await expect(fixHardcodedSecret(finding, tmpDir)).rejects.toThrow('Line 999 not found');
  });

  it('throws when no secret value can be extracted', async () => {
    const sourceFile = path.join(tmpDir, 'src/config.ts');
    await fs.writeFile(sourceFile, 'const x = 1;\nconst y = 2;\n', 'utf-8');

    const finding = makeFinding({ file: 'src/config.ts', line: 2 });

    await expect(fixHardcodedSecret(finding, tmpDir)).rejects.toThrow(
      'Could not extract secret value',
    );
  });

  it('returns the correct secretType based on the value', async () => {
    const sourceFile = path.join(tmpDir, 'src/config.ts');
    await fs.writeFile(
      sourceFile,
      `const x = 1;\nconst awsKey = "AKIAIOSFODNN7EXAMPLE";\n`,
      'utf-8',
    );

    const finding = makeFinding({ file: 'src/config.ts', line: 2 });
    const result = await fixHardcodedSecret(finding, tmpDir);

    expect(result.secretType).toBe('aws_access_key');
  });
});
