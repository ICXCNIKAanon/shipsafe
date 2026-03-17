import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type { Finding } from '../types.js';

export interface SecretFix {
  file: string;
  line: number;
  secretType: string; // 'api_key', 'database_url', 'token', etc.
  envVarName: string; // e.g., 'SUPABASE_KEY'
  filesModified: string[]; // [original file, .env, .gitignore]
}

/**
 * Generate an appropriate env var name from the secret type and surrounding context.
 */
export function generateEnvVarName(secretType: string, context: string): string {
  // Combine type and context, remove non-alphanumeric chars, convert to UPPER_SNAKE_CASE
  let raw = context || secretType;

  // Remove common prefixes like 'const', 'let', 'var'
  raw = raw.replace(/^(?:const|let|var)\s+/, '');

  // Take just the first identifier if there's an assignment (include hyphens for kebab-case)
  const identMatch = raw.match(/^([\w-]+)/);
  if (identMatch) {
    raw = identMatch[1];
  }

  // Convert camelCase / PascalCase to UPPER_SNAKE_CASE
  const snaked = raw
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]/g, '_')
    .toUpperCase();

  // Remove leading/trailing underscores
  const cleaned = snaked.replace(/^_+|_+$/g, '').replace(/_+/g, '_');

  return cleaned || 'SECRET_VALUE';
}

/**
 * Detect the type of secret from the value or context.
 */
export function detectSecretType(value: string, context: string): string {
  const lower = (value + ' ' + context).toLowerCase();

  if (/AKIA[0-9A-Z]{16}/.test(value)) return 'aws_access_key';
  if (lower.includes('database') || lower.includes('postgres') || lower.includes('mysql'))
    return 'database_url';
  if (lower.includes('stripe') && lower.includes('sk_')) return 'stripe_secret_key';
  if (lower.includes('supabase')) return 'supabase_key';
  if (lower.includes('firebase')) return 'firebase_key';
  if (lower.includes('jwt') || lower.includes('token')) return 'token';
  if (lower.includes('password') || lower.includes('passwd')) return 'password';
  if (lower.includes('key') || lower.includes('apikey') || lower.includes('api_key'))
    return 'api_key';
  if (lower.includes('secret')) return 'secret';

  return 'api_key';
}

/**
 * Ensure .env is in .gitignore. Creates .gitignore if it doesn't exist.
 * Returns true if .gitignore was modified, false if .env was already present.
 */
export async function ensureGitignoreHasEnv(projectDir?: string): Promise<boolean> {
  const dir = projectDir ?? process.cwd();
  const gitignorePath = path.join(dir, '.gitignore');

  let content = '';
  try {
    content = await fs.readFile(gitignorePath, 'utf-8');
  } catch {
    // .gitignore doesn't exist — we'll create it
  }

  // Check if .env is already covered
  const lines = content.split('\n');
  const hasEnv = lines.some((line) => {
    const trimmed = line.trim();
    return trimmed === '.env' || trimmed === '.env*' || trimmed === '.env.*';
  });

  if (hasEnv) return false;

  // Append .env entry
  const separator = content.length > 0 && !content.endsWith('\n') ? '\n' : '';
  await fs.writeFile(gitignorePath, content + separator + '.env\n', 'utf-8');
  return true;
}

/**
 * Detect and fix a hardcoded secret by moving it to .env and replacing
 * the inline value with a process.env reference.
 */
export async function fixHardcodedSecret(
  finding: Finding,
  projectDir?: string,
): Promise<SecretFix> {
  const dir = projectDir ?? process.cwd();
  const filePath = path.resolve(dir, finding.file);
  const filesModified: string[] = [];

  // 1. Read the file containing the hardcoded secret
  const content = await fs.readFile(filePath, 'utf-8');
  const lines = content.split('\n');
  const targetLine = lines[finding.line - 1];

  if (!targetLine) {
    throw new Error(`Line ${finding.line} not found in ${finding.file}`);
  }

  // 2. Extract the secret value
  const secretMatch = targetLine.match(/['"`]([A-Za-z0-9_\-./+=:@]{8,})['"`]/);
  if (!secretMatch) {
    throw new Error(`Could not extract secret value from line ${finding.line} in ${finding.file}`);
  }

  const secretValue = secretMatch[1];

  // 3. Determine variable context
  const varNameMatch = targetLine.match(/(?:const|let|var)\s+(\w+)|(\w+)\s*[:=]/);
  const context = varNameMatch?.[1] ?? varNameMatch?.[2] ?? '';

  // 4. Detect secret type
  const secretType = detectSecretType(secretValue, context);

  // 5. Generate env var name
  const envVarName = generateEnvVarName(secretType, context);

  // 6. Replace hardcoded value with process.env reference
  const newLine = targetLine.replace(secretMatch[0], `process.env.${envVarName}`);
  lines[finding.line - 1] = newLine;
  await fs.writeFile(filePath, lines.join('\n'), 'utf-8');
  filesModified.push(finding.file);

  // 7. Append to .env
  const envPath = path.join(dir, '.env');
  let envContent = '';
  try {
    envContent = await fs.readFile(envPath, 'utf-8');
  } catch {
    // .env doesn't exist yet — will be created
  }

  if (!envContent.includes(`${envVarName}=`)) {
    const separator = envContent.length > 0 && !envContent.endsWith('\n') ? '\n' : '';
    await fs.writeFile(envPath, envContent + separator + `${envVarName}=${secretValue}\n`, 'utf-8');
    filesModified.push('.env');
  }

  // 8. Ensure .env is in .gitignore
  const gitignoreModified = await ensureGitignoreHasEnv(dir);
  if (gitignoreModified) {
    filesModified.push('.gitignore');
  }

  return {
    file: finding.file,
    line: finding.line,
    secretType,
    envVarName,
    filesModified,
  };
}
