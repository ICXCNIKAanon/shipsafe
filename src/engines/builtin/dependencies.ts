import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Finding, Severity } from '../../types.js';
import { editDistance } from '../../mcp/tools/check-package.js';

// ── Types ──

export interface DependencyAuditSummary {
  total: number;
  critical: number;
  high: number;
  moderate: number;
  low: number;
}

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface PackageLockJson {
  lockfileVersion?: number;
  packages?: Record<string, { version?: string; resolved?: string; deprecated?: string }>;
  dependencies?: Record<string, { version?: string; resolved?: string }>;
}

interface NpmAuditAdvisory {
  id: number;
  title: string;
  module_name: string;
  severity: string;
  url: string;
  findings: Array<{ version: string; paths: string[] }>;
  vulnerable_versions: string;
  patched_versions: string;
  cves: string[];
  recommendation: string;
}

interface NpmAuditResponse {
  advisories?: Record<string, NpmAuditAdvisory>;
  error?: { code: string; summary: string };
}

// ── Constants ──

const POPULAR_PACKAGES = [
  'react',
  'express',
  'lodash',
  'axios',
  'moment',
  'chalk',
  'commander',
  'next',
  'vue',
  'angular',
  'webpack',
  'typescript',
  'zod',
  'prisma',
  'drizzle',
  'hono',
  'fastify',
  'vite',
  'esbuild',
  'rollup',
  'jest',
  'vitest',
  'mocha',
  'prettier',
  'eslint',
  'tailwindcss',
  'postcss',
  'dotenv',
  'cors',
  'helmet',
  'jsonwebtoken',
  'bcrypt',
  'mongoose',
  'sequelize',
  'socket.io',
  'redis',
  'bull',
  'passport',
  'multer',
  'sharp',
  'puppeteer',
  'playwright',
];

const NPM_AUDIT_URL = 'https://registry.npmjs.org/-/npm/v1/security/audits';

// ── Helpers ──

function mapNpmSeverity(npmSeverity: string): Severity {
  switch (npmSeverity) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
      return 'info';
    default:
      return 'medium';
  }
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const content = await readFile(filePath, 'utf-8');
    return JSON.parse(content) as T;
  } catch {
    return null;
  }
}

function isWildcardVersion(version: string): boolean {
  return version === '*' || version === 'latest' || version === '';
}

function checkTyposquat(name: string): { isTyposquat: boolean; similarTo?: string } {
  // If the package itself is a known popular package, it's not a typosquat
  if (POPULAR_PACKAGES.includes(name.toLowerCase())) {
    return { isTyposquat: false };
  }
  for (const popular of POPULAR_PACKAGES) {
    const distance = editDistance(name.toLowerCase(), popular.toLowerCase());
    if (distance > 0 && distance <= 2) {
      return { isTyposquat: true, similarTo: popular };
    }
  }
  return { isTyposquat: false };
}

/**
 * Build the payload that the npm audit API expects.
 * This mimics what `npm audit` sends internally.
 */
function buildAuditPayload(
  pkgJson: PackageJson,
  lockData: PackageLockJson | null,
): Record<string, unknown> {
  const allDeps: Record<string, string> = {
    ...pkgJson.dependencies,
    ...pkgJson.devDependencies,
  };

  // Build the "requires" and "dependencies" maps for the audit API
  const requires: Record<string, string> = {};
  const dependencies: Record<string, { version: string }> = {};

  for (const [name, specifier] of Object.entries(allDeps)) {
    requires[name] = specifier;

    // Prefer the resolved version from the lockfile
    let resolvedVersion = specifier;

    if (lockData) {
      // lockfileVersion 2/3 uses "packages" with "" prefix entries
      const lockPackages = lockData.packages;
      if (lockPackages) {
        const lockEntry =
          lockPackages[`node_modules/${name}`] ?? lockPackages[name];
        if (lockEntry?.version) {
          resolvedVersion = lockEntry.version;
        }
      }
      // lockfileVersion 1 uses "dependencies"
      const lockDeps = lockData.dependencies;
      if (lockDeps?.[name]?.version) {
        resolvedVersion = lockDeps[name].version;
      }
    }

    // Strip semver range prefixes for the version field
    const cleaned = resolvedVersion.replace(/^[\^~>=<\s]+/, '');
    dependencies[name] = { version: cleaned || '0.0.0' };
  }

  return {
    name: pkgJson.name ?? 'unknown',
    version: pkgJson.version ?? '0.0.0',
    requires,
    dependencies,
  };
}

// ── Audit API call ──

async function callNpmAudit(
  pkgJson: PackageJson,
  lockData: PackageLockJson | null,
): Promise<NpmAuditResponse | null> {
  const payload = buildAuditPayload(pkgJson, lockData);

  try {
    const response = await fetch(NPM_AUDIT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5_000),
    });

    if (!response.ok) {
      return null;
    }

    return (await response.json()) as NpmAuditResponse;
  } catch {
    // Offline or API unreachable — fall back to local-only checks
    return null;
  }
}

// ── Local checks (work offline) ──

function runLocalChecks(
  pkgJson: PackageJson,
  lockData: PackageLockJson | null,
  packageJsonPath: string,
): Finding[] {
  const findings: Finding[] = [];
  const allDeps: Record<string, string> = {
    ...pkgJson.dependencies,
    ...pkgJson.devDependencies,
  };

  let findingIndex = 0;

  for (const [name, versionSpec] of Object.entries(allDeps)) {
    // 1. Wildcard / latest versions
    if (isWildcardVersion(versionSpec)) {
      findings.push({
        id: `dep-wildcard-${findingIndex++}`,
        engine: 'pattern',
        severity: 'high',
        type: 'dependency-wildcard-version',
        file: packageJsonPath,
        line: 0,
        description: `Dependency "${name}" uses wildcard version "${versionSpec}". This allows arbitrary versions to be installed, including potentially malicious ones.`,
        fix_suggestion: `Pin "${name}" to a specific version range (e.g., "^x.y.z") instead of "${versionSpec}".`,
        auto_fixable: false,
      });
    }

    // 2. Phantom dependencies (in package.json but not in lockfile)
    if (lockData && !isWildcardVersion(versionSpec)) {
      const inLock = hasLockEntry(lockData, name);
      if (!inLock) {
        findings.push({
          id: `dep-phantom-${findingIndex++}`,
          engine: 'pattern',
          severity: 'medium',
          type: 'dependency-phantom',
          file: packageJsonPath,
          line: 0,
          description: `Dependency "${name}" is declared in package.json but has no entry in the lockfile. This may indicate the lockfile is out of date or the dependency was never installed.`,
          fix_suggestion: `Run "npm install" to regenerate the lockfile and ensure "${name}" is properly resolved.`,
          auto_fixable: false,
        });
      }
    }

    // 3. Deprecated packages (from lockfile metadata)
    if (lockData) {
      const deprecationMsg = getDeprecationMessage(lockData, name);
      if (deprecationMsg) {
        findings.push({
          id: `dep-deprecated-${findingIndex++}`,
          engine: 'pattern',
          severity: 'medium',
          type: 'dependency-deprecated',
          file: packageJsonPath,
          line: 0,
          description: `Dependency "${name}" is deprecated: ${deprecationMsg}`,
          fix_suggestion: `Find an actively maintained alternative to "${name}" and migrate away from this package.`,
          auto_fixable: false,
        });
      }
    }

    // 4. Typosquat detection
    const typoCheck = checkTyposquat(name);
    if (typoCheck.isTyposquat) {
      findings.push({
        id: `dep-typosquat-${findingIndex++}`,
        engine: 'pattern',
        severity: 'critical',
        type: 'dependency-typosquat',
        file: packageJsonPath,
        line: 0,
        description: `Dependency "${name}" looks like a typosquat of popular package "${typoCheck.similarTo}". This could be a malicious package impersonating a legitimate one.`,
        fix_suggestion: `Verify that "${name}" is the intended package. If you meant "${typoCheck.similarTo}", replace it immediately.`,
        auto_fixable: false,
      });
    }

    // 5. Very old version ranges (heuristic: major version 0 for well-known packages,
    //    or version specifiers that pin to extremely old majors)
    const oldVersionWarning = checkForVeryOldVersion(name, versionSpec);
    if (oldVersionWarning) {
      findings.push({
        id: `dep-outdated-${findingIndex++}`,
        engine: 'pattern',
        severity: 'low',
        type: 'dependency-outdated',
        file: packageJsonPath,
        line: 0,
        description: oldVersionWarning.description,
        fix_suggestion: oldVersionWarning.fix,
        auto_fixable: false,
      });
    }
  }

  return findings;
}

function hasLockEntry(lockData: PackageLockJson, name: string): boolean {
  // Check lockfileVersion 2/3 "packages" field
  if (lockData.packages) {
    if (
      lockData.packages[`node_modules/${name}`] ||
      lockData.packages[name]
    ) {
      return true;
    }
  }
  // Check lockfileVersion 1 "dependencies" field
  if (lockData.dependencies?.[name]) {
    return true;
  }
  return false;
}

function getDeprecationMessage(
  lockData: PackageLockJson,
  name: string,
): string | null {
  if (lockData.packages) {
    const entry =
      lockData.packages[`node_modules/${name}`] ?? lockData.packages[name];
    if (entry?.deprecated) {
      return entry.deprecated;
    }
  }
  return null;
}

/**
 * Heuristic check for very old dependency versions.
 * We track known "current" major versions for popular packages. If the installed
 * major is 3+ behind, we flag it as likely outdated (> 3 years old in practice).
 */
const KNOWN_CURRENT_MAJORS: Record<string, number> = {
  react: 19,
  express: 5,
  lodash: 4,
  axios: 1,
  chalk: 5,
  commander: 12,
  next: 15,
  vue: 3,
  webpack: 5,
  typescript: 5,
  zod: 3,
  jest: 29,
  eslint: 9,
  prettier: 3,
  tailwindcss: 4,
  postcss: 8,
  vite: 6,
  esbuild: 0,
  rollup: 4,
  vitest: 2,
  mocha: 10,
  fastify: 5,
  hono: 4,
  mongoose: 8,
  sequelize: 6,
  redis: 4,
  passport: 0,
  sharp: 0,
  puppeteer: 23,
  playwright: 1,
};

function checkForVeryOldVersion(
  name: string,
  versionSpec: string,
): { description: string; fix: string } | null {
  const currentMajor = KNOWN_CURRENT_MAJORS[name];
  if (currentMajor === undefined) return null;

  // Extract the major version from the specifier
  const match = versionSpec.match(/(\d+)/);
  if (!match) return null;

  const installedMajor = parseInt(match[1], 10);
  const majorsBehind = currentMajor - installedMajor;

  // Only flag if 3+ major versions behind (likely > 3 years old)
  if (majorsBehind >= 3) {
    return {
      description: `Dependency "${name}@${versionSpec}" is ${majorsBehind} major versions behind the current release (v${currentMajor}). Very old versions often have unpatched security vulnerabilities.`,
      fix: `Update "${name}" to a recent version (current major: v${currentMajor}). Review the changelog for breaking changes before upgrading.`,
    };
  }

  return null;
}

// ── Main scanner ──

export async function scanDependencies(
  targetPath: string,
): Promise<Finding[]> {
  const packageJsonPath = join(targetPath, 'package.json');
  const lockfilePath = join(targetPath, 'package-lock.json');

  const pkgJson = await readJsonFile<PackageJson>(packageJsonPath);
  if (!pkgJson) {
    // No package.json — nothing to scan
    return [];
  }

  const allDeps = {
    ...pkgJson.dependencies,
    ...pkgJson.devDependencies,
  };
  if (Object.keys(allDeps).length === 0) {
    return [];
  }

  const lockData = await readJsonFile<PackageLockJson>(lockfilePath);

  // Run local checks (always works, even offline)
  const localFindings = runLocalChecks(pkgJson, lockData, 'package.json');

  // Attempt npm audit API call for known CVEs
  const auditResponse = await callNpmAudit(pkgJson, lockData);
  const auditFindings: Finding[] = [];

  if (auditResponse?.advisories) {
    let auditIndex = 0;
    for (const advisory of Object.values(auditResponse.advisories)) {
      const severity = mapNpmSeverity(advisory.severity);
      const cveList =
        advisory.cves && advisory.cves.length > 0
          ? ` (${advisory.cves.join(', ')})`
          : '';

      const affectedVersions =
        advisory.findings
          ?.map((f) => f.version)
          .filter(Boolean)
          .join(', ') || 'unknown';

      const patchedInfo =
        advisory.patched_versions && advisory.patched_versions !== '<0.0.0'
          ? `Update to ${advisory.patched_versions}.`
          : advisory.recommendation || 'No patched version available. Consider finding an alternative package.';

      auditFindings.push({
        id: `dep-vuln-${advisory.id}-${auditIndex++}`,
        engine: 'pattern',
        severity,
        type: 'dependency-vulnerability',
        file: 'package.json',
        line: 0,
        description: `${advisory.module_name}@${affectedVersions}: ${advisory.title}${cveList}. Vulnerable versions: ${advisory.vulnerable_versions}. See: ${advisory.url}`,
        fix_suggestion: patchedInfo,
        auto_fixable: false,
      });
    }
  }

  return [...auditFindings, ...localFindings];
}

// ── Summary helper ──

export async function getDependencySummary(
  targetPath: string,
): Promise<DependencyAuditSummary> {
  const findings = await scanDependencies(targetPath);

  const summary: DependencyAuditSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
  };

  for (const finding of findings) {
    switch (finding.severity) {
      case 'critical':
        summary.critical++;
        break;
      case 'high':
        summary.high++;
        break;
      case 'medium':
        summary.moderate++;
        break;
      case 'low':
      case 'info':
        summary.low++;
        break;
    }
  }

  return summary;
}
