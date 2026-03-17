export interface CheckPackageParams {
  name: string;
  version?: string;
  registry?: 'npm' | 'pip' | 'cargo';
}

export interface CheckPackageResult {
  name: string;
  version: string;
  safe: boolean;
  cves: string[];
  license: string;
  license_compatible: boolean;
  maintained: boolean;
  last_publish: string;
  typosquat_warning: boolean;
  recommendation: string;
}

// Popular packages to check for typosquatting
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
];

// Licenses generally considered compatible with most projects
const COMPATIBLE_LICENSES = [
  'MIT',
  'ISC',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'Apache-2.0',
  '0BSD',
  'Unlicense',
  'CC0-1.0',
  'BlueOak-1.0.0',
];

/**
 * Compute Levenshtein edit distance between two strings.
 */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  // Create a 2D array for dynamic programming
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    Array.from({ length: n + 1 }, () => 0),
  );

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }

  return dp[m][n];
}

/**
 * Check if a package name looks like a typosquat of a popular package.
 */
export function checkTyposquat(name: string): { isTyposquat: boolean; similarTo?: string } {
  for (const popular of POPULAR_PACKAGES) {
    if (name === popular) {
      // Exact match — not a typosquat
      continue;
    }
    const distance = editDistance(name.toLowerCase(), popular.toLowerCase());
    if (distance <= 2) {
      return { isTyposquat: true, similarTo: popular };
    }
  }
  return { isTyposquat: false };
}

export async function handleCheckPackage(
  params: CheckPackageParams,
): Promise<CheckPackageResult> {
  const { name, version, registry = 'npm' } = params;

  // Currently only npm is supported
  if (registry !== 'npm') {
    return {
      name,
      version: version ?? 'latest',
      safe: false,
      cves: [],
      license: 'unknown',
      license_compatible: false,
      maintained: false,
      last_publish: 'unknown',
      typosquat_warning: false,
      recommendation: `Registry "${registry}" is not yet supported. Only npm is currently available.`,
    };
  }

  // Check typosquatting first (doesn't need network)
  const typosquatCheck = checkTyposquat(name);

  // Fetch package info from npm registry
  let npmData: {
    name: string;
    'dist-tags'?: { latest?: string };
    license?: string;
    time?: Record<string, string>;
    versions?: Record<string, { deprecated?: string }>;
  };

  try {
    const registryUrl = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
    const response = await fetch(registryUrl);

    if (!response.ok) {
      if (response.status === 404) {
        return {
          name,
          version: version ?? 'latest',
          safe: false,
          cves: [],
          license: 'unknown',
          license_compatible: false,
          maintained: false,
          last_publish: 'unknown',
          typosquat_warning: typosquatCheck.isTyposquat,
          recommendation: `Package "${name}" not found on npm registry.${
            typosquatCheck.isTyposquat
              ? ` WARNING: This name is similar to "${typosquatCheck.similarTo}" — possible typosquat.`
              : ''
          }`,
        };
      }
      return {
        name,
        version: version ?? 'latest',
        safe: false,
        cves: [],
        license: 'unknown',
        license_compatible: false,
        maintained: false,
        last_publish: 'unknown',
        typosquat_warning: typosquatCheck.isTyposquat,
        recommendation: `Failed to fetch package info: HTTP ${response.status}`,
      };
    }

    npmData = (await response.json()) as typeof npmData;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      name,
      version: version ?? 'latest',
      safe: false,
      cves: [],
      license: 'unknown',
      license_compatible: false,
      maintained: false,
      last_publish: 'unknown',
      typosquat_warning: typosquatCheck.isTyposquat,
      recommendation: `Failed to fetch package info: ${message}`,
    };
  }

  // Determine version
  const resolvedVersion = version ?? npmData['dist-tags']?.latest ?? 'unknown';

  // Check license
  const license = npmData.license ?? 'unknown';
  const licenseCompatible = COMPATIBLE_LICENSES.includes(license);

  // Check maintenance — last publish date
  const timeEntries = npmData.time ?? {};
  const modified = timeEntries.modified ?? timeEntries[resolvedVersion];
  const lastPublish = modified ?? 'unknown';

  let maintained = true;
  if (lastPublish !== 'unknown') {
    const lastPublishDate = new Date(lastPublish);
    const twoYearsAgo = new Date();
    twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
    maintained = lastPublishDate > twoYearsAgo;
  }

  // Check if the resolved version is deprecated
  const isDeprecated = !!(npmData.versions?.[resolvedVersion]?.deprecated);

  // Build recommendation
  const warnings: string[] = [];
  if (typosquatCheck.isTyposquat) {
    warnings.push(
      `TYPOSQUAT WARNING: "${name}" is similar to "${typosquatCheck.similarTo}". Verify this is the intended package.`,
    );
  }
  if (!maintained) {
    warnings.push('Package has not been updated in over 2 years.');
  }
  if (!licenseCompatible) {
    warnings.push(`License "${license}" may not be compatible with your project.`);
  }
  if (isDeprecated) {
    warnings.push('This version is deprecated.');
  }

  const safe =
    !typosquatCheck.isTyposquat &&
    maintained &&
    licenseCompatible &&
    !isDeprecated;

  const recommendation =
    warnings.length === 0
      ? `Package "${name}@${resolvedVersion}" appears safe to install.`
      : warnings.join(' ');

  return {
    name,
    version: resolvedVersion,
    safe,
    cves: [], // CVE checking will be expanded in future phases
    license,
    license_compatible: licenseCompatible,
    maintained,
    last_publish: lastPublish,
    typosquat_warning: typosquatCheck.isTyposquat,
    recommendation,
  };
}
