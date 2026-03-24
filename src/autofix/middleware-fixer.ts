/**
 * ShipSafe Middleware Auto-Fixer
 *
 * Automatically fixes missing security middleware:
 * - Helmet (security headers) for Express apps
 * - Rate limiting for authentication endpoints
 */

import type { Finding } from '../types.js';

// ── Helmet Auto-Fix ──

/**
 * Fix missing helmet middleware in an Express app.
 *
 * When CONFIG_NO_SECURITY_HEADERS is found:
 * 1. Find the line with express() or app = express()
 * 2. Insert app.use(helmet()) after it
 * 3. Add import helmet from 'helmet' at the top of the file
 *
 * Returns null if the fix cannot be applied.
 */
export function fixMissingHelmet(
  fileContent: string,
  finding: Finding,
): { fixed: string; description: string } | null {
  const lines = fileContent.split('\n');

  // Find the express() call line
  const expressLineIdx = lines.findIndex((line) =>
    /\bexpress\s*\(\s*\)/.test(line),
  );

  if (expressLineIdx === -1) return null;

  const expressLine = lines[expressLineIdx];

  // Detect the app variable name (e.g., 'app' from 'const app = express()')
  const appNameMatch = expressLine.match(
    /(?:const|let|var)\s+(\w+)\s*=\s*express\s*\(\s*\)/,
  );
  const appName = appNameMatch?.[1] ?? 'app';

  // Detect indentation from the express line
  const indentMatch = expressLine.match(/^(\s*)/);
  const indent = indentMatch?.[1] ?? '';

  // Insert app.use(helmet()) after the express() line
  const helmetUseLine = `${indent}${appName}.use(helmet());`;
  lines.splice(expressLineIdx + 1, 0, helmetUseLine);

  // Add import at the top of the file
  const hasEsmImport = /\bimport\s+/.test(fileContent);
  const hasCjsRequire = /\brequire\s*\(/.test(fileContent);

  let importStatement: string;
  if (hasEsmImport) {
    importStatement = "import helmet from 'helmet';";
  } else if (hasCjsRequire) {
    importStatement = "const helmet = require('helmet');";
  } else {
    importStatement = "import helmet from 'helmet';";
  }

  // Find the best position for the import (after existing imports)
  let insertIdx = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (
      /^\s*import\s+/.test(line) ||
      /^\s*(?:const|let|var)\s+\w+\s*=\s*require\s*\(/.test(line)
    ) {
      insertIdx = i + 1;
    }
  }

  // Check if helmet import already exists (shouldn't, but be safe)
  const alreadyImported =
    /\bimport\s+helmet\b/.test(fileContent) ||
    /\brequire\s*\(\s*['"]helmet['"]\s*\)/.test(fileContent);

  if (!alreadyImported) {
    lines.splice(insertIdx, 0, importStatement);
  }

  return {
    fixed: lines.join('\n'),
    description: `Added helmet middleware for security headers. Run \`npm install helmet\` if not already installed.`,
  };
}

// ── Rate Limit Auto-Fix ──

/**
 * Fix missing rate limiting on authentication endpoints.
 *
 * When RATE_LIMIT_AUTH_ENDPOINT is found:
 * 1. Find the auth route definition
 * 2. Insert rate limiter middleware before it
 * 3. Add import at the top
 *
 * Returns null if the fix cannot be applied.
 */
export function fixMissingRateLimit(
  fileContent: string,
  finding: Finding,
): { fixed: string; description: string } | null {
  const lines = fileContent.split('\n');

  // Find the auth route line (the one that triggered the finding)
  const targetLineIdx = finding.line - 1;
  if (targetLineIdx < 0 || targetLineIdx >= lines.length) return null;

  const routeLine = lines[targetLineIdx];

  // Verify this is actually an auth route
  if (
    !/\b(?:app|router)\s*\.\s*(?:post|put)\s*\(\s*['"]\/(?:api\/)?(?:auth\/)?(?:login|signin|register|signup|reset-password|forgot-password|verify)\b/.test(
      routeLine,
    )
  ) {
    return null;
  }

  // Detect indentation from the route line
  const indentMatch = routeLine.match(/^(\s*)/);
  const indent = indentMatch?.[1] ?? '';

  // Create the rate limiter configuration
  const rateLimiterConfig = [
    `${indent}const authLimiter = rateLimit({`,
    `${indent}  windowMs: 15 * 60 * 1000, // 15 minutes`,
    `${indent}  max: 10, // limit each IP to 10 requests per windowMs`,
    `${indent}  message: 'Too many attempts, please try again later.',`,
    `${indent}  standardHeaders: true,`,
    `${indent}  legacyHeaders: false,`,
    `${indent}});`,
    ``,
  ];

  // Check if a rate limiter variable already exists somewhere in the file
  const hasExistingLimiter = /\bconst\s+\w*[Ll]imiter\s*=\s*rateLimit\s*\(/.test(fileContent);

  if (!hasExistingLimiter) {
    // Insert rate limiter config before the route definition
    lines.splice(targetLineIdx, 0, ...rateLimiterConfig);
  }

  // Now the route line has shifted down by the number of inserted lines
  const offset = hasExistingLimiter ? 0 : rateLimiterConfig.length;
  const shiftedRouteIdx = targetLineIdx + offset;
  const shiftedRouteLine = lines[shiftedRouteIdx];

  // Insert authLimiter as first middleware in the route
  // Pattern: app.post('/login', handler) -> app.post('/login', authLimiter, handler)
  const limiterName = hasExistingLimiter ? findExistingLimiterName(fileContent) : 'authLimiter';
  const updatedLine = shiftedRouteLine.replace(
    /(\b(?:app|router)\s*\.\s*(?:post|put)\s*\(\s*['"][^'"]+['"]\s*,\s*)/,
    `$1${limiterName}, `,
  );
  lines[shiftedRouteIdx] = updatedLine;

  // Add import at the top of the file
  const hasEsmImport = /\bimport\s+/.test(fileContent);

  let importStatement: string;
  if (hasEsmImport) {
    importStatement = "import rateLimit from 'express-rate-limit';";
  } else {
    importStatement = "const rateLimit = require('express-rate-limit');";
  }

  // Check if express-rate-limit is already imported
  const alreadyImported =
    /\bimport\s+.*\bfrom\s+['"]express-rate-limit['"]/.test(fileContent) ||
    /\brequire\s*\(\s*['"]express-rate-limit['"]\s*\)/.test(fileContent);

  if (!alreadyImported) {
    // Find the best position for the import (after existing imports)
    let insertIdx = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (
        /^\s*import\s+/.test(line) ||
        /^\s*(?:const|let|var)\s+\w+\s*=\s*require\s*\(/.test(line)
      ) {
        insertIdx = i + 1;
      }
    }
    lines.splice(insertIdx, 0, importStatement);
  }

  return {
    fixed: lines.join('\n'),
    description: `Added rate limiting to authentication endpoint. Run \`npm install express-rate-limit\` if not already installed.`,
  };
}

// ── Helpers ──

function findExistingLimiterName(fileContent: string): string {
  const match = fileContent.match(/\bconst\s+(\w*[Ll]imiter)\s*=\s*rateLimit\s*\(/);
  return match?.[1] ?? 'authLimiter';
}
