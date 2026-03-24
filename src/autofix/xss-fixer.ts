/**
 * ShipSafe XSS Auto-Fixer
 *
 * Automatically fixes cross-site scripting vulnerabilities:
 * - dangerouslySetInnerHTML: wraps value with DOMPurify.sanitize()
 * - innerHTML assignment: replaces with textContent assignment
 * - eval(): replaces with JSON.parse() or adds removal comment
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type { Finding } from '../types.js';

// ── dangerouslySetInnerHTML Fix ──

/**
 * Fix dangerouslySetInnerHTML by wrapping the __html value with DOMPurify.sanitize().
 * Also adds the DOMPurify import if not already present.
 *
 * Handles patterns:
 *   dangerouslySetInnerHTML={{ __html: userContent }}
 *   dangerouslySetInnerHTML={{ __html: someVar }}
 *   dangerouslySetInnerHTML={{ __html: getData() }}
 */
export function fixDangerouslySetInnerHTML(
  fileContent: string,
  finding: Finding,
): { fixed: string; description: string } | null {
  const lines = fileContent.split('\n');
  const targetLineIdx = finding.line - 1;
  if (targetLineIdx < 0 || targetLineIdx >= lines.length) return null;

  const targetLine = lines[targetLineIdx];

  // Match __html: <value> }} pattern
  const htmlValueMatch = targetLine.match(/__html\s*:\s*(.+?)\s*\}\}/);
  if (!htmlValueMatch) return null;

  const rawValue = htmlValueMatch[1].trim();

  // Don't fix if already sanitized
  if (/\bDOMPurify\b/.test(rawValue) || /\bsanitize\b/i.test(rawValue)) return null;

  // Replace the value with DOMPurify.sanitize(value)
  const fixedLine = targetLine.replace(
    /(__html\s*:\s*)(.+?)(\s*\}\})/,
    (_match, prefix: string, value: string, suffix: string) => {
      return `${prefix}DOMPurify.sanitize(${value.trim()})${suffix}`;
    },
  );

  if (fixedLine === targetLine) return null;

  lines[targetLineIdx] = fixedLine;

  // Add DOMPurify import if not present
  const result = addDomPurifyImport(lines.join('\n'));

  return {
    fixed: result,
    description: `Wrapped dangerouslySetInnerHTML value with DOMPurify.sanitize(). Run \`npm install dompurify\` if not already installed.`,
  };
}

// ── innerHTML Fix ──

/**
 * Fix innerHTML assignment by replacing with textContent.
 *
 * Handles patterns:
 *   element.innerHTML = userInput;
 *   el.innerHTML = someVar;
 *   document.getElementById('x').innerHTML = data;
 */
export function fixInnerHTML(
  fileContent: string,
  finding: Finding,
): { fixed: string; description: string } | null {
  const lines = fileContent.split('\n');
  const targetLineIdx = finding.line - 1;
  if (targetLineIdx < 0 || targetLineIdx >= lines.length) return null;

  const targetLine = lines[targetLineIdx];

  // Match .innerHTML = <value> pattern
  if (!/\.innerHTML\s*=/.test(targetLine)) return null;

  // Don't fix if already using DOMPurify
  if (/\bDOMPurify\b/.test(targetLine) || /\bsanitize\b/i.test(targetLine)) return null;

  // Replace innerHTML with textContent
  const fixedLine = targetLine.replace(/\.innerHTML\s*=/, '.textContent =');

  if (fixedLine === targetLine) return null;

  lines[targetLineIdx] = fixedLine;

  return {
    fixed: lines.join('\n'),
    description: `Replaced innerHTML with textContent to prevent XSS. If HTML rendering is needed, use DOMPurify.sanitize() instead.`,
  };
}

// ── eval Fix ──

/**
 * Fix eval() usage by replacing with JSON.parse() when context suggests data parsing,
 * or adding a removal comment otherwise.
 *
 * Handles patterns:
 *   eval(code)
 *   eval(userInput)
 *   const result = eval(data)
 */
export function fixEval(
  fileContent: string,
  finding: Finding,
): { fixed: string; description: string } | null {
  const lines = fileContent.split('\n');
  const targetLineIdx = finding.line - 1;
  if (targetLineIdx < 0 || targetLineIdx >= lines.length) return null;

  const targetLine = lines[targetLineIdx];

  // Match eval(<arg>) pattern — but not redis.eval, setInterval, etc.
  if (!/\beval\s*\(/.test(targetLine)) return null;
  if (/\b(?:redis|client|ioredis|redisClient|cache)\s*\.\s*eval\s*\(/.test(targetLine)) return null;
  if (/\bsetInterval\b/.test(targetLine)) return null;

  // Detect if this looks like data parsing context
  const isDataContext = /\b(?:json|data|config|parse|response|body|payload|result|message)\b/i.test(targetLine);

  if (isDataContext) {
    // Replace eval(x) with JSON.parse(x)
    const fixedLine = targetLine.replace(/\beval\s*\(/, 'JSON.parse(');
    if (fixedLine === targetLine) return null;

    lines[targetLineIdx] = fixedLine;

    return {
      fixed: lines.join('\n'),
      description: `Replaced eval() with JSON.parse() for safer data parsing. Verify that the input is valid JSON.`,
    };
  }

  // For non-data contexts, add a security comment suggesting removal
  const indent = targetLine.match(/^(\s*)/)?.[1] ?? '';
  lines.splice(targetLineIdx, 0, `${indent}// SECURITY: eval() is a code injection risk — remove or replace with a safe alternative`);

  return {
    fixed: lines.join('\n'),
    description: `Added security warning comment above eval() call. Manual removal recommended — eval() enables arbitrary code execution.`,
  };
}

// ── Unified XSS Fix ──

/**
 * Apply the appropriate XSS fix based on the finding type.
 * Returns null if the finding type is not supported or the fix cannot be applied.
 */
export function fixXss(
  fileContent: string,
  finding: Finding,
): { fixed: string; description: string } | null {
  const xssType = finding.type || finding.id;

  // dangerouslySetInnerHTML findings
  if (
    xssType === 'XSS_DANGEROUSLY_SET_INNERHTML' ||
    xssType === 'REACT_DANGEROUSLYSETINNERHTML_VARIABLE' ||
    xssType === 'RSC_DANGEROUSLY_SET_DB_DATA'
  ) {
    return fixDangerouslySetInnerHTML(fileContent, finding);
  }

  // innerHTML assignment findings
  if (
    xssType === 'XSS_INNERHTML' ||
    xssType === 'DOM_XSS_INNERHTML_ASSIGN'
  ) {
    return fixInnerHTML(fileContent, finding);
  }

  // eval() findings
  if (xssType === 'XSS_EVAL') {
    return fixEval(fileContent, finding);
  }

  return null;
}

// ── File-level fix ──

/**
 * Apply a XSS fix to a file at the specified line.
 * Reads the file, fixes the vulnerability, writes it back.
 */
export async function fixXssInFile(
  finding: Finding,
  projectDir?: string,
): Promise<{ file: string; description: string; filesModified: string[] }> {
  const dir = projectDir ?? process.cwd();
  const filePath = path.resolve(dir, finding.file);

  // Read the file
  const content = await fs.readFile(filePath, 'utf-8');

  // Attempt the fix
  const result = fixXss(content, finding);
  if (!result) {
    throw new Error(
      `Could not auto-fix XSS on line ${finding.line} in ${finding.file}. ` +
      `The pattern may be too complex for automatic fixing. Apply the fix manually: ${finding.fix_suggestion}`,
    );
  }

  // Write the fixed file
  await fs.writeFile(filePath, result.fixed, 'utf-8');

  return {
    file: finding.file,
    description: result.description,
    filesModified: [finding.file],
  };
}

// ── Helpers ──

/**
 * Add `import DOMPurify from 'dompurify';` to the file if not already present.
 */
function addDomPurifyImport(content: string): string {
  // Check if DOMPurify is already imported
  if (/\bimport\s+.*DOMPurify\b/.test(content) || /\brequire\s*\(\s*['"]dompurify['"]\s*\)/.test(content)) {
    return content;
  }

  const lines = content.split('\n');
  const hasEsmImport = /\bimport\s+/.test(content);
  const hasCjsRequire = /\brequire\s*\(/.test(content);

  let importStatement: string;
  if (hasEsmImport) {
    importStatement = "import DOMPurify from 'dompurify';";
  } else if (hasCjsRequire) {
    importStatement = "const DOMPurify = require('dompurify');";
  } else {
    importStatement = "import DOMPurify from 'dompurify';";
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

  lines.splice(insertIdx, 0, importStatement);
  return lines.join('\n');
}
