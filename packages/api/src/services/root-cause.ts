import type { RootCauseAnalysis } from '../types.js';

interface ErrorInfo {
  name: string;
  message: string;
  stack?: string;
}

/**
 * Analyze a stack trace to determine root cause.
 * Identifies the originating function/file and suggests a fix.
 */
export function analyzeRootCause(error: ErrorInfo): RootCauseAnalysis {
  const { originatingFunction, originatingFile } = parseStackOrigin(error.stack);
  const rootCause = generateRootCauseDescription(error, originatingFunction, originatingFile);
  const suggestedFix = suggestFix(error);

  return {
    root_cause: rootCause,
    originating_function: originatingFunction,
    originating_file: originatingFile,
    suggested_fix: suggestedFix,
  };
}

/**
 * Parse the stack trace to find the originating function and file.
 * The first user-code frame (skipping node_modules) is considered the origin.
 */
function parseStackOrigin(stack?: string): {
  originatingFunction: string;
  originatingFile: string;
} {
  if (!stack) {
    return { originatingFunction: 'unknown', originatingFile: 'unknown' };
  }

  const lines = stack.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('at ')) continue;

    // Skip node_modules frames
    if (trimmed.includes('node_modules')) continue;

    // Match "at functionName (file:line:col)"
    const parenMatch = trimmed.match(/^at\s+(.+?)\s+\((.+?):\d+:\d+\)/);
    if (parenMatch) {
      return {
        originatingFunction: parenMatch[1],
        originatingFile: parenMatch[2],
      };
    }

    // Match "at file:line:col" (anonymous)
    const directMatch = trimmed.match(/^at\s+(.+?):\d+:\d+/);
    if (directMatch) {
      return {
        originatingFunction: '<anonymous>',
        originatingFile: directMatch[1],
      };
    }
  }

  return { originatingFunction: 'unknown', originatingFile: 'unknown' };
}

/**
 * Generate a human-readable root cause description.
 */
function generateRootCauseDescription(
  error: ErrorInfo,
  fn: string,
  file: string,
): string {
  const location = fn !== 'unknown' && file !== 'unknown'
    ? `in ${fn} (${file})`
    : fn !== 'unknown'
      ? `in ${fn}`
      : file !== 'unknown'
        ? `in ${file}`
        : 'at an unknown location';

  switch (error.name) {
    case 'TypeError':
      return `A TypeError occurred ${location}: ${error.message}. This typically indicates an operation on an undefined or null value.`;
    case 'ReferenceError':
      return `A ReferenceError occurred ${location}: ${error.message}. A variable or function was used before being defined.`;
    case 'SyntaxError':
      return `A SyntaxError occurred ${location}: ${error.message}. The code contains invalid syntax.`;
    case 'RangeError':
      return `A RangeError occurred ${location}: ${error.message}. A value is outside the allowed range.`;
    case 'SecurityError':
      return `A SecurityError occurred ${location}: ${error.message}. A security policy was violated.`;
    default:
      return `${error.name} occurred ${location}: ${error.message}.`;
  }
}

/**
 * Suggest a fix based on error type and message patterns.
 */
function suggestFix(error: ErrorInfo): string {
  const { name, message } = error;
  const lowerMessage = message.toLowerCase();

  switch (name) {
    case 'TypeError': {
      if (lowerMessage.includes('undefined') || lowerMessage.includes('null')) {
        return 'Add a null/undefined check before accessing the property or calling the method. Consider using optional chaining (?.) or nullish coalescing (??) operators.';
      }
      if (lowerMessage.includes('is not a function')) {
        return 'Verify the value is a function before calling it. Check that the import/require is correct and the module exports the expected function.';
      }
      return 'Check that all values are the expected type before performing operations on them. Add type guards or validation at function boundaries.';
    }
    case 'ReferenceError': {
      if (lowerMessage.includes('is not defined')) {
        const varMatch = message.match(/(\w+) is not defined/);
        const varName = varMatch ? varMatch[1] : 'the variable';
        return `Ensure ${varName} is defined and imported before use. Check for typos in the variable name and verify the import path is correct.`;
      }
      return 'Verify all variables and functions are properly declared and imported before use.';
    }
    case 'SyntaxError':
      return 'Fix the syntax error in the source code. Run a linter to catch additional syntax issues.';
    case 'RangeError':
      return 'Add bounds checking to prevent values from exceeding the allowed range. Validate inputs before passing them to functions.';
    case 'SecurityError':
      return 'Review the security policy configuration (CORS, CSP, etc.). Ensure the operation is allowed by the current security context.';
    default:
      return `Investigate the ${name} error. Check the stack trace for the originating function and add appropriate error handling.`;
  }
}
