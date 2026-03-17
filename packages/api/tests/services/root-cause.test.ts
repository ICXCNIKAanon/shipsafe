import { describe, it, expect } from 'vitest';
import { analyzeRootCause } from '../../src/services/root-cause.js';

describe('analyzeRootCause', () => {
  it('parses stack trace to identify originating function', () => {
    const result = analyzeRootCause({
      name: 'TypeError',
      message: 'Cannot read properties of undefined',
      stack: `TypeError: Cannot read properties of undefined
    at handleClick (/app/src/components/Button.tsx:15:10)
    at HTMLButtonElement.dispatch (/app/node_modules/react-dom/cjs/react-dom.development.js:3945:16)`,
    });

    expect(result.originating_function).toBe('handleClick');
    expect(result.originating_file).toBe('/app/src/components/Button.tsx');
  });

  it('skips node_modules frames', () => {
    const result = analyzeRootCause({
      name: 'Error',
      message: 'Something failed',
      stack: `Error: Something failed
    at Object.dispatch (/app/node_modules/some-lib/index.js:42:5)
    at processData (/app/src/utils/data.ts:88:12)
    at main (/app/src/index.ts:5:3)`,
    });

    expect(result.originating_function).toBe('processData');
    expect(result.originating_file).toBe('/app/src/utils/data.ts');
  });

  it('generates root cause description for TypeError', () => {
    const result = analyzeRootCause({
      name: 'TypeError',
      message: 'Cannot read properties of null',
      stack: `TypeError: Cannot read properties of null
    at render (/app/src/pages/Home.tsx:22:5)`,
    });

    expect(result.root_cause).toContain('TypeError');
    expect(result.root_cause).toContain('render');
    expect(result.root_cause).toContain('undefined or null');
  });

  it('generates root cause description for ReferenceError', () => {
    const result = analyzeRootCause({
      name: 'ReferenceError',
      message: 'myVar is not defined',
      stack: `ReferenceError: myVar is not defined
    at calculate (/app/src/math.ts:10:5)`,
    });

    expect(result.root_cause).toContain('ReferenceError');
    expect(result.root_cause).toContain('variable or function was used before being defined');
  });

  it('suggests null check fix for TypeError with undefined', () => {
    const result = analyzeRootCause({
      name: 'TypeError',
      message: 'Cannot read properties of undefined',
      stack: 'TypeError: Cannot read properties of undefined\n    at fn (/app/src/a.ts:1:1)',
    });

    expect(result.suggested_fix).toContain('null');
    expect(result.suggested_fix).toContain('optional chaining');
  });

  it('suggests import check for "is not a function" TypeError', () => {
    const result = analyzeRootCause({
      name: 'TypeError',
      message: 'foo is not a function',
      stack: 'TypeError: foo is not a function\n    at bar (/app/src/b.ts:5:3)',
    });

    expect(result.suggested_fix).toContain('function');
    expect(result.suggested_fix).toContain('import');
  });

  it('suggests variable definition for ReferenceError', () => {
    const result = analyzeRootCause({
      name: 'ReferenceError',
      message: 'myHelper is not defined',
      stack: 'ReferenceError: myHelper is not defined\n    at run (/app/src/c.ts:3:1)',
    });

    expect(result.suggested_fix).toContain('myHelper');
  });

  it('handles errors without stack traces', () => {
    const result = analyzeRootCause({
      name: 'Error',
      message: 'Unknown error',
    });

    expect(result.originating_function).toBe('unknown');
    expect(result.originating_file).toBe('unknown');
    expect(result.root_cause).toContain('Error');
  });

  it('handles SecurityError', () => {
    const result = analyzeRootCause({
      name: 'SecurityError',
      message: 'Blocked by CORS policy',
      stack: 'SecurityError: Blocked by CORS policy\n    at fetch (/app/src/api.ts:12:5)',
    });

    expect(result.root_cause).toContain('SecurityError');
    expect(result.root_cause).toContain('security policy');
    expect(result.suggested_fix).toContain('CORS');
  });

  it('handles anonymous function in stack trace', () => {
    const result = analyzeRootCause({
      name: 'Error',
      message: 'oops',
      stack: `Error: oops
    at /app/src/lambda.ts:5:10`,
    });

    expect(result.originating_function).toBe('<anonymous>');
    expect(result.originating_file).toBe('/app/src/lambda.ts');
  });
});
