import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  initParser,
  parseFile,
  parseProject,
  detectLanguage,
} from '../../../src/engines/graph/parser.js';
import type { SupportedLanguage } from '../../../src/types.js';

const FIXTURES_DIR = path.resolve(import.meta.dirname, '../../fixtures');

beforeAll(async () => {
  await initParser();
}, 30_000);

// ── detectLanguage ──

describe('detectLanguage', () => {
  it('returns typescript for .ts files', () => {
    expect(detectLanguage('foo.ts')).toBe('typescript');
  });

  it('returns typescript for .tsx files', () => {
    expect(detectLanguage('foo.tsx')).toBe('typescript');
  });

  it('returns javascript for .js files', () => {
    expect(detectLanguage('foo.js')).toBe('javascript');
  });

  it('returns javascript for .jsx files', () => {
    expect(detectLanguage('bar.jsx')).toBe('javascript');
  });

  it('returns javascript for .mjs files', () => {
    expect(detectLanguage('lib.mjs')).toBe('javascript');
  });

  it('returns javascript for .cjs files', () => {
    expect(detectLanguage('lib.cjs')).toBe('javascript');
  });

  it('returns python for .py files', () => {
    expect(detectLanguage('foo.py')).toBe('python');
  });

  it('returns null for unsupported extensions', () => {
    expect(detectLanguage('foo.md')).toBeNull();
    expect(detectLanguage('readme.txt')).toBeNull();
    expect(detectLanguage('data.json')).toBeNull();
    expect(detectLanguage('style.css')).toBeNull();
  });

  it('handles paths with directories', () => {
    expect(detectLanguage('src/utils/helper.ts')).toBe('typescript');
    expect(detectLanguage('/home/user/project/main.py')).toBe('python');
  });
});

// ── parseFile: TypeScript ──

describe('parseFile — TypeScript', () => {
  let tsContent: string;
  const tsFile = 'tests/fixtures/sample.ts';

  beforeAll(async () => {
    tsContent = await readFile(path.join(FIXTURES_DIR, 'sample.ts'), 'utf-8');
  });

  it('extracts functions from TypeScript file', async () => {
    const result = await parseFile(tsFile, tsContent);

    const funcNames = result.functions.map((f) => f.name);
    expect(funcNames).toContain('validateInput');
    expect(funcNames).toContain('helper');
  });

  it('extracts class methods as functions', async () => {
    const result = await parseFile(tsFile, tsContent);

    const methods = result.functions.filter((f) => f.className === 'UserController');
    const methodNames = methods.map((m) => m.name);
    expect(methodNames).toContain('getUser');
    expect(methodNames).toContain('deleteUser');
  });

  it('extracts classes with their method names', async () => {
    const result = await parseFile(tsFile, tsContent);

    expect(result.classes).toHaveLength(1);
    expect(result.classes[0].name).toBe('UserController');
    expect(result.classes[0].methods).toContain('getUser');
    expect(result.classes[0].methods).toContain('deleteUser');
  });

  it('extracts imports from TypeScript file', async () => {
    const result = await parseFile(tsFile, tsContent);

    expect(result.imports).toHaveLength(2);

    const expressImport = result.imports.find((i) => i.source === 'express');
    expect(expressImport).toBeDefined();
    expect(expressImport!.specifiers).toContain('Request');
    expect(expressImport!.specifiers).toContain('Response');

    const dbImport = result.imports.find((i) => i.source === './database');
    expect(dbImport).toBeDefined();
    expect(dbImport!.specifiers).toContain('db');
  });

  it('extracts exports from TypeScript file', async () => {
    const result = await parseFile(tsFile, tsContent);

    const exportNames = result.exports.map((e) => e.name);
    expect(exportNames).toContain('UserController');
    expect(exportNames).toContain('validateInput');

    const classExport = result.exports.find((e) => e.name === 'UserController');
    expect(classExport!.type).toBe('class');

    const funcExport = result.exports.find((e) => e.name === 'validateInput');
    expect(funcExport!.type).toBe('function');
  });

  it('identifies async functions', async () => {
    const result = await parseFile(tsFile, tsContent);

    const getUser = result.functions.find((f) => f.name === 'getUser');
    expect(getUser).toBeDefined();
    expect(getUser!.isAsync).toBe(true);

    const validateInput = result.functions.find((f) => f.name === 'validateInput');
    expect(validateInput).toBeDefined();
    expect(validateInput!.isAsync).toBe(false);

    const helper = result.functions.find((f) => f.name === 'helper');
    expect(helper).toBeDefined();
    expect(helper!.isAsync).toBe(false);
  });

  it('extracts function parameters', async () => {
    const result = await parseFile(tsFile, tsContent);

    const getUser = result.functions.find((f) => f.name === 'getUser');
    expect(getUser!.params).toEqual(['req', 'res']);

    const validateInput = result.functions.find((f) => f.name === 'validateInput');
    expect(validateInput!.params).toEqual(['data']);

    const helper = result.functions.find((f) => f.name === 'helper');
    expect(helper!.params).toEqual(['x']);
  });

  it('marks exported functions correctly', async () => {
    const result = await parseFile(tsFile, tsContent);

    const validateInput = result.functions.find((f) => f.name === 'validateInput');
    expect(validateInput!.isExported).toBe(true);

    const helper = result.functions.find((f) => f.name === 'helper');
    expect(helper!.isExported).toBe(false);

    // Methods of exported class should be marked as exported
    const getUser = result.functions.find((f) => f.name === 'getUser');
    expect(getUser!.isExported).toBe(true);
  });

  it('extracts call sites', async () => {
    const result = await parseFile(tsFile, tsContent);

    // db.findUser called inside getUser
    const findUserCall = result.callSites.find((c) => c.calleeName === 'findUser');
    expect(findUserCall).toBeDefined();
    expect(findUserCall!.callerName).toBe('getUser');
    expect(findUserCall!.receiver).toBe('db');

    // res.json called inside getUser
    const jsonCall = result.callSites.find(
      (c) => c.calleeName === 'json' && c.callerName === 'getUser',
    );
    expect(jsonCall).toBeDefined();
    expect(jsonCall!.receiver).toBe('res');
  });

  it('records correct line numbers for functions', async () => {
    const result = await parseFile(tsFile, tsContent);

    const validateInput = result.functions.find((f) => f.name === 'validateInput');
    expect(validateInput!.startLine).toBe(16);
    expect(validateInput!.endLine).toBe(18);
  });

  it('sets filePath on all extracted nodes', async () => {
    const result = await parseFile(tsFile, tsContent);

    expect(result.filePath).toBe(tsFile);
    for (const fn of result.functions) expect(fn.filePath).toBe(tsFile);
    for (const cls of result.classes) expect(cls.filePath).toBe(tsFile);
    for (const imp of result.imports) expect(imp.filePath).toBe(tsFile);
    for (const exp of result.exports) expect(exp.filePath).toBe(tsFile);
    for (const call of result.callSites) expect(call.filePath).toBe(tsFile);
  });
});

// ── parseFile: Python ──

describe('parseFile — Python', () => {
  let pyContent: string;
  const pyFile = 'tests/fixtures/sample.py';

  beforeAll(async () => {
    pyContent = await readFile(path.join(FIXTURES_DIR, 'sample.py'), 'utf-8');
  });

  it('extracts functions from Python file', async () => {
    const result = await parseFile(pyFile, pyContent);

    const funcNames = result.functions.map((f) => f.name);
    expect(funcNames).toContain('validate_input');
  });

  it('extracts class methods from Python file', async () => {
    const result = await parseFile(pyFile, pyContent);

    const methods = result.functions.filter((f) => f.className === 'UserService');
    const methodNames = methods.map((m) => m.name);
    expect(methodNames).toContain('get_user');
    expect(methodNames).toContain('delete_user');
  });

  it('extracts classes from Python file', async () => {
    const result = await parseFile(pyFile, pyContent);

    expect(result.classes).toHaveLength(1);
    expect(result.classes[0].name).toBe('UserService');
    expect(result.classes[0].methods).toContain('get_user');
    expect(result.classes[0].methods).toContain('delete_user');
  });

  it('extracts imports from Python file', async () => {
    const result = await parseFile(pyFile, pyContent);

    expect(result.imports).toHaveLength(2);

    const flaskImport = result.imports.find((i) => i.source === 'flask');
    expect(flaskImport).toBeDefined();
    expect(flaskImport!.specifiers).toContain('request');
    expect(flaskImport!.specifiers).toContain('jsonify');

    const modelsImport = result.imports.find((i) => i.source === 'models');
    expect(modelsImport).toBeDefined();
    expect(modelsImport!.specifiers).toContain('User');
  });

  it('excludes self from method parameters', async () => {
    const result = await parseFile(pyFile, pyContent);

    const getUser = result.functions.find((f) => f.name === 'get_user');
    expect(getUser).toBeDefined();
    expect(getUser!.params).toEqual(['user_id']);
    expect(getUser!.params).not.toContain('self');
  });

  it('extracts call sites from Python file', async () => {
    const result = await parseFile(pyFile, pyContent);

    // User.query.get called inside get_user
    const getCalls = result.callSites.filter((c) => c.calleeName === 'get');
    expect(getCalls.length).toBeGreaterThanOrEqual(1);

    // isinstance called inside validate_input
    const isinstanceCall = result.callSites.find((c) => c.calleeName === 'isinstance');
    expect(isinstanceCall).toBeDefined();
    expect(isinstanceCall!.callerName).toBe('validate_input');
  });
});

// ── parseProject ──

describe('parseProject', () => {
  it('parses all supported files in a directory', async () => {
    const results = await parseProject(FIXTURES_DIR);

    // Should find both sample.ts and sample.py
    const filePaths = results.map((r) => r.filePath);
    expect(filePaths.some((p) => p.endsWith('sample.ts'))).toBe(true);
    expect(filePaths.some((p) => p.endsWith('sample.py'))).toBe(true);
  });

  it('excludes node_modules by default', async () => {
    // Use the project root which has node_modules
    const results = await parseProject(path.resolve(FIXTURES_DIR, '../..'), {
      include: ['tests/fixtures/**'],
    });

    const filePaths = results.map((r) => r.filePath);
    const nodeModulesFiles = filePaths.filter((p) => p.includes('node_modules'));
    expect(nodeModulesFiles).toHaveLength(0);
  });

  it('respects custom exclude patterns', async () => {
    const results = await parseProject(FIXTURES_DIR, {
      exclude: ['**/sample.py'],
    });

    const filePaths = results.map((r) => r.filePath);
    expect(filePaths.some((p) => p.endsWith('sample.py'))).toBe(false);
    expect(filePaths.some((p) => p.endsWith('sample.ts'))).toBe(true);
  });
});
