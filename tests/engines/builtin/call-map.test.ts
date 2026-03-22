import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { buildCallMap, findClosestFunctionKey } from '../../../src/engines/builtin/call-map.js';
import type { CallMap } from '../../../src/engines/builtin/call-map.js';

let testDir: string;

beforeAll(async () => {
  testDir = join(tmpdir(), `shipsafe-callmap-test-${randomUUID().slice(0, 8)}`);
  await mkdir(testDir, { recursive: true });
});

afterAll(async () => {
  await rm(testDir, { recursive: true, force: true });
});

async function writeTestFile(name: string, content: string): Promise<string> {
  const filePath = join(testDir, name);
  const dir = filePath.substring(0, filePath.lastIndexOf('/'));
  await mkdir(dir, { recursive: true });
  await writeFile(filePath, content, 'utf-8');
  return filePath;
}

describe('buildCallMap', () => {
  describe('basic function extraction', () => {
    it('extracts functions and call sites from a single file', async () => {
      const file = await writeTestFile('basic.ts', `
function greet(name: string) {
  return "Hello " + name;
}

function main() {
  greet("world");
}
`);
      const callMap = await buildCallMap(testDir, [file]);

      expect(callMap.functions.size).toBeGreaterThanOrEqual(2);

      const mainKey = `${file}:main`;
      const mainNode = callMap.functions.get(mainKey);
      expect(mainNode).toBeDefined();
      expect(mainNode!.callees.has('greet')).toBe(true);

      const greetKey = `${file}:greet`;
      const greetNode = callMap.functions.get(greetKey);
      expect(greetNode).toBeDefined();
      expect(greetNode!.callers.has(mainKey)).toBe(true);
    });

    it('extracts exported functions', async () => {
      const file = await writeTestFile('exported.ts', `
export function authenticate(req: any) {
  return req.user;
}
`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = `${file}:authenticate`;
      const node = callMap.functions.get(key);
      expect(node).toBeDefined();
      expect(node!.isExported).toBe(true);
    });

    it('extracts async functions', async () => {
      const file = await writeTestFile('async-fn.ts', `
export async function fetchData() {
  return await fetch('/api/data');
}
`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = `${file}:fetchData`;
      const node = callMap.functions.get(key);
      expect(node).toBeDefined();
      expect(node!.isAsync).toBe(true);
    });
  });

  describe('cross-file resolution', () => {
    it('connects imported function callers across files', async () => {
      const authFile = await writeTestFile('cross/auth.ts', `
export function requireAuth(req: any) {
  if (!req.user) throw new Error('Unauthorized');
}
`);
      const routeFile = await writeTestFile('cross/routes.ts', `
import { requireAuth } from './auth';

export function handleAdmin(req: any) {
  requireAuth(req);
  return { data: 'admin' };
}
`);

      const callMap = await buildCallMap(testDir, [authFile, routeFile]);

      // handleAdmin should call requireAuth
      const handlerKey = `${routeFile}:handleAdmin`;
      const handlerNode = callMap.functions.get(handlerKey);
      expect(handlerNode).toBeDefined();
      expect(handlerNode!.callees.has('requireAuth')).toBe(true);

      // requireAuth should be called from handleAdmin
      const authKey = `${authFile}:requireAuth`;
      const authNode = callMap.functions.get(authKey);
      expect(authNode).toBeDefined();
      expect(authNode!.callers.has(handlerKey)).toBe(true);
    });
  });

  describe('query: isCalledFromAuthContext', () => {
    it('returns true when function is called from auth middleware', async () => {
      const file = await writeTestFile('auth-ctx.ts', `
function authenticateUser(req: any) {
  return handleRequest(req);
}

function handleRequest(req: any) {
  return req.body;
}
`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = `${file}:handleRequest`;
      expect(callMap.isCalledFromAuthContext(key)).toBe(true);
    });

    it('returns false when function has no auth callers', async () => {
      const file = await writeTestFile('no-auth-ctx.ts', `
function processData(data: any) {
  return data;
}

function main() {
  processData({});
}
`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = `${file}:processData`;
      expect(callMap.isCalledFromAuthContext(key)).toBe(false);
    });

    it('detects auth context through guard function name', async () => {
      const file = await writeTestFile('guard-ctx.ts', `
function authGuard(req: any) {
  return getUser(req);
}

function getUser(req: any) {
  return req.user;
}
`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = `${file}:getUser`;
      expect(callMap.isCalledFromAuthContext(key)).toBe(true);
    });
  });

  describe('query: hasValidationInCallChain', () => {
    it('returns true when function calls a validation function', async () => {
      const file = await writeTestFile('validate-chain.ts', `
function validateInput(data: any) {
  return data;
}

function processRequest(req: any) {
  validateInput(req.body);
  return req.body;
}
`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = `${file}:processRequest`;
      expect(callMap.hasValidationInCallChain(key)).toBe(true);
    });

    it('returns true when callee chain includes sanitize function', async () => {
      const file = await writeTestFile('sanitize-chain.ts', `
function sanitizeHtml(html: string) {
  return html.replace(/<script>/g, '');
}

function renderContent(content: string) {
  return sanitizeHtml(content);
}
`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = `${file}:renderContent`;
      expect(callMap.hasValidationInCallChain(key)).toBe(true);
    });

    it('returns false when no validation in call chain', async () => {
      const file = await writeTestFile('no-validate-chain.ts', `
function processData(data: any) {
  return formatOutput(data);
}

function formatOutput(data: any) {
  return JSON.stringify(data);
}
`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = `${file}:processData`;
      expect(callMap.hasValidationInCallChain(key)).toBe(false);
    });
  });

  describe('query: getCallers / getCallees', () => {
    it('returns direct callers', async () => {
      const file = await writeTestFile('callers.ts', `
function target() { return 1; }
function callerA() { target(); }
function callerB() { target(); }
`);
      const callMap = await buildCallMap(testDir, [file]);
      const callers = callMap.getCallers(`${file}:target`);
      expect(callers).toContain(`${file}:callerA`);
      expect(callers).toContain(`${file}:callerB`);
    });

    it('returns direct callees', async () => {
      const file = await writeTestFile('callees.ts', `
function helper1() { return 1; }
function helper2() { return 2; }
function main() { helper1(); helper2(); }
`);
      const callMap = await buildCallMap(testDir, [file]);
      const callees = callMap.getCallees(`${file}:main`);
      expect(callees).toContain(`${file}:helper1`);
      expect(callees).toContain(`${file}:helper2`);
    });
  });

  describe('findClosestFunctionKey', () => {
    it('finds the function containing a given line', async () => {
      const file = await writeTestFile('closest.ts', `
function foo() {
  const x = 1;
  return x;
}

function bar() {
  const y = 2;
  return y;
}
`);
      const callMap = await buildCallMap(testDir, [file]);

      // Line 3 is inside foo (starts at line 2)
      const key1 = findClosestFunctionKey(callMap, file, 3);
      expect(key1).toBe(`${file}:foo`);

      // Line 8 is inside bar (starts at line 7)
      const key2 = findClosestFunctionKey(callMap, file, 8);
      expect(key2).toBe(`${file}:bar`);
    });

    it('returns null for unknown file', async () => {
      const file = await writeTestFile('known.ts', `function f() {}`);
      const callMap = await buildCallMap(testDir, [file]);
      const key = findClosestFunctionKey(callMap, '/nonexistent.ts', 1);
      expect(key).toBeNull();
    });
  });

  describe('file imports tracking', () => {
    it('tracks imported modules per file', async () => {
      const file = await writeTestFile('imports-tracking.ts', `
import express from 'express';
import helmet from 'helmet';

const app = express();
`);
      const callMap = await buildCallMap(testDir, [file]);
      const imports = callMap.fileImports.get(file);
      expect(imports).toBeDefined();
      expect(imports).toContain('express');
      expect(imports).toContain('helmet');
    });
  });
});
