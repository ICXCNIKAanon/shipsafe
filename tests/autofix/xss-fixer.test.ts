import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import type { Finding } from '../../src/types.js';
import {
  fixDangerouslySetInnerHTML,
  fixInnerHTML,
  fixEval,
  fixXss,
  fixXssInFile,
} from '../../src/autofix/xss-fixer.js';

let tmpDir: string;

async function createTmpDir(): Promise<string> {
  return await fs.mkdtemp(path.join(os.tmpdir(), 'shipsafe-xss-test-'));
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'xss_001',
    engine: 'pattern',
    severity: 'high',
    type: 'XSS_DANGEROUSLY_SET_INNERHTML',
    file: 'src/component.tsx',
    line: 5,
    description: 'dangerouslySetInnerHTML renders raw HTML',
    fix_suggestion: 'Sanitize with DOMPurify',
    auto_fixable: true,
    ...overrides,
  };
}

// ── fixDangerouslySetInnerHTML ──

describe('fixDangerouslySetInnerHTML', () => {
  it('wraps __html value with DOMPurify.sanitize()', () => {
    const content = [
      "import React from 'react';",
      '',
      'function Component({ html }) {',
      '  return (',
      '    <div dangerouslySetInnerHTML={{ __html: userContent }} />',
      '  );',
      '}',
    ].join('\n');

    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 5 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('DOMPurify.sanitize(userContent)');
    expect(result!.fixed).toContain("import DOMPurify from 'dompurify';");
    expect(result!.description).toContain('DOMPurify');
  });

  it('handles variable expressions in __html value', () => {
    const content = [
      "import React from 'react';",
      '',
      'function Component({ data }) {',
      '  return (',
      '    <div dangerouslySetInnerHTML={{ __html: data.htmlContent }} />',
      '  );',
      '}',
    ].join('\n');

    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 5 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('DOMPurify.sanitize(data.htmlContent)');
  });

  it('handles function call expressions in __html value', () => {
    const content = [
      "import React from 'react';",
      '',
      'function Component() {',
      '  return (',
      '    <div dangerouslySetInnerHTML={{ __html: getContent() }} />',
      '  );',
      '}',
    ].join('\n');

    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 5 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('DOMPurify.sanitize(getContent())');
  });

  it('does not double-wrap if already sanitized', () => {
    const content = [
      "import DOMPurify from 'dompurify';",
      '',
      'function Component({ html }) {',
      '  return (',
      '    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />',
      '  );',
      '}',
    ].join('\n');

    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 5 }));
    expect(result).toBeNull();
  });

  it('adds DOMPurify import after existing imports', () => {
    const content = [
      "import React from 'react';",
      "import { useState } from 'react';",
      '',
      'function Component({ html }) {',
      '  return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
    ].join('\n');

    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 5 }));
    expect(result).not.toBeNull();
    const lines = result!.fixed.split('\n');
    // DOMPurify import should be after the existing imports (line index 2)
    const dpImportIdx = lines.findIndex((l) => l.includes("import DOMPurify from 'dompurify'"));
    const lastReactImportIdx = lines.findIndex((l) => l.includes("import { useState }"));
    expect(dpImportIdx).toBeGreaterThan(lastReactImportIdx);
  });

  it('does not duplicate DOMPurify import if already present', () => {
    const content = [
      "import React from 'react';",
      "import DOMPurify from 'dompurify';",
      '',
      'function Component({ html }) {',
      '  return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
    ].join('\n');

    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 5 }));
    expect(result).not.toBeNull();
    const matches = result!.fixed.match(/import DOMPurify/g);
    expect(matches).toHaveLength(1);
  });

  it('returns null when line does not match pattern', () => {
    const content = [
      "import React from 'react';",
      '',
      'function Component() {',
      '  return <div>Hello</div>;',
      '}',
    ].join('\n');

    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 4 }));
    expect(result).toBeNull();
  });

  it('returns null for invalid line number', () => {
    const content = 'const x = 1;';
    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 999 }));
    expect(result).toBeNull();
  });

  it('uses require() syntax for CJS files', () => {
    const content = [
      "const React = require('react');",
      '',
      'function Component({ html }) {',
      '  return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
    ].join('\n');

    const result = fixDangerouslySetInnerHTML(content, makeFinding({ line: 4 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain("const DOMPurify = require('dompurify');");
  });
});

// ── fixInnerHTML ──

describe('fixInnerHTML', () => {
  it('replaces innerHTML with textContent', () => {
    const content = [
      'function render(el, data) {',
      '  el.innerHTML = data;',
      '}',
    ].join('\n');

    const result = fixInnerHTML(content, makeFinding({ type: 'XSS_INNERHTML', line: 2 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('el.textContent = data;');
    expect(result!.fixed).not.toContain('innerHTML');
    expect(result!.description).toContain('textContent');
  });

  it('handles document.getElementById().innerHTML', () => {
    const content = [
      'function update(text) {',
      "  document.getElementById('output').innerHTML = text;",
      '}',
    ].join('\n');

    const result = fixInnerHTML(content, makeFinding({ type: 'XSS_INNERHTML', line: 2 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain("document.getElementById('output').textContent = text;");
  });

  it('does not fix when already using DOMPurify', () => {
    const content = [
      'function render(el, data) {',
      '  el.innerHTML = DOMPurify.sanitize(data);',
      '}',
    ].join('\n');

    const result = fixInnerHTML(content, makeFinding({ type: 'XSS_INNERHTML', line: 2 }));
    expect(result).toBeNull();
  });

  it('returns null for non-innerHTML line', () => {
    const content = [
      'function render(el, data) {',
      '  el.textContent = data;',
      '}',
    ].join('\n');

    const result = fixInnerHTML(content, makeFinding({ type: 'XSS_INNERHTML', line: 2 }));
    expect(result).toBeNull();
  });
});

// ── fixEval ──

describe('fixEval', () => {
  it('replaces eval() with JSON.parse() for data context', () => {
    const content = [
      'function parseData(jsonData) {',
      '  const result = eval(jsonData);',
      '  return result;',
      '}',
    ].join('\n');

    const result = fixEval(content, makeFinding({ type: 'XSS_EVAL', line: 2 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('JSON.parse(jsonData)');
    expect(result!.description).toContain('JSON.parse');
  });

  it('replaces eval() with JSON.parse() for response context', () => {
    const content = [
      'function process(response) {',
      '  return eval(response);',
      '}',
    ].join('\n');

    const result = fixEval(content, makeFinding({ type: 'XSS_EVAL', line: 2 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('JSON.parse(response)');
  });

  it('adds security comment for non-data eval()', () => {
    const content = [
      'function execute(code) {',
      '  eval(code);',
      '}',
    ].join('\n');

    const result = fixEval(content, makeFinding({ type: 'XSS_EVAL', line: 2 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('// SECURITY: eval()');
    expect(result!.description).toContain('security warning');
  });

  it('does not fix redis.eval()', () => {
    const content = [
      'async function runLua() {',
      '  await redis.eval(luaScript, keys, args);',
      '}',
    ].join('\n');

    const result = fixEval(content, makeFinding({ type: 'XSS_EVAL', line: 2 }));
    expect(result).toBeNull();
  });

  it('returns null when line has no eval()', () => {
    const content = [
      'function noEval() {',
      '  return JSON.parse(data);',
      '}',
    ].join('\n');

    const result = fixEval(content, makeFinding({ type: 'XSS_EVAL', line: 2 }));
    expect(result).toBeNull();
  });
});

// ── fixXss (unified dispatcher) ──

describe('fixXss', () => {
  it('dispatches XSS_DANGEROUSLY_SET_INNERHTML to fixDangerouslySetInnerHTML', () => {
    const content = [
      "import React from 'react';",
      '<div dangerouslySetInnerHTML={{ __html: content }} />',
    ].join('\n');

    const result = fixXss(content, makeFinding({ type: 'XSS_DANGEROUSLY_SET_INNERHTML', line: 2 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('DOMPurify.sanitize');
  });

  it('dispatches REACT_DANGEROUSLYSETINNERHTML_VARIABLE', () => {
    const content = [
      "import React from 'react';",
      '<div dangerouslySetInnerHTML={{ __html: userHtml }} />',
    ].join('\n');

    const result = fixXss(content, makeFinding({ type: 'REACT_DANGEROUSLYSETINNERHTML_VARIABLE', line: 2 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('DOMPurify.sanitize');
  });

  it('dispatches XSS_INNERHTML to fixInnerHTML', () => {
    const content = 'el.innerHTML = value;';

    const result = fixXss(content, makeFinding({ type: 'XSS_INNERHTML', line: 1 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('textContent');
  });

  it('dispatches DOM_XSS_INNERHTML_ASSIGN to fixInnerHTML', () => {
    const content = 'element.innerHTML = userInput;';

    const result = fixXss(content, makeFinding({ type: 'DOM_XSS_INNERHTML_ASSIGN', line: 1 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('textContent');
  });

  it('dispatches XSS_EVAL to fixEval', () => {
    const content = 'const result = eval(jsonData);';

    const result = fixXss(content, makeFinding({ type: 'XSS_EVAL', line: 1 }));
    expect(result).not.toBeNull();
    expect(result!.fixed).toContain('JSON.parse');
  });

  it('returns null for unsupported finding type', () => {
    const content = 'document.write(data);';

    const result = fixXss(content, makeFinding({ type: 'XSS_DOCUMENT_WRITE', line: 1 }));
    expect(result).toBeNull();
  });
});

// ── fixXssInFile ──

describe('fixXssInFile', () => {
  beforeEach(async () => {
    tmpDir = await createTmpDir();
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('fixes dangerouslySetInnerHTML in a real file', async () => {
    const filePath = path.join(tmpDir, 'src');
    await fs.mkdir(filePath, { recursive: true });
    const file = path.join(filePath, 'component.tsx');
    const content = [
      "import React from 'react';",
      '',
      'export function Page({ html }) {',
      '  return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
    ].join('\n');
    await fs.writeFile(file, content, 'utf-8');

    const finding = makeFinding({
      type: 'XSS_DANGEROUSLY_SET_INNERHTML',
      file: 'src/component.tsx',
      line: 4,
    });

    const result = await fixXssInFile(finding, tmpDir);
    expect(result.filesModified).toContain('src/component.tsx');

    const fixed = await fs.readFile(file, 'utf-8');
    expect(fixed).toContain('DOMPurify.sanitize(html)');
    expect(fixed).toContain("import DOMPurify from 'dompurify';");
  });

  it('fixes innerHTML in a real file', async () => {
    const filePath = path.join(tmpDir, 'src');
    await fs.mkdir(filePath, { recursive: true });
    const file = path.join(filePath, 'render.ts');
    const content = [
      'function render(el: HTMLElement, data: string) {',
      '  el.innerHTML = data;',
      '}',
    ].join('\n');
    await fs.writeFile(file, content, 'utf-8');

    const finding = makeFinding({
      type: 'XSS_INNERHTML',
      file: 'src/render.ts',
      line: 2,
    });

    const result = await fixXssInFile(finding, tmpDir);
    expect(result.filesModified).toContain('src/render.ts');

    const fixed = await fs.readFile(file, 'utf-8');
    expect(fixed).toContain('el.textContent = data;');
  });

  it('throws when the fix cannot be applied', async () => {
    const filePath = path.join(tmpDir, 'src');
    await fs.mkdir(filePath, { recursive: true });
    const file = path.join(filePath, 'safe.ts');
    await fs.writeFile(file, 'const x = 1;\n', 'utf-8');

    const finding = makeFinding({
      type: 'XSS_INNERHTML',
      file: 'src/safe.ts',
      line: 1,
    });

    await expect(fixXssInFile(finding, tmpDir)).rejects.toThrow('Could not auto-fix XSS');
  });
});
