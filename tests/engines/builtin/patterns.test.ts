import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { scanPatterns } from '../../../src/engines/builtin/patterns.js';
import type { Finding } from '../../../src/types.js';

// ── Helpers ──

let testDir: string;

beforeAll(async () => {
  testDir = join(tmpdir(), `shipsafe-pattern-test-${randomUUID().slice(0, 8)}`);
  await mkdir(testDir, { recursive: true });
});

afterAll(async () => {
  await rm(testDir, { recursive: true, force: true });
});

async function scanCode(code: string, filename = 'test.ts'): Promise<Finding[]> {
  const filePath = join(testDir, filename);
  await writeFile(filePath, code, 'utf-8');
  return scanPatterns(testDir, [filePath]);
}

function hasRule(findings: Finding[], ruleId: string): boolean {
  return findings.some((f) => f.id === ruleId);
}

// ════════════════════════════════════════════
// SQL Injection Rules
// ════════════════════════════════════════════

describe('SQL Injection detection', () => {
  describe('SQL_INJECTION_CONCAT', () => {
    it('catches db.get() with string concatenation', async () => {
      const findings = await scanCode(`
        db.get("SELECT * FROM users WHERE username = '" + username + "'", cb);
      `);
      expect(hasRule(findings, 'SQL_INJECTION_CONCAT')).toBe(true);
    });

    it('catches db.run() with string concatenation', async () => {
      const findings = await scanCode(`
        db.run("INSERT INTO users VALUES ('" + name + "')", cb);
      `);
      expect(hasRule(findings, 'SQL_INJECTION_CONCAT')).toBe(true);
    });

    it('catches query() with string concatenation', async () => {
      const findings = await scanCode(`
        pool.query("SELECT * FROM users WHERE id = " + userId, cb);
      `);
      expect(hasRule(findings, 'SQL_INJECTION_CONCAT')).toBe(true);
    });

    it('does NOT flag parameterized queries', async () => {
      const findings = await scanCode(`
        db.get("SELECT * FROM users WHERE id = ?", [userId], cb);
      `);
      expect(hasRule(findings, 'SQL_INJECTION_CONCAT')).toBe(false);
    });

    it('does NOT flag static SQL strings without concatenation', async () => {
      const findings = await scanCode(`
        db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY)");
      `);
      expect(hasRule(findings, 'SQL_INJECTION_CONCAT')).toBe(false);
    });
  });

  describe('SQL_INJECTION_TEMPLATE', () => {
    it('catches db.run() with template literal interpolation', async () => {
      const findings = await scanCode(
        'db.run(`INSERT INTO users (name) VALUES (\'${name}\')`);',
      );
      expect(hasRule(findings, 'SQL_INJECTION_TEMPLATE')).toBe(true);
    });

    it('catches query() with template literal interpolation', async () => {
      const findings = await scanCode(
        'pool.query(`SELECT * FROM users WHERE id = ${userId}`);',
      );
      expect(hasRule(findings, 'SQL_INJECTION_TEMPLATE')).toBe(true);
    });

    it('does NOT flag tagged template literals (sql`...`)', async () => {
      const findings = await scanCode(
        'const result = sql`SELECT * FROM users WHERE id = ${userId}`;',
      );
      expect(hasRule(findings, 'SQL_INJECTION_TEMPLATE')).toBe(false);
      expect(hasRule(findings, 'SQL_INJECTION_TEMPLATE_STRING')).toBe(false);
    });

    it('does NOT flag Prisma $queryRaw tagged templates', async () => {
      const findings = await scanCode(
        'const result = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;',
      );
      expect(hasRule(findings, 'SQL_INJECTION_TEMPLATE_STRING')).toBe(false);
    });
  });

  describe('SQL_INJECTION_TEMPLATE_STRING', () => {
    it('catches standalone template literal SQL strings', async () => {
      const findings = await scanCode(
        'const sql = `SELECT * FROM users WHERE id = ${userId}`;',
      );
      expect(hasRule(findings, 'SQL_INJECTION_TEMPLATE_STRING')).toBe(true);
    });

    it('does NOT flag template literals without SQL keywords', async () => {
      const findings = await scanCode(
        'const msg = `Hello ${userName}, welcome!`;',
      );
      expect(hasRule(findings, 'SQL_INJECTION_TEMPLATE_STRING')).toBe(false);
    });
  });

  describe('SQL_INJECTION_INLINE_VAR', () => {
    it('catches SQL string concatenated with a variable', async () => {
      const findings = await scanCode(`
        const sql = "SELECT * FROM users WHERE id = " + userId;
      `);
      expect(hasRule(findings, 'SQL_INJECTION_INLINE_VAR')).toBe(true);
    });

    it('does NOT flag non-SQL string concatenation', async () => {
      const findings = await scanCode(`
        const greeting = "Hello, " + userName;
      `);
      expect(hasRule(findings, 'SQL_INJECTION_INLINE_VAR')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Prompt Injection Rules
// ════════════════════════════════════════════

describe('Prompt Injection detection', () => {
  describe('PROMPT_INJECTION_CONCAT', () => {
    it('catches prompt variable built with req.body concatenation', async () => {
      const findings = await scanCode(`
        const prompt = "You are a helpful assistant. Answer: " + req.body.message;
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_CONCAT')).toBe(true);
    });

    it('catches systemPrompt with template literal and req.body', async () => {
      const findings = await scanCode(
        'const systemPrompt = `You are a helper. Topic: ${req.body.topic}`;',
      );
      expect(hasRule(findings, 'PROMPT_INJECTION_CONCAT')).toBe(true);
    });

    it('does NOT flag prompt assigned from env variable', async () => {
      const findings = await scanCode(`
        const prompt = process.env.SYSTEM_PROMPT;
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_CONCAT')).toBe(false);
    });

    it('does NOT flag static prompt strings', async () => {
      const findings = await scanCode(`
        const prompt = "You are a helpful assistant. Be concise.";
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_CONCAT')).toBe(false);
    });

    it('does NOT flag normal string concatenation unrelated to prompts', async () => {
      const findings = await scanCode(`
        const url = baseUrl + "/api/users/" + userId;
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_CONCAT')).toBe(false);
    });

    it('does NOT flag prompt with hardcoded constant concatenation', async () => {
      const findings = await scanCode(`
        const version = "v2";
        const greeting = "Hello! How can I help?";
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_CONCAT')).toBe(false);
    });
  });

  describe('PROMPT_INJECTION_TEMPLATE', () => {
    it('catches "You are..." prompt with interpolated user input', async () => {
      const findings = await scanCode(
        'const msg = `You are a summarizer. Summarize: ${req.body.text}`;',
      );
      expect(hasRule(findings, 'PROMPT_INJECTION_TEMPLATE')).toBe(true);
    });

    it('catches "Act as..." prompt with variable', async () => {
      const findings = await scanCode(
        'const p = `Act as a ${role} expert. Answer: ${userInput}`;',
      );
      expect(hasRule(findings, 'PROMPT_INJECTION_TEMPLATE')).toBe(true);
    });

    it('does NOT flag template literal without prompt-like language', async () => {
      const findings = await scanCode(
        'const html = `<div class="${className}">Hello ${name}</div>`;',
      );
      expect(hasRule(findings, 'PROMPT_INJECTION_TEMPLATE')).toBe(false);
    });

    it('does NOT flag "You are" in a plain comment', async () => {
      const findings = await scanCode(`
        // You are not going to believe this works
        const x = 42;
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_TEMPLATE')).toBe(false);
    });

    it('does NOT flag "You are" in a string without interpolation', async () => {
      const findings = await scanCode(`
        const systemMsg = "You are a helpful assistant.";
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_TEMPLATE')).toBe(false);
    });
  });

  describe('PROMPT_INJECTION_API_UNSANITIZED', () => {
    it('catches req.body passed directly to content field in AI context', async () => {
      const findings = await scanCode(`
        const response = await openai.chat.completions.create({
          model: 'gpt-4',
          messages: [
            { role: 'user', content: req.body.message },
          ],
        });
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_API_UNSANITIZED')).toBe(true);
    });

    it('does NOT flag content field in non-AI context', async () => {
      const findings = await scanCode(`
        const blogPost = {
          title: "Hello",
          content: req.body.content,
          author: "me",
        };
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_API_UNSANITIZED')).toBe(false);
    });

    it('does NOT flag sanitized input passed to content', async () => {
      const findings = await scanCode(`
        const sanitized = sanitize(req.body.message);
        const response = await openai.chat.completions.create({
          model: 'gpt-4',
          messages: [
            { role: 'user', content: sanitized },
          ],
        });
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_API_UNSANITIZED')).toBe(false);
    });
  });

  describe('PROMPT_INJECTION_SYSTEM_ROLE_USER_INPUT', () => {
    it('catches user input in system role message via template literal', async () => {
      const findings = await scanCode(`
        const messages = [
          { role: 'system', content: \`You are helping with \${req.body.topic}\` },
          { role: 'user', content: userMessage },
        ];
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_SYSTEM_ROLE_USER_INPUT')).toBe(true);
    });

    it('catches user input in system role message via req.body', async () => {
      const findings = await scanCode(`
        const messages = [
          { role: "system", content: req.body.systemPrompt },
          { role: "user", content: req.body.message },
        ];
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_SYSTEM_ROLE_USER_INPUT')).toBe(true);
    });

    it('does NOT flag static system message', async () => {
      const findings = await scanCode(`
        const messages = [
          { role: 'system', content: 'You are a helpful assistant.' },
          { role: 'user', content: userMessage },
        ];
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_SYSTEM_ROLE_USER_INPUT')).toBe(false);
    });

    it('does NOT flag user role messages with req.body', async () => {
      const findings = await scanCode(`
        const messages = [
          { role: 'user', content: req.body.message },
        ];
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_SYSTEM_ROLE_USER_INPUT')).toBe(false);
    });
  });

  describe('PROMPT_INJECTION_NO_INPUT_LIMIT', () => {
    it('catches completions.create without nearby length check', async () => {
      const findings = await scanCode(`
        app.post('/chat', async (req, res) => {
          const response = await openai.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'user', content: req.body.message }],
          });
          res.json(response);
        });
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_NO_INPUT_LIMIT')).toBe(true);
    });

    it('does NOT flag when length validation exists nearby', async () => {
      const findings = await scanCode(`
        app.post('/chat', async (req, res) => {
          const message = req.body.message;
          if (message.length > 4000) return res.status(400).json({ error: 'Too long' });
          const response = await openai.chat.completions.create({
            model: 'gpt-4',
            messages: [{ role: 'user', content: message }],
          });
          res.json(response);
        });
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_NO_INPUT_LIMIT')).toBe(false);
    });

    it('does NOT flag when maxTokens is set nearby', async () => {
      const findings = await scanCode(`
        const maxTokens = 1000;
        const input = req.body.message.slice(0, maxTokens);
        const response = await openai.chat.completions.create({
          model: 'gpt-4',
          messages: [{ role: 'user', content: input }],
        });
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_NO_INPUT_LIMIT')).toBe(false);
    });

    it('does NOT flag calls without user input', async () => {
      const findings = await scanCode(`
        const response = await openai.chat.completions.create({
          model: 'gpt-4',
          messages: [{ role: 'user', content: 'Hello, how are you?' }],
        });
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_NO_INPUT_LIMIT')).toBe(false);
    });
  });

  describe('PROMPT_INJECTION_RAG_UNSANITIZED', () => {
    it('catches retrieved documents injected into prompt', async () => {
      const findings = await scanCode(`
        const messages = [
          { role: 'system', content: \`Answer based on these documents: \${retrievedContext}\` },
          { role: 'user', content: userQuery },
        ];
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_RAG_UNSANITIZED')).toBe(true);
    });

    it('does NOT flag searchResults used outside LLM context', async () => {
      const findings = await scanCode(`
        const results = searchResults.map(r => r.content);
        res.json({ results });
      `);
      expect(hasRule(findings, 'PROMPT_INJECTION_RAG_UNSANITIZED')).toBe(false);
    });
  });

  describe('PROMPT_INJECTION_PYTHON_FSTRING (Python)', () => {
    it('catches Python f-string prompt with variable', async () => {
      const findings = await scanCode(
        'prompt = f"You are a helpful assistant. The user asks: {user_input}"',
        'test.py',
      );
      expect(hasRule(findings, 'PROMPT_INJECTION_PYTHON_FSTRING')).toBe(true);
    });

    it('does NOT flag regular Python f-string', async () => {
      const findings = await scanCode(
        'greeting = f"Hello {name}, welcome!"',
        'test.py',
      );
      expect(hasRule(findings, 'PROMPT_INJECTION_PYTHON_FSTRING')).toBe(false);
    });

    it('does NOT flag Python prompt without f-string', async () => {
      const findings = await scanCode(
        'prompt = "You are a helpful assistant."',
        'test.py',
      );
      expect(hasRule(findings, 'PROMPT_INJECTION_PYTHON_FSTRING')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// False positive regression tests
// ════════════════════════════════════════════

describe('False positive prevention', () => {
  it('does NOT flag normal Express route handlers as prompt injection', async () => {
    const findings = await scanCode(`
      app.post('/users', async (req, res) => {
        const { name, email } = req.body;
        const user = await db.create({ name, email });
        res.json(user);
      });
    `);
    const promptFindings = findings.filter((f) => f.id.startsWith('PROMPT_INJECTION'));
    expect(promptFindings).toHaveLength(0);
  });

  it('does NOT flag React components as prompt injection', async () => {
    const findings = await scanCode(`
      function ChatMessage({ role, content }: { role: string; content: string }) {
        return (
          <div className={role === 'system' ? 'system' : 'user'}>
            {content}
          </div>
        );
      }
    `, 'ChatMessage.tsx');
    const promptFindings = findings.filter((f) => f.id.startsWith('PROMPT_INJECTION'));
    expect(promptFindings).toHaveLength(0);
  });

  it('does NOT flag test files', async () => {
    const findings = await scanCode(`
      const prompt = "You are a helpful assistant. " + userInput;
      db.get("SELECT * FROM users WHERE id = " + id);
    `, 'api.test.ts');
    // Most security rules skip test files
    const sqlFindings = findings.filter((f) => f.id.startsWith('SQL_INJECTION'));
    const promptFindings = findings.filter((f) => f.id.startsWith('PROMPT_INJECTION'));
    expect(sqlFindings).toHaveLength(0);
    expect(promptFindings).toHaveLength(0);
  });

  it('does NOT flag i18n/localization strings as prompts', async () => {
    const findings = await scanCode(`
      const translations = {
        greeting: "You are welcome here!",
        instructions: "Your task is to select a plan.",
      };
    `);
    const promptFindings = findings.filter((f) => f.id.startsWith('PROMPT_INJECTION'));
    expect(promptFindings).toHaveLength(0);
  });

  it('does NOT flag logging statements as prompt injection', async () => {
    const findings = await scanCode(`
      logger.info("System: processing request for " + userId);
      console.log("Instructions: " + taskName + " completed");
    `);
    const promptFindings = findings.filter((f) => f.id.startsWith('PROMPT_INJECTION'));
    expect(promptFindings).toHaveLength(0);
  });

  it('does NOT flag README/documentation content in code', async () => {
    const findings = await scanCode(`
      const HELP_TEXT = "You are using ShipSafe v2. Your role is to keep code secure.";
    `);
    const promptFindings = findings.filter((f) => f.id.startsWith('PROMPT_INJECTION'));
    expect(promptFindings).toHaveLength(0);
  });

  it('does NOT flag ORM operations with destructured req.body as SQL injection', async () => {
    const findings = await scanCode(`
      const { name, email } = req.body;
      await db.run("INSERT INTO users (name, email) VALUES (?, ?)", [name, email]);
    `);
    const sqlFindings = findings.filter((f) => f.id === 'SQL_INJECTION_CONCAT');
    expect(sqlFindings).toHaveLength(0);
  });

  it('does NOT flag content field in CMS/blog contexts as prompt injection', async () => {
    const findings = await scanCode(`
      const post = {
        title: req.body.title,
        content: req.body.content,
        slug: req.body.slug,
      };
      await db.run("INSERT INTO posts (title, content, slug) VALUES (?, ?, ?)", [post.title, post.content, post.slug]);
    `);
    const promptFindings = findings.filter((f) => f.id.startsWith('PROMPT_INJECTION'));
    expect(promptFindings).toHaveLength(0);
  });

  it('does NOT flag string concatenation in error messages as SQL injection', async () => {
    const findings = await scanCode(`
      throw new Error("Failed to process user: " + userId);
    `);
    const sqlFindings = findings.filter((f) => f.id.startsWith('SQL_INJECTION'));
    expect(sqlFindings).toHaveLength(0);
  });
});
