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
  // Ensure parent directory exists for nested paths like 'docs/examples/demo.ts'
  const parentDir = filePath.substring(0, filePath.lastIndexOf('/'));
  await mkdir(parentDir, { recursive: true });
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

// ════════════════════════════════════════════
// Cycle 61: Web Framework Middleware Patterns
// ════════════════════════════════════════════

describe('Web Framework Middleware detection', () => {
  describe('BODYPARSER_MISSING_LIMIT', () => {
    it('catches express.json() without limit', async () => {
      const findings = await scanCode(`
        app.use(express.json());
      `);
      expect(hasRule(findings, 'BODYPARSER_MISSING_LIMIT')).toBe(true);
    });
    it('catches bodyParser.urlencoded() without limit', async () => {
      const findings = await scanCode(`
        app.use(bodyParser.urlencoded({ extended: true }));
      `);
      expect(hasRule(findings, 'BODYPARSER_MISSING_LIMIT')).toBe(true);
    });
    it('does NOT flag express.json with limit', async () => {
      const findings = await scanCode(`
        app.use(express.json({ limit: "100kb" }));
      `);
      expect(hasRule(findings, 'BODYPARSER_MISSING_LIMIT')).toBe(false);
    });
  });

  describe('EXPRESS_STATIC_FROM_ROOT', () => {
    it('catches express.static serving from current directory', async () => {
      const findings = await scanCode(`
        app.use(express.static('.'));
      `);
      expect(hasRule(findings, 'EXPRESS_STATIC_FROM_ROOT')).toBe(true);
    });
    it('catches express.static with __dirname', async () => {
      const findings = await scanCode(`
        app.use(express.static(__dirname));
      `);
      expect(hasRule(findings, 'EXPRESS_STATIC_FROM_ROOT')).toBe(true);
    });
    it('does NOT flag express.static with public dir', async () => {
      const findings = await scanCode(`
        app.use(express.static('public'));
      `);
      expect(hasRule(findings, 'EXPRESS_STATIC_FROM_ROOT')).toBe(false);
    });
  });

  describe('COOKIE_NO_SIGNED_OPTION', () => {
    it('catches cookieParser without secret', async () => {
      const findings = await scanCode(`
        app.use(cookieParser());
      `);
      expect(hasRule(findings, 'COOKIE_NO_SIGNED_OPTION')).toBe(true);
    });
    it('does NOT flag cookieParser with secret', async () => {
      const findings = await scanCode(`
        app.use(cookieParser("my-secret"));
      `);
      expect(hasRule(findings, 'COOKIE_NO_SIGNED_OPTION')).toBe(false);
    });
  });

  describe('DOUBLE_CALLBACK_MIDDLEWARE', () => {
    it('catches next() followed by more code on same line', async () => {
      const findings = await scanCode(`
        app.use((req, res, next) => { next(); res.send("done"); });
      `);
      expect(hasRule(findings, 'DOUBLE_CALLBACK_MIDDLEWARE')).toBe(true);
    });
    it('does NOT flag return next()', async () => {
      const findings = await scanCode(`
        app.use((req, res, next) => { return next(); });
      `);
      expect(hasRule(findings, 'DOUBLE_CALLBACK_MIDDLEWARE')).toBe(false);
    });
  });

  describe('HELMET_MISSING_HSTS_MAXAGE', () => {
    it('catches HSTS with short maxAge', async () => {
      const findings = await scanCode(`
        app.use(helmet.hsts({ maxAge: 86400 }));
      `);
      expect(hasRule(findings, 'HELMET_MISSING_HSTS_MAXAGE')).toBe(true);
    });
    it('does NOT flag proper HSTS maxAge', async () => {
      const findings = await scanCode(`
        app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
      `);
      expect(hasRule(findings, 'HELMET_MISSING_HSTS_MAXAGE')).toBe(false);
    });
  });

  describe('HELMET_MISSING_REFERRER_POLICY', () => {
    it('catches helmet with referrerPolicy: false', async () => {
      const findings = await scanCode(`
        app.use(helmet({
          referrerPolicy: false
        }));
      `);
      expect(hasRule(findings, 'HELMET_MISSING_REFERRER_POLICY')).toBe(true);
    });
    it('does NOT flag helmet with referrerPolicy configured', async () => {
      const findings = await scanCode(`
        app.use(helmet({
          referrerPolicy: { policy: "strict-origin-when-cross-origin" }
        }));
      `);
      expect(hasRule(findings, 'HELMET_MISSING_REFERRER_POLICY')).toBe(false);
    });
  });

  describe('FASTIFY_NO_BODY_LIMIT', () => {
    it('catches fastify without bodyLimit', async () => {
      const findings = await scanCode(`
        const server = fastify({ logger: true });
      `);
      expect(hasRule(findings, 'FASTIFY_NO_BODY_LIMIT')).toBe(true);
    });
    it('does NOT flag fastify with bodyLimit', async () => {
      const findings = await scanCode(`
        const server = fastify({ bodyLimit: 1048576 });
      `);
      expect(hasRule(findings, 'FASTIFY_NO_BODY_LIMIT')).toBe(false);
    });
  });

  describe('TRUST_USER_AGENT_HEADER', () => {
    it('catches auth decision based on user-agent', async () => {
      const findings = await scanCode(`
        if (req.headers['user-agent'].includes('internal-service')) { isAdmin = true; }
      `);
      expect(hasRule(findings, 'TRUST_USER_AGENT_HEADER')).toBe(true);
    });
    it('does NOT flag logging user-agent', async () => {
      const findings = await scanCode(`
        logger.info("Request from: " + req.headers['user-agent']);
      `);
      expect(hasRule(findings, 'TRUST_USER_AGENT_HEADER')).toBe(false);
    });
  });

  describe('KOA_NO_BODY_LIMIT', () => {
    it('catches koaBody without limit options', async () => {
      const findings = await scanCode(`
        app.use(koaBody());
      `);
      expect(hasRule(findings, 'KOA_NO_BODY_LIMIT')).toBe(true);
    });
    it('does NOT flag koaBody with options', async () => {
      const findings = await scanCode(`
        app.use(koaBody({ jsonLimit: "100kb" }));
      `);
      expect(hasRule(findings, 'KOA_NO_BODY_LIMIT')).toBe(false);
    });
  });

  describe('HELMET_MISSING_XCTO', () => {
    it('catches helmet with noSniff disabled', async () => {
      const findings = await scanCode(`
        app.use(helmet({
          noSniff: false
        }));
      `);
      expect(hasRule(findings, 'HELMET_MISSING_XCTO')).toBe(true);
    });
    it('does NOT flag helmet without noSniff override', async () => {
      const findings = await scanCode(`
        app.use(helmet({
          contentSecurityPolicy: false
        }));
      `);
      expect(hasRule(findings, 'HELMET_MISSING_XCTO')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 62: Database Patterns Comprehensive
// ════════════════════════════════════════════

describe('Database Patterns detection', () => {
  describe('N_PLUS_ONE_QUERY', () => {
    it('catches await query inside for loop', async () => {
      const findings = await scanCode(`
        for (const id of ids) {
          const user = await db.findOne({ id });
        }
      `);
      expect(hasRule(findings, 'N_PLUS_ONE_QUERY')).toBe(true);
    });
    it('does NOT flag single query outside loop', async () => {
      const findings = await scanCode(`
        const user = await db.findOne({ id: userId });
      `);
      expect(hasRule(findings, 'N_PLUS_ONE_QUERY')).toBe(false);
    });
  });

  describe('MONGO_SET_FROM_BODY', () => {
    it('catches $set with req.body', async () => {
      const findings = await scanCode(`
        await collection.updateOne({ _id: id }, { $set: req.body });
      `);
      expect(hasRule(findings, 'MONGO_SET_FROM_BODY')).toBe(true);
    });
    it('does NOT flag $set with specific fields', async () => {
      const findings = await scanCode(`
        await collection.updateOne({ _id: id }, { $set: { name: req.body.name } });
      `);
      expect(hasRule(findings, 'MONGO_SET_FROM_BODY')).toBe(false);
    });
  });

  describe('REDIS_PUBSUB_UNVALIDATED_CHANNEL', () => {
    it('catches subscribe with user input channel', async () => {
      const findings = await scanCode(`
        redis.subscribe(req.query.channel);
      `);
      expect(hasRule(findings, 'REDIS_PUBSUB_UNVALIDATED_CHANNEL')).toBe(true);
    });
    it('does NOT flag subscribe with hardcoded channel', async () => {
      const findings = await scanCode(`
        redis.subscribe("notifications");
      `);
      expect(hasRule(findings, 'REDIS_PUBSUB_UNVALIDATED_CHANNEL')).toBe(false);
    });
  });

  describe('DB_RESULT_DIRECT_RESPONSE', () => {
    it('catches res.json(rows)', async () => {
      const findings = await scanCode(`
        const rows = await db.query("SELECT * FROM users");
        res.json(rows);
      `);
      expect(hasRule(findings, 'DB_RESULT_DIRECT_RESPONSE')).toBe(true);
    });
    it('does NOT flag mapped response', async () => {
      const findings = await scanCode(`
        const rows = await db.query("SELECT * FROM users");
        res.json(rows.map(r => ({ id: r.id, name: r.name })));
      `);
      expect(hasRule(findings, 'DB_RESULT_DIRECT_RESPONSE')).toBe(false);
    });
  });

  describe('DB_CREDENTIALS_IN_LOG', () => {
    it('catches console.log with connectionString', async () => {
      const findings = await scanCode(`
        console.log("Connecting to: " + connectionString);
      `);
      expect(hasRule(findings, 'DB_CREDENTIALS_IN_LOG')).toBe(true);
    });
    it('does NOT flag logging unrelated strings', async () => {
      const findings = await scanCode(`
        console.log("Server started on port " + port);
      `);
      expect(hasRule(findings, 'DB_CREDENTIALS_IN_LOG')).toBe(false);
    });
  });

  describe('DRIZZLE_RAW_TEMPLATE', () => {
    it('catches sql.raw with template literal', async () => {
      const findings = await scanCode(
        'const result = sql.raw(`SELECT * FROM users WHERE name = ${name}`);',
      );
      expect(hasRule(findings, 'DRIZZLE_RAW_TEMPLATE')).toBe(true);
    });
    it('does NOT flag sql tagged template', async () => {
      const findings = await scanCode(
        'const result = sql`SELECT * FROM users WHERE name = ${name}`;',
      );
      expect(hasRule(findings, 'DRIZZLE_RAW_TEMPLATE')).toBe(false);
    });
  });

  describe('TYPEORM_SYNCHRONIZE_PRODUCTION', () => {
    it('catches TypeORM synchronize: true', async () => {
      const findings = await scanCode(`
        const ds = new DataSource({ type: "postgres", synchronize: true });
      `);
      expect(hasRule(findings, 'TYPEORM_SYNCHRONIZE_PRODUCTION')).toBe(true);
    });
    it('does NOT flag synchronize: false', async () => {
      const findings = await scanCode(`
        const ds = new DataSource({ type: "postgres", synchronize: false });
      `);
      expect(hasRule(findings, 'TYPEORM_SYNCHRONIZE_PRODUCTION')).toBe(false);
    });
  });

  describe('MONGOOSE_NO_STRICT', () => {
    it('catches mongoose schema with strict: false', async () => {
      const findings = await scanCode(`
        const schema = new mongoose.Schema({ name: String }, { strict: false });
      `);
      expect(hasRule(findings, 'MONGOOSE_NO_STRICT')).toBe(true);
    });
    it('does NOT flag schema without strict option', async () => {
      const findings = await scanCode(`
        const schema = new mongoose.Schema({ name: String });
      `);
      expect(hasRule(findings, 'MONGOOSE_NO_STRICT')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 63: Authentication Patterns Deep
// ════════════════════════════════════════════

describe('Authentication Patterns detection', () => {
  describe('TIMING_UNSAFE_RESET_TOKEN', () => {
    it('catches resetToken compared with ===', async () => {
      const findings = await scanCode(`
        if (resetToken === storedToken) { allowReset(); }
      `);
      expect(hasRule(findings, 'TIMING_UNSAFE_RESET_TOKEN')).toBe(true);
    });
    it('does NOT flag timingSafeEqual comparison', async () => {
      const findings = await scanCode(`
        if (crypto.timingSafeEqual(Buffer.from(resetToken), Buffer.from(storedToken))) { allowReset(); }
      `);
      expect(hasRule(findings, 'TIMING_UNSAFE_RESET_TOKEN')).toBe(false);
    });
  });

  describe('PASSWORD_RESET_TOKEN_NO_TTL', () => {
    it('catches reset token without expiry', async () => {
      const findings = await scanCode(`
        const resetToken = crypto.randomBytes(32).toString('hex');
        await db.save({ token: resetToken, userId });
      `);
      expect(hasRule(findings, 'PASSWORD_RESET_TOKEN_NO_TTL')).toBe(true);
    });
    it('does NOT flag reset token with expiry', async () => {
      const findings = await scanCode(`
        const resetToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 3600000;
        await db.save({ token: resetToken, userId, expiresAt });
      `);
      expect(hasRule(findings, 'PASSWORD_RESET_TOKEN_NO_TTL')).toBe(false);
    });
  });

  describe('TWO_FA_BACKUP_CODES_UNHASHED', () => {
    it('catches backup codes stored as plain array', async () => {
      const findings = await scanCode(`
        const backupCodes = ['abc123', 'def456', 'ghi789'];
        await user.save({ backupCodes });
      `);
      expect(hasRule(findings, 'TWO_FA_BACKUP_CODES_UNHASHED')).toBe(true);
    });
    it('does NOT flag hashed backup codes', async () => {
      const findings = await scanCode(`
        const backupCodes = [await bcrypt.hash('abc123', 10), await bcrypt.hash('def456', 10)];
      `);
      expect(hasRule(findings, 'TWO_FA_BACKUP_CODES_UNHASHED')).toBe(false);
    });
  });

  describe('AUTH_TOKEN_IN_URL', () => {
    it('catches fetch with token in URL path', async () => {
      const findings = await scanCode(
        'const resp = await fetch(`/api/auth/${token}/verify`);',
      );
      expect(hasRule(findings, 'AUTH_TOKEN_IN_URL')).toBe(true);
    });
    it('does NOT flag fetch with token in header', async () => {
      const findings = await scanCode(`
        const resp = await fetch("/api/verify", { headers: { Authorization: "Bearer " + token } });
      `);
      expect(hasRule(findings, 'AUTH_TOKEN_IN_URL')).toBe(false);
    });
  });

  describe('SERVICE_ACCOUNT_ADMIN', () => {
    it('catches service account with admin role', async () => {
      const findings = await scanCode(`
        const serviceAccount = { name: "deployer", role: "admin" };
      `);
      expect(hasRule(findings, 'SERVICE_ACCOUNT_ADMIN')).toBe(true);
    });
    it('does NOT flag service account with limited role', async () => {
      const findings = await scanCode(`
        const serviceAccount = { name: "deployer", role: "reader" };
      `);
      expect(hasRule(findings, 'SERVICE_ACCOUNT_ADMIN')).toBe(false);
    });
  });

  describe('SSO_CALLBACK_NO_STATE', () => {
    it('catches OAuth callback without state validation', async () => {
      const findings = await scanCode(`
        app.get('/auth/callback', async (req, res) => {
          const code = req.query.code;
          const tokens = await oauth.exchange(code);
          res.json(tokens);
        });
      `);
      expect(hasRule(findings, 'SSO_CALLBACK_NO_STATE')).toBe(true);
    });
    it('does NOT flag callback with state check', async () => {
      const findings = await scanCode(`
        app.get('/auth/callback', async (req, res) => {
          const { code, state } = req.query;
          if (state !== req.session.oauthState) return res.status(403).send('Invalid state');
          const tokens = await oauth.exchange(code);
          res.json(tokens);
        });
      `);
      expect(hasRule(findings, 'SSO_CALLBACK_NO_STATE')).toBe(false);
    });
  });

  describe('LOGIN_NO_LOCKOUT', () => {
    it('catches login route without lockout', async () => {
      const findings = await scanCode(`
        app.post('/login', async (req, res) => {
          const user = await findUser(req.body.email);
          if (await bcrypt.compare(req.body.password, user.hash)) {
            res.json({ token: createToken(user) });
          }
        });
      `);
      expect(hasRule(findings, 'LOGIN_NO_LOCKOUT')).toBe(true);
    });
    it('does NOT flag login with rate limiting', async () => {
      const findings = await scanCode(`
        const loginLimiter = rateLimit({ maxAttempts: 5 });
        app.post('/login', loginLimiter, async (req, res) => {
          const user = await findUser(req.body.email);
          res.json({ token: createToken(user) });
        });
      `);
      expect(hasRule(findings, 'LOGIN_NO_LOCKOUT')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 64: Cryptography Comprehensive
// ════════════════════════════════════════════

describe('Cryptography Comprehensive detection', () => {
  describe('RSA_KEY_TOO_SMALL', () => {
    it('catches RSA key size 1024', async () => {
      const findings = await scanCode(`
        crypto.generateKeyPair('rsa', { modulusLength: 1024 });
      `);
      expect(hasRule(findings, 'RSA_KEY_TOO_SMALL')).toBe(true);
    });
    it('does NOT flag RSA key size 4096', async () => {
      const findings = await scanCode(`
        crypto.generateKeyPair('rsa', { modulusLength: 4096 });
      `);
      expect(hasRule(findings, 'RSA_KEY_TOO_SMALL')).toBe(false);
    });
  });

  describe('ECDSA_P192_CURVE', () => {
    it('catches P-192 curve usage', async () => {
      const findings = await scanCode(`
        const key = crypto.generateKeyPair('ec', { namedCurve: 'secp192r1' });
      `);
      expect(hasRule(findings, 'ECDSA_P192_CURVE')).toBe(true);
    });
    it('does NOT flag P-256 curve', async () => {
      const findings = await scanCode(`
        const key = crypto.generateKeyPair('ec', { namedCurve: 'prime256v1' });
      `);
      expect(hasRule(findings, 'ECDSA_P192_CURVE')).toBe(false);
    });
  });

  describe('CRYPTO_DSA_USAGE', () => {
    it('catches DSA key generation', async () => {
      const findings = await scanCode(`
        crypto.generateKeyPair('dsa', { modulusLength: 2048 });
      `);
      expect(hasRule(findings, 'CRYPTO_DSA_USAGE')).toBe(true);
    });
    it('does NOT flag ECDSA usage', async () => {
      const findings = await scanCode(`
        crypto.generateKeyPair('ec', { namedCurve: 'P-256' });
      `);
      expect(hasRule(findings, 'CRYPTO_DSA_USAGE')).toBe(false);
    });
  });

  describe('CRYPTO_NO_AEAD', () => {
    it('catches AES-CBC decryption', async () => {
      const findings = await scanCode(`
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      `);
      expect(hasRule(findings, 'CRYPTO_NO_AEAD')).toBe(true);
    });
    it('does NOT flag AES-GCM', async () => {
      const findings = await scanCode(`
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      `);
      expect(hasRule(findings, 'CRYPTO_NO_AEAD')).toBe(false);
    });
  });

  describe('HMAC_WITH_SHA1', () => {
    it('catches HMAC-SHA1', async () => {
      const findings = await scanCode(`
        const hmac = crypto.createHmac('sha1', secret);
      `);
      expect(hasRule(findings, 'HMAC_WITH_SHA1')).toBe(true);
    });
    it('does NOT flag HMAC-SHA256', async () => {
      const findings = await scanCode(`
        const hmac = crypto.createHmac('sha256', secret);
      `);
      expect(hasRule(findings, 'HMAC_WITH_SHA1')).toBe(false);
    });
  });

  describe('TLS_CERT_VALIDATION_BYPASS', () => {
    it('catches rejectUnauthorized: false', async () => {
      const findings = await scanCode(`
        const agent = new https.Agent({ rejectUnauthorized: false });
      `);
      expect(hasRule(findings, 'TLS_CERT_VALIDATION_BYPASS')).toBe(true);
    });
    it('does NOT flag rejectUnauthorized: true', async () => {
      const findings = await scanCode(`
        const agent = new https.Agent({ rejectUnauthorized: true });
      `);
      expect(hasRule(findings, 'TLS_CERT_VALIDATION_BYPASS')).toBe(false);
    });
  });

  describe('PKCS1_V15_PADDING', () => {
    it('catches RSA_PKCS1_PADDING usage', async () => {
      const findings = await scanCode(`
        crypto.publicEncrypt({ key: pubKey, padding: crypto.constants.RSA_PKCS1_PADDING }, data);
      `);
      expect(hasRule(findings, 'PKCS1_V15_PADDING')).toBe(true);
    });
    it('does NOT flag OAEP padding', async () => {
      const findings = await scanCode(`
        crypto.publicEncrypt({ key: pubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, data);
      `);
      expect(hasRule(findings, 'PKCS1_V15_PADDING')).toBe(false);
    });
  });

  describe('HARDCODED_ENCRYPTION_KEY_V2', () => {
    it('catches hardcoded encryption key', async () => {
      const findings = await scanCode(`
        const encryptionKey = "aGVsbG93b3JsZGhlbGxvd29ybGQ=";
      `);
      expect(hasRule(findings, 'HARDCODED_ENCRYPTION_KEY_V2')).toBe(true);
    });
    it('does NOT flag key loaded from env', async () => {
      const findings = await scanCode(`
        const encryptionKey = process.env.ENCRYPTION_KEY;
      `);
      expect(hasRule(findings, 'HARDCODED_ENCRYPTION_KEY_V2')).toBe(false);
    });
  });

  describe('KEY_MATERIAL_IN_LOG', () => {
    it('catches logging private key', async () => {
      const findings = await scanCode(`
        console.log("Key: " + privateKey);
      `);
      expect(hasRule(findings, 'KEY_MATERIAL_IN_LOG')).toBe(true);
    });
    it('does NOT flag logging public info', async () => {
      const findings = await scanCode(`
        console.log("User: " + userId);
      `);
      expect(hasRule(findings, 'KEY_MATERIAL_IN_LOG')).toBe(false);
    });
  });

  describe('WEAK_RANDOM_SEED', () => {
    it('catches seed from Date.now()', async () => {
      const findings = await scanCode(`
        const seed = Date.now();
      `);
      expect(hasRule(findings, 'WEAK_RANDOM_SEED')).toBe(true);
    });
    it('does NOT flag seed from randomBytes', async () => {
      const findings = await scanCode(`
        const seed = crypto.randomBytes(32);
      `);
      expect(hasRule(findings, 'WEAK_RANDOM_SEED')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 65: Network Security
// ════════════════════════════════════════════

describe('Network Security detection', () => {
  describe('HOST_HEADER_INJECTION', () => {
    it('catches Host header used in URL construction', async () => {
      const findings = await scanCode(`
        const url = "https://" + req.headers.host + "/reset";
      `);
      expect(hasRule(findings, 'HOST_HEADER_INJECTION')).toBe(true);
    });
    it('does NOT flag env-based hostname', async () => {
      const findings = await scanCode(`
        const url = "https://" + process.env.HOSTNAME + "/reset";
      `);
      expect(hasRule(findings, 'HOST_HEADER_INJECTION')).toBe(false);
    });
  });

  describe('TRACE_METHOD_ENABLED', () => {
    it('catches app.trace route', async () => {
      const findings = await scanCode(`
        app.trace('/debug', (req, res) => { res.send(req.headers); });
      `);
      expect(hasRule(findings, 'TRACE_METHOD_ENABLED')).toBe(true);
    });
    it('does NOT flag app.get route', async () => {
      const findings = await scanCode(`
        app.get('/debug', (req, res) => { res.send("ok"); });
      `);
      expect(hasRule(findings, 'TRACE_METHOD_ENABLED')).toBe(false);
    });
  });

  describe('HTTP_METHOD_OVERRIDE', () => {
    it('catches methodOverride middleware', async () => {
      const findings = await scanCode(`
        app.use(methodOverride());
      `);
      expect(hasRule(findings, 'HTTP_METHOD_OVERRIDE')).toBe(true);
    });
    it('does NOT flag normal middleware', async () => {
      const findings = await scanCode(`
        app.use(cors());
      `);
      expect(hasRule(findings, 'HTTP_METHOD_OVERRIDE')).toBe(false);
    });
  });

  describe('WEBSOCKET_UPGRADE_NO_AUTH', () => {
    it('catches WebSocket upgrade without auth', async () => {
      const findings = await scanCode(`
        server.on('upgrade', (request, socket, head) => {
          wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
          });
        });
      `);
      expect(hasRule(findings, 'WEBSOCKET_UPGRADE_NO_AUTH')).toBe(true);
    });
    it('does NOT flag upgrade with auth check', async () => {
      const findings = await scanCode(`
        server.on('upgrade', (request, socket, head) => {
          const token = request.headers.authorization;
          if (!verifyToken(token)) { socket.destroy(); return; }
          wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
          });
        });
      `);
      expect(hasRule(findings, 'WEBSOCKET_UPGRADE_NO_AUTH')).toBe(false);
    });
  });

  describe('REDIRECT_CHAIN_NO_LIMIT', () => {
    it('catches axios.create without maxRedirects', async () => {
      const findings = await scanCode(`
        const client = axios.create({ baseURL: "https://api.example.com" });
      `);
      expect(hasRule(findings, 'REDIRECT_CHAIN_NO_LIMIT')).toBe(true);
    });
    it('does NOT flag axios with maxRedirects', async () => {
      const findings = await scanCode(`
        const client = axios.create({ baseURL: "https://api.example.com", maxRedirects: 5 });
      `);
      expect(hasRule(findings, 'REDIRECT_CHAIN_NO_LIMIT')).toBe(false);
    });
  });

  describe('TRANSFER_ENCODING_SMUGGLING', () => {
    it('catches manual transfer-encoding header', async () => {
      const findings = await scanCode(`
        res.setHeader('transfer-encoding', 'chunked');
      `);
      expect(hasRule(findings, 'TRANSFER_ENCODING_SMUGGLING')).toBe(true);
    });
    it('does NOT flag content-type header', async () => {
      const findings = await scanCode(`
        res.setHeader('content-type', 'application/json');
      `);
      expect(hasRule(findings, 'TRANSFER_ENCODING_SMUGGLING')).toBe(false);
    });
  });

  describe('SNI_MISMATCH_IGNORE', () => {
    it('catches empty checkServerIdentity', async () => {
      const findings = await scanCode(`
        const options = { checkServerIdentity: () => undefined };
      `);
      expect(hasRule(findings, 'SNI_MISMATCH_IGNORE')).toBe(true);
    });
    it('does NOT flag proper checkServerIdentity', async () => {
      const findings = await scanCode(`
        const options = { checkServerIdentity: (host, cert) => tls.checkServerIdentity(host, cert) };
      `);
      expect(hasRule(findings, 'SNI_MISMATCH_IGNORE')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 66: Data Privacy & Compliance
// ════════════════════════════════════════════

describe('Data Privacy & Compliance detection', () => {
  describe('PII_IN_ANALYTICS', () => {
    it('catches email in analytics track call', async () => {
      const findings = await scanCode(`
        analytics.track("purchase", { email: user.email, amount: 100 });
      `);
      expect(hasRule(findings, 'PII_IN_ANALYTICS')).toBe(true);
    });
    it('does NOT flag anonymized analytics', async () => {
      const findings = await scanCode(`
        analytics.track("purchase", { userId: hashedId, amount: 100 });
      `);
      expect(hasRule(findings, 'PII_IN_ANALYTICS')).toBe(false);
    });
  });

  describe('SENTRY_FULL_USER', () => {
    it('catches Sentry with email in setUser', async () => {
      const findings = await scanCode(`
        Sentry.setUser({ id: user.id, email: user.email, username: user.name });
      `);
      expect(hasRule(findings, 'SENTRY_FULL_USER')).toBe(true);
    });
    it('does NOT flag Sentry with only id', async () => {
      const findings = await scanCode(`
        Sentry.setUser({ id: user.id });
      `);
      expect(hasRule(findings, 'SENTRY_FULL_USER')).toBe(false);
    });
  });

  describe('SENSITIVE_DATA_IN_URL', () => {
    it('catches password in URL parameter', async () => {
      const findings = await scanCode(`
        fetch("/api/login?password=" + password);
      `);
      expect(hasRule(findings, 'SENSITIVE_DATA_IN_URL')).toBe(true);
    });
    it('does NOT flag normal URL parameter', async () => {
      const findings = await scanCode(`
        fetch("/api/users?page=1&limit=20");
      `);
      expect(hasRule(findings, 'SENSITIVE_DATA_IN_URL')).toBe(false);
    });
  });

  describe('DATA_RETENTION_NO_TTL', () => {
    it('catches redis set without TTL for user data', async () => {
      const findings = await scanCode(`
        redis.set("user:123", JSON.stringify(userData));
      `);
      expect(hasRule(findings, 'DATA_RETENTION_NO_TTL')).toBe(true);
    });
    it('does NOT flag redis set with EX', async () => {
      const findings = await scanCode(`
        redis.set("user:123", JSON.stringify(userData), "EX", 3600);
      `);
      expect(hasRule(findings, 'DATA_RETENTION_NO_TTL')).toBe(false);
    });
  });

  describe('BACKUP_NO_ENCRYPTION', () => {
    it('catches pg_dump without encryption', async () => {
      const findings = await scanCode(`
        exec("pg_dump -h localhost mydb > backup.sql");
      `);
      expect(hasRule(findings, 'BACKUP_NO_ENCRYPTION')).toBe(true);
    });
    it('does NOT flag encrypted backup', async () => {
      const findings = await scanCode(`
        exec("pg_dump mydb | gpg --encrypt -r admin > backup.sql.gpg");
      `);
      expect(hasRule(findings, 'BACKUP_NO_ENCRYPTION')).toBe(false);
    });
  });

  describe('PII_IN_DEBUG_LOG', () => {
    it('catches email in debug log', async () => {
      const findings = await scanCode(`
        console.debug("Processing user with email:", email);
      `);
      expect(hasRule(findings, 'PII_IN_DEBUG_LOG')).toBe(true);
    });
    it('does NOT flag debug log without PII', async () => {
      const findings = await scanCode(`
        console.debug("Processing request:", requestId);
      `);
      expect(hasRule(findings, 'PII_IN_DEBUG_LOG')).toBe(false);
    });
  });

  describe('CACHE_KEY_PII', () => {
    it('catches email in cache key', async () => {
      const findings = await scanCode(`
        const data = await cache.get("user:email:john@example.com");
      `);
      expect(hasRule(findings, 'CACHE_KEY_PII')).toBe(true);
    });
    it('does NOT flag hashed cache key', async () => {
      const findings = await scanCode(`
        const data = await cache.get("user:abc123def456");
      `);
      expect(hasRule(findings, 'CACHE_KEY_PII')).toBe(false);
    });
  });

  describe('TRACKING_NO_CONSENT', () => {
    it('catches analytics init without consent check', async () => {
      const findings = await scanCode(`
        analytics.init("UA-12345");
      `);
      expect(hasRule(findings, 'TRACKING_NO_CONSENT')).toBe(true);
    });
    it('does NOT flag analytics with consent check', async () => {
      const findings = await scanCode(`
        if (hasConsent('analytics')) {
          analytics.init("UA-12345");
        }
      `);
      expect(hasRule(findings, 'TRACKING_NO_CONSENT')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 67: Mobile/PWA Security
// ════════════════════════════════════════════

describe('Mobile/PWA Security detection', () => {
  describe('PWA_LOCALSTORAGE_AUTH', () => {
    it('catches localStorage auth token storage', async () => {
      const findings = await scanCode(`
        localStorage.setItem("accessToken", response.token);
      `);
      expect(hasRule(findings, 'PWA_LOCALSTORAGE_AUTH')).toBe(true);
    });
    it('does NOT flag localStorage for non-auth data', async () => {
      const findings = await scanCode(`
        localStorage.setItem("theme", "dark");
      `);
      expect(hasRule(findings, 'PWA_LOCALSTORAGE_AUTH')).toBe(false);
    });
  });

  describe('POSTMESSAGE_PARENT_NO_ORIGIN', () => {
    it('catches postMessage with wildcard origin', async () => {
      const findings = await scanCode(`
        parent.postMessage({ type: "auth", token }, "*");
      `);
      expect(hasRule(findings, 'POSTMESSAGE_PARENT_NO_ORIGIN')).toBe(true);
    });
    it('does NOT flag postMessage with specific origin', async () => {
      const findings = await scanCode(`
        parent.postMessage({ type: "auth", token }, "https://example.com");
      `);
      expect(hasRule(findings, 'POSTMESSAGE_PARENT_NO_ORIGIN')).toBe(false);
    });
  });

  describe('CLIPBOARD_NO_GESTURE', () => {
    it('catches clipboard read without user gesture', async () => {
      const findings = await scanCode(`
        async function init() {
          const text = await navigator.clipboard.readText();
          processClipboard(text);
        }
      `);
      expect(hasRule(findings, 'CLIPBOARD_NO_GESTURE')).toBe(true);
    });
    it('does NOT flag clipboard read on click handler', async () => {
      const findings = await scanCode(`
        button.addEventListener('click', async () => {
          const text = await navigator.clipboard.readText();
          processClipboard(text);
        });
      `);
      expect(hasRule(findings, 'CLIPBOARD_NO_GESTURE')).toBe(false);
    });
  });

  describe('INDEXEDDB_SENSITIVE_UNENCRYPTED', () => {
    it('catches storing token in IndexedDB', async () => {
      const findings = await scanCode(`
        const store = tx.objectStore("auth");
        store.put({ token: authToken, user: userId });
      `);
      expect(hasRule(findings, 'INDEXEDDB_SENSITIVE_UNENCRYPTED')).toBe(true);
    });
    it('does NOT flag storing non-sensitive data', async () => {
      const findings = await scanCode(`
        const store = tx.objectStore("preferences");
        store.put({ theme: "dark", lang: "en" });
      `);
      expect(hasRule(findings, 'INDEXEDDB_SENSITIVE_UNENCRYPTED')).toBe(false);
    });
  });

  describe('SW_CACHE_SENSITIVE', () => {
    it('catches service worker caching auth endpoint', async () => {
      const findings = await scanCode(`
        cache.put("/api/auth/session", response);
      `);
      expect(hasRule(findings, 'SW_CACHE_SENSITIVE')).toBe(true);
    });
    it('does NOT flag caching static assets', async () => {
      const findings = await scanCode(`
        cache.put("/static/style.css", response);
      `);
      expect(hasRule(findings, 'SW_CACHE_SENSITIVE')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 68: GraphQL Deep
// ════════════════════════════════════════════

describe('GraphQL Deep detection', () => {
  describe('GRAPHQL_NO_COMPLEXITY_LIMIT', () => {
    it('catches ApolloServer without complexity limit', async () => {
      const findings = await scanCode(`
        const server = new ApolloServer({ typeDefs, resolvers });
      `);
      expect(hasRule(findings, 'GRAPHQL_NO_COMPLEXITY_LIMIT')).toBe(true);
    });
    it('does NOT flag server with complexity plugin', async () => {
      const findings = await scanCode(`
        const complexityPlugin = createComplexityPlugin({ maxComplexity: 1000 });
        const server = new ApolloServer({ typeDefs, resolvers, plugins: [complexityPlugin] });
      `);
      expect(hasRule(findings, 'GRAPHQL_NO_COMPLEXITY_LIMIT')).toBe(false);
    });
  });

  describe('GRAPHQL_BATCH_UNLIMITED', () => {
    it('catches batching without limit', async () => {
      const findings = await scanCode(`
        const server = new ApolloServer({ allowBatchedHttpRequests: true });
      `);
      expect(hasRule(findings, 'GRAPHQL_BATCH_UNLIMITED')).toBe(true);
    });
    it('does NOT flag batching with limit', async () => {
      const findings = await scanCode(`
        const server = new ApolloServer({ allowBatchedHttpRequests: true, maxBatchSize: 10 });
      `);
      expect(hasRule(findings, 'GRAPHQL_BATCH_UNLIMITED')).toBe(false);
    });
  });

  describe('GRAPHQL_RESOLVER_ERROR_LEAK', () => {
    it('catches throwing error with internal message', async () => {
      const findings = await scanCode(`
        throw new GraphQLError(error.message);
      `);
      expect(hasRule(findings, 'GRAPHQL_RESOLVER_ERROR_LEAK')).toBe(true);
    });
    it('does NOT flag generic error', async () => {
      const findings = await scanCode(`
        throw new GraphQLError("An internal error occurred");
      `);
      expect(hasRule(findings, 'GRAPHQL_RESOLVER_ERROR_LEAK')).toBe(false);
    });
  });

  describe('GRAPHQL_INTROSPECTION_INTERNAL', () => {
    it('catches introspection: true', async () => {
      const findings = await scanCode(`
        const server = new ApolloServer({ introspection: true, typeDefs });
      `);
      expect(hasRule(findings, 'GRAPHQL_INTROSPECTION_INTERNAL')).toBe(true);
    });
    it('does NOT flag introspection: false', async () => {
      const findings = await scanCode(`
        const server = new ApolloServer({ introspection: false, typeDefs });
      `);
      expect(hasRule(findings, 'GRAPHQL_INTROSPECTION_INTERNAL')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 69: Serverless & Edge Deep
// ════════════════════════════════════════════

describe('Serverless & Edge detection', () => {
  describe('ENV_VARS_IN_RESPONSE', () => {
    it('catches process.env in response', async () => {
      const findings = await scanCode(`
        res.json(process.env);
      `);
      expect(hasRule(findings, 'ENV_VARS_IN_RESPONSE')).toBe(true);
    });
    it('does NOT flag specific env var usage', async () => {
      const findings = await scanCode(`
        res.json({ port: process.env.PORT });
      `);
      expect(hasRule(findings, 'ENV_VARS_IN_RESPONSE')).toBe(false);
    });
  });

  describe('EDGE_FUNCTION_DYNAMIC_IMPORT', () => {
    it('catches dynamic import from user input', async () => {
      const findings = await scanCode(
        'const mod = await import(req.query.module);',
      );
      expect(hasRule(findings, 'EDGE_FUNCTION_DYNAMIC_IMPORT')).toBe(true);
    });
    it('does NOT flag static import', async () => {
      const findings = await scanCode(`
        const mod = await import("./utils.js");
      `);
      expect(hasRule(findings, 'EDGE_FUNCTION_DYNAMIC_IMPORT')).toBe(false);
    });
  });

  describe('FUNCTION_URL_NO_AUTH', () => {
    it('catches FunctionUrl with AuthType NONE', async () => {
      const findings = await scanCode(`
        const url = fn.addFunctionUrl({ authType: "NONE" });
      `);
      expect(hasRule(findings, 'FUNCTION_URL_NO_AUTH')).toBe(true);
    });
    it('does NOT flag FunctionUrl with AWS_IAM', async () => {
      const findings = await scanCode(`
        const url = fn.addFunctionUrl({ authType: "AWS_IAM" });
      `);
      expect(hasRule(findings, 'FUNCTION_URL_NO_AUTH')).toBe(false);
    });
  });

  describe('STEP_FUNCTION_USER_STATE', () => {
    it('catches startExecution with req.body', async () => {
      const findings = await scanCode(`
        await sfn.startExecution({ stateMachineArn: arn, input: JSON.stringify(req.body) });
      `);
      expect(hasRule(findings, 'STEP_FUNCTION_USER_STATE')).toBe(true);
    });
    it('does NOT flag startExecution with validated input', async () => {
      const findings = await scanCode(`
        await sfn.startExecution({ stateMachineArn: arn, input: JSON.stringify({ orderId }) });
      `);
      expect(hasRule(findings, 'STEP_FUNCTION_USER_STATE')).toBe(false);
    });
  });

  describe('SQS_MESSAGE_NO_VALIDATION', () => {
    it('catches parsing SQS message without validation', async () => {
      const findings = await scanCode(`
        const data = JSON.parse(record.body);
        await processOrder(data);
      `);
      expect(hasRule(findings, 'SQS_MESSAGE_NO_VALIDATION')).toBe(true);
    });
    it('does NOT flag SQS message with schema validation', async () => {
      const findings = await scanCode(`
        const data = JSON.parse(record.body);
        const validated = schema.parse(data);
        await processOrder(validated);
      `);
      expect(hasRule(findings, 'SQS_MESSAGE_NO_VALIDATION')).toBe(false);
    });
  });
});

// ════════════════════════════════════════════
// Cycle 70: Final False Positive Hardening
// ════════════════════════════════════════════

describe('Cycle 70: False Positive Hardening', () => {
  it('does NOT flag parameterized SQL in ORM models', async () => {
    const findings = await scanCode(`
      const users = await User.findAll({ where: { status: 'active' } });
      res.json(users.map(u => ({ id: u.id, name: u.name })));
    `);
    expect(hasRule(findings, 'SQL_INJECTION_CONCAT')).toBe(false);
    expect(hasRule(findings, 'DB_RESULT_DIRECT_RESPONSE')).toBe(false);
  });

  it('does NOT flag helmet() with default options', async () => {
    const findings = await scanCode(`
      app.use(helmet());
    `);
    expect(hasRule(findings, 'HELMET_MISSING_REFERRER_POLICY')).toBe(false);
    expect(hasRule(findings, 'HELMET_MISSING_XCTO')).toBe(false);
  });

  it('does NOT flag express.json with limit as bodyparser missing limit', async () => {
    const findings = await scanCode(`
      app.use(express.json({ limit: "1mb" }));
      app.use(express.urlencoded({ extended: true, limit: "1mb" }));
    `);
    expect(hasRule(findings, 'BODYPARSER_MISSING_LIMIT')).toBe(false);
  });

  it('does NOT flag normal crypto.randomBytes as weak seed', async () => {
    const findings = await scanCode(`
      const id = crypto.randomBytes(16).toString('hex');
    `);
    expect(hasRule(findings, 'WEAK_RANDOM_SEED')).toBe(false);
  });

  it('does NOT flag createCipheriv with aes-256-gcm as no AEAD', async () => {
    const findings = await scanCode(`
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    `);
    expect(hasRule(findings, 'CRYPTO_NO_AEAD')).toBe(false);
  });

  it('does NOT flag proper cookie configuration', async () => {
    const findings = await scanCode(`
      res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict', signed: true });
    `);
    expect(hasRule(findings, 'COOKIE_NO_SIGNED_OPTION')).toBe(false);
  });

  it('does NOT flag Redis set with TTL for user data', async () => {
    const findings = await scanCode(`
      await redis.set("user:session:abc", data, "EX", 3600);
    `);
    expect(hasRule(findings, 'DATA_RETENTION_NO_TTL')).toBe(false);
  });

  it('does NOT flag Sentry.setUser with only ID', async () => {
    const findings = await scanCode(`
      Sentry.setUser({ id: user.id });
    `);
    expect(hasRule(findings, 'SENTRY_FULL_USER')).toBe(false);
  });

  it('does NOT flag HSTS with proper maxAge', async () => {
    const findings = await scanCode(`
      app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));
    `);
    expect(hasRule(findings, 'HELMET_MISSING_HSTS_MAXAGE')).toBe(false);
  });

  it('does NOT flag localStorage for theme preference', async () => {
    const findings = await scanCode(`
      localStorage.setItem("language", "en");
      localStorage.setItem("theme", "dark");
      localStorage.setItem("sidebar", "collapsed");
    `);
    expect(hasRule(findings, 'PWA_LOCALSTORAGE_AUTH')).toBe(false);
  });

  it('does NOT flag postMessage with explicit origin', async () => {
    const findings = await scanCode(`
      window.parent.postMessage({ data }, "https://trusted-origin.com");
    `);
    expect(hasRule(findings, 'POSTMESSAGE_PARENT_NO_ORIGIN')).toBe(false);
  });

  it('does NOT flag proper fetch with body POST', async () => {
    const findings = await scanCode(`
      fetch("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
    `);
    expect(hasRule(findings, 'SENSITIVE_DATA_IN_URL')).toBe(false);
  });

  it('does NOT flag GraphQL server with depth and complexity limits', async () => {
    const findings = await scanCode(`
      const depthLimit = require('graphql-depth-limit');
      const costAnalysis = require('graphql-cost-analysis');
      const server = new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(10), costAnalysis()] });
    `);
    expect(hasRule(findings, 'GRAPHQL_NO_COMPLEXITY_LIMIT')).toBe(false);
  });

  it('does NOT flag proper password reset flow with expiry', async () => {
    const findings = await scanCode(`
      const resetToken = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 3600000);
      await db.insert({ token: resetToken, userId, expiresAt });
    `);
    expect(hasRule(findings, 'PASSWORD_RESET_TOKEN_NO_TTL')).toBe(false);
  });

  it('does NOT flag AES-256-GCM encryption', async () => {
    const findings = await scanCode(`
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const authTag = cipher.getAuthTag();
    `);
    expect(hasRule(findings, 'CRYPTO_CTR_NO_MAC')).toBe(false);
  });

  it('does NOT flag proper analytics with consent', async () => {
    const findings = await scanCode(`
      if (cookieConsent.analytics) {
        gtag('config', 'GA_MEASUREMENT_ID');
      }
    `);
    expect(hasRule(findings, 'TRACKING_NO_CONSENT')).toBe(false);
  });

  it('does NOT flag encrypted backup', async () => {
    const findings = await scanCode(`
      exec("pg_dump mydb | openssl enc -aes-256-cbc -out backup.enc");
    `);
    expect(hasRule(findings, 'BACKUP_NO_ENCRYPTION')).toBe(false);
  });

  it('does NOT flag RSA 4096 key generation', async () => {
    const findings = await scanCode(`
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
    `);
    expect(hasRule(findings, 'RSA_KEY_TOO_SMALL')).toBe(false);
  });

  it('does NOT flag P-256 ECDSA curve', async () => {
    const findings = await scanCode(`
      crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    `);
    expect(hasRule(findings, 'ECDSA_P192_CURVE')).toBe(false);
  });

  it('does NOT flag HMAC-SHA256', async () => {
    const findings = await scanCode(`
      const hmac = crypto.createHmac('sha256', secret);
    `);
    expect(hasRule(findings, 'HMAC_WITH_SHA1')).toBe(false);
  });

  it('does NOT flag fastify with bodyLimit configured', async () => {
    const findings = await scanCode(`
      const app = fastify({ logger: true, bodyLimit: 1048576 });
    `);
    expect(hasRule(findings, 'FASTIFY_NO_BODY_LIMIT')).toBe(false);
  });

  it('does NOT flag specific env var in response', async () => {
    const findings = await scanCode(`
      res.json({ version: process.env.APP_VERSION, uptime: process.uptime() });
    `);
    expect(hasRule(findings, 'ENV_VARS_IN_RESPONSE')).toBe(false);
  });

  it('does NOT flag SQS message with zod validation', async () => {
    const findings = await scanCode(`
      const raw = JSON.parse(record.body);
      const data = orderSchema.parse(raw);
      await processOrder(data);
    `);
    expect(hasRule(findings, 'SQS_MESSAGE_NO_VALIDATION')).toBe(false);
  });

  it('does NOT flag WebSocket upgrade with token verification', async () => {
    const findings = await scanCode(`
      server.on('upgrade', async (req, socket, head) => {
        const token = new URL(req.url, "http://localhost").searchParams.get('token');
        const user = await verifyToken(token);
        if (!user) { socket.destroy(); return; }
        wss.handleUpgrade(req, socket, head, ws => ws.emit('connection', ws));
      });
    `);
    expect(hasRule(findings, 'WEBSOCKET_UPGRADE_NO_AUTH')).toBe(false);
  });

  it('does NOT flag introspection: false in production', async () => {
    const findings = await scanCode(`
      const server = new ApolloServer({ typeDefs, resolvers, introspection: false });
    `);
    expect(hasRule(findings, 'GRAPHQL_INTROSPECTION_INTERNAL')).toBe(false);
  });

  it('does NOT flag static import as dynamic import injection', async () => {
    const findings = await scanCode(`
      import { handler } from './handler.js';
      const mod = await import('./config.js');
    `);
    expect(hasRule(findings, 'EDGE_FUNCTION_DYNAMIC_IMPORT')).toBe(false);
  });

  it('does NOT flag clipboard read in click handler', async () => {
    const findings = await scanCode(`
      document.getElementById('paste').addEventListener('click', async () => {
        const text = await navigator.clipboard.readText();
        input.value = text;
      });
    `);
    expect(hasRule(findings, 'CLIPBOARD_NO_GESTURE')).toBe(false);
  });

  it('does NOT flag debug log without PII', async () => {
    const findings = await scanCode(`
      console.debug("Cache miss for key:", cacheKey);
      console.debug("Processing batch:", batchId);
    `);
    expect(hasRule(findings, 'PII_IN_DEBUG_LOG')).toBe(false);
  });

  it('does NOT flag PBKDF2 with high iterations', async () => {
    const findings = await scanCode(`
      crypto.pbkdf2Sync(password, salt, 600000, 64, 'sha512');
    `);
    expect(hasRule(findings, 'PBKDF2_LOW_ITERATION_COUNT')).toBe(false);
  });
});

// ════════════════════════════════════════════
// Cycle 81: Django ORM & Models Deep
// ════════════════════════════════════════════

describe('Cycle 81: Django ORM & Models Deep', () => {
  it('catches QuerySet.extra() with user input in select', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.all().extra(select={'val': request.GET['field']})`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_QUERYSET_EXTRA_SQL')).toBe(true);
  });

  it('does NOT flag QuerySet.extra() with static values', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.all().extra(select={'is_recent': "created_at > NOW() - INTERVAL '7 days'"})`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_QUERYSET_EXTRA_SQL')).toBe(false);
  });

  it('catches annotate() with RawSQL f-string', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.annotate(val=RawSQL(f"SELECT {col} FROM table"))`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_ANNOTATE_RAWSQL_INJECT')).toBe(true);
  });

  it('does NOT flag annotate() with RawSQL using params', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.annotate(val=RawSQL("SELECT col FROM t WHERE id = %s", [pk]))`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_ANNOTATE_RAWSQL_INJECT')).toBe(false);
  });

  it('catches F() expression with user input', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.filter(val=F(request.GET['field']))`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_F_EXPRESSION_USER_STRING')).toBe(true);
  });

  it('does NOT flag F() with static field name', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.filter(val=F('other_field'))`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_F_EXPRESSION_USER_STRING')).toBe(false);
  });

  it('catches Subquery with RawSQL f-string', async () => {
    const findings = await scanCode(
      `sub = Subquery(RawSQL(f"SELECT id FROM {table_name}"))`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_SUBQUERY_RAW_SQL')).toBe(true);
  });

  it('catches .only() exposing password field', async () => {
    const findings = await scanCode(
      `users = User.objects.only('username', 'password', 'email')`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_DEFER_SENSITIVE_FIELDS')).toBe(true);
  });

  it('catches order_by with user-controlled field', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.order_by(request.GET['sort'])`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_META_ORDERING_USER_INPUT')).toBe(true);
  });

  it('does NOT flag order_by with static field', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.order_by('-created_at')`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_META_ORDERING_USER_INPUT')).toBe(false);
  });

  it('catches CharField without max_length', async () => {
    const findings = await scanCode(
      `name = models.CharField()`,
      'models.py',
    );
    expect(hasRule(findings, 'DJANGO_CHARFIELD_NO_MAX_LENGTH')).toBe(true);
  });

  it('does NOT flag CharField with max_length', async () => {
    const findings = await scanCode(
      `name = models.CharField(max_length=255)`,
      'models.py',
    );
    expect(hasRule(findings, 'DJANGO_CHARFIELD_NO_MAX_LENGTH')).toBe(false);
  });

  it('catches FileField without upload_to', async () => {
    const findings = await scanCode(
      `from django.db import models\ndocument = models.FileField()`,
      'models.py',
    );
    expect(hasRule(findings, 'DJANGO_FILEFIELD_NO_VALIDATION')).toBe(true);
  });

  it('catches .filter() with unpacked user kwargs', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.filter(**request.GET.dict())`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_JSONFIELD_USER_PATH')).toBe(true);
  });

  it('catches GenericForeignKey without limit_choices_to', async () => {
    const findings = await scanCode(
      `content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)\nobject_id = models.PositiveIntegerField()\ncontent_object = GenericForeignKey('content_type', 'object_id')`,
      'models.py',
    );
    expect(hasRule(findings, 'DJANGO_GENERIC_FK_NO_VALIDATION')).toBe(true);
  });

  it('catches bulk_create without ignore_conflicts', async () => {
    const findings = await scanCode(
      `MyModel.objects.bulk_create(objects_list)`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_BULK_CREATE_NO_UNIQUE')).toBe(true);
  });

  it('does NOT flag bulk_create with ignore_conflicts', async () => {
    const findings = await scanCode(
      `MyModel.objects.bulk_create(objects_list, ignore_conflicts=True)`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_BULK_CREATE_NO_UNIQUE')).toBe(false);
  });

  it('catches update_or_create without transaction', async () => {
    const findings = await scanCode(
      `obj, created = MyModel.objects.update_or_create(name=name, defaults={'value': value})`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_UPDATE_OR_CREATE_RACE')).toBe(true);
  });

  it('catches select_for_update without timeout', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.select_for_update().get(pk=pk)`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_SELECT_FOR_UPDATE_NO_TIMEOUT')).toBe(true);
  });

  it('does NOT flag select_for_update with nowait', async () => {
    const findings = await scanCode(
      `qs = MyModel.objects.select_for_update(nowait=True).get(pk=pk)`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_SELECT_FOR_UPDATE_NO_TIMEOUT')).toBe(false);
  });

  it('catches aggregate with user-controlled field name', async () => {
    const findings = await scanCode(
      `result = MyModel.objects.aggregate(total=Sum(request.GET['agg_field']))`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_AGGREGATE_USER_FIELD')).toBe(true);
  });

  it('catches values_list exposing password field', async () => {
    const findings = await scanCode(
      `data = User.objects.values_list('username', 'password', flat=False)`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_VALUES_LIST_SENSITIVE')).toBe(true);
  });

  it('does NOT flag values_list with safe fields', async () => {
    const findings = await scanCode(
      `data = User.objects.values_list('username', 'email', flat=False)`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_VALUES_LIST_SENSITIVE')).toBe(false);
  });
});

// ════════════════════════════════════════════
// Cycle 82: Django Views & Forms
// ════════════════════════════════════════════

describe('Cycle 82: Django Views & Forms', () => {
  it('catches FormView with csrf_exempt', async () => {
    const findings = await scanCode(
      `@csrf_exempt\n@method_decorator(csrf_exempt)\nclass MyFormView(FormView):\n    form_class = MyForm`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_FORMVIEW_NO_CSRF')).toBe(true);
  });

  it('does NOT flag FormView without csrf_exempt', async () => {
    const findings = await scanCode(
      `class MyFormView(FormView):\n    form_class = MyForm\n    template_name = 'form.html'`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_FORMVIEW_NO_CSRF')).toBe(false);
  });

  it('catches ModelForm with exclude', async () => {
    const findings = await scanCode(
      `class UserForm(ModelForm):\n    class Meta:\n        model = User\n        exclude = ['is_staff']`,
      'forms.py',
    );
    expect(hasRule(findings, 'DJANGO_MODELFORM_EXCLUDE')).toBe(true);
  });

  it('catches StreamingHttpResponse with user content', async () => {
    const findings = await scanCode(
      `return StreamingHttpResponse(request.body)`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_STREAMING_USER_CONTENT')).toBe(true);
  });

  it('catches HttpResponse with user content_type', async () => {
    const findings = await scanCode(
      `return HttpResponse(data, content_type=request.GET['type'])`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_RESPONSE_USER_CONTENT_TYPE')).toBe(true);
  });

  it('does NOT flag HttpResponse with static content_type', async () => {
    const findings = await scanCode(
      `return HttpResponse(data, content_type='application/json')`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_RESPONSE_USER_CONTENT_TYPE')).toBe(false);
  });

  it('catches redirect with user URL from GET', async () => {
    const findings = await scanCode(
      `return redirect(request.GET.get('next', '/'))`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_REDIRECT_USER_URL')).toBe(true);
  });

  it('does NOT flag redirect with static URL', async () => {
    const findings = await scanCode(
      `return redirect('/dashboard/')`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_REDIRECT_USER_URL')).toBe(false);
  });

  it('catches LoginView without rate limit', async () => {
    const findings = await scanCode(
      `from django.contrib.auth.views import LoginView\nclass MyLogin(LoginView):\n    template_name = 'login.html'`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_LOGINVIEW_NO_RATE_LIMIT')).toBe(true);
  });

  it('catches admin site without 2FA', async () => {
    const findings = await scanCode(
      `from django.contrib import admin\nurlpatterns = [path('admin/', admin.site.urls)]`,
      'urls.py',
    );
    expect(hasRule(findings, 'DJANGO_ADMIN_NO_2FA')).toBe(true);
  });

  it('catches permission_required without login_url', async () => {
    const findings = await scanCode(
      `@permission_required('app.can_edit')`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_PERMISSION_NO_LOGIN_URL')).toBe(true);
  });

  it('does NOT flag permission_required with login_url', async () => {
    const findings = await scanCode(
      `@permission_required('app.can_edit', login_url='/accounts/login/')`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_PERMISSION_NO_LOGIN_URL')).toBe(false);
  });

  it('catches cache_page on authenticated view', async () => {
    const findings = await scanCode(
      `@cache_page(60 * 15)\n@login_required\ndef profile_view(request):`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_CACHE_PAGE_AUTHENTICATED')).toBe(true);
  });

  it('catches JsonResponse with __dict__', async () => {
    const findings = await scanCode(
      `return JsonResponse(user.__dict__)`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_JSONRESPONSE_MODEL_INSTANCE')).toBe(true);
  });

  it('does NOT flag JsonResponse with explicit dict', async () => {
    const findings = await scanCode(
      `return JsonResponse({'name': user.name, 'email': user.email})`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_JSONRESPONSE_MODEL_INSTANCE')).toBe(false);
  });

  it('catches request.FILES without type check', async () => {
    const findings = await scanCode(
      `uploaded = request.FILES['document']\nobj.file = uploaded\nobj.save()`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_SIMPLE_UPLOADED_NO_TYPE_CHECK')).toBe(true);
  });
});

// ════════════════════════════════════════════
// Cycle 83: Flask Deep
// ════════════════════════════════════════════

describe('Cycle 83: Flask Deep', () => {
  it('catches Blueprint without auth', async () => {
    const findings = await scanCode(
      `from flask import Blueprint\napi_bp = Blueprint('api', __name__)\n@api_bp.route('/data')\ndef get_data():\n    return jsonify(data)`,
      'routes.py',
    );
    expect(hasRule(findings, 'FLASK_BLUEPRINT_NO_AUTH')).toBe(true);
  });

  it('does NOT flag Blueprint with login_required', async () => {
    const findings = await scanCode(
      `from flask import Blueprint\nfrom flask_login import login_required\napi_bp = Blueprint('api', __name__)\n@api_bp.route('/data')\n@login_required\ndef get_data():\n    return jsonify(data)`,
      'routes.py',
    );
    expect(hasRule(findings, 'FLASK_BLUEPRINT_NO_AUTH')).toBe(false);
  });

  it('catches Flask-Login without session_protection', async () => {
    const findings = await scanCode(
      `from flask_login import LoginManager\nlogin_manager = LoginManager(app)`,
      'app.py',
    );
    expect(hasRule(findings, 'FLASK_LOGIN_NO_SESSION_PROTECTION')).toBe(true);
  });

  it('catches Flask-WTF CSRF disabled', async () => {
    const findings = await scanCode(
      `app.config['WTF_CSRF_ENABLED'] = False`,
      'config.py',
    );
    expect(hasRule(findings, 'FLASK_WTF_CSRF_DISABLED')).toBe(true);
  });

  it('catches Flask-SQLAlchemy raw SQL f-string', async () => {
    const findings = await scanCode(
      `result = db.session.execute(f"SELECT * FROM users WHERE name = '{name}'")`,
      'views.py',
    );
    expect(hasRule(findings, 'FLASK_SQLALCHEMY_RAW_SQL')).toBe(true);
  });

  it('does NOT flag Flask-SQLAlchemy with text() and params', async () => {
    const findings = await scanCode(
      `result = db.session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})`,
      'views.py',
    );
    expect(hasRule(findings, 'FLASK_SQLALCHEMY_RAW_SQL')).toBe(false);
  });

  it('catches Flask-Mail without TLS', async () => {
    const findings = await scanCode(
      `MAIL_USE_TLS = False`,
      'config.py',
    );
    expect(hasRule(findings, 'FLASK_MAIL_NO_TLS')).toBe(true);
  });

  it('catches Flask-CORS credentials with wildcard', async () => {
    const findings = await scanCode(
      `CORS(app, origins="*", supports_credentials=True)`,
      'app.py',
    );
    expect(hasRule(findings, 'FLASK_CORS_CREDENTIALS_WILDCARD')).toBe(true);
  });

  it('does NOT flag Flask-CORS with specific origin', async () => {
    const findings = await scanCode(
      `CORS(app, origins="https://example.com", supports_credentials=True)`,
      'app.py',
    );
    expect(hasRule(findings, 'FLASK_CORS_CREDENTIALS_WILDCARD')).toBe(false);
  });

  it('catches send_from_directory with user path', async () => {
    const findings = await scanCode(
      `return send_from_directory(upload_dir, request.args.get('filename'))`,
      'views.py',
    );
    expect(hasRule(findings, 'FLASK_SEND_FROM_DIR_USER_SUBPATH')).toBe(true);
  });

  it('catches Flask-Limiter without default_limits', async () => {
    const findings = await scanCode(
      `from flask_limiter import Limiter\nlimiter = Limiter(app, key_func=get_remote_address)`,
      'app.py',
    );
    expect(hasRule(findings, 'FLASK_LIMITER_NOT_GLOBAL')).toBe(true);
  });

  it('catches Flask errorhandler exposing traceback', async () => {
    const findings = await scanCode(
      `@app.errorhandler(500)\ndef handle_500(e):\n    return jsonify(error=str(e), trace=traceback.format_exc()), 500`,
      'app.py',
    );
    expect(hasRule(findings, 'FLASK_ERRORHANDLER_TRACEBACK')).toBe(true);
  });

  it('catches Flask-Session filesystem backend', async () => {
    const findings = await scanCode(
      `SESSION_TYPE = 'filesystem'`,
      'config.py',
    );
    expect(hasRule(findings, 'FLASK_SESSION_FILESYSTEM_BACKEND')).toBe(true);
  });

  it('does NOT flag Flask-Session with redis backend', async () => {
    const findings = await scanCode(
      `SESSION_TYPE = 'redis'`,
      'config.py',
    );
    expect(hasRule(findings, 'FLASK_SESSION_FILESYSTEM_BACKEND')).toBe(false);
  });

  it('catches Flask-Migrate with user-controlled revision', async () => {
    const findings = await scanCode(
      `upgrade(request.args.get('revision'))`,
      'views.py',
    );
    expect(hasRule(findings, 'FLASK_MIGRATE_USER_REVISION')).toBe(true);
  });
});

// ════════════════════════════════════════════
// Cycle 84: FastAPI & Pydantic Deep
// ════════════════════════════════════════════

describe('Cycle 84: FastAPI & Pydantic Deep', () => {
  it('catches FastAPI without middleware stack', async () => {
    const findings = await scanCode(
      `from fastapi import FastAPI\napp = FastAPI()`,
      'main.py',
    );
    expect(hasRule(findings, 'FASTAPI_NO_MIDDLEWARE_STACK')).toBe(true);
  });

  it('does NOT flag FastAPI with TrustedHostMiddleware', async () => {
    const findings = await scanCode(
      `from fastapi import FastAPI\nfrom starlette.middleware.trustedhost import TrustedHostMiddleware\napp = FastAPI()\napp.add_middleware(TrustedHostMiddleware, allowed_hosts=["example.com"])\napp.add_middleware(HTTPSRedirectMiddleware)`,
      'main.py',
    );
    expect(hasRule(findings, 'FASTAPI_NO_MIDDLEWARE_STACK')).toBe(false);
  });

  it('catches Pydantic model without validators for email used in route', async () => {
    const findings = await scanCode(
      `class UserCreate(BaseModel):\n    email: str\n    password: str\n    name: str\n\n@app.post("/users")\ndef create_user(data: UserCreate):\n    return {"ok": True}`,
      'schemas.py',
    );
    expect(hasRule(findings, 'PYDANTIC_MODEL_NO_VALIDATORS')).toBe(true);
  });

  it('catches FastAPI BackgroundTask with user function', async () => {
    const findings = await scanCode(
      `from fastapi import FastAPI\nbackground_tasks.add_task(getattr(module, request.query_params['func']))`,
      'routes.py',
    );
    expect(hasRule(findings, 'FASTAPI_BACKGROUND_TASK_USER_FUNC')).toBe(true);
  });

  it('catches SQLModel with raw SQL f-string', async () => {
    const findings = await scanCode(
      `result = session.exec(f"SELECT * FROM users WHERE id = {user_id}")`,
      'crud.py',
    );
    expect(hasRule(findings, 'SQLMODEL_RAW_SQL')).toBe(true);
  });

  it('does NOT flag SQLModel with proper query', async () => {
    const findings = await scanCode(
      `result = session.exec(select(User).where(User.id == user_id))`,
      'crud.py',
    );
    expect(hasRule(findings, 'SQLMODEL_RAW_SQL')).toBe(false);
  });

  it('catches FastAPI WebSocket without auth', async () => {
    const findings = await scanCode(
      `from fastapi import FastAPI\n@app.websocket("/ws")\nasync def websocket_endpoint(websocket: WebSocket):\n    await websocket.accept()\n    data = await websocket.receive_text()`,
      'main.py',
    );
    expect(hasRule(findings, 'FASTAPI_WEBSOCKET_NO_AUTH')).toBe(true);
  });

  it('catches Pydantic arbitrary_types_allowed', async () => {
    const findings = await scanCode(
      `class Config:\n    arbitrary_types_allowed = True`,
      'schemas.py',
    );
    expect(hasRule(findings, 'PYDANTIC_ARBITRARY_TYPES')).toBe(true);
  });

  it('catches FastAPI mount with f-string path', async () => {
    const findings = await scanCode(
      `from fastapi import FastAPI\napp.mount(f"/api/{version}", sub_app)`,
      'main.py',
    );
    expect(hasRule(findings, 'FASTAPI_MOUNT_NO_PATH_VALIDATION')).toBe(true);
  });

  it('does NOT flag FastAPI mount with static path', async () => {
    const findings = await scanCode(
      `app.mount("/static", StaticFiles(directory="static"))`,
      'main.py',
    );
    expect(hasRule(findings, 'FASTAPI_MOUNT_NO_PATH_VALIDATION')).toBe(false);
  });

  it('catches FastAPI Response with user headers', async () => {
    const findings = await scanCode(
      `from fastapi import FastAPI\nreturn Response(content=data, headers=request.headers)`,
      'routes.py',
    );
    expect(hasRule(findings, 'FASTAPI_RESPONSE_USER_HEADERS')).toBe(true);
  });

  it('catches Starlette middleware without exception handling', async () => {
    const findings = await scanCode(
      `class MyMiddleware(BaseHTTPMiddleware):\n    async def dispatch(self, request, call_next):\n        response = await call_next(request)\n        return response`,
      'middleware.py',
    );
    expect(hasRule(findings, 'STARLETTE_MIDDLEWARE_NO_EXCEPTION')).toBe(true);
  });

  it('catches uvicorn with reload in production', async () => {
    const findings = await scanCode(
      `uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)`,
      'main.py',
    );
    expect(hasRule(findings, 'UVICORN_RELOAD_PRODUCTION')).toBe(true);
  });

  it('does NOT flag uvicorn without reload', async () => {
    const findings = await scanCode(
      `uvicorn.run("app:app", host="0.0.0.0", port=8000, workers=4)`,
      'main.py',
    );
    expect(hasRule(findings, 'UVICORN_RELOAD_PRODUCTION')).toBe(false);
  });
});

// ════════════════════════════════════════════
// Cycle 85: Python Async Deep
// ════════════════════════════════════════════

describe('Cycle 85: Python Async Deep', () => {
  it('catches asyncio create_subprocess_shell with user cmd', async () => {
    const findings = await scanCode(
      `proc = await asyncio.create_subprocess_shell(f"ls {user_dir}")`,
      'utils.py',
    );
    expect(hasRule(findings, 'ASYNCIO_SUBPROCESS_SHELL_TRUE')).toBe(true);
  });

  it('does NOT flag create_subprocess_exec', async () => {
    const findings = await scanCode(
      `proc = await asyncio.create_subprocess_exec("ls", "-la", "/tmp")`,
      'utils.py',
    );
    expect(hasRule(findings, 'ASYNCIO_SUBPROCESS_SHELL_TRUE')).toBe(false);
  });

  it('catches aiofiles.open with user path', async () => {
    const findings = await scanCode(
      `async with aiofiles.open(request.args['path']) as f:`,
      'handlers.py',
    );
    expect(hasRule(findings, 'AIOFILES_USER_PATH')).toBe(true);
  });

  it('catches asyncpg fetch with f-string', async () => {
    const findings = await scanCode(
      `rows = await conn.fetch(f"SELECT * FROM users WHERE name = '{name}'")`,
      'db.py',
    );
    expect(hasRule(findings, 'ASYNCPG_UNSAFE_QUERY')).toBe(true);
  });

  it('does NOT flag asyncpg with parameterized query', async () => {
    const findings = await scanCode(
      `rows = await conn.fetch("SELECT * FROM users WHERE name = $1", name)`,
      'db.py',
    );
    expect(hasRule(findings, 'ASYNCPG_UNSAFE_QUERY')).toBe(false);
  });

  it('catches aioredis with user key f-string', async () => {
    const findings = await scanCode(
      `val = await redis.get(f"session:{user_input}")`,
      'cache.py',
    );
    expect(hasRule(findings, 'AIOREDIS_USER_KEY')).toBe(true);
  });

  it('catches trio.open_tcp_stream without TLS', async () => {
    const findings = await scanCode(
      `stream = await trio.open_tcp_stream("api.example.com", 80)\nawait stream.send_all(data)`,
      'client.py',
    );
    expect(hasRule(findings, 'TRIO_TCP_NO_TLS')).toBe(true);
  });

  it('catches aiohttp ClientSession without timeout', async () => {
    const findings = await scanCode(
      `async with aiohttp.ClientSession() as session:`,
      'client.py',
    );
    expect(hasRule(findings, 'AIOHTTP_SESSION_NO_TIMEOUT')).toBe(true);
  });

  it('does NOT flag aiohttp ClientSession with timeout', async () => {
    const findings = await scanCode(
      `async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:`,
      'client.py',
    );
    expect(hasRule(findings, 'AIOHTTP_SESSION_NO_TIMEOUT')).toBe(false);
  });

  it('catches asyncio Lock acquire without timeout', async () => {
    const findings = await scanCode(
      `await lock.acquire()`,
      'workers.py',
    );
    expect(hasRule(findings, 'ASYNCIO_LOCK_NO_TIMEOUT')).toBe(true);
  });

  it('catches concurrent.futures submit with user function', async () => {
    const findings = await scanCode(
      `executor.submit(getattr(module, user_input), *args)`,
      'workers.py',
    );
    expect(hasRule(findings, 'CONCURRENT_FUTURES_USER_EXECUTOR')).toBe(true);
  });

  it('does NOT flag concurrent.futures submit with static function', async () => {
    const findings = await scanCode(
      `executor.submit(process_data, item)`,
      'workers.py',
    );
    expect(hasRule(findings, 'CONCURRENT_FUTURES_USER_EXECUTOR')).toBe(false);
  });
});

// ════════════════════════════════════════════
// Cycle 86: Python Security Libraries Misuse
// ════════════════════════════════════════════

describe('Cycle 86: Python Security Libraries Misuse', () => {
  it('catches RSA with 1024-bit key', async () => {
    const findings = await scanCode(
      `key = rsa.generate_private_key(public_exponent=65537, key_size=1024)`,
      'crypto.py',
    );
    expect(hasRule(findings, 'CRYPTOGRAPHY_UNSAFE_PARAMS')).toBe(true);
  });

  it('does NOT flag RSA with 4096-bit key', async () => {
    const findings = await scanCode(
      `key = rsa.generate_private_key(public_exponent=65537, key_size=4096)`,
      'crypto.py',
    );
    expect(hasRule(findings, 'CRYPTOGRAPHY_UNSAFE_PARAMS')).toBe(false);
  });

  it('catches PyJWT decode without algorithms', async () => {
    const findings = await scanCode(
      `payload = jwt.decode(token, SECRET_KEY)`,
      'auth.py',
    );
    expect(hasRule(findings, 'PYJWT_NO_ALGORITHM_VERIFY')).toBe(true);
  });

  it('does NOT flag PyJWT decode with algorithms', async () => {
    const findings = await scanCode(
      `payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])`,
      'auth.py',
    );
    expect(hasRule(findings, 'PYJWT_NO_ALGORITHM_VERIFY')).toBe(false);
  });

  it('catches passlib with md5_crypt', async () => {
    const findings = await scanCode(
      `hashed = passlib.hash.md5_crypt.hash(password)`,
      'auth.py',
    );
    expect(hasRule(findings, 'PASSLIB_DEPRECATED_SCHEME')).toBe(true);
  });

  it('catches itsdangerous with short secret', async () => {
    const findings = await scanCode(
      `s = URLSafeTimedSerializer('mysecret')`,
      'tokens.py',
    );
    expect(hasRule(findings, 'ITSDANGEROUS_SHORT_SECRET')).toBe(true);
  });

  it('does NOT flag itsdangerous with long secret', async () => {
    const findings = await scanCode(
      `s = URLSafeTimedSerializer(os.environ['SECRET_KEY'])`,
      'tokens.py',
    );
    expect(hasRule(findings, 'ITSDANGEROUS_SHORT_SECRET')).toBe(false);
  });

  it('catches python-jose with none algorithm', async () => {
    const findings = await scanCode(
      `payload = jwt.decode(token, key, algorithms=["none", "HS256"])`,
      'auth.py',
    );
    expect(hasRule(findings, 'PYTHON_JOSE_NONE_ALGORITHM')).toBe(true);
  });

  it('catches bcrypt with low rounds', async () => {
    const findings = await scanCode(
      `salt = bcrypt.gensalt(rounds=4)`,
      'auth.py',
    );
    expect(hasRule(findings, 'BCRYPT_LOW_ROUNDS')).toBe(true);
  });

  it('does NOT flag bcrypt with 12 rounds', async () => {
    const findings = await scanCode(
      `salt = bcrypt.gensalt(rounds=12)`,
      'auth.py',
    );
    expect(hasRule(findings, 'BCRYPT_LOW_ROUNDS')).toBe(false);
  });

  it('catches Fernet with hardcoded key', async () => {
    const findings = await scanCode(
      `f = Fernet(b'ZmRmZHNhZnNkYWZkc2FmZHNhZnNkYWY=')`,
      'crypto.py',
    );
    expect(hasRule(findings, 'FERNET_HARDCODED_KEY')).toBe(true);
  });

  it('catches Paramiko AutoAddPolicy', async () => {
    const findings = await scanCode(
      `client.set_missing_host_key_policy(paramiko.AutoAddPolicy())`,
      'ssh.py',
    );
    expect(hasRule(findings, 'PARAMIKO_NO_HOST_KEY_VERIFY')).toBe(true);
  });

  it('catches SSL with weak protocol', async () => {
    const findings = await scanCode(
      `ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)`,
      'server.py',
    );
    expect(hasRule(findings, 'SSL_WEAK_PROTOCOL')).toBe(true);
  });

  it('does NOT flag SSL with TLS client', async () => {
    const findings = await scanCode(
      `ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)`,
      'server.py',
    );
    expect(hasRule(findings, 'SSL_WEAK_PROTOCOL')).toBe(false);
  });
});

// ════════════════════════════════════════════
// Cycle 87: Python Data Processing
// ════════════════════════════════════════════

describe('Cycle 87: Python Data Processing', () => {
  it('catches pandas read_csv with user path', async () => {
    const findings = await scanCode(
      `df = pd.read_csv(request.args['file_path'])`,
      'views.py',
    );
    expect(hasRule(findings, 'PANDAS_READ_CSV_USER_PATH')).toBe(true);
  });

  it('does NOT flag pandas read_csv with static path', async () => {
    const findings = await scanCode(
      `df = pd.read_csv('data/report.csv')`,
      'analysis.py',
    );
    expect(hasRule(findings, 'PANDAS_READ_CSV_USER_PATH')).toBe(false);
  });

  it('catches openpyxl with keep_vba=True', async () => {
    const findings = await scanCode(
      `wb = load_workbook('file.xlsm', keep_vba=True)`,
      'process.py',
    );
    expect(hasRule(findings, 'OPENPYXL_MACRO_ENABLED')).toBe(true);
  });

  it('catches PIL MAX_IMAGE_PIXELS set to None', async () => {
    const findings = await scanCode(
      `Image.MAX_IMAGE_PIXELS = None`,
      'images.py',
    );
    expect(hasRule(findings, 'PIL_IMAGE_BOMB')).toBe(true);
  });

  it('catches csv.reader without field_size_limit', async () => {
    const findings = await scanCode(
      `reader = csv.reader(open('data.csv'))`,
      'process.py',
    );
    expect(hasRule(findings, 'CSV_READER_NO_FIELD_SIZE_LIMIT')).toBe(true);
  });

  it('does NOT flag csv.reader with field_size_limit set', async () => {
    const findings = await scanCode(
      `import csv\ncsv.field_size_limit(131072)\nreader = csv.reader(open('data.csv'))`,
      'process.py',
    );
    expect(hasRule(findings, 'CSV_READER_NO_FIELD_SIZE_LIMIT')).toBe(false);
  });

  it('catches json.loads on request body', async () => {
    const findings = await scanCode(
      `data = json.loads(request.body)`,
      'views.py',
    );
    expect(hasRule(findings, 'JSON_LOADS_NO_SIZE_LIMIT')).toBe(true);
  });

  it('catches yaml.load without SafeLoader', async () => {
    const findings = await scanCode(
      `data = yaml.load(content)`,
      'config.py',
    );
    expect(hasRule(findings, 'YAML_LOAD_UNSAFE_LOADER')).toBe(true);
  });

  it('does NOT flag yaml.safe_load', async () => {
    const findings = await scanCode(
      `data = yaml.safe_load(content)`,
      'config.py',
    );
    expect(hasRule(findings, 'YAML_LOAD_UNSAFE_LOADER')).toBe(false);
  });

  it('catches sqlite3.connect with user path', async () => {
    const findings = await scanCode(
      `conn = sqlite3.connect(request.args['db_path'])`,
      'db.py',
    );
    expect(hasRule(findings, 'SQLITE3_USER_DB_PATH')).toBe(true);
  });

  it('catches h5py with user file path', async () => {
    const findings = await scanCode(
      `f = h5py.File(request.files['data'].filename, 'r')`,
      'process.py',
    );
    expect(hasRule(findings, 'H5PY_UNTRUSTED_HDF5')).toBe(true);
  });

  it('catches pd.read_parquet with user path', async () => {
    const findings = await scanCode(
      `df = pd.read_parquet(request.args['file_path'])`,
      'views.py',
    );
    expect(hasRule(findings, 'PARQUET_USER_SCHEMA')).toBe(true);
  });

  it('catches xlrd with user file', async () => {
    const findings = await scanCode(
      `wb = xlrd.open_workbook(request.files['upload'].filename)`,
      'views.py',
    );
    expect(hasRule(findings, 'XLRD_FORMULA_EVAL')).toBe(true);
  });
});

// ════════════════════════════════════════════
// Cycle 88: Python Web Scraping & Network
// ════════════════════════════════════════════

describe('Cycle 88: Python Web Scraping & Network', () => {
  it('catches requests.get without timeout', async () => {
    const findings = await scanCode(
      `response = requests.get(url)`,
      'client.py',
    );
    expect(hasRule(findings, 'REQUESTS_NO_TIMEOUT')).toBe(true);
  });

  it('does NOT flag requests.get with timeout', async () => {
    const findings = await scanCode(
      `response = requests.get(url, timeout=30)`,
      'client.py',
    );
    expect(hasRule(findings, 'REQUESTS_NO_TIMEOUT')).toBe(false);
  });

  it('catches urllib3.disable_warnings', async () => {
    const findings = await scanCode(
      `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)`,
      'client.py',
    );
    expect(hasRule(findings, 'URLLIB3_DISABLED_WARNINGS')).toBe(true);
  });

  it('catches selenium driver.get with user URL', async () => {
    const findings = await scanCode(
      `driver.get(request.args['url'])`,
      'scraper.py',
    );
    expect(hasRule(findings, 'SELENIUM_USER_URL')).toBe(true);
  });

  it('catches BeautifulSoup with lxml-xml parser', async () => {
    const findings = await scanCode(
      `soup = BeautifulSoup(xml_data, 'lxml-xml')`,
      'parser.py',
    );
    expect(hasRule(findings, 'BEAUTIFULSOUP_LXML_UNTRUSTED_XML')).toBe(true);
  });

  it('does NOT flag BeautifulSoup with html.parser', async () => {
    const findings = await scanCode(
      `soup = BeautifulSoup(html_data, 'html.parser')`,
      'parser.py',
    );
    expect(hasRule(findings, 'BEAUTIFULSOUP_LXML_UNTRUSTED_XML')).toBe(false);
  });

  it('catches Paramiko exec_command with f-string', async () => {
    const findings = await scanCode(
      `stdin, stdout, stderr = client.exec_command(f"grep {user_input} /var/log/app.log")`,
      'ssh.py',
    );
    expect(hasRule(findings, 'PARAMIKO_EXEC_USER_INPUT')).toBe(true);
  });

  it('catches ftplib without TLS', async () => {
    const findings = await scanCode(
      `ftp = ftplib.FTP('ftp.example.com')`,
      'transfer.py',
    );
    expect(hasRule(findings, 'FTPLIB_NO_TLS')).toBe(true);
  });

  it('does NOT flag ftplib with FTP_TLS', async () => {
    const findings = await scanCode(
      `ftp = ftplib.FTP_TLS('ftp.example.com')`,
      'transfer.py',
    );
    expect(hasRule(findings, 'FTPLIB_NO_TLS')).toBe(false);
  });

  it('catches socket bind to 0.0.0.0', async () => {
    const findings = await scanCode(
      `s.bind(('0.0.0.0', 8080))`,
      'server.py',
    );
    expect(hasRule(findings, 'SOCKET_BIND_ALL_INTERFACES')).toBe(true);
  });

  it('catches httplib2 without cert verification', async () => {
    const findings = await scanCode(
      `h = httplib2.Http(disable_ssl_certificate_validation=True)`,
      'client.py',
    );
    expect(hasRule(findings, 'HTTPLIB2_NO_CERT_VERIFY')).toBe(true);
  });

  it('catches DNS resolver with user query', async () => {
    const findings = await scanCode(
      `answer = resolver.resolve(request.args['domain'], 'A')`,
      'dns.py',
    );
    expect(hasRule(findings, 'DNS_RESOLVER_USER_QUERY')).toBe(true);
  });
});

// ════════════════════════════════════════════
// Cycle 89: Python Testing & DevOps
// ════════════════════════════════════════════

describe('Cycle 89: Python Testing & DevOps', () => {
  it('catches pytest fixture with hardcoded password', async () => {
    const findings = await scanCode(
      `@pytest.fixture\ndef test_user():\n    password = 'SuperSecretPass123!'`,
      'conftest.py',
    );
    expect(hasRule(findings, 'PYTEST_FIXTURE_REAL_CREDS')).toBe(true);
  });

  it('catches mock side_effect with eval', async () => {
    const findings = await scanCode(
      `mock.patch('module.func', side_effect=eval(code))`,
      'test_views.py',
    );
    expect(hasRule(findings, 'UNITTEST_MOCK_SIDE_EFFECT_EXEC')).toBe(true);
  });

  it('does NOT flag mock side_effect with lambda', async () => {
    const findings = await scanCode(
      `mock.patch('module.func', side_effect=lambda x: x + 1)`,
      'test_views.py',
    );
    expect(hasRule(findings, 'UNITTEST_MOCK_SIDE_EFFECT_EXEC')).toBe(false);
  });

  it('catches fabric Connection.run with f-string', async () => {
    const findings = await scanCode(
      `from fabric import Connection\nc = Connection('host')\nc.run(f"deploy {user_input}")`,
      'deploy.py',
    );
    expect(hasRule(findings, 'FABRIC_INVOKE_USER_CMD')).toBe(true);
  });

  it('catches boto3 with user-controlled region', async () => {
    const findings = await scanCode(
      `client = boto3.client('s3', region_name=request.args['region'])`,
      'aws.py',
    );
    expect(hasRule(findings, 'BOTO3_NO_REGION_VALIDATION')).toBe(true);
  });

  it('does NOT flag boto3 with static region', async () => {
    const findings = await scanCode(
      `client = boto3.client('s3', region_name='us-east-1')`,
      'aws.py',
    );
    expect(hasRule(findings, 'BOTO3_NO_REGION_VALIDATION')).toBe(false);
  });

  it('catches docker-py with user-controlled image', async () => {
    const findings = await scanCode(
      `client.containers.run(request.json['image_name'], detach=True)`,
      'docker_mgr.py',
    );
    expect(hasRule(findings, 'DOCKER_PY_USER_IMAGE')).toBe(true);
  });

  it('catches Kubernetes client with user namespace', async () => {
    const findings = await scanCode(
      `pods = v1.list_namespaced_pod(namespace=request.args['ns'])`,
      'k8s.py',
    );
    expect(hasRule(findings, 'K8S_CLIENT_USER_NAMESPACE')).toBe(true);
  });

  it('catches Celery send_task with user task name', async () => {
    const findings = await scanCode(
      `result = app.send_task(request.json['task_name'], args=[data])`,
      'tasks.py',
    );
    expect(hasRule(findings, 'CELERY_TASK_USER_ARGS')).toBe(true);
  });

  it('catches gunicorn with debug loglevel', async () => {
    const findings = await scanCode(
      `# gunicorn config\nloglevel = 'debug'`,
      'gunicorn.py',
    );
    expect(hasRule(findings, 'GUNICORN_DEBUG_MODE')).toBe(true);
  });
});

// ════════════════════════════════════════════
// Cycle 90: Final Python FP Hardening (25 FP tests)
// ════════════════════════════════════════════

describe('Cycle 90: Python False Positive Hardening', () => {
  it('does NOT flag Django model field definition with CharField', async () => {
    const findings = await scanCode(
      `class Article(models.Model):\n    title = models.CharField(max_length=200)\n    slug = models.SlugField(max_length=200)`,
      'models.py',
    );
    expect(hasRule(findings, 'DJANGO_CHARFIELD_NO_MAX_LENGTH')).toBe(false);
  });

  it('does NOT flag Flask route with login_required decorator', async () => {
    const findings = await scanCode(
      `from flask_login import login_required\n@app.route('/dashboard')\n@login_required\ndef dashboard():\n    return render_template('dashboard.html')`,
      'views.py',
    );
    expect(hasRule(findings, 'FLASK_BLUEPRINT_NO_AUTH')).toBe(false);
  });

  it('does NOT flag FastAPI Depends chain with proper yield', async () => {
    const findings = await scanCode(
      `async def get_db():\n    db = SessionLocal()\n    try:\n        yield db\n    finally:\n        db.close()`,
      'deps.py',
    );
    expect(hasRule(findings, 'FASTAPI_DEPENDS_NO_ERROR_HANDLING')).toBe(false);
  });

  it('does NOT flag SQLAlchemy model class definition', async () => {
    const findings = await scanCode(
      `class User(Base):\n    __tablename__ = "users"\n    id = Column(Integer, primary_key=True)\n    email = Column(String(255), unique=True)`,
      'models.py',
    );
    expect(hasRule(findings, 'FLASK_SQLALCHEMY_RAW_SQL')).toBe(false);
  });

  it('does NOT flag Alembic migration upgrade function', async () => {
    const findings = await scanCode(
      `def upgrade():\n    op.create_table('users',\n        sa.Column('id', sa.Integer(), nullable=False),\n        sa.Column('name', sa.String(length=255)))`,
      'versions_001.py',
    );
    expect(hasRule(findings, 'FLASK_MIGRATE_USER_REVISION')).toBe(false);
  });

  it('does NOT flag pytest fixture with mock data', async () => {
    const findings = await scanCode(
      `@pytest.fixture\ndef sample_data():\n    return {"name": "Test User", "email": "test@example.com"}`,
      'conftest.py',
    );
    expect(hasRule(findings, 'PYTEST_FIXTURE_REAL_CREDS')).toBe(false);
  });

  it('does NOT flag Pydantic BaseModel definition with Field', async () => {
    const findings = await scanCode(
      `class ItemCreate(BaseModel):\n    name: str = Field(..., min_length=1, max_length=100)\n    price: float = Field(..., gt=0)\n    @field_validator('name')\n    def validate_name(cls, v):\n        return v.strip()`,
      'schemas.py',
    );
    expect(hasRule(findings, 'PYDANTIC_MODEL_NO_VALIDATORS')).toBe(false);
  });

  it('does NOT flag Django form with clean method', async () => {
    const findings = await scanCode(
      `class ContactForm(forms.Form):\n    email = forms.EmailField()\n    message = forms.CharField(widget=forms.Textarea)\n    def clean_email(self):\n        email = self.cleaned_data['email']\n        return email.lower()`,
      'forms.py',
    );
    expect(hasRule(findings, 'DJANGO_MODELFORM_EXCLUDE')).toBe(false);
  });

  it('does NOT flag type hints containing security-related names', async () => {
    const findings = await scanCode(
      `def get_token_data(token: str) -> TokenPayload:\n    """Decode and validate the token."""\n    return decode_token(token)`,
      'auth.py',
    );
    expect(hasRule(findings, 'PYJWT_NO_ALGORITHM_VERIFY')).toBe(false);
  });

  it('does NOT flag Django management command', async () => {
    const findings = await scanCode(
      `from django.core.management.base import BaseCommand\nclass Command(BaseCommand):\n    help = 'Import data from CSV'\n    def handle(self, *args, **options):\n        self.stdout.write('Starting import...')`,
      'import_data.py',
    );
    expect(hasRule(findings, 'DJANGO_REDIRECT_USER_URL')).toBe(false);
  });

  it('does NOT flag Django admin.site.register', async () => {
    const findings = await scanCode(
      `from django.contrib import admin\nfrom .models import Article\nadmin.site.register(Article)`,
      'admin.py',
    );
    expect(hasRule(findings, 'DJANGO_ADMIN_NO_2FA')).toBe(false);
  });

  it('does NOT flag Flask-Login UserMixin class', async () => {
    const findings = await scanCode(
      `from flask_login import UserMixin\nclass User(UserMixin, db.Model):\n    id = db.Column(db.Integer, primary_key=True)\n    username = db.Column(db.String(80))`,
      'models.py',
    );
    expect(hasRule(findings, 'FLASK_LOGIN_NO_SESSION_PROTECTION')).toBe(false);
  });

  it('does NOT flag FastAPI Security dependency', async () => {
    const findings = await scanCode(
      `from fastapi.security import OAuth2PasswordBearer\noauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")\nasync def get_current_user(token: str = Depends(oauth2_scheme)):\n    return verify_token(token)`,
      'auth.py',
    );
    expect(hasRule(findings, 'FASTAPI_WEBSOCKET_NO_AUTH')).toBe(false);
  });

  it('does NOT flag dataclass definition', async () => {
    const findings = await scanCode(
      `from dataclasses import dataclass\n@dataclass\nclass Config:\n    host: str\n    port: int\n    debug: bool = False`,
      'config.py',
    );
    expect(hasRule(findings, 'PYDANTIC_ARBITRARY_TYPES')).toBe(false);
  });

  it('does NOT flag Django settings with env() calls', async () => {
    const findings = await scanCode(
      `import environ\nenv = environ.Env()\nSECRET_KEY = env('SECRET_KEY')\nDEBUG = env.bool('DEBUG', default=False)\nDATABASES = {'default': env.db()}`,
      'settings.py',
    );
    expect(hasRule(findings, 'DJANGO_SECRET_KEY_HARDCODED')).toBe(false);
  });

  it('does NOT flag requests.post with timeout', async () => {
    const findings = await scanCode(
      `response = requests.post(url, json=data, timeout=30, headers=headers)`,
      'api_client.py',
    );
    expect(hasRule(findings, 'REQUESTS_NO_TIMEOUT')).toBe(false);
  });

  it('does NOT flag socket bind to localhost', async () => {
    const findings = await scanCode(
      `s.bind(('127.0.0.1', 8080))`,
      'server.py',
    );
    expect(hasRule(findings, 'SOCKET_BIND_ALL_INTERFACES')).toBe(false);
  });

  it('does NOT flag yaml.load with SafeLoader', async () => {
    const findings = await scanCode(
      `data = yaml.load(content, Loader=yaml.SafeLoader)`,
      'config.py',
    );
    expect(hasRule(findings, 'YAML_LOAD_UNSAFE_LOADER')).toBe(false);
  });

  it('does NOT flag bcrypt with 12 rounds (gensalt)', async () => {
    const findings = await scanCode(
      `hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=14))`,
      'auth.py',
    );
    expect(hasRule(findings, 'BCRYPT_LOW_ROUNDS')).toBe(false);
  });

  it('does NOT flag Fernet with env key', async () => {
    const findings = await scanCode(
      `key = os.environ['FERNET_KEY']\nf = Fernet(key.encode())`,
      'crypto.py',
    );
    expect(hasRule(findings, 'FERNET_HARDCODED_KEY')).toBe(false);
  });

  it('does NOT flag PyJWT with explicit algorithms', async () => {
    const findings = await scanCode(
      `payload = jwt.decode(token, public_key, algorithms=["RS256"])`,
      'auth.py',
    );
    expect(hasRule(findings, 'PYJWT_NO_ALGORITHM_VERIFY')).toBe(false);
  });

  it('does NOT flag static redirect URL', async () => {
    const findings = await scanCode(
      `return redirect(reverse('home'))`,
      'views.py',
    );
    expect(hasRule(findings, 'DJANGO_REDIRECT_USER_URL')).toBe(false);
  });

  it('does NOT flag ssl.PROTOCOL_TLS_CLIENT', async () => {
    const findings = await scanCode(
      `context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\ncontext.load_default_certs()`,
      'tls.py',
    );
    expect(hasRule(findings, 'SSL_WEAK_PROTOCOL')).toBe(false);
  });

  it('does NOT flag pandas read_csv with static path', async () => {
    const findings = await scanCode(
      `df = pd.read_csv('/data/reports/monthly.csv', dtype={'amount': float})`,
      'analysis.py',
    );
    expect(hasRule(findings, 'PANDAS_READ_CSV_USER_PATH')).toBe(false);
  });

  it('does NOT flag ftplib.FTP_TLS', async () => {
    const findings = await scanCode(
      `ftp = ftplib.FTP_TLS('secure.example.com')\nftp.prot_p()`,
      'transfer.py',
    );
    expect(hasRule(findings, 'FTPLIB_NO_TLS')).toBe(false);
  });
});

// ════════════════════════════════════════════
// Real-world False Positive Regression Tests
// ════════════════════════════════════════════

describe('Real-world false positive regressions', () => {
  describe('GRAPHQL_CIRCULAR_REF should not fire on non-GraphQL code', () => {
    it('does NOT fire on TypeScript import statements', async () => {
      const findings = await scanCode(`
import type { User } from './types';
import { UserService } from './services';

interface User {
  id: string;
  name: string;
  friends: User[];
}
      `);
      expect(hasRule(findings, 'GRAPHQL_CIRCULAR_REF')).toBe(false);
    });

    it('does NOT fire on TypeScript interface definitions', async () => {
      const findings = await scanCode(`
type TreeNode = {
  value: string;
  children: TreeNode[];
};

type LinkedList = {
  data: number;
  next: LinkedList | null;
};
      `);
      expect(hasRule(findings, 'GRAPHQL_CIRCULAR_REF')).toBe(false);
    });

    it('does NOT fire on React component type definitions', async () => {
      const findings = await scanCode(`
type ComponentProps = {
  title: string;
  children: React.ReactNode;
};

type FormState = {
  values: Record<string, string>;
  errors: Record<string, string>;
};
      `);
      expect(hasRule(findings, 'GRAPHQL_CIRCULAR_REF')).toBe(false);
    });
  });

  describe('FastAPI rules should not fire in docs_src/', () => {
    it('does NOT fire FASTAPI_NO_MIDDLEWARE_STACK in docs_src/', async () => {
      const findings = await scanCode(
        `from fastapi import FastAPI\n\napp = FastAPI()`,
        'docs_src/first_steps/tutorial001.py',
      );
      expect(hasRule(findings, 'FASTAPI_NO_MIDDLEWARE_STACK')).toBe(false);
    });

    it('does NOT fire FASTAPI_TRUSTED_HOST_MISSING in tests/', async () => {
      const findings = await scanCode(
        `from fastapi import FastAPI\n\napp = FastAPI()`,
        'tests/test_main.py',
      );
      expect(hasRule(findings, 'FASTAPI_TRUSTED_HOST_MISSING')).toBe(false);
    });

    it('does NOT fire FASTAPI_NO_CORS_MIDDLEWARE in examples/', async () => {
      const findings = await scanCode(
        `from fastapi import FastAPI\n\napp = FastAPI()`,
        'examples/basic.py',
      );
      expect(hasRule(findings, 'FASTAPI_NO_CORS_MIDDLEWARE')).toBe(false);
    });
  });

  describe('NEXT_PUBLIC_SECRET should not fire on publishable keys', () => {
    it('does NOT fire on NEXT_PUBLIC_SUPABASE_ANON_KEY', async () => {
      const findings = await scanCode(
        `const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;`,
      );
      expect(hasRule(findings, 'NEXT_PUBLIC_SECRET')).toBe(false);
    });

    it('does NOT fire on NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY', async () => {
      const findings = await scanCode(
        `const stripeKey = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;`,
      );
      expect(hasRule(findings, 'NEXT_PUBLIC_SECRET')).toBe(false);
    });

    it('does NOT fire on NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY', async () => {
      const findings = await scanCode(
        `const clerkKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;`,
      );
      expect(hasRule(findings, 'NEXT_PUBLIC_SECRET')).toBe(false);
    });

    it('still fires on genuinely secret NEXT_PUBLIC_ vars', async () => {
      const findings = await scanCode(
        `const secret = process.env.NEXT_PUBLIC_DATABASE_SECRET;`,
      );
      expect(hasRule(findings, 'NEXT_PUBLIC_SECRET')).toBe(true);
    });
  });

  describe('Framework cross-fire prevention', () => {
    it('FLASK_SESSION_COOKIE_NO_SIGNING does NOT fire in Django code', async () => {
      const findings = await scanCode(
        `from django.contrib.sessions.backends.db import SessionStore\n\ndef view(request):\n    session['user_id'] = request.user.id`,
        'views.py',
      );
      expect(hasRule(findings, 'FLASK_SESSION_COOKIE_NO_SIGNING')).toBe(false);
    });

    it('NEXTJS_REDIRECT_USER_INPUT does NOT fire in Express code', async () => {
      const findings = await scanCode(`
import express from 'express';
const app = express();
app.get('/login', (req, res) => {
  const url = req.query.redirect;
  redirect(url);
});
      `);
      expect(hasRule(findings, 'NEXTJS_REDIRECT_USER_INPUT')).toBe(false);
    });

    it('PYTHON_DJANGO_DEBUG does NOT fire in Flask code', async () => {
      const findings = await scanCode(
        `from flask import Flask\n\nDEBUG = True\napp = Flask(__name__)`,
        'app.py',
      );
      expect(hasRule(findings, 'PYTHON_DJANGO_DEBUG')).toBe(false);
    });
  });

  describe('FETCH_NO_ERROR_HANDLING respects try/catch', () => {
    it('does NOT fire when fetch is inside try/catch', async () => {
      const findings = await scanCode(`
try {
  const response = await fetch('/api/data');
  const data = await response.json();
} catch (error) {
  console.error(error);
}
      `);
      expect(hasRule(findings, 'FETCH_NO_ERROR_HANDLING')).toBe(false);
    });
  });

  describe('TIMING_UNSAFE_COMPARISON respects nearby timingSafeEqual', () => {
    it('does NOT fire when timingSafeEqual is used nearby', async () => {
      const findings = await scanCode(`
const crypto = require('crypto');
function verifyToken(provided, stored) {
  const a = Buffer.from(provided);
  const b = Buffer.from(stored);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
// Usage:
const tokenMatch = token === storedToken;
      `);
      expect(hasRule(findings, 'TIMING_UNSAFE_COMPARISON')).toBe(false);
    });
  });

  describe('MONITORING_BLIND_SPOT_ERROR only flags empty catch blocks', () => {
    it('does NOT fire on catch blocks with console.error', async () => {
      const findings = await scanCode(`
try { await process(); } catch (err) {
  console.error('Failed:', err);
}
      `);
      expect(hasRule(findings, 'MONITORING_BLIND_SPOT_ERROR')).toBe(false);
    });

    it('fires on truly empty catch blocks', async () => {
      const findings = await scanCode(`
try { await process(); } catch (err) {
}
      `);
      expect(hasRule(findings, 'MONITORING_BLIND_SPOT_ERROR')).toBe(true);
    });
  });

  describe('RECURSIVE_NO_DEPTH_LIMIT requires user input', () => {
    it('does NOT fire on utility recursive functions without user input', async () => {
      const findings = await scanCode(`
function flatten(arr) {
  return arr.reduce((acc, item) =>
    Array.isArray(item) ? acc.concat(flatten(item)) : acc.concat(item), []);
}
      `);
      expect(hasRule(findings, 'RECURSIVE_NO_DEPTH_LIMIT')).toBe(false);
    });
  });

  describe('isTestFile expanded coverage', () => {
    it('skips files in i18n directory', async () => {
      const findings = await scanCode(
        `const password = "some-secret-value-123";`,
        'src/i18n/en.ts',
      );
      // skipTestFiles rules should not fire
      expect(hasRule(findings, 'AUTH_PLAINTEXT_PASSWORD_STORAGE')).toBe(false);
    });

    it('skips files in fixtures directory', async () => {
      const findings = await scanCode(
        `const apiKey = "sk-1234567890abcdef";`,
        'tests/fixtures/data.ts',
      );
      expect(hasRule(findings, 'API_KEY_LITERAL_REACT')).toBe(false);
    });

    it('skips files in docs directory', async () => {
      const findings = await scanCode(
        `eval(userInput);`,
        'docs/examples/demo.ts',
      );
      expect(hasRule(findings, 'EVAL_USER_INPUT')).toBe(false);
    });
  });

  // ════════════════════════════════════════════
  // False Positive Regression Tests
  // Real-world FPs from scanning express, hono, payload, fastapi, flask
  // ════════════════════════════════════════════

  describe('FP Regression: TS_UNKNOWN_NO_NARROWING', () => {
    it('does NOT fire on generic unknown-to-type cast in non-security code', async () => {
      const findings = await scanCode(`
const data: unknown = JSON.parse(rawText);
const parsed = data as ConfigOptions;
console.log(parsed.timeout);
      `);
      expect(hasRule(findings, 'TS_UNKNOWN_NO_NARROWING')).toBe(false);
    });

    it('DOES fire on unknown cast in auth context', async () => {
      const findings = await scanCode(`
function getUser(session: { data: unknown }) {
  const token = session.data;
  const user: unknown = decodeJwt(token as string); return user as UserClaims;
}
      `);
      // Line with "unknown" and "as UserClaims"; nearby has "session" and "token"
      expect(hasRule(findings, 'TS_UNKNOWN_NO_NARROWING')).toBe(true);
    });

    it('does NOT fire on unknown cast in a utility/data transformation', async () => {
      const findings = await scanCode(`
function parseResponse(body: unknown): ApiResponse {
  return body as ApiResponse;
}
      `);
      expect(hasRule(findings, 'TS_UNKNOWN_NO_NARROWING')).toBe(false);
    });
  });

  describe('FP Regression: FETCH_NO_ERROR_HANDLING', () => {
    it('does NOT fire when fetch is inside a try block 10 lines up', async () => {
      const findings = await scanCode(`
async function loadData() {
  try {
    const headers = getHeaders();
    const url = buildUrl();
    const options = { headers };
    const extra = "some-setup";
    const debug = true;
    const mode = "cors";
    const ref = null;
    const timeout = 5000;
    const response = await fetch(url, options);
    return response.json();
  } catch (err) {
    handleError(err);
  }
}
      `);
      expect(hasRule(findings, 'FETCH_NO_ERROR_HANDLING')).toBe(false);
    });

    it('does NOT fire when file has a global error handler function', async () => {
      const findings = await scanCode(`
function handleError(err: Error) {
  console.error("Error:", err.message);
}

async function getData() {
  const response = await fetch("/api/data");
  return response.json();
}
      `);
      expect(hasRule(findings, 'FETCH_NO_ERROR_HANDLING')).toBe(false);
    });

    it('does NOT fire when fetch is inside a fetchWrapper utility', async () => {
      const findings = await scanCode(`
export async function fetchWrapper(url: string) {
  const response = await fetch(url);
  return response.json();
}
      `);
      expect(hasRule(findings, 'FETCH_NO_ERROR_HANDLING')).toBe(false);
    });

    it('does NOT fire on framework source code', async () => {
      const findings = await scanCode(
        `const response = await fetch(endpoint);`,
        'node_modules/hono/src/client/fetch.ts',
      );
      expect(hasRule(findings, 'FETCH_NO_ERROR_HANDLING')).toBe(false);
    });
  });

  describe('FP Regression: COOKIE_NO_SAMESITE on cookie libraries', () => {
    it('does NOT fire on hono cookie helper source', async () => {
      const findings = await scanCode(
        `setCookie(c, "name", "value", { httpOnly: true, secure: true, path: "/" });`,
        'node_modules/hono/src/helper/cookie/index.ts',
      );
      expect(hasRule(findings, 'COOKIE_NO_SAMESITE')).toBe(false);
    });

    it('does NOT fire on express cookie-parser source', async () => {
      const findings = await scanCode(
        `res.cookie("session", token, { httpOnly: true, secure: true, maxAge: 3600 });`,
        'node_modules/cookie-parser/lib/index.js',
      );
      expect(hasRule(findings, 'COOKIE_NO_SAMESITE')).toBe(false);
    });

    it('DOES fire on application code missing sameSite', async () => {
      const findings = await scanCode(`
setCookie(c, "session", token, { httpOnly: true, secure: true, maxAge: 3600 });
      `);
      expect(hasRule(findings, 'COOKIE_NO_SAMESITE')).toBe(true);
    });
  });

  describe('FP Regression: UPLOAD_MIME_ONLY_CHECK on framework code', () => {
    it('does NOT fire on hono framework source', async () => {
      const findings = await scanCode(
        `if (file.mimeType === "image/png") { return true; }`,
        'node_modules/hono/src/middleware/body-parser.ts',
      );
      expect(hasRule(findings, 'UPLOAD_MIME_ONLY_CHECK')).toBe(false);
    });

    it('DOES fire on application code with MIME-only check', async () => {
      const findings = await scanCode(
        `if (file.mimeType.startsWith("image/")) { saveFile(file); }`,
        'src/upload-handler.ts',
      );
      expect(hasRule(findings, 'UPLOAD_MIME_ONLY_CHECK')).toBe(true);
    });
  });

  describe('FP Regression: FASTAPI_WEBSOCKET_NO_AUTH in examples', () => {
    it('does NOT fire on example directory WebSocket code', async () => {
      const findings = await scanCode(
        `async def websocket_endpoint(websocket: WebSocket):\n    await websocket.accept()\n    data = await websocket.receive_text()`,
        'docs/examples/websocket_demo.py',
      );
      expect(hasRule(findings, 'FASTAPI_WEBSOCKET_NO_AUTH')).toBe(false);
    });

    it('does NOT fire on docs_src directory', async () => {
      const findings = await scanCode(
        `async def websocket_endpoint(websocket: WebSocket):\n    await websocket.accept()`,
        'docs_src/websockets/tutorial001.py',
      );
      expect(hasRule(findings, 'FASTAPI_WEBSOCKET_NO_AUTH')).toBe(false);
    });
  });

  describe('FP Regression: PYDANTIC_MODEL_NO_VALIDATORS on simple models', () => {
    it('does NOT fire on a standalone data model not used in routes', async () => {
      const findings = await scanCode(
        `class UserProfile(BaseModel):\n    email: str\n    name: str`,
        'models.py',
      );
      expect(hasRule(findings, 'PYDANTIC_MODEL_NO_VALIDATORS')).toBe(false);
    });

    it('does NOT fire on models in example directories', async () => {
      const findings = await scanCode(
        `class CreateUser(BaseModel):\n    email: str\n    password: str`,
        'examples/schemas.py',
      );
      expect(hasRule(findings, 'PYDANTIC_MODEL_NO_VALIDATORS')).toBe(false);
    });
  });

  describe('FP Regression: framework source general detection', () => {
    it('does NOT fire cookie rules on node_modules package source', async () => {
      const findings = await scanCode(
        `res.cookie("token", value, { httpOnly: true, secure: true, maxAge: 86400 });`,
        'node_modules/some-auth-lib/src/session.js',
      );
      expect(hasRule(findings, 'COOKIE_NO_SAMESITE')).toBe(false);
      expect(hasRule(findings, 'COOKIE_MISSING_SAMESITE')).toBe(false);
      expect(hasRule(findings, 'COOKIE_NO_HTTPONLY')).toBe(false);
    });

    it('does NOT fire UPLOAD_MIME_ONLY_CHECK on payload CMS source', async () => {
      const findings = await scanCode(
        `if (file.mimeType.startsWith("image/")) { processImage(file); }`,
        'node_modules/payload/src/uploads/handler.ts',
      );
      expect(hasRule(findings, 'UPLOAD_MIME_ONLY_CHECK')).toBe(false);
    });
  });
});
