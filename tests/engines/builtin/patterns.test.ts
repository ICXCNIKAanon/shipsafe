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
