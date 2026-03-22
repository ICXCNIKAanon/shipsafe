# ShipSafe

Security scanning for developers who ship fast.

[![npm version](https://img.shields.io/npm/v/@shipsafe/cli.svg)](https://www.npmjs.com/package/@shipsafe/cli)
[![license](https://img.shields.io/badge/license-proprietary-blue.svg)](https://shipsafe.org)

## What it does

ShipSafe catches vulnerabilities, hardcoded secrets, and dangerous dependencies before they reach production. It ships with 1,266 detection rules (1,062 vulnerability + 174 secret + 30 environment threat patterns), requires zero configuration, and works with Claude Code, Cursor, Windsurf, Copilot, Cline, and any AI coding tool. Every scan runs in pure TypeScript with no external binary dependencies.

## Quick Start

```bash
npm install -g @shipsafe/cli
```

That's it. One command installs the CLI, the MCP server for AI assistants, and auto-registers with Claude Code. Run `shipsafe init` inside any project to install git hooks and write AI instructions to your editor config files.

## What it catches

- **1,062 vulnerability patterns** -- SQL injection, prompt injection, XSS, command injection, path traversal, SSRF, CSRF, prototype pollution, insecure cryptography, insecure deserialization, authentication issues, and more
- **174 secret patterns** -- AWS keys, GCP service accounts, Azure tokens, GitHub PATs, Stripe keys, database URLs, JWTs, private keys, OAuth secrets, and dozens more -- with Shannon entropy validation to reduce false positives
- **30 environment threat patterns** -- prompt injection in CLAUDE.md, malicious MCP server configs, dangerous hooks, skill file manipulation, obfuscated instructions, credential theft, reverse shells
- **Dependency vulnerabilities** -- deprecated packages, known CVEs, typosquatting detection, maintenance status checks

## How it works

ShipSafe protects your code through three layers:

1. **Git hooks** (pre-commit and pre-push) -- installed automatically on first scan, they block commits and pushes that contain critical or high-severity findings. Works with any editor, any workflow.

2. **MCP server** -- exposes 7 tools over stdio transport so AI coding assistants can scan, fix, and query your project's security posture in real time.

3. **CLI** -- direct commands for scanning, baselining known findings, checking packages before install, and managing configuration.

## CLI Commands

| Command | Description |
|---------|-------------|
| `shipsafe scan` | Scan project for vulnerabilities. Options: `--scope staged\|all\|file:<path>`, `--fix`, `--json` |
| `shipsafe init` | Initialize ShipSafe in a project. Installs hooks, writes AI config files (CLAUDE.md, .cursorrules, etc.), registers MCP servers |
| `shipsafe setup` | Register MCP server with Claude Code, Cursor, and other editors |
| `shipsafe baseline` | Snapshot current findings so only new issues are reported. Options: `--show`, `--clear` |
| `shipsafe activate <key>` | Activate a Pro or Team license key |
| `shipsafe config list` | View current configuration |
| `shipsafe config set <key> <value>` | Set a config value. Add `--global` for user-wide settings |
| `shipsafe audit <url>` | Audit a remote GitHub/GitLab repo before installing. Checks for vulnerabilities, secrets, malicious patterns, obfuscation, postinstall threats, and environment risks. Options: `--json` |
| `shipsafe scan-environment` | Scan Claude Code environment for malicious MCP servers, hooks, skills, and prompt injection in CLAUDE.md. Options: `--json` |
| `shipsafe status` | Show project security status, hook state, and available engines |
| `shipsafe connect` | Connect project to ShipSafe cloud for monitoring |
| `shipsafe upload-sourcemaps` | Upload source maps for production error resolution |
| `shipsafe mcp-server` | Start MCP server (stdio transport, used by AI assistants) |

## .shipsafeignore

Create a `.shipsafeignore` file in your project root to exclude files and directories from scanning. Uses gitignore-style syntax:

```gitignore
# Exclude test fixtures
tests/fixtures/

# Exclude generated files
src/generated/

# Exclude specific file
config/legacy-secrets.ts
```

ShipSafe also respects your `.gitignore` and always skips `node_modules`, `dist`, `.git`, and `coverage` by default.

## Configuration

ShipSafe uses two config files, merged together (project overrides global):

- **Global**: `~/.shipsafe/config.json`
- **Project**: `shipsafe.config.json`

```bash
# View current config
shipsafe config list

# Set project-level config
shipsafe config set scan.severity_threshold medium

# Set global config
shipsafe config set licenseKey SS-PRO-abc123 --global
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHIPSAFE_API_URL` | API endpoint override | `https://shipsafe-m9nc6.ondigitalocean.app` |
| `SHIPSAFE_DB_PATH` | SQLite database path (API) | `~/.shipsafe/shipsafe.db` |

## MCP Tools

ShipSafe exposes 7 tools through the [Model Context Protocol](https://modelcontextprotocol.io) for AI coding assistants:

| Tool | Description |
|------|-------------|
| `shipsafe_scan` | Run a security scan on a project directory |
| `shipsafe_status` | Get project security status, hook state, and scanner availability |
| `shipsafe_check_package` | Vet an npm package before installing (typosquatting, CVEs, maintenance) |
| `shipsafe_fix` | Apply auto-fix for a finding (moves secrets to .env, suggests code fixes) |
| `shipsafe_graph_query` | Query the knowledge graph for callers, callees, attack paths, blast radius |
| `shipsafe_production_errors` | Fetch production errors with stack traces and suggested fixes |
| `shipsafe_verify_resolution` | Check if a production error has been resolved |

The MCP server is registered automatically during `shipsafe init` or `shipsafe setup`. To configure it manually:

```json
{
  "mcpServers": {
    "shipsafe": {
      "command": "npx",
      "args": ["-y", "shipsafe", "mcp-server"]
    }
  }
}
```

## Pricing

| | Free | Pro ($19/mo) | Team ($49/mo) |
|--|------|-------------|---------------|
| Vulnerability + secret scanning | Yes | Yes | Yes |
| Git hooks (pre-commit, pre-push) | Yes | Yes | Yes |
| Projects | 1 | 5 | 20 |
| Knowledge graph engine | -- | Yes | Yes |
| Auto-fix (secrets to .env) | -- | Yes | Yes |
| Production error monitoring | -- | Yes | Yes |
| MCP server tools | -- | Yes | Yes |
| GitHub App (PR checks) | -- | -- | Yes |
| Source map resolution | -- | -- | Yes |

```bash
shipsafe activate SS-PRO-yourkeyhere
```

## Development

Requires Node.js >= 20.

```bash
# Install dependencies
npm install

# Build
npm run build

# Run CLI locally (without building)
npm run dev -- scan
npm run dev -- init
npm run dev -- setup

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Type-check without emitting
npm run lint

# Run cloud API locally
cd packages/api && npm run dev
```

### Architecture

```
bin/shipsafe.ts          CLI entry point (Commander.js)
src/
  engines/
    builtin/             Pure TS pattern + secret + dependency scanners
    pattern/             Scanner orchestration (Semgrep, Gitleaks, Trivy wrappers)
    graph/               Tree-sitter + KuzuDB knowledge graph
  cli/                   CLI commands (scan, init, activate, config, baseline, etc.)
  mcp/                   MCP server + 7 tools (stdio transport)
  autofix/               Auto-fix engine (secret fixer, scaffolding, PR generation)
  github/                GitHub App (webhooks, PR scanner, checks API)
  hooks/                 Git hook installer (pre-commit, pre-push)
  config/                Global + project config manager
  claude-md/             CLAUDE.md / .cursorrules injection manager
packages/
  api/                   Hono cloud API with SQLite persistence
  monitor/               @shipsafe/monitor client error capture snippet
```

### Conventions

- TypeScript strict mode, ESM modules
- Vitest for testing
- No classes -- plain functions and types
- Errors are thrown as typed errors, never swallowed silently

## License

UNLICENSED -- proprietary software by ShipSafe.

`@shipsafe/monitor` is MIT licensed.

---

[shipsafe.org](https://shipsafe.org)
