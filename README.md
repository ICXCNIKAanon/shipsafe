# ShipSafe

Full-lifecycle security and reliability platform for vibe coders. Scan for vulnerabilities, auto-fix secrets, monitor production errors, and get AI-powered security insights — all from your terminal or IDE.

## Features

- **Security scanning** — wraps Semgrep, Gitleaks, and Trivy into a single `shipsafe scan` command
- **Knowledge graph engine** — builds a call graph with Tree-sitter + KuzuDB to find attack paths, missing auth, and tainted data flows
- **Auto-fix** — moves hardcoded secrets to `.env` files automatically with `--fix`
- **MCP server** — 7 tools for Claude, Cursor, and other AI coding assistants
- **Production monitoring** — lightweight `@shipsafe/monitor` snippet captures errors and performance data
- **Git hooks** — pre-commit scanning to catch issues before they land
- **GitHub App** — PR checks and automated security reviews
- **License tiers** — FREE (scan), PRO (+ autofix, graph, monitoring, MCP), TEAM/AGENCY (+ sourcemaps, GitHub App)

## Install

```bash
npm install -g shipsafe
```

## Quick start

```bash
# Initialize ShipSafe in your project
shipsafe init

# Scan for vulnerabilities (staged files by default)
shipsafe scan

# Scan all files
shipsafe scan --scope all

# Auto-fix hardcoded secrets
shipsafe scan --fix

# Activate a license
shipsafe activate SS-PRO-yourkeyhere

# Start the MCP server (for AI assistants)
shipsafe mcp-server
```

## Configuration

ShipSafe uses two config files merged together (project overrides global):

- **Global**: `~/.shipsafe/config.json`
- **Project**: `shipsafe.config.json`

```bash
# View current config
shipsafe config list

# Set a value
shipsafe config set apiEndpoint https://api.shipsafe.org
shipsafe config set scan.severity_threshold medium

# Set globally
shipsafe config set licenseKey SS-PRO-abc123 --global
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHIPSAFE_API_URL` | API endpoint override | `http://localhost:3747` |
| `SHIPSAFE_DB_PATH` | SQLite database path (API) | `~/.shipsafe/shipsafe.db` |

## MCP Server

ShipSafe exposes an MCP server with 7 tools for AI coding assistants:

- `scan` — run security scan
- `status` — project security status
- `check_package` — check npm packages for vulnerabilities
- `production_errors` — fetch production errors
- `verify_resolution` — verify if an error is resolved
- `blast_radius` — analyze impact of changing a function
- `explain_finding` — get detailed explanation of a finding

Add to your Claude/Cursor MCP config:

```json
{
  "mcpServers": {
    "shipsafe": {
      "command": "shipsafe",
      "args": ["mcp-server"]
    }
  }
}
```

## Monitor snippet

Capture production errors with `@shipsafe/monitor`:

```bash
npm install @shipsafe/monitor
```

```typescript
import { init } from '@shipsafe/monitor';

const monitor = init({
  projectId: 'your-project-id',
  endpoint: 'https://api.shipsafe.org/v1/events', // optional
});
```

Features: automatic error capture, PII scrubbing, sampling, batching with retries, auto-disable on repeated failures.

## Cloud API

The ShipSafe API handles monitoring ingest, error processing, source map resolution, and license validation.

```bash
cd packages/api

# Development
npm run dev

# Production (Docker)
docker compose up -d
```

Runs on port 3747 by default.

## Architecture

```
bin/shipsafe.ts          CLI entry point (Commander.js)
src/
  engines/
    pattern/             Semgrep, Gitleaks, Trivy wrappers
    graph/               Tree-sitter + KuzuDB knowledge graph
  cli/                   CLI commands (scan, init, activate, config, etc.)
  mcp/                   MCP server + tools
  autofix/               Auto-fix engine (secrets, scaffolding, PR generation)
  github/                GitHub App (webhooks, PR scanner, checks)
  hooks/                 Git hook installer
  config/                Config manager
packages/
  api/                   Hono cloud API with SQLite
  monitor/               @shipsafe/monitor client snippet
```

## Development

```bash
# Run tests
npm test

# Build
npm run build

# Run CLI locally
npm run dev -- scan
npm run dev -- init
```

## License

UNLICENSED — proprietary software by Connect Holdings LLC.

`@shipsafe/monitor` is MIT licensed.
