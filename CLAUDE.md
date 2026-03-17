# ShipSafe Development

## Project
ShipSafe — full-lifecycle security + monitoring platform for vibe coders.

## Commands
- `npm run dev -- scan` — run scan command locally
- `npm run dev -- setup` — run setup command locally
- `npm run dev -- upload-sourcemaps --dir ./dist --release 1.0.0` — upload source maps
- `npm test` — run all tests (main + packages)
- `npm run build` — compile TypeScript
- `cd packages/api && npm run dev` — run cloud API locally
- `cd packages/api && npm test` — run API tests only

## Architecture
- `bin/shipsafe.ts` — CLI entry point (Commander.js)
- `src/engines/pattern/` — wraps Semgrep, Gitleaks, Trivy
- `src/engines/graph/` — tree-sitter parsing + KuzuDB knowledge graph
- `src/mcp/` — MCP server (stdio transport, 7 tools)
- `src/hooks/` — git hook scripts + installer
- `src/claude-md/` — CLAUDE.md injection manager
- `src/autofix/` — auto-fix PR generator, secret fixer, scaffolding
- `src/github/` — GitHub App webhook handler, PR scanner, checks
- `src/config/` — global + project config manager
- `packages/api/` — Hono cloud API with SQLite persistence
- `packages/monitor/` — @shipsafe/monitor client error capture snippet

## Conventions
- TypeScript strict mode
- ESM modules (type: "module")
- Vitest for testing
- No classes — use plain functions and types
- Errors: throw typed errors, never swallow silently
