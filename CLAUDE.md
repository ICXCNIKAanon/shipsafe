# ShipSafe Development

## Project
ShipSafe CLI — security scanning + MCP server for vibe coders.

## Commands
- `npm run dev -- scan` — run scan command locally
- `npm run dev -- setup` — run setup command locally
- `npm test` — run all tests
- `npm run build` — compile TypeScript

## Architecture
- `bin/shipsafe.ts` — CLI entry point
- `src/engines/pattern/` — wraps Semgrep, Gitleaks, Trivy
- `src/mcp/` — MCP server (stdio transport)
- `src/hooks/` — git hook scripts + installer
- `src/claude-md/` — CLAUDE.md injection manager

## Conventions
- TypeScript strict mode
- ESM modules (type: "module")
- Vitest for testing
- No classes — use plain functions and types
- Errors: throw typed errors, never swallow silently
