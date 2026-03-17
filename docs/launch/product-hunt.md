# Product Hunt Launch Copy

## Tagline (60 chars max)
Security scanning for developers who ship fast

## Description
ShipSafe is a one-command security scanner that wraps Semgrep, Gitleaks, and Trivy into a single CLI. But it goes beyond pattern matching — a knowledge graph engine builds your codebase's call graph to find attack paths, missing auth, and tainted data flows.

Key features:
- `shipsafe scan` — one command, zero config
- Knowledge graph engine finds what pattern matching can't
- `--fix` flag auto-moves hardcoded secrets to .env
- MCP server with 7 tools for Claude, Cursor, and other AI assistants
- Production monitoring with automatic PII scrubbing
- Git hooks block secrets before they reach your repo

Your source code never leaves your machine. Free forever for solo projects.

## Maker Comment
I built ShipSafe because I was tired of AI-generated code shipping with hardcoded secrets and missing auth checks. Pattern matching catches the obvious stuff, but the knowledge graph finds the things you'd only catch in a manual code review — attack paths through your call chain, unvalidated user input flowing to databases, endpoints with no auth middleware.

The MCP server is the part I'm most excited about. Your AI assistant can check security while it writes code, not after. It's like having a security engineer pair-programming with you.

Free tier is free forever. Built in San Juan, PR.

## Topics
- Developer Tools
- Security
- Open Source
- CLI
- Artificial Intelligence

## Gallery images needed
1. Terminal showing `shipsafe scan` output (score A)
2. Hero section of shipsafe.org
3. Feature grid showing 6 capabilities
4. MCP server integration with Claude
5. Pricing comparison (Free vs Pro vs Team)
