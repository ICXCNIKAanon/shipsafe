import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { handleScan } from './tools/scan.js';
import { handleStatus } from './tools/status.js';
import { handleGraphQuery } from './tools/graph-query.js';
import { handleProductionErrors } from './tools/production-errors.js';
import { handleFix } from './tools/fix.js';
import { handleVerifyResolution } from './tools/verify-resolution.js';
import { handleCheckPackage } from './tools/check-package.js';
import { handleEnvironmentScan } from './tools/environment-scan.js';

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: 'shipsafe',
    version: '0.1.0',
  });

  // Register shipsafe_scan tool
  server.tool(
    'shipsafe_scan',
    'Run security scan on a project directory. Checks for vulnerabilities, hardcoded secrets, and dependency CVEs. IMPORTANT: Always pass the project path.',
    {
      path: z.string().optional().describe('Absolute path to the project directory to scan (e.g. /Users/jake/my-project). Defaults to cwd.'),
      scope: z.string().optional().describe('Scan scope: all (default), staged, or file:<path>'),
      fix: z.boolean().optional().describe('Attempt auto-fix (default: false)'),
    },
    async (params) => {
      const result = await handleScan(params);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Register shipsafe_status tool
  server.tool(
    'shipsafe_status',
    'Get current project security status, hook state, and scanner availability.',
    async () => {
      const result = await handleStatus();
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Register shipsafe_graph_query tool
  server.tool(
    'shipsafe_graph_query',
    'Query the project knowledge graph for callers, callees, attack paths, blast radius, or missing auth chains.',
    {
      query_type: z.enum(['callers', 'callees', 'data_flow', 'attack_paths', 'blast_radius', 'auth_chain'])
        .describe('Type of graph query to run'),
      target: z.string().optional()
        .describe('Target function name (required for callers, callees, data_flow, blast_radius)'),
      depth: z.number().optional()
        .describe('Max traversal depth (default: 3 for callers/callees, 5 for data_flow)'),
    },
    async (params) => {
      const result = await handleGraphQuery({
        query_type: params.query_type,
        target: params.target,
        depth: params.depth,
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Register shipsafe_production_errors tool
  server.tool(
    'shipsafe_production_errors',
    'Fetch queued production errors for this project. Returns errors with stack traces, root causes, and suggested fixes.',
    {
      severity: z.enum(['all', 'critical', 'high', 'medium', 'low']).optional()
        .describe('Filter by severity (default: all)'),
      status: z.enum(['open', 'resolved', 'all']).optional()
        .describe('Filter by status (default: open)'),
    },
    async (params) => {
      const result = await handleProductionErrors({
        severity: params.severity,
        status: params.status,
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Register shipsafe_fix tool
  server.tool(
    'shipsafe_fix',
    'Apply a fix for a scan finding. For hardcoded secrets, moves them to .env automatically. For other findings, returns the suggestion.',
    {
      finding_id: z.string().describe('The ID of the finding to fix (from shipsafe_scan results)'),
      strategy: z.enum(['suggested', 'custom']).optional()
        .describe('Fix strategy: suggested (default) or custom'),
    },
    async (params) => {
      const result = await handleFix({
        finding_id: params.finding_id,
        strategy: params.strategy,
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Register shipsafe_verify_resolution tool
  server.tool(
    'shipsafe_verify_resolution',
    'Check if a production error has been resolved or is still recurring.',
    {
      error_id: z.string().describe('The ID of the production error to check'),
    },
    async (params) => {
      const result = await handleVerifyResolution({
        error_id: params.error_id,
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Register shipsafe_check_package tool
  server.tool(
    'shipsafe_check_package',
    'Vet an npm package before installing. Checks for typosquatting, maintenance status, license compatibility, and known vulnerabilities.',
    {
      name: z.string().describe('Package name to check'),
      version: z.string().optional().describe('Specific version to check (default: latest)'),
      registry: z.enum(['npm', 'pip', 'cargo']).optional()
        .describe('Package registry (default: npm, only npm currently supported)'),
    },
    async (params) => {
      const result = await handleCheckPackage({
        name: params.name,
        version: params.version,
        registry: params.registry,
      });
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Register shipsafe_scan_environment tool
  server.tool(
    'shipsafe_scan_environment',
    'Scan Claude Code environment for malicious MCP servers, hooks, skills, and prompt injection in CLAUDE.md files.',
    {},
    async () => {
      const result = await handleEnvironmentScan();
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
