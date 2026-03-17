import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { handleScan } from './tools/scan.js';
import { handleStatus } from './tools/status.js';

export async function startMcpServer(): Promise<void> {
  const server = new McpServer({
    name: 'shipsafe',
    version: '0.1.0',
  });

  // Register shipsafe_scan tool
  server.tool(
    'shipsafe_scan',
    'Run security scan on the current project. Checks for vulnerabilities, hardcoded secrets, and dependency CVEs.',
    {
      scope: z.string().optional().describe('Scan scope: staged (default), all, or file:<path>'),
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

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
