#!/usr/bin/env node
import { Command } from 'commander';
import { VERSION } from '../src/constants.js';
import { registerScanCommand } from '../src/cli/scan.js';
import { registerStatusCommand } from '../src/cli/status.js';
import { registerActivateCommand } from '../src/cli/activate.js';
import { registerSetupCommand } from '../src/cli/setup.js';

const program = new Command();
program
  .name('shipsafe')
  .description('Full-lifecycle security and reliability for vibe coders')
  .version(VERSION);

registerScanCommand(program);
registerStatusCommand(program);
registerActivateCommand(program);
registerSetupCommand(program);

program
  .command('mcp-server')
  .description('Start ShipSafe MCP server (stdio transport)')
  .action(async () => {
    const { startMcpServer } = await import('../src/mcp/server.js');
    await startMcpServer();
  });

program.parse();
