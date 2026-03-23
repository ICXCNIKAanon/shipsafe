#!/usr/bin/env node
import { Command } from 'commander';
import { VERSION } from '../src/constants.js';
import { registerScanCommand } from '../src/cli/scan.js';
import { registerStatusCommand } from '../src/cli/status.js';
import { registerActivateCommand } from '../src/cli/activate.js';
import { registerSetupCommand } from '../src/cli/setup.js';
import { registerConnectCommand } from '../src/cli/connect.js';
import { registerUploadSourcemapsCommand } from '../src/cli/upload-sourcemaps.js';
import { registerConfigCommand } from '../src/cli/config.js';
import { registerInitCommand } from '../src/cli/init.js';
import { registerBaselineCommand } from '../src/cli/baseline.js';
import { registerScanEnvironmentCommand } from '../src/cli/scan-environment.js';
import { registerAuditCommand } from '../src/cli/audit.js';
import { checkForUpdate } from '../src/cli/update-check.js';

checkForUpdate();

const program = new Command();
program
  .name('shipsafe')
  .description('Full-lifecycle security and reliability for vibe coders')
  .version(VERSION);

registerScanCommand(program);
registerStatusCommand(program);
registerActivateCommand(program);
registerSetupCommand(program);
registerConnectCommand(program);
registerUploadSourcemapsCommand(program);
registerConfigCommand(program);
registerInitCommand(program);
registerBaselineCommand(program);
registerScanEnvironmentCommand(program);
registerAuditCommand(program);

program
  .command('mcp-server')
  .description('Start ShipSafe MCP server (stdio transport)')
  .action(async () => {
    const { startMcpServer } = await import('../src/mcp/server.js');
    await startMcpServer();
  });

program.parse();
