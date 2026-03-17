#!/usr/bin/env node
import { Command } from 'commander';
import { VERSION } from '../src/constants.js';
import { registerScanCommand } from '../src/cli/scan.js';

const program = new Command();
program
  .name('shipsafe')
  .description('Full-lifecycle security and reliability for vibe coders')
  .version(VERSION);

registerScanCommand(program);
// Other commands will be registered by later tasks

program.parse();
