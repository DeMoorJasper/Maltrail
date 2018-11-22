#!/usr/bin/env node

const commander = require('commander');
const process = require('process');

const package = require('../package.json');
const compare = require('./index');

commander.version(package.version);

commander
  .command('compare [input...]')
  .description('compare csv output files of maltrail.')
  .option('-o, --output <output>', 'Output file location')
  .option('-c, --config <config>', 'Config file location')
  .action(start);

commander.parse(process.argv);

async function start(inputs, command) {
  await compare(inputs, command);
}
