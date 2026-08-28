#!/usr/bin/env node
import { Command } from 'commander';
import { DEFAULT_PACK_ID, listPacks, loadPack } from '@assay/policy';
import { runScan } from './commands/scan.js';

const program = new Command('assay').description(
  'Cryptographic bill of materials - discovery, inventory, migration ranking',
);

program
  .command('scan <path>')
  .description('scan a repo: source AST + config + dependency manifests')
  .option('--policy <pack>', 'policy pack id', DEFAULT_PACK_ID)
  .option('--out <file>', 'CBOM output path', 'cbom.json')
  .option('--profile <profile>', 'cyclonedx-1.7 | cyclonedx-1.6 | cisa-min-elements', 'cyclonedx-1.7')
  .option('--system <id>', 'system identifier (defaults to the directory name)')
  .option('--secrecy-years <n>', 'years the data must stay confidential (X in Mosca)', '5')
  .option('--include-dev', 'include devDependencies - off by default, dev tooling is not the estate')
  .option('--include-suspected', 'export SUSPECTED findings as well')
  .option('--json', 'emit machine-readable worklists on stdout')
  .option('--now <iso>', 'override the current time, for reproducible runs')
  .action(async (path: string, options) => {
    await runScan(path, options);
  });

program
  .command('probe <target>')
  .description('active TLS/SSH capability enumeration (REQUIRES signed scope grant)')
  .requiredOption('--grant <file>', 'signed scope grant')
  .action(() => {
    throw new Error('not implemented - Phase 2');
  });

const policy = program.command('policy').description('inspect deadline policy packs');

policy
  .command('list')
  .description('list available policy packs')
  .action(() => {
    for (const id of listPacks()) {
      const p = loadPack(id);
      process.stdout.write(
        `${id}@${p.packVersion}  crqc=${p.crqcYear}  ` +
          `deadline(conf)=${p.regulatoryDeadlines.CONFIDENTIALITY ?? 'none'}  ` +
          `deadline(auth)=${p.regulatoryDeadlines.AUTHENTICITY ?? 'none'}\n`,
      );
    }
  });

policy
  .command('show <pack>')
  .description('print a policy pack, including its caveats')
  .action((pack: string) => {
    process.stdout.write(`${JSON.stringify(loadPack(pack), null, 2)}\n`);
  });

program.parseAsync().catch((e: unknown) => {
  process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
  process.exitCode = 1;
});
