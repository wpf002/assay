#!/usr/bin/env node
import { Command } from 'commander';
import { DEFAULT_PACK_ID, listPacks, loadPack } from '@assay/policy';

const program = new Command('assay').description(
  'Cryptographic bill of materials - discovery, inventory, migration ranking',
);

program
  .command('scan <path>')
  .description('scan a repo: source AST + dependency manifests')
  .option('--policy <pack>', 'policy pack id', DEFAULT_PACK_ID)
  .option('--out <file>', 'CBOM output path', 'cbom.json')
  .option('--profile <profile>', 'cyclonedx-1.7 | cyclonedx-1.6 | cisa-min-elements', 'cyclonedx-1.7')
  .action(() => {
    throw new Error('not implemented - Phase 1');
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
      const kex = p.regulatoryDeadlines.CONFIDENTIALITY;
      const sig = p.regulatoryDeadlines.AUTHENTICITY;
      process.stdout.write(
        `${id}@${p.packVersion}  crqc=${p.crqcYear}  ` +
          `deadline(conf)=${kex ?? 'none'}  deadline(auth)=${sig ?? 'none'}\n`,
      );
    }
  });

policy
  .command('show <pack>')
  .description('print a policy pack, including its caveats')
  .action((pack: string) => {
    process.stdout.write(`${JSON.stringify(loadPack(pack), null, 2)}\n`);
  });

program.parse();
