#!/usr/bin/env node
import { Command } from 'commander';
import { DEFAULT_PACK_ID, listPacks, loadPack } from '@assay/policy';
import { runScan } from './commands/scan.js';
import { runProbe } from './commands/probe.js';
import { keygen, sign, verify } from './commands/scope.js';

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
  .option('--key-inventory <file>', 'normalized cloud KMS / HSM key export to fold in')
  .option('--json', 'emit machine-readable worklists on stdout')
  .option('--now <iso>', 'override the current time, for reproducible runs')
  .action(async (path: string, options) => {
    await runScan(path, options);
  });

program
  .command('probe <targets...>')
  .description('active TLS/SSH capability enumeration (REQUIRES a signed scope grant)')
  .requiredOption('--grant <file>', 'signed scope grant')
  .option('--pubkey <file>', 'grant verification key (or ASSAY_SCOPE_PUBKEY_FILE)')
  .option('--policy <pack>', 'policy pack id', DEFAULT_PACK_ID)
  .option('--out <file>', 'CBOM output path', 'cbom.json')
  .option('--profile <profile>', 'cyclonedx-1.7 | cyclonedx-1.6 | cisa-min-elements', 'cyclonedx-1.7')
  .option('--system <id>', 'system identifier', 'probed-estate')
  .option('--secrecy-years <n>', 'years the data must stay confidential (X in Mosca)', '5')
  .option('--timeout-ms <n>', 'per-handshake timeout', '5000')
  .option('--clock-skew-seconds <n>', 'tolerance for issuer clock skew, capped at 300')
  .option('--json', 'emit machine-readable output on stdout')
  .option('--now <iso>', 'override the current time, for reproducible runs')
  .action(async (targets: string[], options) => {
    await runProbe(targets, options);
  });

const scope = program
  .command('scope')
  .description('signed authorization for anything that touches a host you did not build');

scope
  .command('keygen')
  .description('generate an Ed25519 grant signing keypair')
  .option('--out-dir <dir>', 'where to write the keys', '.')
  .action(async (options: { outDir: string }) => {
    await keygen(options.outDir);
  });

scope
  .command('sign')
  .description('issue a signed scope grant')
  .requiredOption('--key <file>', 'grant signing private key')
  .requiredOption('--issued-by <who>', 'who is authorizing this')
  .requiredOption('--targets <list>', 'comma-separated CIDRs, hostnames or *.glob patterns')
  .requiredOption('--not-after <iso>', 'when authorization ends')
  .option('--ports <list>', 'comma-separated ports; omit for any port')
  .option('--not-before <iso>', 'when authorization begins (default: now)')
  .option('--purpose <text>', 'recorded in the scan, e.g. a ticket reference')
  .option('--grant-id <id>', 'identifier for this grant')
  .option('--out <file>', 'output path', 'grant.json')
  .action(async (options) => {
    await sign(options);
  });

scope
  .command('verify <grant>')
  .description('check a grant signature against a public key')
  .requiredOption('--pubkey <file>', 'grant verification key')
  .action(async (grant: string, options: { pubkey: string }) => {
    await verify(grant, options.pubkey);
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
