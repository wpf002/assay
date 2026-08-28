import { writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import {
  rank,
  toCycloneDX,
  type CryptoAsset,
  type ExportProfile,
  type Finding,
  type Occurrence,
  type RankedFinding,
  type Worklists,
} from '@assay/core';
import { assemble } from '@assay/correlate';
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { decimalYear, loadPack } from '@assay/policy';

export interface ScanOptions {
  readonly policy: string;
  readonly out: string;
  readonly profile: string;
  readonly system?: string;
  readonly secrecyYears: string;
  readonly includeDev?: boolean;
  readonly includeSuspected?: boolean;
  readonly json?: boolean;
  readonly now?: string;
}

export async function runScan(path: string, options: ScanOptions): Promise<void> {
  const root = resolve(path);
  const systemId = options.system ?? basename(root);
  const pack = loadPack(options.policy);
  const now = options.now ? new Date(options.now) : new Date();
  const collectedAt = now.toISOString();

  const [source, deps] = await Promise.all([
    scanSource({ root, systemId, collectedAt }),
    scanDependencies({ root, systemId, collectedAt, includeDev: options.includeDev === true }),
  ]);

  const findings: Finding[] = [...source.findings, ...deps.findings];
  const { occurrences, assets } = assemble(findings);

  const secrecyYears = Number(options.secrecyYears);
  const worklists = rank(occurrences, assets, {
    policy: pack,
    currentYear: decimalYear(now),
    // Operator-supplied and unverified until a data-classification source says
    // otherwise, so it enters the ranking derivation as an ASSUMPTION. It taints
    // the ranking tree, not the confidence tree - see I6.
    secrecyLifetime: () => ({ years: secrecyYears, assumed: true }),
  });

  const cbom = toCycloneDX(occurrences, assets, {
    profile: options.profile as ExportProfile,
    policyPackId: pack.packId,
    policyPackVersion: pack.packVersion,
    timestamp: collectedAt,
    toolVersion: '0.1.0',
    includeFactorTrees: true,
    includeSuspected: options.includeSuspected === true,
  });
  await writeFile(resolve(options.out), `${JSON.stringify(cbom, null, 2)}\n`, 'utf8');

  if (options.json === true) {
    process.stdout.write(`${JSON.stringify({ worklists, cbomPath: options.out }, null, 2)}\n`);
    return;
  }

  report({
    root,
    systemId,
    pack: `${pack.packId}@${pack.packVersion}`,
    filesScanned: source.filesScanned,
    manifests: deps.manifests.length,
    uncatalogued: deps.uncatalogued,
    occurrences,
    assets,
    worklists,
    out: options.out,
  });
}

interface ReportInput {
  readonly root: string;
  readonly systemId: string;
  readonly pack: string;
  readonly filesScanned: number;
  readonly manifests: number;
  readonly uncatalogued: readonly string[];
  readonly occurrences: readonly Occurrence[];
  readonly assets: readonly CryptoAsset[];
  readonly worklists: Worklists;
  readonly out: string;
}

function report(r: ReportInput): void {
  const w = r.worklists;
  const line = (s = ''): void => {
    process.stdout.write(`${s}\n`);
  };

  line();
  line(`assay  ${r.systemId}`);
  line(
    `  ${r.filesScanned} file(s), ${r.manifests} manifest(s) -> ` +
      `${r.assets.length} asset(s), ${r.occurrences.length} occurrence(s)`,
  );
  line(`  policy ${r.pack}`);
  line();

  // Two worklists. Never one. The EO splits its own deadlines the same way.
  track('CONFIDENTIALITY  (harvest-now-decrypt-later applies)', w.confidentiality, line);
  track('AUTHENTICITY     (forgery risk begins at the deadline)', w.authenticity, line);

  const h = w.headline;
  line(
    `headline  ${(h.value * 100).toFixed(0)}%  ${h.numerator}/${h.denominator} ` +
      `confirmed reachable quantum-vulnerable work item(s) already past the binding deadline`,
  );
  if (w.unreached.length > 0) {
    line(`unreached ${w.unreached.length} finding(s) reported separately - presence is not exposure`);
  }
  if (w.hints.length > 0) {
    line(
      `hints     ${w.hints.length} SUSPECTED finding(s) held out of the worklists - ` +
        'dependency evidence directs scanning, it does not confirm use',
    );
  }
  if (w.unanalyzed.length > 0) {
    line(`unanalyzed ${w.unanalyzed.length} finding(s) - reachability analysis is Phase 3`);
  }
  if (r.uncatalogued.length > 0) {
    line(
      `coverage  ${r.uncatalogued.length} crypto-looking dependenc(ies) not in the catalog: ` +
        `${r.uncatalogued.slice(0, 5).join(', ')}${r.uncatalogued.length > 5 ? ', ...' : ''}`,
    );
  }
  line();
  line(`cbom      ${r.out}`);
  line();
}

/** Two assets can share a name and differ only by purpose. Show the purpose. */
const PURPOSE_LABEL: Readonly<Record<RankedFinding['purpose'], string>> = {
  KEY_ESTABLISHMENT: 'kex',
  DATA_ENCRYPTION: 'encrypt',
  DIGITAL_SIGNATURE: 'sign',
  CERTIFICATE_AUTH: 'cert',
  INTEGRITY: 'integrity',
  KEY_DERIVATION: 'kdf',
  RANDOMNESS: 'random',
};

function track(title: string, findings: readonly RankedFinding[], line: (s?: string) => void): void {
  line(title);
  if (findings.length === 0) {
    line('  (nothing)');
    line();
    return;
  }
  for (const f of findings.slice(0, 20)) {
    const slack = f.slackYears >= 0 ? `+${f.slackYears.toFixed(1)}y` : `${f.slackYears.toFixed(1)}y`;
    line(
      `  ${(f.late ? 'LATE' : '    ').padEnd(5)}${slack.padStart(7)}  ` +
        `${f.assertionLevel.padEnd(9)} ${f.controlClass.padEnd(19)} ` +
        `${PURPOSE_LABEL[f.purpose].padEnd(9)} ${f.assetName.padEnd(38)} ` +
        `${f.bindingConstraint.toLowerCase()}`,
    );
  }
  if (findings.length > 20) line(`  ... ${findings.length - 20} more`);
  line();
}
