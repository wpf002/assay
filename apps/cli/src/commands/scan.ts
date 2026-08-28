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
import { analyzeReachability, assemble } from '@assay/correlate';
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { scanCertificates } from '@assay/detect-pki';
import { importInventory, kmsFindings } from '@assay/detect-kms';
import { scanBinaries } from '@assay/detect-binary';
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
  /** Normalized key-store inventory exported by the customer. See @assay/detect-kms. */
  readonly keyInventory?: string;
  /** Binary analysis is on by default; vendor blobs are where the surprises live. */
  readonly binaries?: boolean;
}

export async function runScan(path: string, options: ScanOptions): Promise<void> {
  const root = resolve(path);
  const systemId = options.system ?? basename(root);
  const pack = loadPack(options.policy);
  const now = options.now ? new Date(options.now) : new Date();
  const collectedAt = now.toISOString();

  const [source, deps, pki, binary] = await Promise.all([
    scanSource({ root, systemId, collectedAt }),
    scanDependencies({ root, systemId, collectedAt, includeDev: options.includeDev === true }),
    scanCertificates({ root, systemId, collectedAt }),
    options.binaries === false
      ? Promise.resolve({ findings: [], reports: [], filesScanned: 0 })
      : scanBinaries({ root, systemId, collectedAt }),
  ]);

  const findings: Finding[] = [
    ...source.findings,
    ...deps.findings,
    ...pki.findings,
    ...binary.findings,
  ];
  let kmsKeys = 0;
  if (options.keyInventory !== undefined) {
    const inventory = await importInventory(options.keyInventory);
    const { findings: kms } = kmsFindings(inventory, { systemId, collectedAt });
    findings.push(...kms);
    kmsKeys = inventory.keys.length;
  }
  const assembled = assemble(findings);
  // Presence is not exposure (I5). Reachability runs before ranking so that
  // unreached findings never reach a worklist in the first place.
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  const occurrences = reach.occurrences;
  const assets = assembled.assets;

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
    certificates: pki.certificates.length,
    binaries: binary.filesScanned,
    kmsKeys,
    uncatalogued: deps.uncatalogued,
    occurrences,
    assets,
    worklists,
    out: options.out,
    entryPoints: reach.entryPoints,
    reachabilityAnalyzed: reach.analyzed,
  });
}

interface ReportInput {
  readonly root: string;
  readonly systemId: string;
  readonly pack: string;
  readonly filesScanned: number;
  readonly manifests: number;
  readonly certificates: number;
  readonly binaries: number;
  readonly kmsKeys: number;
  readonly uncatalogued: readonly string[];
  readonly occurrences: readonly Occurrence[];
  readonly assets: readonly CryptoAsset[];
  readonly worklists: Worklists;
  readonly out: string;
  readonly entryPoints: readonly string[];
  readonly reachabilityAnalyzed: boolean;
}

function report(r: ReportInput): void {
  const w = r.worklists;
  const line = (s = ''): void => {
    process.stdout.write(`${s}\n`);
  };

  line();
  line(`assay  ${r.systemId}`);
  line(
    `  ${r.filesScanned} file(s), ${r.manifests} manifest(s), ` +
      `${r.certificates} certificate(s)` +
      (r.binaries > 0 ? `, ${r.binaries} binar${r.binaries === 1 ? 'y' : 'ies'}` : '') +
      (r.kmsKeys > 0 ? `, ${r.kmsKeys} managed key(s)` : '') +
      ` -> ${r.assets.length} asset(s), ${r.occurrences.length} occurrence(s)`,
  );
  line(`  policy ${r.pack}`);
  line(
    r.reachabilityAnalyzed
      ? `  reachability from ${r.entryPoints.length} entry point(s): ${r.entryPoints.slice(0, 3).join(', ')}${r.entryPoints.length > 3 ? ', ...' : ''}`
      : '  reachability not analyzed: no entry point found (presence is not exposure, so nothing is claimed)',
  );
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
    line(
      `unanalyzed ${w.unanalyzed.length} finding(s) - no call site to trace ` +
        '(certificates, managed keys); "not looked at" is not "not reached"',
    );
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

/**
 * How reachability was concluded. "reached from a request handler" and
 * "published, so somebody's handler might" justify different urgency, and a
 * bare boolean cannot say which one you are looking at.
 */
const VIA_LABEL: Readonly<Record<string, string>> = {
  OBSERVED: 'on the wire',
  ENTRY_POINT: 'from entry point',
  DEPLOYED_CONFIG: 'deployed config',
  LIBRARY_SURFACE: 'published surface',
  UNANALYZED: '',
  NONE: '',
};

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
        `${PURPOSE_LABEL[f.purpose].padEnd(9)} ${f.assetName.padEnd(36)} ` +
        `${f.bindingConstraint.toLowerCase().padEnd(11)} ${VIA_LABEL[f.reachedVia] ?? ''}`,
    );
  }
  if (findings.length > 20) line(`  ... ${findings.length - 20} more`);
  line();
}
