import { writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { rank, type Finding } from '@assay/core';
import { analyzeReachability, assemble } from '@assay/correlate';
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { scanCertificates } from '@assay/detect-pki';
import {
  attestationFindings,
  loadAttestation,
  migrationEstimate,
  reconcile,
  VendorAttestationSchema,
} from '@assay/attest';
import { decimalYear, loadPack } from '@assay/policy';
import { nowOption } from '../options.js';

/** A blank questionnaire, so the vendor is asked for the right things. */
export async function attestTemplate(options: {
  vendor: string;
  product: string;
  system: string;
  out: string;
}): Promise<void> {
  const now = new Date();
  const oneYear = new Date(now.getTime() + 365 * 86_400_000);
  const template = VendorAttestationSchema.parse({
    schema: 'assay.attestation/v1',
    vendor: options.vendor,
    product: options.product,
    version: 'FILL IN: the exact version this attestation covers',
    systemId: options.system,
    controlClass: 'VENDOR_LOCKED',
    attestedBy: 'FILL IN: name and email of whoever is signing this',
    attestedAt: now.toISOString(),
    validUntil: oneYear.toISOString(),
    claims: [
      {
        primitive: 'RSA',
        parameters: { modulusLength: 2048 },
        purpose: 'KEY_ESTABLISHMENT',
        component: 'FILL IN: where in the product this is used',
        configurable: false,
      },
    ],
    roadmap: {
      // The single most valuable field in the file. A date turns "we are
      // waiting on the vendor" into a slack figure that either clears the
      // deadline or does not.
      status: 'evaluating',
      availableFrom: null,
      algorithms: [],
      requiresHardwareReplacement: false,
      notes: 'FILL IN: if status is committed, availableFrom must be a date. "Evaluating" is not a date and is scored as no commitment.',
    },
    reference: '',
  });
  await writeFile(resolve(options.out), `${JSON.stringify(template, null, 2)}\n`, 'utf8');
  process.stdout.write(
    `wrote ${resolve(options.out)}\n\n` +
      'The roadmap.availableFrom date is the field that changes the ranking.\n' +
      'A vendor answering "evaluating" is declining to give one, and is scored as such.\n',
  );
}

export interface ReconcileOptions {
  readonly policy: string;
  readonly system?: string;
  readonly json?: boolean;
  readonly now?: string;
}

export async function attestReconcile(
  attestationPath: string,
  path: string,
  options: ReconcileOptions,
): Promise<void> {
  const attestation = await loadAttestation(attestationPath);
  const root = resolve(path);
  const systemId = options.system ?? attestation.systemId ?? basename(root);
  const now = nowOption(options.now);
  const collectedAt = now.toISOString();
  const pack = loadPack(options.policy);

  const [source, deps, pki] = await Promise.all([
    scanSource({ root, systemId, collectedAt }),
    scanDependencies({ root, systemId, collectedAt }),
    scanCertificates({ root, systemId, collectedAt }),
  ]);
  const attested = attestationFindings(attestation, { collectedAt, now });

  const findings: Finding[] = [
    ...source.findings,
    ...deps.findings,
    ...pki.findings,
    ...attested.findings,
  ];
  const assembled = assemble(findings);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  const estimate = migrationEstimate(attestation, decimalYear(now));

  const worklists = rank(reach.occurrences, assembled.assets, {
    policy: pack,
    currentYear: decimalYear(now),
    secrecyLifetime: () => ({ years: 5, assumed: true }),
    // The vendor's own date, where they gave one, in place of the class average.
    migrationYears: (o) =>
      o.systemId === attestation.systemId
        ? { years: estimate.years, label: estimate.label, kind: estimate.kind }
        : undefined,
  });

  const results = reconcile(attestation, reach.occurrences, assembled.assets);

  if (options.json === true) {
    process.stdout.write(`${JSON.stringify({ estimate, results, worklists }, null, 2)}\n`);
    return;
  }

  const line = (s = ''): void => {
    process.stdout.write(`${s}\n`);
  };

  line();
  line(`assay attest  ${attestation.vendor} / ${attestation.product} ${attestation.version}`);
  line(`  attested by ${attestation.attestedBy} on ${attestation.attestedAt.slice(0, 10)}`);
  line(
    `  valid until ${attestation.validUntil.slice(0, 10)}${attested.expired ? '  EXPIRED - this describes a product several releases ago' : ''}`,
  );
  line();
  line(`  migration estimate  Y = ${estimate.years}y as ${estimate.controlClass}`);
  line(`    ${estimate.label}`);
  line();

  const groups: [string, string][] = [
    ['UNDISCLOSED', 'observed in the product and absent from the attestation'],
    ['CONTRADICTED_ROADMAP', 'the roadmap claims post-quantum support that the wire does not show'],
    ['CORROBORATED', 'claimed and independently observed'],
    ['UNVERIFIED', 'claimed and not observed by this scan'],
  ];
  for (const [verdict, description] of groups) {
    const rows = results.filter((r) => r.verdict === verdict);
    if (rows.length === 0) continue;
    line(`${verdict}  (${rows.length}) - ${description}`);
    for (const r of rows.slice(0, 15)) {
      line(
        `  ${r.asset.primitive.padEnd(10)} ${r.asset.purpose.padEnd(18)} ` +
          `${r.observedModalities.join(',') || '-'}`,
      );
    }
    line();
  }

  line(
    `worklists: ${worklists.confidentiality.length} confidentiality, ` +
      `${worklists.authenticity.length} authenticity, ranked with the vendor's own date`,
  );
  line();
}
