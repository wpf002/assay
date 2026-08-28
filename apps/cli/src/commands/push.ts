import { basename, resolve } from 'node:path';
import { analyzeReachability, assemble } from '@assay/correlate';
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { scanCertificates } from '@assay/detect-pki';
import { importInventory, kmsFindings } from '@assay/detect-kms';
import { loadPack } from '@assay/policy';
import type { Finding } from '@assay/core';

/**
 * Scan and ship the evidence to the API.
 *
 * Only evidence crosses the wire - no ranking. The server ranks on read, under
 * whichever policy pack is being asked about, so a re-rank under a new deadline
 * is a query rather than a re-scan.
 */
export interface PushOptions {
  readonly api: string;
  readonly policy: string;
  readonly system?: string;
  readonly includeDev?: boolean;
  readonly keyInventory?: string;
  readonly now?: string;
}

export async function runPush(path: string, options: PushOptions): Promise<void> {
  const root = resolve(path);
  const systemName = options.system ?? basename(root);
  const pack = loadPack(options.policy);
  const now = options.now ? new Date(options.now) : new Date();
  const collectedAt = now.toISOString();

  const [source, deps, pki] = await Promise.all([
    scanSource({ root, systemId: systemName, collectedAt }),
    scanDependencies({ root, systemId: systemName, collectedAt, includeDev: options.includeDev === true }),
    scanCertificates({ root, systemId: systemName, collectedAt }),
  ]);

  const findings: Finding[] = [...source.findings, ...deps.findings, ...pki.findings];
  if (options.keyInventory !== undefined) {
    const inventory = await importInventory(options.keyInventory);
    findings.push(...kmsFindings(inventory, { systemId: systemName, collectedAt }).findings);
  }

  const assembled = assemble(findings);
  const reach = analyzeReachability(assembled.occurrences, source.graph);

  const body = {
    systemName,
    detectors: ['detect-source', 'detect-deps', 'detect-pki', ...(options.keyInventory ? ['detect-kms'] : [])],
    policyPackId: pack.packId,
    policyPackVersion: pack.packVersion,
    scopeGrantId: null,
    startedAt: collectedAt,
    finishedAt: new Date().toISOString(),
    occurrences: reach.occurrences,
    assets: assembled.assets,
  };

  const res = await fetch(`${options.api.replace(/\/$/, '')}/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`push failed: ${res.status} ${await res.text()}`);
  }
  const summary = (await res.json()) as { id: string; occurrenceCount: number };
  process.stdout.write(
    `pushed ${summary.occurrenceCount} work item(s) as scan ${summary.id}\n` +
      `  ${options.api}/scans/${summary.id}/worklists\n`,
  );
}
