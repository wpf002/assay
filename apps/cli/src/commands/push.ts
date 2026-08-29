import { basename, resolve } from 'node:path';
import { analyzeReachability, applyTraceReachability, assemble } from '@assay/correlate';
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { scanCertificates } from '@assay/detect-pki';
import { importInventory, kmsFindings } from '@assay/detect-kms';
import { scanBinaries } from '@assay/detect-binary';
import { loadPack } from '@assay/policy';
import { loadTraces } from './traces.js';
import { nowOption } from '../options.js';
import { requestHeaders } from '../http.js';
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
  /** API token. The API has no anonymous access; there is no way to disable that. */
  readonly token?: string;
  readonly policy: string;
  readonly system?: string;
  readonly includeDev?: boolean;
  readonly keyInventory?: string;
  /** Binary analysis is on by default; vendor blobs are where the surprises live. */
  readonly binaries?: boolean;
  /** OTLP export or normalized bundle. Reaches across the network edge. */
  readonly traces?: string;
  readonly now?: string;
}

export async function runPush(path: string, options: PushOptions): Promise<void> {
  // Before the scan, not after it. A monorepo scan is minutes of work, and
  // discovering the missing token only once there is something to send threw
  // all of it away - reliably, on the first run anyone ever does.
  const headers = requestHeaders(options.api, options.token);
  const root = resolve(path);
  const systemName = options.system ?? basename(root);
  const pack = loadPack(options.policy);
  const now = nowOption(options.now);
  const collectedAt = now.toISOString();

  const [source, deps, pki, binary] = await Promise.all([
    scanSource({ root, systemId: systemName, collectedAt }),
    scanDependencies({ root, systemId: systemName, collectedAt, includeDev: options.includeDev === true }),
    scanCertificates({ root, systemId: systemName, collectedAt }),
    options.binaries === false
      ? Promise.resolve({ findings: [], reports: [], filesScanned: 0 })
      : scanBinaries({ root, systemId: systemName, collectedAt }),
  ]);

  const findings: Finding[] = [
    ...source.findings,
    ...deps.findings,
    ...pki.findings,
    ...binary.findings,
  ];
  if (options.keyInventory !== undefined) {
    const inventory = await importInventory(options.keyInventory);
    findings.push(...kmsFindings(inventory, { systemId: systemName, collectedAt }).findings);
  }

  const assembled = assemble(findings);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  const traces = options.traces === undefined ? null : await loadTraces(options.traces);
  const occurrences =
    traces === null
      ? reach.occurrences
      : applyTraceReachability(reach.occurrences, {
          rootSystems: [...traces.roots, ...(reach.entryPoints.length > 0 ? [systemName] : [])],
          graph: traces.graph,
        });

  const body = {
    systemName,
    detectors: [
      'detect-source',
      'detect-deps',
      'detect-pki',
      ...(binary.filesScanned > 0 ? ['detect-binary'] : []),
      ...(options.keyInventory ? ['detect-kms'] : []),
    ],
    policyPackId: pack.packId,
    policyPackVersion: pack.packVersion,
    scopeGrantId: null,
    startedAt: collectedAt,
    finishedAt: new Date().toISOString(),
    occurrences,
    assets: assembled.assets,
  };

  const res = await fetch(`${options.api.replace(/\/$/, '')}/scans`, {
    method: 'POST',
    headers,
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
