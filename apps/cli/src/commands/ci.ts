import { readFile, writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import {
  BaselineSchema,
  MAX_SUPPRESSION_DAYS,
  evaluateGate,
  makeBaseline,
  rank,
  type Baseline,
  type Finding,
  type GateOptions,
  type GateResult,
  type Suppression,
  type Worklists,
} from '@assay/core';
import { analyzeReachability, assemble } from '@assay/correlate';
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { scanCertificates } from '@assay/detect-pki';
import { scanBinaries } from '@assay/detect-binary';
import { decimalYear, loadPack } from '@assay/policy';
import { nowOption } from '../options.js';

/**
 * The build gate.
 *
 * Exit code 1 only for work that is NEW relative to the baseline, confirmed,
 * reachable and quantum-vulnerable. A gate that fails on the existing estate
 * fails on day one in every repository and is switched off by Friday, which
 * protects nothing.
 */

export interface CiOptions {
  readonly baseline: string;
  readonly policy: string;
  readonly system?: string;
  readonly updateBaseline?: boolean;
  readonly includeLibrarySurface?: boolean;
  readonly binaries?: boolean;
  readonly json?: boolean;
  readonly now?: string;
}

export async function runCi(path: string, options: CiOptions): Promise<void> {
  const root = resolve(path);
  const systemName = options.system ?? basename(root);
  const pack = loadPack(options.policy);
  const now = nowOption(options.now);
  const collectedAt = now.toISOString();

  const [source, deps, pki, binary] = await Promise.all([
    scanSource({ root, systemId: systemName, collectedAt }),
    scanDependencies({ root, systemId: systemName, collectedAt }),
    scanCertificates({ root, systemId: systemName, collectedAt }),
    options.binaries === false
      ? Promise.resolve({ findings: [] as Finding[], reports: [], filesScanned: 0 })
      : scanBinaries({ root, systemId: systemName, collectedAt }),
  ]);

  const assembled = assemble([...source.findings, ...deps.findings, ...pki.findings, ...binary.findings]);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  const worklists = rank(reach.occurrences, assembled.assets, {
    policy: pack,
    currentYear: decimalYear(now),
    secrecyLifetime: () => ({ years: 5, assumed: true }),
  });

  const baselinePath = resolve(options.baseline);
  const existing = await readBaseline(baselinePath, now);
  const gateOptions = {
    now,
    ...(options.includeLibrarySurface === true ? { includeLibrarySurface: true } : {}),
  };

  if (options.updateBaseline === true) {
    const next = rebaseline(
      worklists,
      { systemName, createdAt: collectedAt },
      gateOptions,
      existing?.suppressions ?? [],
    );
    await writeFile(baselinePath, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
    const dropped = (existing?.suppressions.length ?? 0) - next.suppressions.length;
    process.stdout.write(
      `wrote ${baselinePath}\n` +
        `  ${next.accepted.length} accepted work item(s), ${next.suppressions.length} live suppression(s)` +
        (dropped > 0 ? `, ${dropped} expired suppression(s) dropped rather than renewed\n` : '\n'),
    );
    return;
  }

  const result = evaluateGate(worklists, existing, gateOptions);

  if (options.json === true) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    report(result, worklists, existing, baselinePath);
  }
  if (!result.passed) process.exitCode = 1;
}

/**
 * The baseline that --update-baseline writes.
 *
 * Every finding a suppression can suppress is also one `makeBaseline` accepts,
 * so writing both records the same occurrence twice: once as a decision that
 * expires and once as one that never does. Once the window closes the gate
 * skips it as accepted instead of reporting it, and the expiry can never fail
 * a build - which is exactly the temporary exception quietly made permanent
 * that the expiry exists to prevent.
 */
export function rebaseline(
  worklists: Worklists,
  meta: { systemName: string; createdAt: string },
  opts: GateOptions,
  carryOver: readonly Suppression[],
): Baseline {
  const next = makeBaseline(worklists, meta, opts, carryOver);
  const suppressed = new Set(next.suppressions.map((s) => s.occurrenceId));
  return { ...next, accepted: next.accepted.filter((id) => !suppressed.has(id)) };
}

async function readBaseline(path: string, now: Date): Promise<Baseline | null> {
  let baseline: Baseline;
  try {
    baseline = BaselineSchema.parse(JSON.parse(await readFile(path, 'utf8')));
  } catch (e) {
    if (e instanceof Error && 'code' in e && (e as { code?: string }).code === 'ENOENT') return null;
    // A malformed baseline must not silently degrade into "no baseline",
    // which would fail the build on the entire estate and look like an outage.
    throw new Error(`baseline at ${path} could not be read: ${e instanceof Error ? e.message : String(e)}`);
  }

  for (const s of baseline.suppressions) {
    // The schema takes any date, so a hand-written expiry decades out parses
    // and suppresses forever. The bound the creation path applies has to hold
    // for an edited file too, or the expiry is advisory. Suppressions already
    // past their date pass through: reporting those is the gate's job.
    const days = (Date.parse(s.expiresAt) - now.getTime()) / 86_400_000;
    if (days > MAX_SUPPRESSION_DAYS) {
      throw new Error(
        `baseline at ${path}: the suppression for ${s.occurrenceId} runs until ` +
          `${s.expiresAt.slice(0, 10)}, more than ${MAX_SUPPRESSION_DAYS} days out; anything ` +
          'longer is a decision to never fix it, and should be recorded as one',
      );
    }
  }
  return baseline;
}

function report(
  result: GateResult,
  worklists: Worklists,
  baseline: Baseline | null,
  path: string,
): void {
  const line = (s = ''): void => {
    process.stdout.write(`${s}\n`);
  };

  line();
  line(`assay ci  ${result.passed ? 'PASS' : 'FAIL'}`);
  line(`  ${result.summary}`);
  line(
    `  baseline ${baseline === null ? `${path} (absent)` : `${path} @ ${baseline.policyPackId}@${baseline.policyPackVersion}`}`,
  );
  if (baseline !== null && baseline.policyPackId !== worklists.policyPackId) {
    line(
      `  NOTE the baseline was taken under ${baseline.policyPackId} and this run used ` +
        `${worklists.policyPackId}; slack figures are not comparable across packs`,
    );
  }
  line();

  if (result.introduced.length > 0) {
    line('new work introduced by this change:');
    for (const f of result.introduced) {
      line(
        `  ${f.late ? 'LATE ' : '     '}${f.slackYears.toFixed(1).padStart(6)}y  ` +
          `${f.track.padEnd(16)} ${f.controlClass.padEnd(19)} ${f.assetName}`,
      );
      line(`         reached ${f.reachedVia.toLowerCase().replace(/_/g, ' ')}, ${f.occurrenceId}`);
    }
    line();
  }

  if (result.expired.length > 0) {
    line('suppressions that have expired - renew or fix, but decide:');
    for (const s of result.expired) {
      line(`  ${s.expiresAt.slice(0, 10)}  ${s.occurrenceId}  ${s.reason} (${s.approvedBy})`);
    }
    line();
  }

  if (result.suppressed.length > 0) {
    line(`${result.suppressed.length} finding(s) suppressed and still in date:`);
    for (const { finding, suppression } of result.suppressed.slice(0, 10)) {
      line(`  until ${suppression.expiresAt.slice(0, 10)}  ${finding.assetName}  ${suppression.reason}`);
    }
    line();
  }

  if (result.stale.length > 0) {
    line(`${result.stale.length} suppression(s) name work items that no longer exist.`);
  }
  if (result.resolved.length > 0) {
    line(`${result.resolved.length} baseline entr(ies) are gone; re-run with --update-baseline to prune.`);
  }
  if (!result.passed) {
    line();
    line('To accept these deliberately, either re-baseline or add a suppression with an expiry:');
    line('  assay ci . --update-baseline');
  }
  line();
}
