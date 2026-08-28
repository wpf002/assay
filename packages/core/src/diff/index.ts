import { ASSERTION_ORDER, gate, type AssertionLevel } from '../cbom/index.js';
import type { CryptoAsset, Occurrence } from '../types/crypto-asset.js';
import type { Factor } from '../types/factor.js';

/**
 * Scan diff.
 *
 * The number a CISO is asked about at the next meeting is not "how much
 * crypto do we have" - it is "did it get better". That question is only
 * answerable because an Occurrence id is a content hash of
 * (system, asset, control class): the same work item keeps the same identity
 * across scans without anyone maintaining a mapping.
 *
 * REGRESSED is the category that earns the feature. A finding that was
 * OBSERVED and is now CONFIRMED did not appear - it was always there, and the
 * scan got better at seeing it. A finding that was unreached and is now
 * reached is genuinely worse. Reporting both as "new" would make every
 * detector improvement look like a security incident, and teams learn to
 * ignore tools that do that.
 */

export interface ScanSnapshot {
  readonly scanId: string;
  readonly takenAt: string;
  readonly policyPackId: string;
  readonly policyPackVersion: string;
  readonly occurrences: readonly Occurrence[];
  readonly assets: readonly CryptoAsset[];
}

export type ChangeKind =
  | 'APPEARED'
  | 'REMEDIATED'
  | 'REGRESSED'
  | 'IMPROVED'
  | 'RECLASSIFIED'
  | 'UNCHANGED';

export interface ChangeEntry {
  readonly occurrenceId: string;
  readonly assetId: string;
  readonly assetName: string;
  readonly systemId: string;
  readonly kind: ChangeKind;
  readonly before: OccurrenceSummary | null;
  readonly after: OccurrenceSummary | null;
  /** Plain-language statement of what moved, for a changelog a human reads. */
  readonly reason: string;
}

export interface OccurrenceSummary {
  readonly assertionLevel: AssertionLevel;
  readonly confidence: number;
  readonly reachable: boolean | null;
  readonly evidenceCount: number;
  readonly modalities: readonly string[];
}

export interface ScanDiff {
  readonly from: { readonly scanId: string; readonly takenAt: string };
  readonly to: { readonly scanId: string; readonly takenAt: string };
  /** True when the two scans were ranked under different policy. */
  readonly policyChanged: boolean;
  readonly entries: readonly ChangeEntry[];
  readonly counts: Readonly<Record<ChangeKind, number>>;
}

export function diffScans(previous: ScanSnapshot, current: ScanSnapshot): ScanDiff {
  const before = new Map(previous.occurrences.map((o) => [o.id, o]));
  const after = new Map(current.occurrences.map((o) => [o.id, o]));
  const names = new Map(
    [...previous.assets, ...current.assets].map((a) => [a.id, assetName(a)] as const),
  );

  const ids = [...new Set([...before.keys(), ...after.keys()])].sort();
  const entries: ChangeEntry[] = [];

  for (const id of ids) {
    const b = before.get(id);
    const a = after.get(id);
    const bs = b === undefined ? null : summarize(b);
    const as = a === undefined ? null : summarize(a);
    const anchor = a ?? (b as Occurrence);

    const { kind, reason } = classify(bs, as);
    entries.push({
      occurrenceId: id,
      assetId: anchor.assetId,
      assetName: names.get(anchor.assetId) ?? anchor.assetId,
      systemId: anchor.systemId,
      kind,
      before: bs,
      after: as,
      reason,
    });
  }

  const counts: Record<ChangeKind, number> = {
    APPEARED: 0,
    REMEDIATED: 0,
    REGRESSED: 0,
    IMPROVED: 0,
    RECLASSIFIED: 0,
    UNCHANGED: 0,
  };
  for (const e of entries) counts[e.kind]++;

  return {
    from: { scanId: previous.scanId, takenAt: previous.takenAt },
    to: { scanId: current.scanId, takenAt: current.takenAt },
    policyChanged:
      previous.policyPackId !== current.policyPackId ||
      previous.policyPackVersion !== current.policyPackVersion,
    entries,
    counts,
  };
}

function classify(
  before: OccurrenceSummary | null,
  after: OccurrenceSummary | null,
): { kind: ChangeKind; reason: string } {
  if (before === null && after !== null) {
    return { kind: 'APPEARED', reason: 'not present in the previous scan' };
  }
  if (before !== null && after === null) {
    return {
      kind: 'REMEDIATED',
      reason: 'no longer found - the code changed, or the scan no longer reaches it',
    };
  }
  if (before === null || after === null) {
    return { kind: 'UNCHANGED', reason: 'no data on either side' };
  }

  // Reachability moving is the only change that is unambiguously about the
  // estate rather than about the scanner - and only between two verdicts. `null`
  // is not `false`: a scan that found no entry point analyzed nothing, so the
  // next scan that does find one would report the entire estate as REGRESSED at
  // once, which is the false-positive storm this module exists to avoid.
  if (before.reachable === false && after.reachable === true) {
    return { kind: 'REGRESSED', reason: 'became reachable from an entry point' };
  }
  if (before.reachable === true && after.reachable === false) {
    return { kind: 'IMPROVED', reason: 'no longer reachable' };
  }
  if (before.reachable === null && after.reachable !== null) {
    return {
      kind: 'RECLASSIFIED',
      reason: `reachability analyzed for the first time: ${
        after.reachable ? 'reachable from an entry point' : 'not reached'
      }`,
    };
  }
  if (before.reachable !== null && after.reachable === null) {
    return {
      kind: 'RECLASSIFIED',
      reason:
        'reachability verdict lost - nothing to trace from in this scan, which is a coverage question',
    };
  }

  const levelDelta = ASSERTION_ORDER[after.assertionLevel] - ASSERTION_ORDER[before.assertionLevel];
  if (levelDelta !== 0) {
    // Deliberately NOT called a regression. Nothing about the estate changed;
    // corroborating evidence arrived, or was lost.
    return {
      kind: 'RECLASSIFIED',
      reason:
        levelDelta > 0
          ? `assertion rose ${before.assertionLevel} -> ${after.assertionLevel} on new corroborating evidence, not on a change to the code`
          : `assertion fell ${before.assertionLevel} -> ${after.assertionLevel}; evidence was lost, which is a coverage question`,
    };
  }

  const newModalities = after.modalities.filter((m) => !before.modalities.includes(m));
  if (newModalities.length > 0) {
    return {
      kind: 'RECLASSIFIED',
      reason: `corroborated by a new modality: ${newModalities.join(', ')}`,
    };
  }
  return { kind: 'UNCHANGED', reason: 'no material change' };
}

function summarize(o: Occurrence): OccurrenceSummary {
  return {
    assertionLevel: gate(o).assertionLevel,
    confidence: Number(o.confidence.value),
    reachable: o.reachability === null ? null : o.reachability.reachable,
    evidenceCount: o.evidence.length,
    modalities: [...new Set(o.evidence.map((e) => e.modality))].sort(),
  };
}

function assetName(a: CryptoAsset): string {
  const parts = Object.entries(a.parameters)
    .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0))
    .map(([k, v]) => `${k}=${String(v)}`);
  return parts.length > 0 ? `${a.primitive}(${parts.join(',')})` : a.primitive;
}

export type { Factor };
