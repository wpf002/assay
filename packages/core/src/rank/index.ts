import { gate, type AssertionLevel } from '../cbom/index.js';
import { scoreMosca, type MoscaPolicy, type MoscaResult } from '../mosca/index.js';
import { trackFor, type CryptoAsset, type Occurrence, type UrgencyTrack } from '../types/crypto-asset.js';
import type { Factor } from '../types/factor.js';

/**
 * Two worklists. Never one.
 *
 * Confidentiality and authenticity are ranked separately because
 * harvest-now-decrypt-later applies to one and not the other. EO 14412 splits
 * its own deadlines the same way - key establishment 2030-12-31, digital
 * signatures 2031-12-31 - so a single pooled "quantum readiness" score is now
 * misaligned with the mandate it claims to serve, not merely imprecise.
 */

export interface RankedFinding {
  readonly occurrenceId: string;
  readonly assetId: string;
  readonly systemId: string;
  readonly assetName: string;
  readonly controlClass: Occurrence['controlClass'];
  readonly track: UrgencyTrack;
  readonly assertionLevel: AssertionLevel;
  readonly confidence: number;
  readonly mosca: MoscaResult;
  readonly slackYears: number;
  readonly late: boolean;
  readonly bindingConstraint: MoscaResult['bindingConstraint'];
  readonly reachable: boolean | null;
  readonly downgradeReason: string | null;
}

export interface Worklists {
  readonly policyPackId: string;
  readonly policyPackVersion: string;
  readonly currentYear: number;
  /** Reached findings only. These are the work items. */
  readonly confidentiality: readonly RankedFinding[];
  readonly authenticity: readonly RankedFinding[];
  /**
   * Presence is not exposure (I5). Unreached findings are reported here and
   * never pad the headline count.
   */
  readonly unreached: readonly RankedFinding[];
  /** Reachability not yet analyzed. Distinct from "analyzed and not reached". */
  readonly unanalyzed: readonly RankedFinding[];
  readonly headline: HeadlineMetric;
}

/**
 * Exactly one number for the board, and it is derived rather than asserted.
 *
 * Competitors ship a pooled "quantum readiness %" that averages a code-signing
 * cert against a VPN concentrator. This one answers a single falsifiable
 * question - how much reachable, confirmed, quantum-vulnerable work is already
 * past its binding deadline - and every term in it is clickable.
 */
export interface HeadlineMetric {
  readonly label: string;
  readonly value: number;
  readonly numerator: number;
  readonly denominator: number;
  readonly factor: Factor;
}

export interface RankOptions {
  readonly policy: MoscaPolicy;
  readonly currentYear: number;
  /**
   * Years the data behind an occurrence must stay confidential. Returning
   * `assumed: true` marks X as an ASSUMPTION in the ranking derivation.
   */
  readonly secrecyLifetime: (
    o: Occurrence,
    a: CryptoAsset,
  ) => { readonly years: number; readonly assumed: boolean };
  readonly confirmThreshold?: number;
}

export function rank(
  occurrences: readonly Occurrence[],
  assets: readonly CryptoAsset[],
  opts: RankOptions,
): Worklists {
  const assetById = new Map(assets.map((a) => [a.id, a]));
  const findings: RankedFinding[] = [];

  for (const o of occurrences) {
    const asset = assetById.get(o.assetId);
    if (asset === undefined) continue;
    // A quantum-safe asset is inventory, not a work item. It still exports.
    if (!asset.quantumVulnerable) continue;

    const g = gate(o, opts.confirmThreshold);
    const secrecy = opts.secrecyLifetime(o, asset);
    const mosca = scoreMosca({
      purpose: asset.purpose,
      controlClass: o.controlClass,
      secrecyLifetimeYears: secrecy.years,
      secrecyLifetimeAssumed: secrecy.assumed,
      currentYear: opts.currentYear,
      policy: opts.policy,
    });

    findings.push({
      occurrenceId: o.id,
      assetId: o.assetId,
      systemId: o.systemId,
      assetName: name(asset),
      controlClass: o.controlClass,
      track: trackFor(asset.purpose),
      assertionLevel: g.assertionLevel,
      confidence: g.confidence,
      mosca,
      slackYears: mosca.slackYears,
      late: mosca.late,
      bindingConstraint: mosca.bindingConstraint,
      reachable: o.reachability === null ? null : o.reachability.reachable,
      downgradeReason: g.downgradeReason,
    });
  }

  // Ascending slack: the most overdue item is row one. Ties break on id so the
  // worklist is stable between runs and a diff means something changed.
  const bySlack = (a: RankedFinding, b: RankedFinding): number =>
    a.slackYears !== b.slackYears
      ? a.slackYears - b.slackYears
      : a.occurrenceId < b.occurrenceId
        ? -1
        : a.occurrenceId > b.occurrenceId
          ? 1
          : 0;

  const reached = findings.filter((f) => f.reachable === true).sort(bySlack);
  const unreached = findings.filter((f) => f.reachable === false).sort(bySlack);
  const unanalyzed = findings.filter((f) => f.reachable === null).sort(bySlack);

  // Reachability analysis is Phase 3. Until it runs, unanalyzed findings are
  // the working set - they are not silently treated as unreached, because
  // "we have not looked" and "we looked and it is dead code" are different claims.
  const working = reached.length > 0 || unreached.length > 0 ? reached : unanalyzed;

  return {
    policyPackId: opts.policy.packId,
    policyPackVersion: opts.policy.packVersion,
    currentYear: opts.currentYear,
    confidentiality: working.filter((f) => f.track === 'CONFIDENTIALITY'),
    authenticity: working.filter((f) => f.track === 'AUTHENTICITY'),
    unreached,
    unanalyzed: working === unanalyzed ? [] : unanalyzed,
    headline: headline(working, opts),
  };
}

function headline(working: readonly RankedFinding[], opts: RankOptions): HeadlineMetric {
  const confirmed = working.filter((f) => f.assertionLevel === 'CONFIRMED');
  const late = confirmed.filter((f) => f.late);
  const value = confirmed.length === 0 ? 0 : round4(late.length / confirmed.length);

  return {
    label: 'share of confirmed, reachable, quantum-vulnerable work already past its binding deadline',
    value,
    numerator: late.length,
    denominator: confirmed.length,
    factor: {
      kind: 'INFERENCE',
      label: 'headline = late / confirmed-reachable',
      value,
      weight: 1,
      sources: [
        {
          kind: 'INFERENCE',
          label: `${late.length} finding(s) with negative slack under the binding constraint`,
          value: late.length,
          weight: 1,
          sources: late.slice(0, 25).map((f) => f.mosca.factor),
        },
        {
          kind: 'INFERENCE',
          label: `${confirmed.length} confirmed reachable quantum-vulnerable occurrence(s)`,
          value: confirmed.length,
          weight: 1,
          sources: [],
        },
        {
          kind: 'POLICY',
          label: `policy pack ${opts.policy.packId}@${opts.policy.packVersion}`,
          value: opts.policy.crqcYear,
          weight: 1,
          sources: [],
        },
      ],
    },
  };
}

function name(a: CryptoAsset): string {
  const parts = Object.entries(a.parameters)
    .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0))
    .map(([k, v]) => `${k}=${String(v)}`);
  return parts.length > 0 ? `${a.primitive}(${parts.join(',')})` : a.primitive;
}

function round4(n: number): number {
  return Math.round(n * 1e4) / 1e4;
}
