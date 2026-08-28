import {
  CORRELATED_GROUPS,
  MODALITY_CEILING,
  MODALITIES,
  type Modality,
} from '../types/modality.js';
import type { Evidence } from '../types/crypto-asset.js';
import type { Factor } from '../types/factor.js';

/**
 * Confidence algebra. The whole product rests on this file.
 *
 * I1a: a single modality can never exceed its ceiling, however many
 *      observations of that modality exist. 400 string matches is one weak
 *      fact repeated, not 400 facts.
 * I1b: only INDEPENDENT modality groups combine, by noisy-OR over group
 *      maxima. Source, config and dependency evidence are correlated and do
 *      not stack with each other.
 * I7:  pure function. Same evidence set -> identical Factor tree, always.
 */

/** Group index by modality. Built once; the partition is asserted to be total. */
const GROUP_OF: ReadonlyMap<Modality, number> = (() => {
  const m = new Map<Modality, number>();
  CORRELATED_GROUPS.forEach((group, i) => {
    for (const mod of group) {
      if (m.has(mod)) throw new Error(`modality ${mod} appears in more than one correlated group`);
      m.set(mod, i);
    }
  });
  for (const mod of MODALITIES) {
    if (!m.has(mod)) throw new Error(`modality ${mod} is in no correlated group`);
  }
  return m;
})();

export interface ModalityTally {
  readonly modality: Modality;
  readonly count: number;
  readonly ceiling: number;
}

export interface ConfidenceBreakdown {
  readonly value: number;
  readonly factor: Factor;
  /** Per-group detail, for the UI panel that shows what was suppressed. */
  readonly groups: readonly {
    readonly index: number;
    readonly contributing: Modality;
    readonly ceiling: number;
    readonly tallies: readonly ModalityTally[];
    /** Observations discarded because a stronger or equal modality in the same group won. */
    readonly suppressed: number;
  }[];
}

function evidenceFactor(e: Evidence): Factor {
  return {
    kind: 'EVIDENCE',
    label: `${e.modality} @ ${e.locator}`,
    value: e.raw,
    weight: 1,
    sources: [],
  };
}

/**
 * Noisy-OR across independent groups; max within a group.
 *
 * Evidence is sorted before it is folded so the Factor tree is stable under
 * detector ordering. Determinism is a product claim, not an implementation
 * detail: the same estate must produce a byte-identical CBOM on every run.
 */
export function computeConfidenceBreakdown(evidence: readonly Evidence[]): ConfidenceBreakdown {
  const byModality = new Map<Modality, Evidence[]>();
  for (const e of evidence) {
    const list = byModality.get(e.modality);
    if (list) list.push(e);
    else byModality.set(e.modality, [e]);
  }
  for (const list of byModality.values()) {
    list.sort((a, b) => (a.locator === b.locator ? cmp(a.raw, b.raw) : cmp(a.locator, b.locator)));
  }

  const groups: ConfidenceBreakdown['groups'][number][] = [];
  const groupFactors: Factor[] = [];

  CORRELATED_GROUPS.forEach((group, index) => {
    const present = group.filter((m) => byModality.has(m));
    if (present.length === 0) return;

    const tallies: ModalityTally[] = present.map((m) => ({
      modality: m,
      count: (byModality.get(m) as Evidence[]).length,
      ceiling: MODALITY_CEILING[m],
    }));

    // Highest ceiling wins; ties break on modality order for determinism.
    const contributing = present.reduce((a, m) =>
      MODALITY_CEILING[m] > MODALITY_CEILING[a] ? m : a,
    );
    const winners = byModality.get(contributing) as Evidence[];
    const total = tallies.reduce((n, t) => n + t.count, 0);

    groups.push({
      index,
      contributing,
      ceiling: MODALITY_CEILING[contributing],
      tallies,
      suppressed: total - 1,
    });

    groupFactors.push({
      kind: 'INFERENCE',
      label:
        `group ${index}: ${contributing} ceiling ${MODALITY_CEILING[contributing]} ` +
        `(${total} observation${total === 1 ? '' : 's'} across ${present.join(', ')}, ` +
        `${total - 1} suppressed as same-group repetition)`,
      value: MODALITY_CEILING[contributing],
      weight: 1,
      // Cap the cited evidence: a group of 400 string matches cites the first
      // few and says so. The tally carries the true count.
      sources: winners.slice(0, 5).map(evidenceFactor),
    });
  });

  const combined =
    groupFactors.length === 0
      ? 0
      : 1 - groupFactors.reduce((acc, f) => acc * (1 - Number(f.value)), 1);
  const value = round4(combined);

  return {
    value,
    groups,
    factor: {
      kind: 'INFERENCE',
      label:
        groupFactors.length === 0
          ? 'confidence (no evidence)'
          : `confidence (noisy-OR over ${groupFactors.length} independent modality group${
              groupFactors.length === 1 ? '' : 's'
            })`,
      value,
      weight: 1,
      sources: groupFactors,
    },
  };
}

/** The Factor tree alone, for callers that only need provenance. */
export function computeConfidence(evidence: readonly Evidence[]): Factor {
  return computeConfidenceBreakdown(evidence).factor;
}

/**
 * True when no single group could ever reach the threshold on its own, i.e.
 * the finding only clears the bar because independent modalities corroborate.
 * The UI marks these; they are the findings a reviewer should trust most.
 */
export function requiresCorroboration(b: ConfidenceBreakdown, threshold: number): boolean {
  return b.value >= threshold && b.groups.every((g) => g.ceiling < threshold);
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function round4(n: number): number {
  return Math.round(n * 1e4) / 1e4;
}

export { GROUP_OF };
