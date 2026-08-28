import { isTainted, type Factor } from '../types/factor.js';

/**
 * Factor trees, flattened for a UI.
 *
 * The Phase 4 exit gate is that any slack figure walks to raw evidence in
 * under three clicks. That is a constraint on the SHAPE of the derivation, not
 * on the front end, so it is measurable here: `derivationDepth` counts the
 * hops, and a test can fail when a refactor buries the evidence one level
 * deeper.
 */

export interface ExplainNode {
  readonly id: string;
  readonly kind: Factor['kind'];
  readonly label: string;
  readonly value: number | string | boolean;
  readonly weight: number;
  readonly depth: number;
  readonly tainted: boolean;
  readonly children: readonly ExplainNode[];
  /** True when this node is a leaf that a reviewer can go and check. */
  readonly isEvidence: boolean;
}

export function explain(factor: Factor, prefix = 'f'): ExplainNode {
  const build = (f: Factor, path: string, depth: number): ExplainNode => ({
    id: path,
    kind: f.kind,
    label: f.label,
    value: f.value,
    weight: f.weight,
    depth,
    tainted: isTainted(f),
    isEvidence: f.kind === 'EVIDENCE' || f.sources.length === 0,
    children: f.sources.map((s, i) => build(s, `${path}.${i}`, depth + 1)),
  });
  return build(factor, prefix, 0);
}

/** Hops from the root to the deepest evidence leaf. The three-click budget. */
export function derivationDepth(factor: Factor): number {
  if (factor.sources.length === 0) return 0;
  return 1 + Math.max(...factor.sources.map(derivationDepth));
}

/** Every raw observation under a derived value, for a citation list. */
export function citations(factor: Factor): Factor[] {
  if (factor.kind === 'EVIDENCE') return [factor];
  return factor.sources.flatMap(citations);
}

/**
 * Why is this not CONFIRMED, in one sentence per reason. The UI shows this
 * next to a downgraded finding rather than making the reader infer it from
 * the tree.
 */
export function blockers(factor: Factor): string[] {
  const out: string[] = [];
  const walk = (f: Factor): void => {
    if (f.kind === 'ASSUMPTION') out.push(f.label);
    f.sources.forEach(walk);
  };
  walk(factor);
  return [...new Set(out)];
}
