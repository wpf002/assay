/**
 * Recursive provenance. Every derived value carries the chain back to raw
 * evidence. Nothing in Assay is a bare number.
 */
export type FactorKind =
  | 'EVIDENCE' // a raw observation
  | 'INFERENCE' // derived from other factors
  | 'POLICY' // supplied by a versioned policy pack (deadlines, CRQC year)
  | 'ASSUMPTION'; // operator-supplied, unverified. taints the path.

export interface Factor {
  readonly kind: FactorKind;
  readonly label: string;
  readonly value: number | string | boolean;
  readonly weight: number;
  readonly sources: readonly Factor[];
}

/** True if any node in the dependency path is an ASSUMPTION. Gates export tier (I6). */
export function isTainted(f: Factor): boolean {
  return f.kind === 'ASSUMPTION' || f.sources.some(isTainted);
}

/** Flatten to a citation list for audit output. */
export function trace(f: Factor, depth = 0): string[] {
  return [
    `${'  '.repeat(depth)}[${f.kind}] ${f.label} = ${String(f.value)}`,
    ...f.sources.flatMap((s) => trace(s, depth + 1)),
  ];
}

/** Every ASSUMPTION node in the tree, for "why is this not CONFIRMED" answers. */
export function assumptions(f: Factor): Factor[] {
  return [...(f.kind === 'ASSUMPTION' ? [f] : []), ...f.sources.flatMap(assumptions)];
}

/** Depth of the derivation. The web UI's three-click gate is measured against this. */
export function depth(f: Factor): number {
  return 1 + f.sources.reduce((m, s) => Math.max(m, depth(s)), 0);
}
