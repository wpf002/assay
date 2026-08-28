import {
  computeConfidence,
  canonicalize,
  sha256Hex,
  type ControlClass,
  type CryptoAsset,
  type Evidence,
  type Finding,
  type Occurrence,
} from '@assay/core';

/**
 * Evidence -> Occurrences.
 *
 * THE GROUPING DECISION: an Occurrence is one (system, asset, control class)
 * triple, not one file:line. Four hundred call sites in one service using
 * RSA-2048 for key establishment are ONE work item - you migrate them together,
 * with one decision, on one timeline. Every individual location survives inside
 * `evidence`, so nothing is lost and the drill-down is complete.
 *
 * Emitting a row per call site is exactly how the field produces 40,000-row
 * CBOMs that nobody reads. The confidence ceilings keep bad evidence from
 * confirming; this grouping keeps good evidence from flooding.
 *
 * Control class is part of the key because "our code uses RSA" and "a vendor
 * blob uses RSA" have different Y values and are therefore different work.
 */

export interface AssembleResult {
  readonly occurrences: readonly Occurrence[];
  readonly assets: readonly CryptoAsset[];
}

export function assemble(findings: readonly Finding[]): AssembleResult {
  const assets = new Map<string, CryptoAsset>();
  const groups = new Map<string, { key: GroupKey; evidence: Evidence[] }>();

  for (const f of findings) {
    assets.set(f.asset.id, f.asset);
    const key: GroupKey = {
      systemId: f.systemId,
      assetId: f.asset.id,
      controlClass: f.controlClass,
    };
    const id = occurrenceId(key);
    const group = groups.get(id);
    if (group) group.evidence.push(f.evidence);
    else groups.set(id, { key, evidence: [f.evidence] });
  }

  const occurrences = [...groups.entries()]
    .sort((a, b) => cmp(a[0], b[0]))
    .map(([id, g]) => {
      // Sort evidence so the Occurrence is byte-stable regardless of the order
      // detectors happened to walk the filesystem in.
      const evidence = [...g.evidence].sort((a, b) =>
        a.modality !== b.modality
          ? cmp(a.modality, b.modality)
          : a.locator !== b.locator
            ? cmp(a.locator, b.locator)
            : cmp(a.raw, b.raw),
      );
      return {
        id,
        assetId: g.key.assetId,
        systemId: g.key.systemId,
        controlClass: g.key.controlClass,
        reachability: null,
        evidence,
        confidence: computeConfidence(evidence),
      } satisfies Occurrence;
    });

  return {
    occurrences,
    assets: [...assets.values()].sort((a, b) => cmp(a.id, b.id)),
  };
}

interface GroupKey {
  readonly systemId: string;
  readonly assetId: string;
  readonly controlClass: ControlClass;
}

export function occurrenceId(key: GroupKey): string {
  return sha256Hex(canonicalize({ ...key })).slice(0, 24);
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
