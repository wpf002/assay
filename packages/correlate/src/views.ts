import {
  CAPABILITY_MODALITIES,
  DEPLOYMENT_MODALITIES,
  type CryptoAsset,
  type Occurrence,
} from '@assay/core';

/**
 * Capability and deployment are different questions with different answers,
 * and the answer to one is not evidence about the other.
 *
 * Source says a service supports X25519 and RSA. The network says RSA was
 * negotiated. Both are true. "What is running" is answered by the handshake;
 * "what is possible" is answered by the source. A tool that picks one loses
 * the other, and the two failures look completely different in practice:
 *
 *   deployed but not capable  - a binary or appliance nobody has source for,
 *                               so the migration is a procurement conversation
 *   capable but not deployed  - dormant code paths and fallbacks, which is
 *                               where a downgrade attack lives and where a
 *                               network-only scanner is blind
 *
 * This resolves nothing. It keeps them apart and names the disagreement, which
 * is the only honest thing to do with two correct answers.
 */

export type Answer = 'DEPLOYED' | 'CAPABLE' | 'BOTH' | 'NEITHER';

export function answerOf(occurrence: Occurrence): Answer {
  let deployed = false;
  let capable = false;
  for (const e of occurrence.evidence) {
    if (DEPLOYMENT_MODALITIES.has(e.modality)) deployed = true;
    if (CAPABILITY_MODALITIES.has(e.modality)) capable = true;
  }
  return deployed && capable ? 'BOTH' : deployed ? 'DEPLOYED' : capable ? 'CAPABLE' : 'NEITHER';
}

export interface SystemViews {
  readonly systemId: string;
  /** Asset ids observed running. */
  readonly deployed: ReadonlySet<string>;
  /** Asset ids the code or configuration could produce. */
  readonly capable: ReadonlySet<string>;
  /** Running with no source or config to explain it. */
  readonly deployedOnly: readonly string[];
  /** Present in the estate's code but never observed running. */
  readonly capableOnly: readonly string[];
  /** Corroborated by both, which is the strongest position an asset can be in. */
  readonly corroborated: readonly string[];
}

export function systemViews(occurrences: readonly Occurrence[]): SystemViews[] {
  const bySystem = new Map<string, { deployed: Set<string>; capable: Set<string> }>();

  for (const o of occurrences) {
    const entry = bySystem.get(o.systemId) ?? { deployed: new Set<string>(), capable: new Set<string>() };
    const answer = answerOf(o);
    if (answer === 'DEPLOYED' || answer === 'BOTH') entry.deployed.add(o.assetId);
    if (answer === 'CAPABLE' || answer === 'BOTH') entry.capable.add(o.assetId);
    bySystem.set(o.systemId, entry);
  }

  return [...bySystem.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([systemId, { deployed, capable }]) => ({
      systemId,
      deployed,
      capable,
      deployedOnly: [...deployed].filter((id) => !capable.has(id)).sort(),
      capableOnly: [...capable].filter((id) => !deployed.has(id)).sort(),
      corroborated: [...deployed].filter((id) => capable.has(id)).sort(),
    }));
}

export interface Divergence {
  readonly systemId: string;
  readonly kind: 'DEPLOYED_WITHOUT_SOURCE' | 'CAPABLE_BUT_NOT_OBSERVED';
  readonly asset: CryptoAsset;
  readonly note: string;
}

/**
 * Named divergences, for the UI and for a report a human reads. Only produced
 * when a system actually has both kinds of evidence - with source alone,
 * everything is "capable but not observed", which is a statement about the
 * scan rather than about the estate.
 */
export function divergences(
  occurrences: readonly Occurrence[],
  assets: readonly CryptoAsset[],
): Divergence[] {
  const byId = new Map(assets.map((a) => [a.id, a]));
  const out: Divergence[] = [];

  for (const view of systemViews(occurrences)) {
    if (view.deployed.size === 0 || view.capable.size === 0) continue;

    for (const id of view.deployedOnly) {
      const asset = byId.get(id);
      if (asset === undefined) continue;
      out.push({
        systemId: view.systemId,
        kind: 'DEPLOYED_WITHOUT_SOURCE',
        asset,
        note: 'observed running with no source or configuration accounting for it - a vendor binary, an appliance, or a scan gap',
      });
    }
    for (const id of view.capableOnly) {
      const asset = byId.get(id);
      if (asset === undefined) continue;
      out.push({
        systemId: view.systemId,
        kind: 'CAPABLE_BUT_NOT_OBSERVED',
        asset,
        note: 'present in code or configuration but never observed on the wire - a dormant fallback is still a downgrade target',
      });
    }
  }
  return out;
}
