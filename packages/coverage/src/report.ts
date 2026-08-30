import type { CryptoAsset, Modality, Occurrence } from '@assay/core';
import { CLASSES, type EstateClass } from './classes.js';

/**
 * A coverage attestation.
 *
 * The gate this replaces was "measure recall against a hand-built ground truth
 * and stop below 80%". That gate could not fire: recall gaps close by writing
 * more rules, so the realistic reading of a low number was never "unrecoverable"
 * but "and twelve more rules to write" - a backlog wearing a gate's clothes.
 * And it did not answer the buyer's question anyway. Nobody can attest an
 * inventory to a regulator on the strength of "we find four in five call sites".
 *
 * What a buyer can sign is this: for each part of my estate, did you look, with
 * what, and what did you explicitly not reach. That statement can be wrong in
 * exactly one way - claiming to have looked somewhere it did not - and that is
 * a property tests can hold.
 *
 * Pure (I7): no clock, no I/O, no ambient state. `generatedAt` is supplied by
 * the caller so the same input produces byte-identical output, which is what
 * makes the signature mean anything.
 */

export interface ClassCoverage {
  readonly id: EstateClass;
  readonly label: string;
  /** True only if a modality that can see this class actually produced evidence. */
  readonly examined: boolean;
  /** Whether running the remedy would actually fill this class in today. */
  readonly capability: 'READY' | 'UNBUILT';
  readonly modalitiesAvailable: readonly Modality[];
  readonly modalitiesUsed: readonly Modality[];
  readonly occurrences: number;
  readonly assets: number;
  readonly systems: readonly string[];
  /** What it would take to cover this. Present whether examined or not. */
  readonly remedy: string;
  readonly caveat: string;
}

/** Something the estate contains that has no inventory at all. */
export interface BlindSpot {
  readonly name: string;
  readonly kind: 'SERVICE' | 'HOST' | 'PRODUCT';
  readonly observedBy: string;
  readonly why: string;
}

export interface CoverageReport {
  readonly reportVersion: 1;
  readonly subject: {
    readonly kind: 'SCAN' | 'ESTATE';
    readonly id: string;
    readonly systems: readonly string[];
  };
  readonly generatedAt: string;
  readonly policy: { readonly packId: string; readonly packVersion: string };
  readonly detectors: readonly string[];
  readonly classes: readonly ClassCoverage[];
  readonly blindSpots: readonly BlindSpot[];
  readonly summary: {
    readonly classesExamined: number;
    readonly classesTotal: number;
    readonly occurrences: number;
    readonly statement: string;
  };
  /** What this document deliberately does not claim. Read it before signing. */
  readonly notAsserted: readonly string[];
}

export interface CoverageInput {
  readonly subject: CoverageReport['subject'];
  readonly generatedAt: string;
  readonly policy: CoverageReport['policy'];
  readonly detectors: readonly string[];
  readonly occurrences: readonly Occurrence[];
  readonly assets: readonly CryptoAsset[];
  readonly blindSpots?: readonly BlindSpot[];
}

/**
 * The sentences this report refuses to let a reader infer.
 *
 * Every one of these is a claim someone will otherwise read into a green row,
 * and a signed document that permits that reading is worse than no document.
 */
const NOT_ASSERTED: readonly string[] = [
  'That a class marked unexamined is beyond this tool. Nine of the ten are covered by a detector that already ships and was not pointed at anything; the report says per class which one that is.',
  'That any class is completely inventoried. "Examined" means a modality that can see this class produced evidence; it does not bound what that modality missed.',
  'That a class with no findings contains no vulnerable cryptography. It means nothing was found by the modalities that ran.',
  'That findings are exposed. Presence is not exposure; reachability is stated per finding and is a separate claim (I5).',
  'That evidence gathered from a repository describes what is running. Only deployment modalities - live handshakes, host agents, certificates, KMS enumeration - speak to that.',
  'That the estate is limited to what is listed here. Assay can only enumerate what it was pointed at; anything it was not pointed at is absent from this document, not from the estate.',
];

export function coverageReport(input: CoverageInput): CoverageReport {
  const byClass = new Map<
    EstateClass,
    { modalities: Set<Modality>; occurrences: Set<string>; assets: Set<string>; systems: Set<string> }
  >();
  for (const c of CLASSES) {
    byClass.set(c.id, {
      modalities: new Set(),
      occurrences: new Set(),
      assets: new Set(),
      systems: new Set(),
    });
  }

  for (const occ of input.occurrences) {
    for (const ev of occ.evidence) {
      for (const c of CLASSES) {
        if (!c.modalities.includes(ev.modality)) continue;
        const bucket = byClass.get(c.id);
        /* c8 ignore next */
        if (bucket === undefined) continue;
        bucket.modalities.add(ev.modality);
        bucket.occurrences.add(occ.id);
        bucket.assets.add(occ.assetId);
        bucket.systems.add(occ.systemId);
      }
    }
  }

  const classes: ClassCoverage[] = CLASSES.map((c) => {
    const b = byClass.get(c.id);
    /* c8 ignore next */
    const bucket = b ?? { modalities: new Set<Modality>(), occurrences: new Set<string>(), assets: new Set<string>(), systems: new Set<string>() };
    return {
      id: c.id,
      label: c.label,
      capability: c.capability,
      // Evidence, not intent. A detector that ran and found nothing has not
      // examined the class - it has failed to find anything in it, and those
      // read identically to an operator unless the distinction is enforced here.
      examined: bucket.occurrences.size > 0,
      modalitiesAvailable: [...c.modalities].sort(),
      modalitiesUsed: [...bucket.modalities].sort(),
      occurrences: bucket.occurrences.size,
      assets: bucket.assets.size,
      systems: [...bucket.systems].sort(),
      remedy: c.remedy,
      caveat: c.caveat,
    };
  });

  const examined = classes.filter((c) => c.examined).length;
  const unexamined = classes.filter((c) => !c.examined);
  const blindSpots = [...(input.blindSpots ?? [])].sort((a, b) => a.name.localeCompare(b.name));

  return {
    reportVersion: 1,
    subject: { ...input.subject, systems: [...input.subject.systems].sort() },
    generatedAt: input.generatedAt,
    policy: input.policy,
    detectors: [...input.detectors].sort(),
    classes,
    blindSpots,
    summary: {
      classesExamined: examined,
      classesTotal: classes.length,
      occurrences: input.occurrences.length,
      statement: statement(examined, classes.length, unexamined, blindSpots.length),
    },
    notAsserted: NOT_ASSERTED,
  };
}

/**
 * One sentence an operator can paste into a memo.
 *
 * It leads with what was NOT covered, because that is the part that decides
 * whether the inventory can be attested and the part a summary would otherwise
 * bury under a reassuring fraction.
 */
function statement(
  examined: number,
  total: number,
  unexamined: readonly ClassCoverage[],
  blindSpots: number,
): string {
  const ready = unexamined.filter((c) => c.capability === 'READY');
  const unbuilt = unexamined.filter((c) => c.capability === 'UNBUILT');
  // Leading with "we did not look at six things" reads as six things the tool
  // cannot do. Five of six are usually a detector nobody pointed anywhere, and
  // that is a different sentence with a different next action.
  const missing =
    unexamined.length === 0
      ? 'every class of the estate produced evidence'
      : [
          `no evidence was gathered for ${unexamined.length} of ${total} classes`,
          ready.length === 0
            ? ''
            : `${ready.length} of those need only be pointed at something (${ready.map((c) => c.label).join('; ')})`,
          unbuilt.length === 0
            ? ''
            : `${unbuilt.length} ${unbuilt.length === 1 ? 'has' : 'have'} no detector yet (${unbuilt.map((c) => c.label).join('; ')})`,
        ]
          .filter((p) => p !== '')
          .join('; ')
  const blind =
    blindSpots === 0
      ? ''
      : ` ${blindSpots} ${blindSpots === 1 ? 'service or host was' : 'services or hosts were'} observed in traffic with no inventory of any kind.`;
  return `Examined ${examined} of ${total} classes of the estate; ${missing}.${blind} This is a statement about what was looked at, not about what exists.`;
}
