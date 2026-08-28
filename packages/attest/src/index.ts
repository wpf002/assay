import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  makeAsset,
  type ControlClass,
  type CryptoAsset,
  type Factor,
  type Finding,
  type Occurrence,
} from '@assay/core';
import { VendorAttestationSchema, type VendorAttestation } from './schema.js';

export * from './schema.js';

export const COLLECTOR_VERSION = 'attest/0.1.0';

export async function loadAttestation(path: string): Promise<VendorAttestation> {
  return VendorAttestationSchema.parse(JSON.parse(await readFile(resolve(path), 'utf8')));
}

export interface AttestOptions {
  readonly collectedAt: string;
  /** Supplied by the caller so expiry is evaluated against a known clock (I7). */
  readonly now: Date;
}

export interface AttestResult {
  readonly findings: readonly Finding[];
  readonly expired: boolean;
}

/**
 * A questionnaire response becomes evidence at the ASSERTED ceiling (0.40).
 *
 * It cannot confirm anything alone, which is correct: a vendor saying their
 * product uses AES-256 is not an observation of AES-256. What it does is put
 * the claim into the same inventory as everything else, so it can be
 * reconciled against what the network actually shows.
 */
export function attestationFindings(
  attestation: VendorAttestation,
  opts: AttestOptions,
): AttestResult {
  const expired = Date.parse(attestation.validUntil) <= opts.now.getTime();
  const provenance =
    `${attestation.vendor}/${attestation.product}@${attestation.version} ` +
    `attested by ${attestation.attestedBy} on ${attestation.attestedAt.slice(0, 10)}` +
    (attestation.reference === '' ? '' : ` ref=${attestation.reference}`);

  const findings = attestation.claims.map<Finding>((claim, i) => ({
    asset: makeAsset(claim.primitive, claim.parameters, claim.purpose),
    systemId: attestation.systemId,
    controlClass: attestation.controlClass,
    evidence: {
      modality: 'ASSERTED',
      locator: `${attestation.vendor}/${attestation.product}#${claim.component || `claim-${i}`}`,
      raw:
        `vendor claim :: ${provenance} :: component=${claim.component || '(unspecified)'} ` +
        `configurable=${String(claim.configurable)} ` +
        `:: unverified; a questionnaire is a statement, not an observation` +
        (expired ? ' :: EXPIRED - this attestation is past its validUntil date' : ''),
      collectedAt: opts.collectedAt,
      collectorVersion: COLLECTOR_VERSION,
      occurrence: { location: `${attestation.vendor}/${attestation.product}`, symbol: claim.component },
    },
  }));

  return { findings, expired };
}

/* ------------------------------------------------------- the Y that matters */

export interface MigrationEstimate {
  readonly years: number;
  readonly label: string;
  readonly kind: Factor['kind'];
  readonly controlClass: ControlClass;
}

export const NO_ROADMAP_YEARS = 6;

/**
 * Turn a vendor's stated availability into the Y term, with its provenance.
 *
 * This is the part of vendor attestation worth paying for. A class average
 * says VENDOR_LOCKED is "four years, probably". A vendor saying "2029 Q2"
 * gives a real date, and adding a customer's own integration time to it
 * produces a slack figure that either clears the deadline or does not - which
 * is a procurement conversation with a number in it rather than a shrug.
 *
 * `evaluating` is deliberately not treated as a commitment. It is a vendor
 * declining to give a date, and ranking it as though a date existed is exactly
 * the optimism this tool is built to remove.
 */
export function migrationEstimate(
  attestation: VendorAttestation,
  currentYear: number,
  integrationYears = 0.5,
): MigrationEstimate {
  const { roadmap } = attestation;
  const hardware = roadmap.requiresHardwareReplacement;

  if (roadmap.status === 'available') {
    return {
      years: integrationYears + (hardware ? 2 : 0),
      label: `vendor states post-quantum support is already available${hardware ? ', but it requires hardware replacement' : ''}`,
      kind: 'ASSUMPTION',
      controlClass: hardware ? 'HARDWARE' : 'VENDOR_UPGRADEABLE',
    };
  }

  if (roadmap.status === 'committed' && roadmap.availableFrom !== null) {
    const availableYear = decimalYearOf(roadmap.availableFrom);
    const wait = Math.max(0, round2(availableYear - currentYear));
    return {
      years: round2(wait + integrationYears + (hardware ? 2 : 0)),
      label:
        `vendor committed to ${roadmap.availableFrom.slice(0, 10)} ` +
        `(${wait}y wait + ${integrationYears}y integration` +
        `${hardware ? ' + 2y hardware replacement' : ''})`,
      kind: 'ASSUMPTION',
      controlClass: hardware ? 'HARDWARE' : 'VENDOR_UPGRADEABLE',
    };
  }

  // No date. Not a schedule, and the ranking should not invent one.
  return {
    years: hardware ? NO_ROADMAP_YEARS + 2 : NO_ROADMAP_YEARS,
    label:
      roadmap.status === 'evaluating'
        ? 'vendor is "evaluating" and gave no date; treated as no commitment, because it is not one'
        : 'vendor states no post-quantum roadmap; this is a procurement problem, not an engineering one',
    kind: 'ASSUMPTION',
    controlClass: 'VENDOR_LOCKED',
  };
}

/* ------------------------------------------------------------- reconciliation */

export type ReconcileVerdict =
  | 'CORROBORATED'
  | 'UNDISCLOSED'
  | 'UNVERIFIED'
  | 'CONTRADICTED_ROADMAP';

export interface Reconciliation {
  readonly verdict: ReconcileVerdict;
  readonly asset: CryptoAsset;
  readonly claimed: boolean;
  readonly observed: boolean;
  readonly observedModalities: readonly string[];
  readonly note: string;
}

/**
 * What the vendor says against what the wire shows.
 *
 * The interesting cell is UNDISCLOSED: cryptography observed in a product
 * whose attestation never mentions it. That is the finding that pays for the
 * questionnaire - not because the vendor lied, but because a CBOM assembled
 * from vendor claims alone would have a hole in it exactly there.
 */
export function reconcile(
  attestation: VendorAttestation,
  occurrences: readonly Occurrence[],
  assets: readonly CryptoAsset[],
): Reconciliation[] {
  const byId = new Map(assets.map((a) => [a.id, a]));
  const claimed = new Map<string, CryptoAsset>();
  for (const claim of attestation.claims) {
    const asset = makeAsset(claim.primitive, claim.parameters, claim.purpose);
    claimed.set(asset.id, asset);
  }

  const observedModalities = new Map<string, Set<string>>();
  for (const o of occurrences) {
    if (o.systemId !== attestation.systemId) continue;
    const modalities = o.evidence
      .filter((e) => e.modality !== 'ASSERTED')
      .map((e) => e.modality);
    if (modalities.length === 0) continue;
    const set = observedModalities.get(o.assetId) ?? new Set<string>();
    for (const m of modalities) set.add(m);
    observedModalities.set(o.assetId, set);
  }

  const out: Reconciliation[] = [];
  const roadmapClaimsPq =
    attestation.roadmap.status === 'available' && attestation.roadmap.algorithms.length > 0;

  for (const id of new Set([...claimed.keys(), ...observedModalities.keys()])) {
    const asset = claimed.get(id) ?? byId.get(id);
    if (asset === undefined) continue;
    const isClaimed = claimed.has(id);
    const modalities = [...(observedModalities.get(id) ?? [])].sort();
    const isObserved = modalities.length > 0;

    if (isClaimed && isObserved) {
      // A vendor promising post-quantum support "already available" while the
      // wire still shows a Shor-broken key exchange is the one case where the
      // claim is not merely incomplete but wrong.
      const contradicts = roadmapClaimsPq && asset.quantumVulnerable && isKeyEstablishment(asset);
      out.push({
        verdict: contradicts ? 'CONTRADICTED_ROADMAP' : 'CORROBORATED',
        asset,
        claimed: true,
        observed: true,
        observedModalities: modalities,
        note: contradicts
          ? 'the vendor states post-quantum support is available, and this quantum-vulnerable key establishment is still what gets negotiated'
          : 'claimed by the vendor and independently observed',
      });
      continue;
    }
    if (isObserved) {
      out.push({
        verdict: 'UNDISCLOSED',
        asset,
        claimed: false,
        observed: true,
        observedModalities: modalities,
        note: 'observed in the product and absent from the attestation - a CBOM built from vendor claims alone would have a hole here',
      });
      continue;
    }
    out.push({
      verdict: 'UNVERIFIED',
      asset,
      claimed: true,
      observed: false,
      observedModalities: [],
      note: 'claimed by the vendor and never observed; the claim may be true and simply untested by this scan',
    });
  }

  return out.sort((a, b) => a.verdict.localeCompare(b.verdict) || a.asset.id.localeCompare(b.asset.id));
}

function isKeyEstablishment(asset: CryptoAsset): boolean {
  return asset.purpose === 'KEY_ESTABLISHMENT' || asset.purpose === 'DATA_ENCRYPTION';
}

function decimalYearOf(iso: string): number {
  const d = new Date(iso);
  const year = d.getUTCFullYear();
  const start = Date.UTC(year, 0, 1);
  const end = Date.UTC(year + 1, 0, 1);
  return round2(year + (d.getTime() - start) / (end - start));
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
