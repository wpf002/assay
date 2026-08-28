import { describe, expect, it } from 'vitest';
import {
  computeConfidence,
  gate,
  makeAsset,
  rank,
  scoreMosca,
  type Evidence,
  type Modality,
  type MoscaPolicy,
  type Occurrence,
} from '@assay/core';
import {
  NO_ROADMAP_YEARS,
  VendorAttestationSchema,
  attestationFindings,
  migrationEstimate,
  reconcile,
  type VendorAttestation,
} from '../src/index.js';

const NOW = new Date('2026-08-28T00:00:00.000Z');
const CURRENT_YEAR = 2026.66;

const POLICY: MoscaPolicy = {
  packId: 'eo-14412',
  packVersion: '1.0.0',
  crqcYear: 2035,
  deprecateYear: 2030,
  disallowYear: 2035,
  regulatoryDeadlines: { CONFIDENTIALITY: 2031, AUTHENTICITY: 2032 },
  regulatoryAuthority: 'EO 14412 sec. 4',
  migrationYearsByControl: { SELF: 0.5, VENDOR_UPGRADEABLE: 1.5, VENDOR_LOCKED: 4, HARDWARE: 6, PROTOCOL_BILATERAL: 5 },
};

const base = (over: Partial<VendorAttestation> = {}): VendorAttestation =>
  VendorAttestationSchema.parse({
    schema: 'assay.attestation/v1',
    vendor: 'Acme',
    product: 'PaymentSwitch',
    version: '9.2',
    systemId: 'switch',
    controlClass: 'VENDOR_LOCKED',
    attestedBy: 'security@acme.example',
    attestedAt: '2026-06-01T00:00:00.000Z',
    validUntil: '2027-06-01T00:00:00.000Z',
    claims: [
      { primitive: 'RSA', parameters: { modulusLength: 2048 }, purpose: 'KEY_ESTABLISHMENT', component: 'HSM channel' },
      { primitive: 'AES', parameters: { keySize: 256, mode: 'GCM' }, purpose: 'DATA_ENCRYPTION' },
    ],
    roadmap: { status: 'none', algorithms: [] },
    ...over,
  });

describe('a questionnaire is a statement, not an observation', () => {
  it('ingests claims at the ASSERTED ceiling', () => {
    const { findings } = attestationFindings(base(), { collectedAt: NOW.toISOString(), now: NOW });
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.evidence.modality === 'ASSERTED')).toBe(true);
  });

  it('cannot confirm anything on its own', () => {
    const { findings } = attestationFindings(base(), { collectedAt: NOW.toISOString(), now: NOW });
    const evidence = findings.map((f) => f.evidence);
    const occurrence: Occurrence = {
      id: 'o',
      assetId: findings[0]?.asset.id ?? 'a',
      systemId: 'switch',
      controlClass: 'VENDOR_LOCKED',
      reachability: null,
      evidence,
      confidence: computeConfidence(evidence),
    };
    expect(gate(occurrence).confidence).toBe(0.4);
    expect(gate(occurrence).assertionLevel).toBe('SUSPECTED');
  });

  it('requires an expiry, like a suppression', () => {
    const { validUntil, ...rest } = base();
    expect(validUntil).toBeTruthy();
    expect(VendorAttestationSchema.safeParse(rest).success).toBe(false);
  });

  it('marks an attestation that has aged out', () => {
    const stale = base({ validUntil: '2026-01-01T00:00:00.000Z' });
    const r = attestationFindings(stale, { collectedAt: NOW.toISOString(), now: NOW });
    expect(r.expired).toBe(true);
    expect(r.findings[0]?.evidence.raw).toContain('EXPIRED');
  });

  it('carries who said it and when into the evidence', () => {
    const { findings } = attestationFindings(base(), { collectedAt: NOW.toISOString(), now: NOW });
    expect(findings[0]?.evidence.raw).toContain('security@acme.example');
    expect(findings[0]?.evidence.raw).toContain('2026-06-01');
  });
});

describe('the vendor date becomes Y', () => {
  it('turns a committed date into a wait plus integration time', () => {
    const e = migrationEstimate(
      base({ roadmap: { status: 'committed', availableFrom: '2029-04-01T00:00:00.000Z', algorithms: ['ML-KEM'], requiresHardwareReplacement: false, notes: '' } }),
      CURRENT_YEAR,
    );
    expect(e.years).toBeCloseTo(2.58 + 0.5, 1);
    expect(e.controlClass).toBe('VENDOR_UPGRADEABLE');
    expect(e.label).toContain('2029-04-01');
  });

  it('adds hardware replacement time and reclasses as HARDWARE', () => {
    const e = migrationEstimate(
      base({ roadmap: { status: 'available', availableFrom: null, algorithms: ['ML-KEM'], requiresHardwareReplacement: true, notes: '' } }),
      CURRENT_YEAR,
    );
    expect(e.controlClass).toBe('HARDWARE');
    expect(e.years).toBeGreaterThan(2);
  });

  it('refuses to treat "evaluating" as a commitment', () => {
    // A vendor declining to give a date is not a schedule, and ranking it as
    // though one existed is exactly the optimism this tool removes.
    const e = migrationEstimate(base({ roadmap: { status: 'evaluating', availableFrom: null, algorithms: [], requiresHardwareReplacement: false, notes: '' } }), CURRENT_YEAR);
    expect(e.years).toBe(NO_ROADMAP_YEARS);
    expect(e.controlClass).toBe('VENDOR_LOCKED');
    expect(e.label).toContain('not one');
  });

  it('makes the vendor date visible in the slack derivation, as an assumption', () => {
    const e = migrationEstimate(
      base({ roadmap: { status: 'committed', availableFrom: '2029-04-01T00:00:00.000Z', algorithms: ['ML-KEM'], requiresHardwareReplacement: false, notes: '' } }),
      CURRENT_YEAR,
    );
    const m = scoreMosca({
      purpose: 'KEY_ESTABLISHMENT',
      controlClass: 'VENDOR_LOCKED',
      secrecyLifetimeYears: 5,
      currentYear: CURRENT_YEAR,
      policy: POLICY,
      migrationYearsOverride: { years: e.years, label: e.label, kind: e.kind },
    });
    const s = JSON.stringify(m.factor);
    expect(s).toContain('ASSUMPTION');
    expect(s).toContain('2029-04-01');
    // The class default is still shown, so a reader can see what was replaced.
    expect(s).toContain('class default would have been 4');
  });

  it('changes lateness, which is the whole point of collecting the date', () => {
    const args = {
      purpose: 'KEY_ESTABLISHMENT' as const,
      controlClass: 'VENDOR_LOCKED' as const,
      secrecyLifetimeYears: 5,
      currentYear: CURRENT_YEAR,
      policy: POLICY,
    };
    const classAverage = scoreMosca(args);
    const late = migrationEstimate(
      base({ roadmap: { status: 'committed', availableFrom: '2033-01-01T00:00:00.000Z', algorithms: ['ML-KEM'], requiresHardwareReplacement: false, notes: '' } }),
      CURRENT_YEAR,
    );
    const withVendorDate = scoreMosca({
      ...args,
      migrationYearsOverride: { years: late.years, label: late.label, kind: late.kind },
    });
    expect(withVendorDate.slackYears).toBeLessThan(classAverage.slackYears);
    expect(withVendorDate.late).toBe(true);
  });
});

/* --------------------------------------------------------------- reconcile */

const ev = (modality: Modality): Evidence => ({
  modality,
  locator: 'switch:443',
  raw: 'x',
  collectedAt: NOW.toISOString(),
  collectorVersion: 'test',
});

const observed = (asset: ReturnType<typeof makeAsset>, modalities: Modality[]): Occurrence => {
  const evidence = modalities.map(ev);
  return {
    id: `o-${asset.id}`,
    assetId: asset.id,
    systemId: 'switch',
    controlClass: 'VENDOR_LOCKED',
    reachability: null,
    evidence,
    confidence: computeConfidence(evidence),
  };
};

const RSA = makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT');
const AES = makeAsset('AES', { keySize: 256, mode: 'GCM' }, 'DATA_ENCRYPTION');
const TDES = makeAsset('3DES', { mode: 'CBC' }, 'DATA_ENCRYPTION');

describe('what the vendor says against what the wire shows', () => {
  it('corroborates a claim that is independently observed', () => {
    const r = reconcile(base(), [observed(RSA, ['NETWORK_ACTIVE'])], [RSA, AES]);
    expect(r.find((x) => x.asset.id === RSA.id)?.verdict).toBe('CORROBORATED');
  });

  it('flags cryptography the attestation never mentions', () => {
    // The finding that pays for the questionnaire: a CBOM built from vendor
    // claims alone would have a hole exactly here.
    const r = reconcile(base(), [observed(TDES, ['NETWORK_ACTIVE'])], [RSA, AES, TDES]);
    const undisclosed = r.find((x) => x.asset.id === TDES.id);
    expect(undisclosed?.verdict).toBe('UNDISCLOSED');
    expect(undisclosed?.note).toContain('hole');
  });

  it('marks a claim nothing has tested as unverified rather than as false', () => {
    const r = reconcile(base(), [], [RSA, AES]);
    expect(r.every((x) => x.verdict === 'UNVERIFIED')).toBe(true);
    expect(r[0]?.note).toContain('may be true');
  });

  it('contradicts a post-quantum claim when the wire still negotiates RSA', () => {
    const pqClaim = base({
      roadmap: { status: 'available', availableFrom: null, algorithms: ['ML-KEM'], requiresHardwareReplacement: false, notes: '' },
    });
    const r = reconcile(pqClaim, [observed(RSA, ['NETWORK_ACTIVE'])], [RSA, AES]);
    expect(r.find((x) => x.asset.id === RSA.id)?.verdict).toBe('CONTRADICTED_ROADMAP');
  });

  it('does not count the attestation as its own corroboration', () => {
    // An occurrence whose only evidence is ASSERTED is the claim itself.
    const r = reconcile(base(), [observed(RSA, ['ASSERTED'])], [RSA, AES]);
    expect(r.find((x) => x.asset.id === RSA.id)?.verdict).toBe('UNVERIFIED');
  });

  it('ignores observations from a different system', () => {
    const elsewhere = { ...observed(TDES, ['NETWORK_ACTIVE']), systemId: 'other' };
    const r = reconcile(base(), [elsewhere], [RSA, AES, TDES]);
    expect(r.some((x) => x.verdict === 'UNDISCLOSED')).toBe(false);
  });
});

describe('ranking with a vendor date', () => {
  it('feeds the estimate through rank() so worklists reflect the real wait', () => {
    const occurrences = [observed(RSA, ['NETWORK_ACTIVE'])];
    const attestation = base({
      roadmap: { status: 'committed', availableFrom: '2033-01-01T00:00:00.000Z', algorithms: ['ML-KEM'], requiresHardwareReplacement: false, notes: '' },
    });
    const estimate = migrationEstimate(attestation, CURRENT_YEAR);

    const withoutDate = rank(occurrences, [RSA], {
      policy: POLICY,
      currentYear: CURRENT_YEAR,
      secrecyLifetime: () => ({ years: 5, assumed: false }),
    });
    const withDate = rank(occurrences, [RSA], {
      policy: POLICY,
      currentYear: CURRENT_YEAR,
      secrecyLifetime: () => ({ years: 5, assumed: false }),
      migrationYears: () => ({ years: estimate.years, label: estimate.label, kind: estimate.kind }),
    });

    expect(withDate.unanalyzed[0]?.slackYears ?? withDate.confidentiality[0]?.slackYears).toBeLessThan(
      withoutDate.unanalyzed[0]?.slackYears ?? (withoutDate.confidentiality[0]?.slackYears as number),
    );
  });
});
