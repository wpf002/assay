import { describe, expect, it } from 'vitest';
import { scoreMosca, isTainted, type MoscaPolicy } from '../src/index.js';

const EO: MoscaPolicy = {
  packId: 'eo-14412',
  packVersion: '1.0.0',
  crqcYear: 2035,
  deprecateYear: 2030,
  disallowYear: 2035,
  regulatoryDeadlines: { CONFIDENTIALITY: 2031.0, AUTHENTICITY: 2032.0 },
  regulatoryAuthority: 'EO 14412 sec. 4',
  migrationYearsByControl: {
    SELF: 0.5,
    VENDOR_UPGRADEABLE: 1.5,
    VENDOR_LOCKED: 4.0,
    HARDWARE: 6.0,
    PROTOCOL_BILATERAL: 5.0,
  },
};

const PHYSICS_ONLY: MoscaPolicy = {
  ...EO,
  packId: 'nist-ir-8547-draft',
  regulatoryDeadlines: { CONFIDENTIALITY: null, AUTHENTICITY: null },
  regulatoryAuthority: null,
};

const NOW = 2026.66;

describe('I2: the two tracks are ranked separately', () => {
  it('collapses X to zero on the authenticity track', () => {
    const sig = scoreMosca({
      purpose: 'DIGITAL_SIGNATURE',
      controlClass: 'SELF',
      secrecyLifetimeYears: 25,
      currentYear: NOW,
      policy: PHYSICS_ONLY,
    });
    expect(sig.urgencyTrack).toBe('AUTHENTICITY');
    expect(sig.x).toBe(0);
  });

  it('applies X on the confidentiality track', () => {
    const kex = scoreMosca({
      purpose: 'KEY_ESTABLISHMENT',
      controlClass: 'SELF',
      secrecyLifetimeYears: 25,
      currentYear: NOW,
      policy: PHYSICS_ONLY,
    });
    expect(kex.urgencyTrack).toBe('CONFIDENTIALITY');
    expect(kex.x).toBe(25);
    expect(kex.late).toBe(true);
  });
});

describe('regulatory vs physics constraint', () => {
  it('makes the EO deadline binding for a signature on hardware', () => {
    const r = scoreMosca({
      purpose: 'DIGITAL_SIGNATURE',
      controlClass: 'HARDWARE',
      secrecyLifetimeYears: 0,
      currentYear: NOW,
      policy: EO,
    });
    // physics: 2035 - 2026.66 - 6 = +2.34 slack. regulation: 2032 - 2026.66 - 6 = -0.66.
    expect(r.crqc.slackYears).toBeCloseTo(2.34, 2);
    expect(r.regulatory?.slackYears).toBeCloseTo(-0.66, 2);
    expect(r.bindingConstraint).toBe('REGULATORY');
    expect(r.late).toBe(true);
  });

  it('the same finding is NOT late under a physics-only pack - the delta is the mandate', () => {
    const args = {
      purpose: 'DIGITAL_SIGNATURE',
      controlClass: 'HARDWARE',
      secrecyLifetimeYears: 0,
      currentYear: NOW,
    } as const;
    expect(scoreMosca({ ...args, policy: EO }).late).toBe(true);
    expect(scoreMosca({ ...args, policy: PHYSICS_ONLY }).late).toBe(false);
  });

  it('falls back to CRQC when the pack asserts no deadline', () => {
    const r = scoreMosca({
      purpose: 'KEY_ESTABLISHMENT',
      controlClass: 'SELF',
      secrecyLifetimeYears: 3,
      currentYear: NOW,
      policy: PHYSICS_ONLY,
    });
    expect(r.regulatory).toBeNull();
    expect(r.bindingConstraint).toBe('CRQC');
  });

  it('ranks a VENDOR_LOCKED key exchange as a procurement emergency', () => {
    const r = scoreMosca({
      purpose: 'KEY_ESTABLISHMENT',
      controlClass: 'VENDOR_LOCKED',
      secrecyLifetimeYears: 7,
      currentYear: NOW,
      policy: EO,
    });
    expect(r.late).toBe(true);
    expect(r.regulatory?.slackYears).toBeCloseTo(0.34, 2);
    expect(r.crqc.slackYears).toBeCloseTo(-2.66, 2);
    expect(r.bindingConstraint).toBe('CRQC');
  });
});

describe('provenance', () => {
  it('marks an operator-supplied secrecy lifetime as an ASSUMPTION', () => {
    const r = scoreMosca({
      purpose: 'DATA_ENCRYPTION',
      controlClass: 'SELF',
      secrecyLifetimeYears: 10,
      secrecyLifetimeAssumed: true,
      currentYear: NOW,
      policy: EO,
    });
    expect(isTainted(r.factor)).toBe(true);
  });

  it('cites the policy pack version on every Z and Y term', () => {
    const r = scoreMosca({
      purpose: 'KEY_ESTABLISHMENT',
      controlClass: 'SELF',
      secrecyLifetimeYears: 1,
      currentYear: NOW,
      policy: EO,
    });
    const labels = JSON.stringify(r.factor);
    expect(labels).toContain('eo-14412@1.0.0');
    expect(labels).toContain('EO 14412 sec. 4');
  });
});
