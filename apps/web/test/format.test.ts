import { describe, expect, it } from 'vitest';
import type { RankedFinding } from '../src/lib/api';
import { assetLabel, due, whyThisDate, type MoscaTerms } from '../src/lib/format';

/**
 * The words on the row. Every one of these strings is read by someone who is
 * not the engineer who wrote the rule, so a dropped parameter or a signed
 * number in the prose is a wrong answer, not a typo.
 */

const finding = (over: Partial<RankedFinding>): RankedFinding => ({
  occurrenceId: 'o1',
  assetId: 'a1',
  systemId: 'svc',
  assetName: 'RSA(modulusLength=2048)',
  purpose: 'KEY_ESTABLISHMENT',
  controlClass: 'SELF',
  track: 'CONFIDENTIALITY',
  assertionLevel: 'CONFIRMED',
  confidence: 0.9,
  slackYears: 1.5,
  late: false,
  bindingConstraint: 'CRQC',
  reachable: true,
  reachedVia: 'ENTRY_POINT',
  mosca: {
    x: 5,
    y: 0.5,
    crqc: { horizonYears: 8.34, slackYears: 2.84, late: false },
    regulatory: null,
  },
  ...over,
});

const label = (assetName: string): string => assetLabel(finding({ assetName }));

describe('assetLabel', () => {
  it('keeps the group of a curve the catalog does not name', () => {
    expect(label('ECDH(group=brainpoolP256r1)')).toBe('ECDH brainpoolP256r1');
    expect(label('ECDH(group=brainpoolP384r1)')).toBe('ECDH brainpoolP384r1');
  });

  it('keeps the padding that distinguishes two key-transport rows', () => {
    expect(label('RSA(mode=KEY_TRANSPORT,padding=RSA_PKCS1_OAEP_PADDING)')).toBe(
      'RSA key transport RSA_PKCS1_OAEP_PADDING',
    );
    expect(label('RSA(mode=KEY_TRANSPORT)')).toBe('RSA key transport');
  });

  it('still prefers the named curve and the established spellings', () => {
    expect(label('ECDH(curve=P-256)')).toBe('ECDH P-256');
    expect(label('ECDH(curve=P-256,ephemeral=true)')).toBe('ECDHE');
    expect(label('EdDSA(curve=Ed25519)')).toBe('Ed25519');
    expect(label('SHA2(outputLength=256)')).toBe('SHA-256');
    expect(label('RSA(modulusLength=2048)')).toBe('RSA-2048');
  });
});

describe('due', () => {
  it('counts one month in the singular', () => {
    expect(due(finding({ slackYears: 0.09 }))).toBe('1 month left');
    expect(due(finding({ slackYears: -0.09, late: true }))).toBe('1 month past due');
  });

  it('says less than a month rather than none of it', () => {
    expect(due(finding({ slackYears: 0.01 }))).toBe('less than a month left');
  });

  it('switches to years at a year', () => {
    expect(due(finding({ slackYears: 0.96 }))).toBe('12 months left');
    expect(due(finding({ slackYears: 1.04 }))).toBe('1.0 years left');
    expect(due(finding({ slackYears: -2.53, late: true }))).toBe('2.5 years past due');
  });
});

const terms = (over: Partial<MoscaTerms>): MoscaTerms => ({
  x: 0,
  y: 6,
  bindingConstraint: 'REGULATORY',
  crqc: { horizonYears: 8.34, slackYears: 2.34 },
  regulatory: { deadlineYear: 2032, horizonYears: 5.34, slackYears: -0.66 },
  controlClass: 'HARDWARE',
  track: 'AUTHENTICITY',
  policy: { packId: 'eo-14412', crqcYear: 2035, authority: 'EO 14412 sec. 4' },
  ...over,
});

describe('whyThisDate', () => {
  it('does not offer a negative quantity of time as time you would have had', () => {
    const lines = whyThisDate(
      terms({ crqc: { horizonYears: 8.34, slackYears: -1.66 }, regulatory: { deadlineYear: 2032, horizonYears: 5.34, slackYears: -4.66 } }),
    );
    expect(lines.join(' ')).toContain('you would already have been 1.66 years late');
    expect(lines.join(' ')).not.toContain('-1.66');
  });

  it('still names the physics when the regulation is the earlier of the two', () => {
    expect(whyThisDate(terms({})).join(' ')).toContain('you would have had 2.34 years');
  });
});
