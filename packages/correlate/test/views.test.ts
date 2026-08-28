import { describe, expect, it } from 'vitest';
import { computeConfidence, makeAsset, type Evidence, type Modality, type Occurrence } from '@assay/core';
import { answerOf, divergences, systemViews } from '../src/index.js';

const RSA = makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT');
const X25519 = makeAsset('X25519', {}, 'KEY_ESTABLISHMENT');
const AES = makeAsset('AES', { keySize: 128, mode: 'CBC' }, 'DATA_ENCRYPTION');

const ev = (modality: Modality): Evidence => ({
  modality,
  locator: `${modality}:1`,
  raw: 'x',
  collectedAt: '2026-08-28T00:00:00.000Z',
  collectorVersion: 'test',
});

const occ = (assetId: string, modalities: Modality[], systemId = 'svc'): Occurrence => {
  const evidence = modalities.map(ev);
  return {
    id: `${assetId}-${modalities.join('+')}-${systemId}`,
    assetId,
    systemId,
    controlClass: 'SELF',
    reachability: null,
    evidence,
    confidence: computeConfidence(evidence),
  };
};

describe('which question does this evidence answer', () => {
  it('separates deployment from capability', () => {
    expect(answerOf(occ(RSA.id, ['NETWORK_ACTIVE']))).toBe('DEPLOYED');
    expect(answerOf(occ(RSA.id, ['SOURCE_AST']))).toBe('CAPABLE');
    expect(answerOf(occ(RSA.id, ['SOURCE_AST', 'NETWORK_ACTIVE']))).toBe('BOTH');
  });

  it('counts a parsed certificate and a managed key as deployment facts', () => {
    expect(answerOf(occ(RSA.id, ['PKI_CERTIFICATE']))).toBe('DEPLOYED');
    expect(answerOf(occ(RSA.id, ['CLOUD_KMS_API']))).toBe('DEPLOYED');
  });
});

describe('the two views are kept apart, not resolved', () => {
  const occurrences = [
    // Source says the service can do both.
    occ(RSA.id, ['SOURCE_AST']),
    occ(X25519.id, ['SOURCE_AST']),
    // The wire says only RSA was negotiated, and shows an AES suite the
    // source never mentions.
    occ(RSA.id, ['NETWORK_ACTIVE']),
    occ(AES.id, ['NETWORK_ACTIVE']),
  ];

  it('reports RSA as corroborated by both, which is the strongest position', () => {
    const [view] = systemViews(occurrences);
    expect(view?.corroborated).toEqual([RSA.id]);
  });

  it('keeps X25519 as capable-but-not-observed rather than discarding it', () => {
    const [view] = systemViews(occurrences);
    expect(view?.capableOnly).toEqual([X25519.id]);
  });

  it('keeps AES as deployed-without-source rather than discarding it', () => {
    const [view] = systemViews(occurrences);
    expect(view?.deployedOnly).toEqual([AES.id]);
  });

  it('names both divergences with a reason a human can act on', () => {
    const d = divergences(occurrences, [RSA, X25519, AES]);
    expect(d.map((x) => x.kind).sort()).toEqual([
      'CAPABLE_BUT_NOT_OBSERVED',
      'DEPLOYED_WITHOUT_SOURCE',
    ]);
    expect(d.find((x) => x.kind === 'CAPABLE_BUT_NOT_OBSERVED')?.note).toContain('downgrade');
  });

  it('claims no divergence when only one kind of evidence exists', () => {
    // With source alone, "capable but not observed" is a statement about the
    // scan, not about the estate.
    expect(divergences([occ(RSA.id, ['SOURCE_AST'])], [RSA])).toEqual([]);
    expect(divergences([occ(RSA.id, ['NETWORK_ACTIVE'])], [RSA])).toEqual([]);
  });

  it('does not mix systems', () => {
    const views = systemViews([
      occ(RSA.id, ['NETWORK_ACTIVE'], 'a'),
      occ(X25519.id, ['SOURCE_AST'], 'b'),
    ]);
    expect(views.map((v) => v.systemId)).toEqual(['a', 'b']);
    expect(views[0]?.capable.size).toBe(0);
  });
});
