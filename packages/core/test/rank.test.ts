import { describe, expect, it } from 'vitest';
import {
  computeConfidence,
  makeAsset,
  rank,
  type Evidence,
  type Modality,
  type MoscaPolicy,
  type Occurrence,
} from '../src/index.js';

const POLICY: MoscaPolicy = {
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

const ev = (modality: Modality): Evidence => ({
  modality,
  locator: 'a.ts:1',
  raw: 'x',
  collectedAt: '2026-08-28T00:00:00.000Z',
  collectorVersion: 'test',
});

const KEX = makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT');
const SIG = makeAsset('ECDSA', { curve: 'P-256' }, 'DIGITAL_SIGNATURE');
const SAFE = makeAsset('ML-KEM', { parameterSet: '768' }, 'KEY_ESTABLISHMENT');

const occ = (id: string, assetId: string, o: Partial<Occurrence> = {}): Occurrence => ({
  id,
  assetId,
  systemId: 'svc',
  controlClass: 'SELF',
  reachability: null,
  evidence: [ev('SOURCE_AST')],
  confidence: computeConfidence([ev('SOURCE_AST')]),
  ...o,
});

const reach = (reachable: boolean): Occurrence['reachability'] => ({
  reachable,
  via: reachable ? 'ENTRY_POINT' : 'NONE',
  entryPoint: reachable ? 'http:GET /' : null,
  path: [],
  factor: { kind: 'INFERENCE', label: 'reachability', value: reachable, weight: 1, sources: [] },
});

const OPTS = {
  policy: POLICY,
  currentYear: 2026.66,
  secrecyLifetime: () => ({ years: 5, assumed: false }),
};

describe('two worklists', () => {
  it('never pools confidentiality and authenticity', () => {
    const w = rank(
      [occ('a', KEX.id, { reachability: reach(true) }), occ('b', SIG.id, { reachability: reach(true) })],
      [KEX, SIG],
      OPTS,
    );
    expect(w.confidentiality.map((f) => f.occurrenceId)).toEqual(['a']);
    expect(w.authenticity.map((f) => f.occurrenceId)).toEqual(['b']);
  });

  it('excludes quantum-safe assets from the worklists entirely', () => {
    const w = rank([occ('s', SAFE.id, { reachability: reach(true) })], [SAFE], OPTS);
    expect(w.confidentiality).toHaveLength(0);
    expect(w.headline.denominator).toBe(0);
  });

  it('sorts by ascending slack so the most overdue item is row one', () => {
    const w = rank(
      [
        occ('slow', KEX.id, { controlClass: 'HARDWARE', reachability: reach(true) }),
        occ('fast', KEX.id, { controlClass: 'SELF', reachability: reach(true) }),
      ],
      [KEX],
      OPTS,
    );
    expect(w.confidentiality.map((f) => f.occurrenceId)).toEqual(['slow', 'fast']);
  });
});

describe('I5: presence is not exposure', () => {
  it('reports unreached findings separately and keeps them out of the headline', () => {
    const w = rank(
      [
        occ('prod', KEX.id, { reachability: reach(true) }),
        occ('fixture', KEX.id, { reachability: reach(false) }),
      ],
      [KEX],
      OPTS,
    );
    expect(w.confidentiality.map((f) => f.occurrenceId)).toEqual(['prod']);
    expect(w.unreached.map((f) => f.occurrenceId)).toEqual(['fixture']);
    expect(w.headline.denominator).toBe(1);
  });

  it('distinguishes "not analyzed" from "analyzed and not reached"', () => {
    const w = rank([occ('u', KEX.id)], [KEX], OPTS);
    expect(w.unreached).toHaveLength(0);
    expect(w.confidentiality).toHaveLength(1);
    expect(w.confidentiality[0]?.reachable).toBeNull();
  });

  it('keeps findings with no verdict in the worklist when a sibling comes back unreached', () => {
    // Reachability is decided per occurrence: a certificate has no call site to
    // trace even after the pass runs. Treating one unreached sibling as proof
    // the pass is complete drops every finding nobody has looked at.
    const w = rank(
      [
        occ('n1', KEX.id, { controlClass: 'HARDWARE' }),
        occ('n2', KEX.id, { controlClass: 'HARDWARE' }),
        occ('n3', KEX.id, { controlClass: 'HARDWARE' }),
        occ('dead', KEX.id, { reachability: reach(false) }),
      ],
      [KEX],
      OPTS,
    );
    expect(w.confidentiality.map((f) => f.occurrenceId)).toEqual(['n1', 'n2', 'n3']);
    expect(w.unreached.map((f) => f.occurrenceId)).toEqual(['dead']);
    expect(w.headline.numerator).toBe(3);
    expect(w.headline.denominator).toBe(3);
  });
});

describe('headline metric', () => {
  it('is a ratio with a walkable derivation, not a heuristic score', () => {
    const w = rank(
      [
        occ('late', KEX.id, { controlClass: 'HARDWARE', reachability: reach(true) }),
        occ('ok', SIG.id, { controlClass: 'SELF', reachability: reach(true) }),
      ],
      [KEX, SIG],
      OPTS,
    );
    expect(w.headline.numerator).toBe(1);
    expect(w.headline.denominator).toBe(2);
    expect(w.headline.value).toBe(0.5);
    expect(w.headline.factor.sources.length).toBeGreaterThan(0);
  });

  it('counts only CONFIRMED findings', () => {
    const observed = occ('observed', KEX.id, {
      evidence: [ev('NETWORK_PASSIVE')],
      confidence: computeConfidence([ev('NETWORK_PASSIVE')]),
      reachability: reach(true),
    });
    const w = rank([observed], [KEX], OPTS);
    expect(w.confidentiality).toHaveLength(1);
    expect(w.confidentiality[0]?.assertionLevel).toBe('OBSERVED');
    expect(w.headline.denominator).toBe(0);
  });
});

describe('D1: dependency-grade evidence never leads the worklist', () => {
  it('holds SUSPECTED findings in hints, not in either track', () => {
    const hint = occ('dep', KEX.id, {
      controlClass: 'VENDOR_UPGRADEABLE',
      evidence: [ev('DEPENDENCY')],
      confidence: computeConfidence([ev('DEPENDENCY')]),
      reachability: reach(true),
    });
    const real = occ('src', KEX.id, { reachability: reach(true) });
    const w = rank([hint, real], [KEX], OPTS);

    // A vendor library has a worse Y than our own code, so sorting purely by
    // slack would put a 0.35-confidence hint at the top of the page.
    expect(w.hints.map((f) => f.occurrenceId)).toEqual(['dep']);
    expect(w.confidentiality.map((f) => f.occurrenceId)).toEqual(['src']);
    expect(w.headline.denominator).toBe(1);
  });
});

describe('re-ranking under a different pack is a diff', () => {
  it('changes lateness without changing the finding set', () => {
    const physics: MoscaPolicy = {
      ...POLICY,
      packId: 'nist-ir-8547-draft',
      regulatoryDeadlines: { CONFIDENTIALITY: null, AUTHENTICITY: null },
      regulatoryAuthority: null,
    };
    const occs = [occ('sig', SIG.id, { controlClass: 'HARDWARE', reachability: reach(true) })];
    const eo = rank(occs, [SIG], OPTS);
    const nist = rank(occs, [SIG], { ...OPTS, policy: physics });
    expect(eo.authenticity[0]?.late).toBe(true);
    expect(nist.authenticity[0]?.late).toBe(false);
    expect(eo.authenticity).toHaveLength(nist.authenticity.length);
  });
});
