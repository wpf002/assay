import { describe, expect, it } from 'vitest';
import {
  computeConfidence,
  derivationDepth,
  diffScans,
  explain,
  blockers,
  citations,
  makeAsset,
  scoreMosca,
  type Evidence,
  type Modality,
  type MoscaPolicy,
  type Occurrence,
  type ScanSnapshot,
} from '../src/index.js';

const ASSET = makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT');

const ev = (modality: Modality, locator = 'a.ts:1'): Evidence => ({
  modality,
  locator,
  raw: 'x',
  collectedAt: '2026-08-28T00:00:00.000Z',
  collectorVersion: 'test',
});

const occ = (modalities: Modality[], over: Partial<Occurrence> = {}): Occurrence => {
  const evidence = modalities.map((m) => ev(m));
  return {
    // A stable id across scans is what makes the whole diff possible.
    id: 'occ-1',
    assetId: ASSET.id,
    systemId: 'svc',
    controlClass: 'SELF',
    reachability: null,
    evidence,
    confidence: computeConfidence(evidence),
    ...over,
  };
};

const reach = (reachable: boolean): Occurrence['reachability'] => ({
  reachable,
  via: reachable ? 'ENTRY_POINT' : 'NONE',
  entryPoint: reachable ? 'src/server.ts' : null,
  path: [],
  factor: { kind: 'INFERENCE', label: 'r', value: reachable, weight: 1, sources: [] },
});

const snap = (scanId: string, occurrences: Occurrence[], pack = 'eo-14412'): ScanSnapshot => ({
  scanId,
  takenAt: `2026-0${scanId === 'a' ? 8 : 9}-01T00:00:00.000Z`,
  policyPackId: pack,
  policyPackVersion: '1.0.0',
  occurrences,
  assets: [ASSET],
});

describe('what actually changed', () => {
  it('reports a finding present only in the newer scan as APPEARED', () => {
    const d = diffScans(snap('a', []), snap('b', [occ(['SOURCE_AST'])]));
    expect(d.counts.APPEARED).toBe(1);
  });

  it('reports a finding that went away as REMEDIATED, and says it might be coverage', () => {
    const d = diffScans(snap('a', [occ(['SOURCE_AST'])]), snap('b', []));
    expect(d.entries[0]?.kind).toBe('REMEDIATED');
    expect(d.entries[0]?.reason).toContain('the scan no longer reaches it');
  });

  it('reports becoming reachable as a REGRESSION, because that is about the estate', () => {
    const d = diffScans(
      snap('a', [occ(['SOURCE_AST'], { reachability: reach(false) })]),
      snap('b', [occ(['SOURCE_AST'], { reachability: reach(true) })]),
    );
    expect(d.entries[0]?.kind).toBe('REGRESSED');
  });

  it('does not call the first run of the reachability pass a regression', () => {
    // A scan that found no entry point analyzed nothing, so every occurrence in
    // it is null. Reading null as "was not reachable" reports the whole estate
    // as REGRESSED the day someone adds an entry point the analyzer recognises.
    const d = diffScans(
      snap('a', [occ(['SOURCE_AST'])]),
      snap('b', [occ(['SOURCE_AST'], { reachability: reach(true) })]),
    );
    expect(d.counts.REGRESSED).toBe(0);
    expect(d.entries[0]?.kind).toBe('RECLASSIFIED');
    expect(d.entries[0]?.reason).toContain('analyzed for the first time');
  });

  it('reports a lost reachability verdict rather than swallowing it', () => {
    const d = diffScans(
      snap('a', [occ(['SOURCE_AST'], { reachability: reach(true) })]),
      snap('b', [occ(['SOURCE_AST'])]),
    );
    expect(d.entries[0]?.kind).toBe('RECLASSIFIED');
    expect(d.entries[0]?.reason).toContain('coverage question');
  });

  it('reports becoming unreachable as an improvement', () => {
    const d = diffScans(
      snap('a', [occ(['SOURCE_AST'], { reachability: reach(true) })]),
      snap('b', [occ(['SOURCE_AST'], { reachability: reach(false) })]),
    );
    expect(d.entries[0]?.kind).toBe('IMPROVED');
  });
});

describe('a better scanner is not a security incident', () => {
  it('calls a rise from OBSERVED to CONFIRMED RECLASSIFIED, never REGRESSED', () => {
    const d = diffScans(
      snap('a', [occ(['NETWORK_PASSIVE'])]),
      snap('b', [occ(['NETWORK_PASSIVE', 'SOURCE_AST'])]),
    );
    // The crypto was always there. Corroborating evidence arrived.
    expect(d.entries[0]?.before?.assertionLevel).toBe('OBSERVED');
    expect(d.entries[0]?.after?.assertionLevel).toBe('CONFIRMED');
    expect(d.entries[0]?.kind).toBe('RECLASSIFIED');
    expect(d.entries[0]?.reason).toContain('not on a change to the code');
  });

  it('treats a fall in assertion as a coverage question, not a fix', () => {
    const d = diffScans(
      snap('a', [occ(['SOURCE_AST'])]),
      snap('b', [occ(['NETWORK_PASSIVE'])]),
    );
    expect(d.entries[0]?.kind).toBe('RECLASSIFIED');
    expect(d.entries[0]?.reason).toContain('coverage question');
  });

  it('notes a newly corroborating modality even when the level did not move', () => {
    const d = diffScans(
      snap('a', [occ(['SOURCE_AST'])]),
      snap('b', [occ(['SOURCE_AST', 'PKI_CERTIFICATE'])]),
    );
    expect(d.entries[0]?.kind).toBe('RECLASSIFIED');
    expect(d.entries[0]?.reason).toContain('PKI_CERTIFICATE');
  });

  it('says nothing changed when nothing changed', () => {
    const d = diffScans(snap('a', [occ(['SOURCE_AST'])]), snap('b', [occ(['SOURCE_AST'])]));
    expect(d.counts.UNCHANGED).toBe(1);
  });

  it('flags when the two scans were ranked under different policy', () => {
    const d = diffScans(
      snap('a', [occ(['SOURCE_AST'])], 'nist-ir-8547-draft'),
      snap('b', [occ(['SOURCE_AST'])], 'eo-14412'),
    );
    expect(d.policyChanged).toBe(true);
  });
});

/* ------------------------------------------------------------- derivations */

const POLICY: MoscaPolicy = {
  packId: 'eo-14412',
  packVersion: '1.0.0',
  crqcYear: 2035,
  deprecateYear: 2030,
  disallowYear: 2035,
  regulatoryDeadlines: { CONFIDENTIALITY: 2031, AUTHENTICITY: 2032 },
  regulatoryAuthority: 'EO 14412 sec. 4',
  migrationYearsByControl: {
    SELF: 0.5,
    VENDOR_UPGRADEABLE: 1.5,
    VENDOR_LOCKED: 4,
    HARDWARE: 6,
    PROTOCOL_BILATERAL: 5,
  },
};

describe('the three-click budget is a property of the tree', () => {
  it('reaches every term of a slack figure within three hops', () => {
    const m = scoreMosca({
      purpose: 'KEY_ESTABLISHMENT',
      controlClass: 'HARDWARE',
      secrecyLifetimeYears: 5,
      currentYear: 2026.66,
      policy: POLICY,
    });
    // slack -> constraint -> X/Y/Z. Any deeper and the UI gate is unmeetable.
    expect(derivationDepth(m.factor)).toBeLessThanOrEqual(2);
  });

  it('reaches raw evidence from a confidence figure within three hops', () => {
    const c = computeConfidence([ev('SOURCE_AST'), ev('NETWORK_ACTIVE', 'h:443')]);
    expect(derivationDepth(c)).toBeLessThanOrEqual(2);
  });
});

describe('explain', () => {
  it('gives every node an addressable id and a depth', () => {
    const node = explain(computeConfidence([ev('SOURCE_AST')]));
    expect(node.id).toBe('f');
    expect(node.children[0]?.id).toBe('f.0');
    expect(node.children[0]?.children[0]?.depth).toBe(2);
  });

  it('marks the tainted path so the UI can show why a finding is not CONFIRMED', () => {
    const tainted = {
      kind: 'INFERENCE' as const,
      label: 'confidence',
      value: 0.95,
      weight: 1,
      sources: [
        { kind: 'ASSUMPTION' as const, label: 'operator says it ships', value: true, weight: 1, sources: [] },
      ],
    };
    expect(explain(tainted).tainted).toBe(true);
    expect(blockers(tainted)).toEqual(['operator says it ships']);
  });

  it('collects raw observations as a citation list', () => {
    const c = computeConfidence([ev('SOURCE_AST', 'a.ts:1'), ev('SOURCE_AST', 'b.ts:2')]);
    expect(citations(c).map((f) => f.label)).toEqual([
      'SOURCE_AST @ a.ts:1',
      'SOURCE_AST @ b.ts:2',
    ]);
  });
});
