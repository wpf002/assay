import { describe, expect, it } from 'vitest';
import {
  computeConfidence,
  gate,
  makeAsset,
  toCycloneDX,
  type Evidence,
  type Modality,
  type Occurrence,
} from '../src/index.js';

const ev = (modality: Modality, locator: string): Evidence => ({
  modality,
  locator,
  raw: `observed ${modality}`,
  collectedAt: '2026-08-28T00:00:00.000Z',
  collectorVersion: 'test',
  occurrence: { location: locator.split(':')[0] as string, line: 12, symbol: 'generateKeyPairSync' },
});

const occ = (id: string, evidence: Evidence[], extra: Partial<Occurrence> = {}): Occurrence => ({
  id,
  assetId: ASSET.id,
  systemId: 'svc-payments',
  controlClass: 'SELF',
  reachability: null,
  evidence,
  confidence: computeConfidence(evidence),
  ...extra,
});

const ASSET = makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT');

const OPTS = {
  policyPackId: 'eo-14412',
  policyPackVersion: '1.0.0',
  timestamp: '2026-08-28T00:00:00.000Z',
  toolVersion: '0.0.0',
};

describe('I6: the provenance gate', () => {
  it('confirms an untainted AST finding', () => {
    expect(gate(occ('o1', [ev('SOURCE_AST', 'a.ts:12')])).assertionLevel).toBe('CONFIRMED');
  });

  it('never confirms binary strings alone, however many there are', () => {
    const many = Array.from({ length: 500 }, (_, i) => ev('BINARY_STRING', `lib.so:${i}`));
    const g = gate(occ('o2', many));
    expect(g.confidence).toBe(0.3);
    expect(g.assertionLevel).toBe('SUSPECTED');
  });

  it('promotes binary strings once an independent modality corroborates', () => {
    const g = gate(occ('o3', [ev('BINARY_STRING', 'lib.so:1'), ev('NETWORK_ACTIVE', 'h:443')]));
    expect(g.assertionLevel).toBe('CONFIRMED');
  });

  it('downgrades a tainted tree and says why', () => {
    const evidence = [ev('SOURCE_AST', 'a.ts:12')];
    const tainted = occ('o4', evidence, {
      confidence: {
        kind: 'INFERENCE',
        label: 'confidence',
        value: 0.95,
        weight: 1,
        sources: [
          { kind: 'ASSUMPTION', label: 'operator asserted this file ships', value: true, weight: 1, sources: [] },
        ],
      },
    });
    const g = gate(tainted);
    expect(g.assertionLevel).toBe('OBSERVED');
    expect(g.downgradeReason).toContain('operator asserted this file ships');
  });

  it('leaves a vendor questionnaire at SUSPECTED', () => {
    expect(gate(occ('o5', [ev('ASSERTED', 'vendor-q:acme')])).assertionLevel).toBe('SUSPECTED');
  });
});

describe('CycloneDX export', () => {
  const occurrences = [occ('o1', [ev('SOURCE_AST', 'a.ts:12'), ev('NETWORK_ACTIVE', 'api:443')])];

  it('emits 1.7 by default and 1.6 on request', () => {
    expect(toCycloneDX(occurrences, [ASSET], OPTS).specVersion).toBe('1.7');
    expect(toCycloneDX(occurrences, [ASSET], { ...OPTS, profile: 'cyclonedx-1.6' }).specVersion).toBe('1.6');
  });

  it('flags the CISA profile as provisional rather than faking a schema', () => {
    const doc = toCycloneDX(occurrences, [ASSET], { ...OPTS, profile: 'cisa-min-elements' });
    expect(JSON.stringify(doc)).toContain('PROVISIONAL');
  });

  it('is byte-identical for the same evidence set', () => {
    const a = JSON.stringify(toCycloneDX(occurrences, [ASSET], OPTS));
    const shuffled = [occ('o1', [ev('NETWORK_ACTIVE', 'api:443'), ev('SOURCE_AST', 'a.ts:12')])];
    expect(JSON.stringify(toCycloneDX(shuffled, [ASSET], OPTS))).toBe(a);
  });

  it('derives the serial number from content, not from randomness', () => {
    const a = toCycloneDX(occurrences, [ASSET], OPTS);
    const b = toCycloneDX(occurrences, [ASSET], OPTS);
    expect(a.serialNumber).toBe(b.serialNumber);
    expect(a.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]+$/);
  });

  it('carries the modality and its suppression count into evidence.identity.methods', () => {
    const doc = toCycloneDX(occurrences, [ASSET], OPTS);
    const s = JSON.stringify(doc);
    expect(s).toContain('source-code-analysis');
    expect(s).toContain('suppressed as same-group repetition');
  });

  it('emits occurrences with file and line', () => {
    const s = JSON.stringify(toCycloneDX(occurrences, [ASSET], OPTS));
    expect(s).toContain('"line":12');
    expect(s).toContain('generateKeyPairSync');
  });

  it('emits a reachability path into evidence.callstack', () => {
    const reached = [
      occ('o1', [ev('SOURCE_AST', 'a.ts:12')], {
        reachability: {
          reachable: true,
          entryPoint: 'http:POST /v1/payments',
          path: [
            { module: 'api', function: 'handler', fullFilename: 'src/api.ts', line: 4 },
            { module: 'crypto', function: 'sign', fullFilename: 'src/crypto.ts', line: 12 },
          ],
          factor: { kind: 'INFERENCE', label: 'reached', value: true, weight: 1, sources: [] },
        },
      }),
    ];
    const s = JSON.stringify(toCycloneDX(reached, [ASSET], OPTS));
    expect(s).toContain('callstack');
    expect(s).toContain('src/api.ts');
  });

  it('drops SUSPECTED findings unless asked for them', () => {
    const weak = [occ('w', [ev('ASSERTED', 'vendor-q:acme')])];
    expect(toCycloneDX(weak, [ASSET], OPTS).components).toHaveLength(0);
    expect(
      toCycloneDX(weak, [ASSET], { ...OPTS, includeSuspected: true }).components,
    ).toHaveLength(1);
  });

  it('never emits a `uses` edge from manifest evidence', () => {
    const dep = [occ('d', [ev('DEPENDENCY', 'package.json')])];
    const doc = toCycloneDX(dep, [ASSET], { ...OPTS, includeSuspected: true });
    expect(JSON.stringify(doc.dependencies)).not.toContain('"uses"');
  });
});
