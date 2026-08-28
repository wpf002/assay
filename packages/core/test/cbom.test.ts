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

/** An occurrence whose confidence tree carries an operator assumption. */
const taintedOcc = (id: string, evidence: Evidence[], extra: Partial<Occurrence> = {}): Occurrence =>
  occ(id, evidence, {
    confidence: {
      kind: 'INFERENCE',
      label: 'confidence',
      value: computeConfidence(evidence).value,
      weight: 1,
      sources: [
        {
          kind: 'ASSUMPTION',
          label: 'operator asserts this path never ships',
          value: true,
          weight: 1,
          sources: [],
        },
      ],
    },
    ...extra,
  });

type Prop = { readonly name: string; readonly value: string };

const component = (doc: { components: readonly unknown[] }): {
  evidence: { identity: { confidence: number } };
  properties: readonly Prop[];
} => doc.components[0] as never;

const propOf = (doc: { components: readonly unknown[] }, name: string): string | undefined =>
  component(doc).properties.find((p) => p.name === name)?.value;

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
          via: 'ENTRY_POINT',
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

  it('omits the callstack when reachability found no path to show', () => {
    // A `callstack: { frames: [] }` reads as "we traced this" when we did not.
    // Config and network evidence are reached with no call path to display.
    const reached = [
      occ('o1', [ev('SOURCE_CONFIG', 'nginx.conf:3')], {
        reachability: {
          reachable: true,
          via: 'ENTRY_POINT',
          entryPoint: 'http:POST /v1/payments',
          path: [],
          factor: { kind: 'INFERENCE', label: 'reached', value: true, weight: 1, sources: [] },
        },
      }),
    ];
    expect(JSON.stringify(toCycloneDX(reached, [ASSET], OPTS))).not.toContain('callstack');
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

describe('a component folds many occurrences of one asset', () => {
  const clean = occ('aaa', [ev('SOURCE_AST', 'a.ts:12')], { systemId: 'svc-a' });
  const dirty = taintedOcc('zzz', [ev('SOURCE_AST', 'sign.go:99')], {
    systemId: 'svc-b',
    controlClass: 'VENDOR_LOCKED',
  });

  it('asserts at the weakest level, so a clean sibling cannot launder a tainted one (I6)', () => {
    const doc = toCycloneDX([clean, dirty], [ASSET], OPTS);
    expect(doc.components).toHaveLength(1);
    expect(propOf(doc, 'assay:occurrenceCount')).toBe('2');
    expect(propOf(doc, 'assay:assertionLevel')).toBe('OBSERVED');
    expect(propOf(doc, 'assay:downgradeReason')).toContain('operator asserts this path never ships');
  });

  it('asserts at the same level whichever occurrence id sorts first', () => {
    // The winner used to be settled by a reduce over confidence, which keeps its
    // left operand on a tie - so the exported level turned on a sha256 prefix.
    const swapped = toCycloneDX(
      [occ('zzz', [ev('SOURCE_AST', 'a.ts:12')], { systemId: 'svc-a' }),
       taintedOcc('aaa', [ev('SOURCE_AST', 'sign.go:99')], { systemId: 'svc-b' })],
      [ASSET],
      OPTS,
    );
    expect(propOf(swapped, 'assay:assertionLevel')).toBe('OBSERVED');
  });

  it('never exports a confidence no occurrence in the estate holds', () => {
    // A string match in one service and a vendor questionnaire about another are
    // not two observations of the same thing, so they do not corroborate: pooling
    // them noisy-OR'd 0.30 and 0.40 into 0.58.
    const doc = toCycloneDX(
      [
        occ('binary', [ev('BINARY_STRING', 'lib.so:1')], { systemId: 'svc-a' }),
        occ('vendor', [ev('ASSERTED', 'vendor-q:acme')], { systemId: 'svc-b' }),
      ],
      [ASSET],
      { ...OPTS, includeSuspected: true },
    );
    expect(propOf(doc, 'assay:confidence')).toBe('0.4');
    expect(component(doc).evidence.identity.confidence).toBe(40);
  });

  it('carries each occurrence its own factor tree, assumptions included', () => {
    const doc = toCycloneDX([clean, dirty], [ASSET], { ...OPTS, includeFactorTrees: true });
    const factor = propOf(doc, 'assay:factor') ?? '';
    expect(factor).toContain('ASSUMPTION');
    expect(factor).toContain('occurrence aaa');
    expect(factor).toContain('occurrence zzz');
  });

  it('is byte-identical whichever order the occurrences arrive in', () => {
    // Determinism is a product claim: the same estate produces the same CBOM on
    // every run, and detectors do not emit in a fixed order. The component picks
    // one occurrence's call path out of many, so the choice has to be sorted.
    const reachable = (id: string, file: string): Occurrence =>
      occ(id, [ev('SOURCE_AST', `${file}:12`)], {
        systemId: `svc-${id}`,
        reachability: {
          reachable: true,
          via: 'ENTRY_POINT',
          entryPoint: `http:GET /${id}`,
          path: [{ module: id, function: 'sign', fullFilename: file, line: 1 }],
          factor: { kind: 'INFERENCE', label: 'reached', value: true, weight: 1, sources: [] },
        },
      });
    const first = reachable('aaa', 'src/a.ts');
    const second = reachable('zzz', 'src/z.ts');
    expect(JSON.stringify(toCycloneDX([second, first], [ASSET], OPTS))).toBe(
      JSON.stringify(toCycloneDX([first, second], [ASSET], OPTS)),
    );
    expect(JSON.stringify(toCycloneDX([dirty, clean], [ASSET], OPTS))).toBe(
      JSON.stringify(toCycloneDX([clean, dirty], [ASSET], OPTS)),
    );
  });
});
