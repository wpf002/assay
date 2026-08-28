import { describe, expect, it } from 'vitest';
import { gate, isTainted, makeAsset, type Factor, type Finding, type Modality, type Occurrence } from '@assay/core';
import { assemble } from '../src/index.js';

const ASSET = makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT');

const finding = (
  modality: Modality,
  locator: string,
  over: Partial<Finding> = {},
): Finding => ({
  asset: ASSET,
  systemId: 'svc',
  controlClass: 'SELF',
  evidence: {
    modality,
    locator,
    raw: `observed at ${locator}`,
    collectedAt: '2026-08-28T00:00:00.000Z',
    collectorVersion: 'test',
  },
  ...over,
});

describe('the grouping decision', () => {
  it('folds many call sites of one asset in one system into ONE work item', () => {
    const findings = Array.from({ length: 400 }, (_, i) =>
      finding('SOURCE_AST', `src/f${i}.ts:1`),
    );
    const { occurrences } = assemble(findings);
    expect(occurrences).toHaveLength(1);
    // Nothing is lost - every location survives inside the evidence.
    expect(occurrences[0]?.evidence).toHaveLength(400);
    expect(Number(occurrences[0]?.confidence.value)).toBe(0.95);
  });

  it('splits on control class, because our code and a vendor blob have different Y', () => {
    const { occurrences } = assemble([
      finding('SOURCE_AST', 'src/a.ts:1'),
      finding('DEPENDENCY', 'package.json:3', { controlClass: 'VENDOR_UPGRADEABLE' }),
    ]);
    expect(occurrences).toHaveLength(2);
  });

  it('splits on system', () => {
    const { occurrences } = assemble([
      finding('SOURCE_AST', 'a.ts:1'),
      finding('SOURCE_AST', 'a.ts:1', { systemId: 'other' }),
    ]);
    expect(occurrences).toHaveLength(2);
  });

  it('deduplicates assets by content hash', () => {
    const { assets } = assemble([
      finding('SOURCE_AST', 'a.ts:1'),
      finding('NETWORK_ACTIVE', 'h:443'),
    ]);
    expect(assets).toHaveLength(1);
  });
});

describe('determinism', () => {
  it('produces identical output regardless of detector ordering', () => {
    const a = [
      finding('SOURCE_AST', 'b.ts:2'),
      finding('NETWORK_ACTIVE', 'h:443'),
      finding('SOURCE_AST', 'a.ts:1'),
    ];
    const b = [a[1] as Finding, a[2] as Finding, a[0] as Finding];
    expect(JSON.stringify(assemble(a))).toBe(JSON.stringify(assemble(b)));
  });

  it('gives an occurrence a stable id across runs', () => {
    const first = assemble([finding('SOURCE_AST', 'a.ts:1')]).occurrences[0]?.id;
    const second = assemble([finding('SOURCE_AST', 'a.ts:1')]).occurrences[0]?.id;
    expect(first).toBe(second);
  });
});

describe('confidence flows through', () => {
  it('corroborates across independent modalities', () => {
    const { occurrences } = assemble([
      finding('SOURCE_AST', 'a.ts:1'),
      finding('NETWORK_ACTIVE', 'h:443'),
      finding('PKI_CERTIFICATE', 'sha256:ab'),
    ]);
    expect(Number(occurrences[0]?.confidence.value)).toBeGreaterThan(0.999);
  });

  it('does not let dependency evidence lift source evidence', () => {
    const source = assemble([finding('SOURCE_AST', 'a.ts:1')]);
    const both = assemble([finding('SOURCE_AST', 'a.ts:1'), finding('DEPENDENCY', 'package.json:2')]);
    expect(Number(both.occurrences[0]?.confidence.value)).toBe(
      Number(source.occurrences[0]?.confidence.value),
    );
  });
});

describe('detector assumptions reach the export gate', () => {
  it('taints the confidence tree without changing the number', () => {
    const plain = assemble([finding('SOURCE_AST', 'a.py:1')]);
    const tainted = assemble([
      { ...finding('SOURCE_AST', 'a.py:1'), assumptions: ['developer asserts usedforsecurity=False'] },
    ]);
    expect(Number(tainted.occurrences[0]?.confidence.value)).toBe(
      Number(plain.occurrences[0]?.confidence.value),
    );
    expect(isTainted(tainted.occurrences[0]?.confidence as Factor)).toBe(true);
    expect(isTainted(plain.occurrences[0]?.confidence as Factor)).toBe(false);
  });

  it('downgrades the assertion from CONFIRMED to OBSERVED', () => {
    const tainted = assemble([
      { ...finding('SOURCE_AST', 'a.py:1'), assumptions: ['developer asserts usedforsecurity=False'] },
    ]);
    expect(gate(tainted.occurrences[0] as Occurrence).assertionLevel).toBe('OBSERVED');
  });

  it('deduplicates identical assumptions across many findings', () => {
    const { occurrences } = assemble(
      Array.from({ length: 5 }, (_, i) => ({
        ...finding('SOURCE_AST', `a.py:${i}`),
        assumptions: ['same claim'],
      })),
    );
    const assumptionNodes = (occurrences[0]?.confidence.sources ?? []).filter(
      (f) => f.kind === 'ASSUMPTION',
    );
    expect(assumptionNodes).toHaveLength(1);
  });
});
