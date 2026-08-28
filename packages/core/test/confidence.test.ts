import { describe, expect, it } from 'vitest';
import {
  CORRELATED_GROUPS,
  MODALITIES,
  MODALITY_CEILING,
  computeConfidenceBreakdown,
  requiresCorroboration,
  type Evidence,
  type Modality,
} from '../src/index.js';

const ev = (modality: Modality, locator: string, raw = 'x'): Evidence => ({
  modality,
  locator,
  raw,
  collectedAt: '2026-08-28T00:00:00.000Z',
  collectorVersion: 'test',
});

describe('modality partition', () => {
  it('assigns every modality to exactly one correlated group', () => {
    const seen = new Map<Modality, number>();
    CORRELATED_GROUPS.forEach((g, i) =>
      g.forEach((m) => {
        expect(seen.has(m)).toBe(false);
        seen.set(m, i);
      }),
    );
    for (const m of MODALITIES) expect(seen.has(m)).toBe(true);
  });

  it('holds DEPENDENCY at 0.35 - a library implementing RSA is not a use of RSA (D1)', () => {
    expect(MODALITY_CEILING.DEPENDENCY).toBe(0.35);
  });
});

describe('I1a: same-modality repetition never raises confidence', () => {
  it('caps 400 binary strings at the BINARY_STRING ceiling', () => {
    const many = Array.from({ length: 400 }, (_, i) => ev('BINARY_STRING', `lib.so:${i}`));
    const one = computeConfidenceBreakdown([ev('BINARY_STRING', 'lib.so:0')]);
    const all = computeConfidenceBreakdown(many);
    expect(all.value).toBe(0.3);
    expect(all.value).toBe(one.value);
    expect(all.groups[0]?.suppressed).toBe(399);
  });

  it('reports the true observation count even though it contributes once', () => {
    const many = Array.from({ length: 12 }, (_, i) => ev('SOURCE_AST', `a.ts:${i}`));
    const b = computeConfidenceBreakdown(many);
    expect(b.groups[0]?.tallies[0]?.count).toBe(12);
    expect(b.value).toBe(0.95);
  });
});

describe('I1b: only independent groups combine', () => {
  it('does not stack source, config and dependency evidence', () => {
    const correlated = computeConfidenceBreakdown([
      ev('SOURCE_AST', 'a.ts:1'),
      ev('SOURCE_CONFIG', 'nginx.conf:3'),
      ev('DEPENDENCY', 'package.json'),
    ]);
    expect(correlated.value).toBe(0.95);
    expect(correlated.groups).toHaveLength(1);
  });

  it('stacks source with a negotiated handshake and a parsed certificate', () => {
    const b = computeConfidenceBreakdown([
      ev('SOURCE_AST', 'a.ts:1'),
      ev('NETWORK_ACTIVE', 'api:443'),
      ev('PKI_CERTIFICATE', 'sha256:ab'),
    ]);
    // 1 - (0.05 * 0.02 * 0.01)
    expect(b.value).toBeGreaterThan(0.9999);
    expect(b.groups).toHaveLength(3);
  });

  it('treats a runtime hook as independent of the source that compiled into it', () => {
    const source = computeConfidenceBreakdown([ev('SOURCE_AST', 'a.ts:1')]);
    const both = computeConfidenceBreakdown([ev('SOURCE_AST', 'a.ts:1'), ev('RUNTIME_HOOK', 'pid:9')]);
    expect(both.value).toBeGreaterThan(source.value);
    expect(both.value).toBe(0.9985);
  });
});

describe('I7: determinism', () => {
  it('produces an identical tree regardless of evidence ordering', () => {
    const a = [ev('SOURCE_AST', 'b.ts:2'), ev('NETWORK_ACTIVE', 'h:443'), ev('SOURCE_AST', 'a.ts:1')];
    const b = [a[2] as Evidence, a[0] as Evidence, a[1] as Evidence];
    expect(JSON.stringify(computeConfidenceBreakdown(a))).toBe(
      JSON.stringify(computeConfidenceBreakdown(b)),
    );
  });

  it('returns zero confidence for no evidence', () => {
    expect(computeConfidenceBreakdown([]).value).toBe(0);
  });
});

describe('corroboration marking', () => {
  it('flags findings that clear the bar only because independent modalities agree', () => {
    // 0.30 and 0.80 ceilings: neither could confirm alone, together they do.
    const b = computeConfidenceBreakdown([ev('BINARY_STRING', 'lib.so:1'), ev('NETWORK_PASSIVE', 'pcap')]);
    expect(b.value).toBeGreaterThanOrEqual(0.85);
    expect(requiresCorroboration(b, 0.85)).toBe(true);
  });

  it('does not flag a finding whose single group already clears the bar', () => {
    const b = computeConfidenceBreakdown([ev('SOURCE_AST', 'a.ts:1')]);
    expect(requiresCorroboration(b, 0.85)).toBe(false);
  });
});
