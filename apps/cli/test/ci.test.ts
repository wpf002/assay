import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  computeConfidence,
  evaluateGate,
  makeAsset,
  rank,
  type Evidence,
  type MoscaPolicy,
  type Occurrence,
  type Suppression,
} from '@assay/core';
import { rebaseline, runCi } from '../src/commands/ci.js';

/**
 * The build gate's expiry. A suppression that never expires is a lie, so the
 * two doors through which one becomes permanent - a re-baseline that also
 * accepts it, and a hand-written date decades out - both have to be shut.
 */

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

const KEX = makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT');
const NOW = new Date('2026-08-28T00:00:00.000Z');
const day = 86_400_000;

const occurrence = (id: string): Occurrence => {
  const evidence: Evidence[] = [
    {
      modality: 'SOURCE_AST',
      locator: 'src/a.ts:1',
      raw: 'crypto.generateKeyPairSync("rsa")',
      collectedAt: NOW.toISOString(),
      collectorVersion: 'test',
    },
  ];
  return {
    id,
    assetId: KEX.id,
    systemId: 'svc',
    controlClass: 'SELF',
    reachability: {
      reachable: true,
      via: 'ENTRY_POINT',
      entryPoint: 'src/server.ts',
      path: [],
      factor: { kind: 'INFERENCE', label: 'reached', value: true, weight: 1, sources: [] },
    },
    evidence,
    confidence: computeConfidence(evidence),
  };
};

const worklists = rank([occurrence('risky')], [KEX], {
  policy: POLICY,
  currentYear: 2026.66,
  secrecyLifetime: () => ({ years: 5, assumed: false }),
});

const suppression = (days: number): Suppression => ({
  occurrenceId: 'risky',
  reason: 'waiting on the library release that ships ML-KEM',
  approvedBy: 'platform-security',
  expiresAt: new Date(NOW.getTime() + days * day).toISOString(),
});

describe('--update-baseline', () => {
  it('does not also accept work that a live suppression covers', () => {
    const next = rebaseline(
      worklists,
      { systemName: 'svc', createdAt: NOW.toISOString() },
      { now: NOW },
      [suppression(30)],
    );
    expect(next.suppressions.map((s) => s.occurrenceId)).toEqual(['risky']);
    expect(next.accepted).not.toContain('risky');
  });

  it('leaves the suppression able to fail the build once its window closes', () => {
    const next = rebaseline(
      worklists,
      { systemName: 'svc', createdAt: NOW.toISOString() },
      { now: NOW },
      [suppression(30)],
    );
    const later = new Date(NOW.getTime() + 31 * day);
    const result = evaluateGate(worklists, next, { now: later });
    expect(result.expired.map((s) => s.occurrenceId)).toEqual(['risky']);
    expect(result.introduced.map((f) => f.occurrenceId)).toEqual(['risky']);
    expect(result.passed).toBe(false);
  });
});

describe('reading a baseline', () => {
  it('refuses a suppression whose window runs past the maximum', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-ci-'));
    const path = join(dir, '.assay-baseline.json');
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        createdAt: NOW.toISOString(),
        systemName: 'svc',
        policyPackId: 'eo-14412',
        policyPackVersion: '1.0.0',
        accepted: [],
        suppressions: [{ ...suppression(0), expiresAt: '2099-01-01T00:00:00.000Z' }],
      }),
      'utf8',
    );

    await expect(
      runCi(dir, { baseline: path, policy: 'eo-14412', binaries: false, now: NOW.toISOString() }),
    ).rejects.toThrow('more than 365 days out');
  });
});
