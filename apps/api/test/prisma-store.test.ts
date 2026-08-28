import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { toCycloneDX } from '@assay/core';
import { scanSource } from '@assay/detect-source';
import { analyzeReachability, assemble } from '@assay/correlate';
import { PrismaScanStore } from '../src/store/prisma.js';
import type { StoredScan } from '../src/store/types.js';

/**
 * Round-trip through Postgres.
 *
 * Skipped unless DATABASE_URL is set, so the suite stays runnable without a
 * database. The assertion that matters is not "the rows came back" - it is
 * that a CBOM exported from the stored scan is byte-identical to one exported
 * from the scan before it was ever written. Persistence must not be a place
 * where determinism quietly dies.
 */

const url = process.env['DATABASE_URL'];
const maybe = url === undefined || url === '' ? describe.skip : describe;
const FIXTURE = resolve(__dirname, '../../../fixtures/sample-repo');
const T = '2026-08-28T00:00:00.000Z';

async function fixtureScan(id: string): Promise<StoredScan> {
  const source = await scanSource({ root: FIXTURE, systemId: 'sample', collectedAt: T });
  const assembled = assemble(source.findings);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  return {
    id,
    systemName: `pg-test-${id}`,
    startedAt: T,
    finishedAt: T,
    detectors: ['detect-source'],
    policyPackId: 'eo-14412',
    policyPackVersion: '1.0.0',
    scopeGrantId: null,
    occurrences: reach.occurrences,
    assets: assembled.assets,
  };
}

const cbomOf = (scan: StoredScan): string =>
  JSON.stringify(
    toCycloneDX(scan.occurrences, scan.assets, {
      policyPackId: scan.policyPackId,
      policyPackVersion: scan.policyPackVersion,
      timestamp: scan.startedAt,
      toolVersion: 'test',
    }),
  );

maybe('postgres round trip', () => {
  it('returns a scan whose CBOM is byte-identical to the one that went in', async () => {
    const store = PrismaScanStore.fromUrl(url as string);
    try {
      const original = await fixtureScan(`rt-${Date.now().toString(36)}`);
      await store.put(original);
      const loaded = await store.get(original.id);

      expect(loaded).not.toBeNull();
      expect(loaded?.occurrences.length).toBe(original.occurrences.length);
      expect(cbomOf(loaded as StoredScan)).toBe(cbomOf(original));
    } finally {
      await store.close();
    }
  }, 120_000);

  it('preserves the Factor tree verbatim rather than recomputing it', async () => {
    const store = PrismaScanStore.fromUrl(url as string);
    try {
      const original = await fixtureScan(`factor-${Date.now().toString(36)}`);
      await store.put(original);
      const loaded = await store.get(original.id);
      const before = original.occurrences[0];
      const after = loaded?.occurrences.find((o) => o.id === before?.id);
      expect(JSON.stringify(after?.confidence)).toBe(JSON.stringify(before?.confidence));
    } finally {
      await store.close();
    }
  }, 120_000);

  it('keeps each scan of the same work item separate, so a diff is possible', async () => {
    const store = PrismaScanStore.fromUrl(url as string);
    try {
      const stamp = Date.now().toString(36);
      const first = { ...(await fixtureScan(`d1-${stamp}`)), systemName: `pg-diff-${stamp}` };
      const second = {
        ...(await fixtureScan(`d2-${stamp}`)),
        systemName: `pg-diff-${stamp}`,
        startedAt: '2026-09-01T00:00:00.000Z',
      };
      await store.put(first);
      await store.put(second);

      const recent = await store.recent(`pg-diff-${stamp}`, 5);
      expect(recent.map((s) => s.id)).toEqual([second.id, first.id]);
      // The same work item exists in both, with the same stable id.
      expect(recent[0]?.occurrences[0]?.id).toBe(recent[1]?.occurrences[0]?.id);
    } finally {
      await store.close();
    }
  }, 120_000);
});
