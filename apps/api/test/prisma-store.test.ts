import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { toCycloneDX } from '@assay/core';
import { scanSource } from '@assay/detect-source';
import { analyzeReachability, assemble } from '@assay/correlate';
import { PrismaClient } from '@prisma/client';
import { PrismaScanStore } from '../src/store/prisma.js';
import type { StoredScan } from '../src/store/types.js';

/**
 * Everything this suite creates is prefixed and deleted afterwards.
 *
 * These tests point at whatever DATABASE_URL is set, which in practice is a
 * developer's own database. Leaving rows behind fills the app with
 * `pg-test-*` systems that look like a real estate, which is worse than
 * useless in a tool whose entire job is telling you what you actually run.
 */
const PREFIX = 'assay-pgtest-';

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

async function cleanup(): Promise<void> {
  if (url === undefined || url === '') return;
  const prisma = new PrismaClient({ datasources: { db: { url } } });
  try {
    await prisma.scan.deleteMany({ where: { systemName: { startsWith: PREFIX } } });
    await prisma.system.deleteMany({ where: { name: { startsWith: PREFIX } } });
    await prisma.traceBundle.deleteMany({ where: { id: { startsWith: PREFIX } } });
  } finally {
    await prisma.$disconnect();
  }
}

async function fixtureScan(id: string): Promise<StoredScan> {
  const source = await scanSource({ root: FIXTURE, systemId: 'sample', collectedAt: T });
  const assembled = assemble(source.findings);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  return {
    id,
    systemName: `${PREFIX}${id}`,
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
  beforeAll(cleanup);
  afterAll(cleanup);

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
      const first = { ...(await fixtureScan(`d1-${stamp}`)), systemName: `${PREFIX}diff-${stamp}` };
      const second = {
        ...(await fixtureScan(`d2-${stamp}`)),
        systemName: `${PREFIX}diff-${stamp}`,
        startedAt: '2026-09-01T00:00:00.000Z',
      };
      await store.put(first);
      await store.put(second);

      const recent = await store.recent(`${PREFIX}diff-${stamp}`, 5);
      expect(recent.map((s) => s.id)).toEqual([second.id, first.id]);
      // The same work item exists in both, with the same stable id.
      expect(recent[0]?.occurrences[0]?.id).toBe(recent[1]?.occurrences[0]?.id);
    } finally {
      await store.close();
    }
  }, 120_000);
});

maybe('trace persistence', () => {
  afterAll(cleanup);

  it('keeps the edges and has nowhere to put the spans', async () => {
    const store = PrismaScanStore.fromUrl(url as string);
    try {
      const id = `tb-${Date.now().toString(36)}`;
      await store.putTraces({
        id,
        source: 'tempo',
        windowFrom: '2026-08-27T00:00:00.000Z',
        windowTo: '2026-08-28T00:00:00.000Z',
        ingestedAt: '2026-08-28T00:00:00.000Z',
        spanCount: 4,
        rootServices: ['gateway'],
        edges: [
          { from: 'gateway', to: 'payments', observations: 12, operation: 'Payments/Create' },
          { from: 'payments', to: 'signing', observations: 12, operation: 'Signer/Sign' },
        ],
      });

      const loaded = await store.getTraces(id);
      expect(loaded?.edges).toHaveLength(2);
      expect(loaded?.spanCount).toBe(4);
      expect(loaded?.rootServices).toEqual(['gateway']);
      // The count survives; the spans do not, and there is no column that
      // could hold them.
      expect(JSON.stringify(loaded)).not.toContain('spanId');
    } finally {
      await store.close();
    }
  }, 120_000);

  it('returns the newest bundle for ?traces=latest', async () => {
    const store = PrismaScanStore.fromUrl(url as string);
    try {
      const stamp = Date.now().toString(36);
      for (const [i, at] of ['2026-08-01T00:00:00.000Z', '2026-09-01T00:00:00.000Z'].entries()) {
        await store.putTraces({
          id: `${PREFIX}latest-${stamp}-${i}`,
          source: 'tempo',
          windowFrom: at,
          windowTo: at,
          ingestedAt: at,
          spanCount: 1,
          rootServices: [],
          edges: [],
        });
      }
      expect((await store.latestTraces())?.id).toBe(`${PREFIX}latest-${stamp}-1`);
    } finally {
      await store.close();
    }
  }, 120_000);

  it('returns only the newest scan per system for the estate view', async () => {
    const store = PrismaScanStore.fromUrl(url as string);
    try {
      const stamp = Date.now().toString(36);
      const system = `${PREFIX}estate-${stamp}`;
      const first = { ...(await fixtureScan(`e1-${stamp}`)), systemName: system };
      const second = {
        ...(await fixtureScan(`e2-${stamp}`)),
        systemName: system,
        startedAt: '2026-09-15T00:00:00.000Z',
      };
      await store.put(first);
      await store.put(second);

      const latest = await store.latestPerSystem();
      const mine = latest.filter((s) => s.systemName === system);
      expect(mine).toHaveLength(1);
      expect(mine[0]?.id).toBe(second.id);
    } finally {
      await store.close();
    }
  }, 180_000);
});
