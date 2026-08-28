import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanSource } from '@assay/detect-source';
import { analyzeReachability, assemble } from '@assay/correlate';
import { buildApp } from '../src/app.js';
import { MemoryScanStore } from '../src/store/memory.js';

/**
 * Routes are tested against the in-memory store so the suite needs no
 * database. The Postgres store gets its own round-trip test, skipped unless
 * DATABASE_URL is set.
 */

const FIXTURE = resolve(__dirname, '../../../fixtures/sample-repo');
const T1 = '2026-08-01T00:00:00.000Z';
const T2 = '2026-09-01T00:00:00.000Z';

let app: FastifyInstance;
let scanA: string;
let scanB: string;

async function scanFixture(startedAt: string): Promise<Record<string, unknown>> {
  const source = await scanSource({ root: FIXTURE, systemId: 'sample', collectedAt: startedAt });
  const assembled = assemble(source.findings);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  return {
    systemName: 'sample',
    detectors: ['detect-source'],
    policyPackId: 'eo-14412',
    policyPackVersion: '1.0.0',
    scopeGrantId: null,
    startedAt,
    finishedAt: startedAt,
    occurrences: reach.occurrences,
    assets: assembled.assets,
  };
}

beforeAll(async () => {
  app = await buildApp({ store: new MemoryScanStore() });
  const a = await app.inject({ method: 'POST', url: '/scans', payload: await scanFixture(T1) });
  scanA = a.json<{ id: string }>().id;
  const b = await app.inject({ method: 'POST', url: '/scans', payload: await scanFixture(T2) });
  scanB = b.json<{ id: string }>().id;
}, 120_000);

afterAll(async () => {
  await app?.close();
});

describe('ingest', () => {
  it('accepts a scan and gives it a deterministic id', async () => {
    expect(scanA).toBe('sample-20260801000000');
    expect(scanA).not.toBe(scanB);
  });

  it('rejects a malformed scan with the reason', async () => {
    const r = await app.inject({ method: 'POST', url: '/scans', payload: { systemName: '' } });
    expect(r.statusCode).toBe(400);
    expect(r.json<{ issues: unknown[] }>().issues.length).toBeGreaterThan(0);
  });

  it('lists scans newest first', async () => {
    const r = await app.inject({ method: 'GET', url: '/scans' });
    expect(r.json<{ id: string }[]>().map((s) => s.id)).toEqual([scanB, scanA]);
  });
});

describe('worklists are ranked on read', () => {
  it('returns two tracks and never pools them', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanA}/worklists?now=${T1}` });
    const w = r.json<{ confidentiality: { track: string }[]; authenticity: { track: string }[] }>();
    expect(w.confidentiality.every((f) => f.track === 'CONFIDENTIALITY')).toBe(true);
    expect(w.authenticity.every((f) => f.track === 'AUTHENTICITY')).toBe(true);
  });

  it('filters to one track on request without merging the other', async () => {
    const r = await app.inject({
      method: 'GET',
      url: `/scans/${scanA}/worklists?track=CONFIDENTIALITY&now=${T1}`,
    });
    expect(r.json<{ authenticity: unknown[] }>().authenticity).toEqual([]);
  });

  it('carries the headline as a ratio with its derivation', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanA}/worklists?now=${T1}` });
    const h = r.json<{ headline: { numerator: number; denominator: number; factor: unknown } }>().headline;
    expect(h.denominator).toBeGreaterThan(0);
    expect(h.factor).toBeTruthy();
  });
});

describe('the policy pack switcher is a live control', () => {
  it('changes lateness without changing the finding set', async () => {
    const eo = await app.inject({ method: 'GET', url: `/scans/${scanA}/worklists?pack=eo-14412&now=${T1}` });
    const nist = await app.inject({
      method: 'GET',
      url: `/scans/${scanA}/worklists?pack=nist-ir-8547-draft&now=${T1}`,
    });
    const a = eo.json<{ confidentiality: unknown[]; authenticity: unknown[] }>();
    const b = nist.json<{ confidentiality: unknown[]; authenticity: unknown[] }>();
    expect(a.confidentiality.length).toBe(b.confidentiality.length);
    expect(a.authenticity.length).toBe(b.authenticity.length);
  });

  it('reports exactly which rows moved and why', async () => {
    const r = await app.inject({
      method: 'GET',
      url: `/scans/${scanA}/rerank?from=nist-ir-8547-draft&to=eo-14412&now=${T1}`,
    });
    const body = r.json<{
      moved: {
        slackYears: { before: number; after: number };
        bindingConstraint: { before: string; after: string };
      }[];
    }>();
    expect(body.moved.length).toBeGreaterThan(0);
    // Every difference here is attributable to policy: the evidence is
    // byte-identical on both sides, only the arithmetic over it changed.
    expect(body.moved.some((m) => m.bindingConstraint.after === 'REGULATORY')).toBe(true);
    expect(body.moved.every((m) => m.slackYears.before !== m.slackYears.after)).toBe(true);
    // The physics-only pack can never make a finding MORE urgent than one that
    // adds a regulatory deadline on top of it.
    expect(body.moved.every((m) => m.slackYears.after <= m.slackYears.before)).toBe(true);
  });

  it('exposes pack caveats rather than presenting the figures as truth', async () => {
    const r = await app.inject({ method: 'GET', url: '/policy-packs' });
    const packs = r.json<{ packId: string; caveats: string[] }[]>();
    expect(packs.find((p) => p.packId === 'eo-14412')?.caveats.length).toBeGreaterThan(0);
  });
});

describe('the three-click gate', () => {
  it('walks any finding to raw evidence in at most three hops', async () => {
    const list = await app.inject({ method: 'GET', url: `/scans/${scanA}/worklists?now=${T1}` });
    const first = list.json<{ confidentiality: { occurrenceId: string }[] }>().confidentiality[0];
    const r = await app.inject({
      method: 'GET',
      url: `/scans/${scanA}/occurrences/${first?.occurrenceId}?now=${T1}`,
    });
    const body = r.json<{
      derivations: {
        confidence: { depth: number; citations: number };
        mosca: { depth: number; bindingConstraint: string } | null;
        reachability: { via: string } | null;
      };
      evidence: unknown[];
    }>();

    expect(body.derivations.confidence.depth).toBeLessThanOrEqual(3);
    expect(body.derivations.confidence.citations).toBeGreaterThan(0);
    expect(body.derivations.mosca?.depth).toBeLessThanOrEqual(3);
    expect(body.evidence.length).toBeGreaterThan(0);
  });

  it('says why a finding is not CONFIRMED, rather than making the reader infer it', async () => {
    const list = await app.inject({ method: 'GET', url: `/scans/${scanA}/worklists?now=${T1}` });
    const hint = list.json<{ hints: { occurrenceId: string }[] }>().hints[0];
    if (hint === undefined) return;
    const r = await app.inject({
      method: 'GET',
      url: `/scans/${scanA}/occurrences/${hint.occurrenceId}?now=${T1}`,
    });
    const body = r.json<{ assertionLevel: string; downgradeReason: string | null }>();
    expect(body.assertionLevel).not.toBe('CONFIRMED');
    expect(body.downgradeReason).toBeTruthy();
  });

  it('404s an unknown occurrence rather than returning an empty derivation', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanA}/occurrences/nope` });
    expect(r.statusCode).toBe(404);
  });
});

describe('CBOM export', () => {
  it('is byte-identical to a fresh export of the same scan', async () => {
    const a = await app.inject({ method: 'GET', url: `/scans/${scanA}/cbom` });
    const b = await app.inject({ method: 'GET', url: `/scans/${scanA}/cbom` });
    expect(a.body).toBe(b.body);
  });

  it('uses the scan timestamp, not the request time', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanA}/cbom` });
    expect(r.json<{ metadata: { timestamp: string } }>().metadata.timestamp).toBe(T1);
  });

  it('honours the export profile', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanA}/cbom?profile=cyclonedx-1.6` });
    expect(r.json<{ specVersion: string }>().specVersion).toBe('1.6');
  });
});

describe('diff', () => {
  it('diffs against the previous scan of the same system by default', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanB}/diff` });
    const d = r.json<{ from: { scanId: string }; counts: Record<string, number> }>();
    expect(d.from.scanId).toBe(scanA);
    // Same tree scanned twice: nothing should have moved.
    expect(d.counts.UNCHANGED).toBeGreaterThan(0);
    expect(d.counts.APPEARED).toBe(0);
    expect(d.counts.REGRESSED).toBe(0);
  });

  it('404s when there is nothing earlier to compare against', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanA}/diff` });
    expect(r.statusCode).toBe(404);
  });
});

describe('ticket export', () => {
  it('emits actionable payloads with the derivation attached', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanA}/export/tickets?now=${T1}&limit=3` });
    const tickets = r.json<{ summary: string; description: string; fields: Record<string, unknown> }[]>();
    expect(tickets.length).toBeGreaterThan(0);
    expect(tickets[0]?.summary).toContain('Migrate');
    expect(tickets[0]?.description).toContain('Evidence:');
    expect(tickets[0]?.fields['policyPack']).toBe('eo-14412@1.0.0');
  });

  it('carries no severity label - slack is the priority and it has a derivation', async () => {
    const r = await app.inject({ method: 'GET', url: `/scans/${scanA}/export/tickets?now=${T1}` });
    const t = r.json<Record<string, unknown>[]>()[0];
    expect(t).toBeDefined();
    expect(Object.keys(t as object)).not.toContain('priority');
  });
});

describe('health and 404s', () => {
  it('reports which store is in use', async () => {
    const r = await app.inject({ method: 'GET', url: '/health' });
    expect(r.json<{ store: string }>().store).toBe('memory');
  });

  it('404s an unknown scan on every scan-scoped route', async () => {
    for (const path of ['', '/worklists', '/cbom', '/diff', '/divergences']) {
      const r = await app.inject({ method: 'GET', url: `/scans/nope${path}` });
      expect(r.statusCode).toBe(404);
    }
  });
});
