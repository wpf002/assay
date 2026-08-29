import { describe, expect, it } from 'vitest';
import { authedApp, issueToken } from './authed.js';
import { MemoryScanStore } from '../src/store/memory.js';
import type { AuthedApp } from './authed.js';
import type { StoredToken } from '../src/store/types.js';

/**
 * The defects an adversarial review of the authentication phase confirmed.
 *
 * Each test here failed before its fix. They are kept separate from auth.test.ts
 * because that file describes what the design intends; this one records what the
 * design actually did, so a regression reads as "we shipped this bug once".
 */

const scan = (systemName: string, startedAt: string) => ({
  systemName,
  detectors: ['detect-source'],
  policyPackId: 'eo-14412',
  policyPackVersion: '1.0.0',
  scopeGrantId: null,
  startedAt,
  finishedAt: startedAt,
  occurrences: [],
  assets: [],
});

async function seed(a: AuthedApp, systemName: string, startedAt = '2026-01-01T00:00:00.000Z') {
  const r = await a.inject({ method: 'POST', url: '/scans', payload: scan(systemName, startedAt) });
  expect(r.statusCode).toBe(201);
  return r.json<{ id: string }>().id;
}

describe('writes are scoped, not just reads', () => {
  it('refuses a scan posted for a system the token does not hold', async () => {
    const a = await authedApp();
    const scoped = await issueToken(a, { name: 'payments-ci', role: 'operator', systems: ['payments'] });

    const r = await a.inject({
      method: 'POST',
      url: '/scans',
      headers: scoped,
      payload: scan('treasury', '2026-02-01T00:00:00.000Z'),
    });

    expect(r.statusCode).toBe(403);
    expect(r.json<{ error: string }>().error).toMatch(/scoped to payments/);
    await a.close();
  });

  it('cannot shadow another system by posting a newer empty scan for it', async () => {
    // latestPerSystem() takes the newest startedAt per system, and the scan id
    // derives from systemName + startedAt - so an unscoped write let a scoped
    // operator blank out another team's estate row for every reader.
    const a = await authedApp();
    await seed(a, 'treasury', '2026-01-01T00:00:00.000Z');
    const before = await a.inject({ url: '/estate/worklists' });
    const scoped = await issueToken(a, { name: 'payments-ci', role: 'operator', systems: ['payments'] });

    await a.inject({
      method: 'POST',
      url: '/scans',
      headers: scoped,
      payload: scan('treasury', '2027-01-01T00:00:00.000Z'),
    });

    const after = await a.inject({ url: '/estate/worklists' });
    expect(after.json()).toEqual(before.json());
    await a.close();
  });

  it('allows the write when the system is in scope', async () => {
    const a = await authedApp();
    const scoped = await issueToken(a, { name: 'payments-ci', role: 'operator', systems: ['payments'] });
    const r = await a.inject({
      method: 'POST',
      url: '/scans',
      headers: scoped,
      payload: scan('payments', '2026-02-01T00:00:00.000Z'),
    });
    expect(r.statusCode).toBe(201);
    await a.close();
  });

  it('refuses a trace upload from a scoped token, because a bundle is estate-wide', async () => {
    const a = await authedApp();
    const scoped = await issueToken(a, { name: 'payments-ci', role: 'operator', systems: ['payments'] });
    const r = await a.inject({
      method: 'POST',
      url: '/traces',
      headers: scoped,
      payload: { from: null, to: null, source: 'tempo', spans: [] },
    });
    expect(r.statusCode).toBe(403);
    await a.close();
  });
});

describe('the coverage report is the estate service list', () => {
  it('is refused to a viewer', async () => {
    const a = await authedApp();
    const viewer = await issueToken(a, { name: 'auditor', role: 'viewer' });
    const r = await a.inject({ url: '/estate/coverage', headers: viewer });
    expect(r.statusCode).toBe(403);
    await a.close();
  });

  it('is refused to a scoped operator, exactly as /traces is', async () => {
    // The whole point of gating /traces is that the bundle names every service.
    // Coverage is derived from that bundle, so leaving it open re-served it.
    const a = await authedApp();
    const scoped = await issueToken(a, { name: 'payments', role: 'operator', systems: ['payments'] });

    const traces = await a.inject({ url: '/traces', headers: scoped });
    const coverage = await a.inject({ url: '/estate/coverage', headers: scoped });

    expect(traces.statusCode).toBe(403);
    expect(coverage.statusCode).toBe(403);
    await a.close();
  });

  it('still answers an unscoped operator', async () => {
    const a = await authedApp();
    await seed(a, 'payments');
    await a.inject({
      method: 'POST',
      url: '/traces',
      payload: {
        from: '2026-08-27T00:00:00.000Z',
        to: '2026-08-28T00:00:00.000Z',
        source: 'tempo',
        spans: [
          { service: 'gateway', spanId: 'a1', parentSpanId: '', operation: 'POST /v1/pay' },
          { service: 'payments', spanId: 'b1', parentSpanId: 'a1', operation: 'Charge' },
        ],
      },
    });
    const op = await issueToken(a, { name: 'platform', role: 'operator' });
    const r = await a.inject({ url: '/estate/coverage', headers: op });
    expect(r.statusCode).toBe(200);
    expect(r.json<{ unscanned: string[] }>().unscanned).toEqual(['gateway']);
    await a.close();
  });
});

describe('out of scope is indistinguishable from absent', () => {
  it('answers 404, not 403, so ids cannot be probed', async () => {
    const a = await authedApp();
    const id = await seed(a, 'treasury');
    const scoped = await issueToken(a, { name: 'payments', role: 'viewer', systems: ['payments'] });

    const real = await a.inject({ url: `/scans/${id}`, headers: scoped });
    const fake = await a.inject({ url: '/scans/does-not-exist', headers: scoped });

    expect(real.statusCode).toBe(404);
    expect(real.statusCode).toBe(fake.statusCode);
    expect(real.json()).toEqual(fake.json());
    await a.close();
  });

  it('does not leak an out-of-scope scan through diff?from=', async () => {
    const a = await authedApp();
    const hidden = await seed(a, 'treasury', '2026-01-01T00:00:00.000Z');
    const scoped = await issueToken(a, { name: 'payments', role: 'operator', systems: ['payments'] });
    const mine = await a.inject({
      method: 'POST',
      url: '/scans',
      headers: scoped,
      payload: scan('payments', '2026-03-01T00:00:00.000Z'),
    });

    const r = await a.inject({
      url: `/scans/${mine.json<{ id: string }>().id}/diff?from=${hidden}`,
      headers: scoped,
    });

    expect(r.statusCode).toBe(404);
    await a.close();
  });
});

describe('bootstrap re-arms when no token can authenticate', () => {
  const NOW = '2026-06-01T00:00:00.000Z';
  const record = (id: string, over: Partial<StoredToken> = {}): StoredToken => ({
    id,
    secretHash: `hash-${id}`,
    name: id,
    role: 'admin',
    systems: [],
    createdAt: '2026-01-01T00:00:00.000Z',
    createdBy: 'test',
    lastUsedAt: null,
    expiresAt: null,
    revokedAt: null,
    ...over,
  });

  it('does not count a revoked token, so a revoked estate is recoverable', async () => {
    const store = new MemoryScanStore();
    await store.putToken(record('live'));
    expect(await store.countUsableTokens(NOW)).toBe(1);

    // Before the fix this stayed 1 - the row still existed - so the server
    // never minted a replacement and the API was locked out permanently.
    await store.putToken(record('live', { revokedAt: '2026-05-01T00:00:00.000Z' }));
    expect(await store.countUsableTokens(NOW)).toBe(0);
  });

  it('does not count an expired token as usable', async () => {
    const store = new MemoryScanStore();
    await store.putToken(record('old', { expiresAt: '2020-01-01T00:00:00.000Z' }));
    expect(await store.countUsableTokens(NOW)).toBe(0);
  });

  it('counts one that has not expired yet', async () => {
    const store = new MemoryScanStore();
    await store.putToken(record('future', { expiresAt: '2030-01-01T00:00:00.000Z' }));
    expect(await store.countUsableTokens(NOW)).toBe(1);
  });
});

describe('the trace graph is the estate map', () => {
  it('is not served to a scoped operator', async () => {
    const a = await authedApp();
    const scoped = await issueToken(a, { name: 'payments', role: 'operator', systems: ['payments'] });
    expect((await a.inject({ url: '/traces', headers: scoped })).statusCode).toBe(403);
    await a.close();
  });
});

describe('the audit trail', () => {
  it('gives every event a distinct id', async () => {
    const a = await authedApp();
    for (let i = 0; i < 25; i++) await a.inject({ url: '/scans' });
    const rows = (await a.inject({ url: '/audit?limit=1000' })).json<{ id: string }[]>();
    expect(new Set(rows.map((r) => r.id)).size).toBe(rows.length);
    await a.close();
  });

  it('is queryable by token and by time, not only newest-first', async () => {
    const a = await authedApp();
    const other = await issueToken(a, { name: 'auditor', role: 'viewer' });
    await a.inject({ url: '/scans', headers: other });
    await a.inject({ url: '/scans' });

    const mine = (await a.inject({ url: `/audit?tokenId=${other.id}` })).json<{ tokenId: string }[]>();
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((r) => r.tokenId === other.id)).toBe(true);

    const future = (await a.inject({ url: '/audit?since=2999-01-01T00:00:00.000Z' })).json<unknown[]>();
    expect(future).toEqual([]);
    await a.close();
  });
});

describe('the drill-down does not name services the token cannot see', () => {
  /**
   * Trace-derived reachability is built out of service names: the frames are
   * `treasury-gateway -> payments`, the entry point is the first hop, and the
   * evidence label spells the whole path out. So the estate drill-down handed a
   * scoped viewer a partial map of the estate around their own system - the
   * same names /traces refuses to serve them.
   *
   * The occurrence carries no reachability of its own, so the only thing that
   * can promote it is the trace graph. That is the case being tested.
   */
  const ASSET = {
    id: '0'.repeat(32),
    primitive: 'RSA' as const,
    parameters: { modulusBits: 2048 },
    purpose: 'KEY_ESTABLISHMENT' as const,
    quantumVulnerable: true,
    classicalSecurityBits: 112,
    nistQuantumSecurityLevel: null,
    oid: null,
  };

  const payload = {
    systemName: 'payments',
    detectors: ['detect-source'],
    policyPackId: 'eo-14412',
    policyPackVersion: '1.0.0',
    scopeGrantId: null,
    startedAt: '2026-08-01T00:00:00.000Z',
    finishedAt: '2026-08-01T00:00:00.000Z',
    assets: [ASSET],
    occurrences: [
      {
        id: '1'.repeat(24),
        assetId: ASSET.id,
        systemId: 'payments',
        controlClass: 'PROTOCOL_BILATERAL' as const,
        reachability: null,
        evidence: [
          {
            modality: 'SOURCE_AST' as const,
            locator: 'src/pay.ts:1',
            raw: 'crypto.createCipheriv',
            collectedAt: '2026-08-01T00:00:00.000Z',
            collectorVersion: 'detect-source/0.1.0',
            occurrence: { location: 'src/pay.ts', line: 1, symbol: 'createCipheriv' },
          },
        ],
        confidence: {
          kind: 'EVIDENCE' as const,
          label: 'SOURCE_AST @ src/pay.ts:1',
          value: 0.85,
          weight: 1,
          sources: [],
        },
      },
    ],
  };

  it('redacts upstream hops from a scoped viewer', async () => {
    const a = await authedApp();
    const ing = await a.inject({ method: 'POST', url: '/scans', payload });
    expect(ing.statusCode, JSON.stringify(ing.json())).toBe(201);
    await a.inject({
      method: 'POST',
      url: '/traces',
      payload: {
        from: '2026-08-27T00:00:00.000Z',
        to: '2026-08-28T00:00:00.000Z',
        source: 'tempo',
        spans: [
          { service: 'treasury-gateway', spanId: 'a1', parentSpanId: '', operation: 'POST /v1/pay' },
          { service: 'payments', spanId: 'b1', parentSpanId: 'a1', operation: 'Charge' },
        ],
      },
    });

    const occId = payload.occurrences[0]!.id;
    const admin = await a.inject({ url: `/estate/occurrences/${occId}` });
    // The control: the upstream name is genuinely in this derivation.
    expect(admin.statusCode).toBe(200);
    expect(admin.body).toContain('treasury-gateway');
    expect(admin.json<Deriv>().derivations.reachability?.via).toBe('TRACE');

    const scoped = await issueToken(a, { name: 'pay', role: 'viewer', systems: ['payments'] });
    const seen = await a.inject({ url: `/estate/occurrences/${occId}`, headers: scoped });

    expect(seen.statusCode).toBe(200);
    expect(seen.body).not.toContain('treasury-gateway');

    const r = seen.json<Deriv>().derivations.reachability;
    expect(r?.entryPoint).toBeNull();
    expect(r?.hopsOutOfScope).toBeGreaterThan(0);
    expect(r?.path).toEqual([]);
    await a.close();
  });
});

interface Deriv {
  derivations: {
    reachability: {
      via: string;
      entryPoint: string | null;
      hopsOutOfScope: number;
      path: unknown[];
    } | null;
  };
}
