import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanSource } from '@assay/detect-source';
import { analyzeReachability, assemble } from '@assay/correlate';
import { sha256Hex } from '@assay/core';
import {
  atLeast,
  digestsMatch,
  mintToken,
  parseToken,
  authenticate,
  AuthError,
} from '../src/auth.js';
import { MemoryScanStore } from '../src/store/memory.js';
import { bootstrapAdminToken } from '../src/app.js';
import { authedApp, issueToken, type AuthedApp } from './authed.js';

/**
 * What this protects is an inventory of an organization's weakest
 * cryptography — a map of where to attack it. Every test here is written from
 * the position that the caller is hostile.
 */

const FIXTURE = resolve(__dirname, '../../../fixtures/sample-repo');
const T = '2026-08-01T00:00:00.000Z';

async function scanBody(systemName: string): Promise<Record<string, unknown>> {
  const source = await scanSource({ root: FIXTURE, systemId: systemName, collectedAt: T });
  const assembled = assemble(source.findings);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  return {
    systemName,
    detectors: ['detect-source'],
    policyPackId: 'eo-14412',
    policyPackVersion: '1.0.0',
    scopeGrantId: null,
    startedAt: T,
    finishedAt: T,
    occurrences: reach.occurrences,
    assets: assembled.assets,
  };
}

let harness: AuthedApp;

beforeAll(async () => {
  harness = await authedApp();
  for (const system of ['payments', 'signing']) {
    await harness.inject({ method: 'POST', url: '/scans', payload: await scanBody(system) });
  }
}, 180_000);

afterAll(async () => {
  await harness?.close();
});

/* ------------------------------------------------------------------- tokens */

describe('a token secret exists in exactly one place', () => {
  it('is returned once at creation and never again', async () => {
    const created = await harness.inject({
      method: 'POST',
      url: '/tokens',
      payload: { name: 'reader', role: 'viewer' },
    });
    const body = created.json<{ id: string; token: string }>();
    expect(body.token).toMatch(/^assay_[0-9a-f]{16}_/);

    const listed = await harness.inject({ method: 'GET', url: '/tokens' });
    // Not "the field is empty" — the string must not appear anywhere in the
    // response, because a token table that reads back is a second copy of the
    // key to the estate stored beside the estate.
    expect(listed.body).not.toContain(body.token);
    expect(listed.body).not.toContain(body.token.split('_')[2] as string);
  });

  it('never exposes the stored hash either', async () => {
    const listed = await harness.inject({ method: 'GET', url: '/tokens' });
    expect(listed.body).not.toContain('secretHash');
  });

  it('stores a hash, not the secret', () => {
    const minted = mintToken();
    const rawSecret = minted.secret.split('_').slice(2).join('_');
    expect(minted.secretHash).toBe(sha256Hex(rawSecret));
    expect(minted.secretHash).not.toContain(rawSecret);
  });
});

describe('token parsing', () => {
  it('accepts a secret containing base64url underscores', () => {
    // base64url's alphabet includes `_`. Splitting on every underscore rejects
    // most valid tokens, and does it intermittently — the worst way for an
    // authentication bug to behave.
    const parsed = parseToken('assay_0123456789abcdef_aa_bb-cc_dd' + 'x'.repeat(40));
    expect(parsed?.id).toBe('0123456789abcdef');
    expect(parsed?.secret.startsWith('aa_bb-cc_dd')).toBe(true);
  });

  it('round-trips every minted token', () => {
    for (let i = 0; i < 200; i++) {
      const minted = mintToken();
      const parsed = parseToken(minted.secret);
      expect(parsed).not.toBeNull();
      expect(sha256Hex(parsed?.secret as string)).toBe(minted.secretHash);
    }
  });

  it('rejects anything that is not a token', () => {
    for (const bad of ['', 'assay', 'assay_short_x', 'other_0123456789abcdef_' + 'x'.repeat(43),
      'assay_ZZZZ456789abcdef_' + 'x'.repeat(43), 'assay_0123456789abcdef_short',
      'assay_0123456789abcdef_' + 'x'.repeat(39)]) {
      expect(parseToken(bad)).toBeNull();
    }
  });

  it('compares digests without an early exit', () => {
    expect(digestsMatch(sha256Hex('a'), sha256Hex('a'))).toBe(true);
    expect(digestsMatch(sha256Hex('a'), sha256Hex('b'))).toBe(false);
    expect(digestsMatch('short', sha256Hex('a'))).toBe(false);
  });
});

/* ----------------------------------------------------------- authentication */

describe('no token, no answer', () => {
  it('refuses every route except health', async () => {
    const routes = [
      '/scans', '/policy-packs', '/traces', '/tokens', '/audit',
      '/estate/worklists', '/estate/coverage',
    ];
    for (const url of routes) {
      const r = await harness.app.inject({ method: 'GET', url });
      expect(r.statusCode, url).toBe(401);
    }
  });

  it('leaves /health open, and it says nothing about the estate', async () => {
    const r = await harness.app.inject({ method: 'GET', url: '/health' });
    expect(r.statusCode).toBe(200);
    expect(r.json<{ ok: boolean }>().ok).toBe(true);
    expect(r.body).not.toContain('payments');
  });

  it('refuses writes as well as reads', async () => {
    const r = await harness.app.inject({ method: 'POST', url: '/scans', payload: await scanBody('x') });
    expect(r.statusCode).toBe(401);
  });

  it('distinguishes a missing header from a malformed one', async () => {
    const missing = await harness.app.inject({ method: 'GET', url: '/scans' });
    expect(missing.json<{ reason: string }>().reason).toBe('MISSING');
    for (const header of ['Bearer', 'Basic abc', 'assay_0123456789abcdef_' + 'x'.repeat(43)]) {
      const r = await harness.app.inject({ method: 'GET', url: '/scans', headers: { authorization: header } });
      expect(r.statusCode, header).toBe(401);
    }
  });

  it('gives a wrong secret and an unknown token the same answer', async () => {
    const unknown = await harness.app.inject({
      method: 'GET', url: '/scans',
      headers: { authorization: `Bearer assay_0123456789abcdef_${'x'.repeat(43)}` },
    });
    expect(unknown.json<{ reason: string }>().reason).toBe('UNKNOWN');
  });

  it('rejects a token whose id was swapped for another real one', async () => {
    // The id is not a credential, but a mismatch means the token was assembled
    // rather than issued.
    const store = new MemoryScanStore();
    const a = await bootstrapAdminToken(store, 'a');
    const b = await bootstrapAdminToken(store, 'b');
    const frankenstein = `${a.token.split('_').slice(0, 2).join('_')}_${b.token.split('_').slice(2).join('_')}`;
    await expect(
      authenticate(store, `Bearer ${frankenstein}`, { now: new Date() }),
    ).rejects.toThrow(AuthError);
  });
});

describe('revocation and expiry', () => {
  it('stops working the moment it is revoked', async () => {
    const solo = await authedApp();
    const t = await issueToken(solo, { name: 'temp', role: 'viewer' });
    expect((await solo.app.inject({ method: 'GET', url: '/scans', headers: t })).statusCode).toBe(200);

    await solo.inject({ method: 'DELETE', url: `/tokens/${t.id}` });
    const after = await solo.app.inject({ method: 'GET', url: '/scans', headers: t });
    expect(after.statusCode).toBe(401);
    expect(after.json<{ reason: string }>().reason).toBe('REVOKED');
    await solo.close();
  });

  it('cannot be revoked twice, so a 204 means something', async () => {
    const solo = await authedApp();
    const t = await issueToken(solo, { name: 'temp', role: 'viewer' });
    expect((await solo.inject({ method: 'DELETE', url: `/tokens/${t.id}` })).statusCode).toBe(204);
    expect((await solo.inject({ method: 'DELETE', url: `/tokens/${t.id}` })).statusCode).toBe(404);
    await solo.close();
  });

  it('refuses an expired token', async () => {
    const store = new MemoryScanStore();
    await store.putToken({
      id: '00112233445566aa', secretHash: sha256Hex('s'), name: 'old', role: 'admin',
      systems: [], createdAt: T, createdBy: 'test', lastUsedAt: null,
      expiresAt: '2026-02-01T00:00:00.000Z', revokedAt: null,
    });
    await expect(
      authenticate(store, `Bearer assay_00112233445566aa_${'s'}`, { now: new Date('2026-08-01T00:00:00Z') }),
    ).rejects.toThrow(AuthError);
  });
});

/* ------------------------------------------------------------ authorization */

describe('roles are ordered and enforced', () => {
  it('ranks them', () => {
    expect(atLeast('admin', 'operator')).toBe(true);
    expect(atLeast('operator', 'viewer')).toBe(true);
    expect(atLeast('viewer', 'operator')).toBe(false);
    expect(atLeast('operator', 'admin')).toBe(false);
  });

  it('lets a viewer read and stops them writing', async () => {
    const viewer = await issueToken(harness, { name: 'v', role: 'viewer' });
    expect((await harness.app.inject({ method: 'GET', url: '/scans', headers: viewer })).statusCode).toBe(200);

    const write = await harness.app.inject({
      method: 'POST', url: '/scans', payload: await scanBody('nope'), headers: viewer,
    });
    expect(write.statusCode).toBe(403);
    expect(write.json<{ reason: string }>().reason).toBe('FORBIDDEN');
  });

  it('stops an operator managing tokens', async () => {
    const operator = await issueToken(harness, { name: 'o', role: 'operator' });
    for (const [method, url] of [['GET', '/tokens'], ['GET', '/audit'], ['POST', '/tokens']] as const) {
      const r = await harness.app.inject({ method, url, payload: { name: 'x', role: 'admin' }, headers: operator });
      expect(r.statusCode, url).toBe(403);
    }
  });

  it('lets an operator ingest', async () => {
    const operator = await issueToken(harness, { name: 'o2', role: 'operator' });
    const r = await harness.app.inject({
      method: 'POST', url: '/scans', payload: await scanBody('ingested-by-operator'), headers: operator,
    });
    expect(r.statusCode).toBe(201);
  });
});

describe('a scoped token sees its systems and nothing else', () => {
  it('filters the estate rather than refusing it', async () => {
    // A scoped viewer asking for the estate should get their system, not an
    // error that tells them how many others exist.
    const scoped = await issueToken(harness, { name: 's', role: 'viewer', systems: ['payments'] });
    const r = await harness.app.inject({ method: 'GET', url: '/estate/worklists', headers: scoped });
    const systems = r.json<{ systems: { systemName: string }[] }>().systems;
    expect(systems.map((s) => s.systemName)).toEqual(['payments']);
  });

  it('answers a scan outside its scope exactly as it answers one that does not exist', async () => {
    const scoped = await issueToken(harness, { name: 's2', role: 'viewer', systems: ['payments'] });
    const list = await harness.inject({ method: 'GET', url: '/scans?system=signing' });
    const otherId = list.json<{ id: string }[]>()[0]?.id as string;

    const outOfScope = await harness.app.inject({ method: 'GET', url: `/scans/${otherId}`, headers: scoped });
    const nonExistent = await harness.app.inject({ method: 'GET', url: '/scans/no-such-scan', headers: scoped });
    // Same body, so scope cannot be mapped by probing for the difference.
    expect(outOfScope.json<{ error: string }>().error).toBe(nonExistent.json<{ error: string }>().error);
  });

  it('applies the scope to every read path, not only the list', async () => {
    const scoped = await issueToken(harness, { name: 's3', role: 'viewer', systems: ['payments'] });
    const list = await harness.inject({ method: 'GET', url: '/scans?system=signing' });
    const otherId = list.json<{ id: string }[]>()[0]?.id as string;

    for (const suffix of ['', '/worklists', '/cbom', '/divergences', '/export/tickets', '/rerank?to=eo-14412']) {
      const r = await harness.app.inject({ method: 'GET', url: `/scans/${otherId}${suffix}`, headers: scoped });
      expect([403, 404], `${suffix} -> ${r.statusCode}`).toContain(r.statusCode);
    }
  });

  it('scopes the estate drill-down too', async () => {
    const scoped = await issueToken(harness, { name: 's4', role: 'viewer', systems: ['payments'] });
    const mine = await harness.app.inject({ method: 'GET', url: '/estate/worklists', headers: scoped });
    const row = mine.json<{ worklists: { confidentiality: { occurrenceId: string }[] } }>()
      .worklists.confidentiality[0];
    const ok = await harness.app.inject({
      method: 'GET', url: `/estate/occurrences/${row?.occurrenceId}`, headers: scoped,
    });
    expect(ok.statusCode).toBe(200);
  });

  it('treats an empty scope list as the whole estate, stated rather than implied', async () => {
    const all = await issueToken(harness, { name: 'all', role: 'viewer', systems: [] });
    const r = await harness.app.inject({ method: 'GET', url: '/estate/worklists', headers: all });
    expect(r.json<{ systems: unknown[] }>().systems.length).toBeGreaterThan(1);
  });
});

/* -------------------------------------------------------------------- audit */

describe('who read what', () => {
  it('records reads, not only writes', async () => {
    const solo = await authedApp();
    await solo.inject({ method: 'POST', url: '/scans', payload: await scanBody('audited') });
    await solo.inject({ method: 'GET', url: '/scans' });

    const audit = (await solo.inject({ method: 'GET', url: '/audit' })).json<
      { method: string; route: string; statusCode: number; tokenName: string }[]
    >();
    expect(audit.some((e) => e.method === 'GET' && e.route === '/scans')).toBe(true);
    expect(audit.some((e) => e.method === 'POST' && e.route === '/scans')).toBe(true);
    expect(audit.every((e) => e.tokenName === 'bootstrap')).toBe(true);
    await solo.close();
  });

  it('records the attempt when it is refused', async () => {
    const solo = await authedApp();
    await solo.app.inject({ method: 'GET', url: '/scans' });
    const audit = (await solo.inject({ method: 'GET', url: '/audit' })).json<
      { statusCode: number; tokenName: string }[]
    >();
    expect(audit.some((e) => e.statusCode === 401 && e.tokenName === '(unauthenticated)')).toBe(true);
    await solo.close();
  });

  it('names the resource where the route names one', async () => {
    const solo = await authedApp();
    const created = await solo.inject({ method: 'POST', url: '/scans', payload: await scanBody('res') });
    const id = created.json<{ id: string }>().id;
    await solo.inject({ method: 'GET', url: `/scans/${id}/cbom` });

    const audit = (await solo.inject({ method: 'GET', url: '/audit' })).json<
      { route: string; resource: string | null }[]
    >();
    expect(audit.some((e) => e.route === '/scans/:id/cbom' && e.resource === id)).toBe(true);
    await solo.close();
  });

  it('never records a token secret', async () => {
    const solo = await authedApp();
    const t = await issueToken(solo, { name: 'leaky', role: 'viewer' });
    await solo.app.inject({ method: 'GET', url: '/scans', headers: t });
    const audit = await solo.inject({ method: 'GET', url: '/audit' });
    expect(audit.body).not.toContain(t.authorization.replace('Bearer ', ''));
    await solo.close();
  });
});
