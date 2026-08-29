import { describe, expect, it } from 'vitest';
import { generateCoverageKeypair, verifyCoverage } from '@assay/coverage';
import type { SignedCoverage } from '@assay/coverage';
import { bootstrapAdminToken, buildApp } from '../src/app.js';
import { MemoryScanStore } from '../src/store/memory.js';
import { authedApp, issueToken } from './authed.js';

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

const scanPayload = (systemName: string, startedAt = '2026-08-01T00:00:00.000Z') => ({
  systemName,
  detectors: ['detect-source'],
  policyPackId: 'eo-14412',
  policyPackVersion: '1.0.0',
  scopeGrantId: null,
  startedAt,
  finishedAt: startedAt,
  assets: [ASSET],
  occurrences: [
    {
      id: `${systemName}`.padEnd(24, '0').slice(0, 24),
      assetId: ASSET.id,
      systemId: systemName,
      controlClass: 'PROTOCOL_BILATERAL' as const,
      reachability: null,
      evidence: [
        {
          modality: 'SOURCE_AST' as const,
          locator: 'src/pay.ts:1',
          raw: 'crypto.createCipheriv',
          collectedAt: startedAt,
          collectorVersion: 'detect-source/0.1.0',
          occurrence: { location: 'src/pay.ts', line: 1, symbol: 'createCipheriv' },
        },
      ],
      confidence: { kind: 'EVIDENCE' as const, label: 'e', value: 0.85, weight: 1, sources: [] },
    },
  ],
});

describe('the coverage attestation', () => {
  it('reports what was not examined, not a reassuring percentage', async () => {
    const a = await authedApp();
    const id = (
      await a.inject({ method: 'POST', url: '/scans', payload: scanPayload('payments') })
    ).json<{ id: string }>().id;

    const r = await a.inject({ url: `/scans/${id}/coverage` });
    expect(r.statusCode).toBe(200);
    const body = r.json<{ report: { summary: { statement: string; classesExamined: number } } }>();

    // One source scan examines one class out of ten. The document has to say
    // that plainly, because the alternative reading - "we scanned it" - is the
    // one that ends up in front of a regulator.
    expect(body.report.summary.classesExamined).toBe(1);
    expect(body.report.summary.statement).toContain('no evidence was gathered for 9 of 10 classes');
    expect(body.report.summary.statement).toContain('Managed keys (KMS, HSM, KMIP)');
    await a.close();
  });

  it('says it is unsigned rather than coming back quietly unsigned', async () => {
    const a = await authedApp();
    const id = (
      await a.inject({ method: 'POST', url: '/scans', payload: scanPayload('payments') })
    ).json<{ id: string }>().id;
    const body = (await a.inject({ url: `/scans/${id}/coverage` })).json<{
      signed: boolean;
      reason: string;
      digest: string;
    }>();
    expect(body.signed).toBe(false);
    expect(body.reason).toContain('ASSAY_COVERAGE_KEY');
    expect(body.digest).toMatch(/^[0-9a-f]{64}$/);
    await a.close();
  });

  it('signs verifiably when the server holds a key', async () => {
    const kp = generateCoverageKeypair();
    const store = new MemoryScanStore();
    const app = await buildApp({ store, coverageKeyPem: kp.privateKeyPem });
    const auth = { authorization: `Bearer ${(await bootstrapAdminToken(store)).token}` };
    const id = (
      await app.inject({ method: 'POST', url: '/scans', payload: scanPayload('payments'), headers: auth })
    ).json<{ id: string }>().id;

    const body = (await app.inject({ url: `/scans/${id}/coverage`, headers: auth })).json<
      SignedCoverage & { signed: true }
    >();
    expect(body.signed).toBe(true);
    expect(verifyCoverage(body, kp.publicKeyPem)).toEqual({ ok: true });

    // And the signature is over the report as served, not a re-derivation.
    const tampered = {
      ...body,
      report: { ...body.report, summary: { ...body.report.summary, classesExamined: 10 } },
    };
    expect(verifyCoverage(tampered, kp.publicKeyPem).ok).toBe(false);
    await app.close();
  });

  it('is scoped: a viewer cannot attest a system they cannot see', async () => {
    const a = await authedApp();
    const id = (
      await a.inject({ method: 'POST', url: '/scans', payload: scanPayload('treasury') })
    ).json<{ id: string }>().id;
    const scoped = await issueToken(a, { name: 'pay', role: 'viewer', systems: ['payments'] });
    const r = await a.inject({ url: `/scans/${id}/coverage`, headers: scoped });
    expect(r.statusCode).toBe(404);
    await a.close();
  });
});

describe('the estate attestation', () => {
  it('names every traced service with no inventory as a blind spot', async () => {
    const a = await authedApp();
    await a.inject({ method: 'POST', url: '/scans', payload: scanPayload('payments') });
    await a.inject({
      method: 'POST',
      url: '/traces',
      payload: {
        from: '2026-08-27T00:00:00.000Z',
        to: '2026-08-28T00:00:00.000Z',
        source: 'tempo',
        spans: [
          { service: 'hsm-broker', spanId: 'a1', parentSpanId: '', operation: 'POST /sign' },
          { service: 'payments', spanId: 'b1', parentSpanId: 'a1', operation: 'Charge' },
        ],
      },
    });

    const body = (await a.inject({ url: '/estate/attestation' })).json<{
      report: { blindSpots: { name: string; kind: string; why: string }[]; summary: { statement: string } };
    }>();

    expect(body.report.blindSpots.map((b) => b.name)).toEqual(['hsm-broker']);
    expect(body.report.blindSpots[0]?.why).toContain('will not close this');
    expect(body.report.summary.statement).toContain('1 service or host was observed');
    await a.close();
  });

  it('is refused to a scoped token, like every other whole-estate view', async () => {
    const a = await authedApp();
    await a.inject({ method: 'POST', url: '/scans', payload: scanPayload('payments') });
    const scoped = await issueToken(a, { name: 'pay', role: 'operator', systems: ['payments'] });
    expect((await a.inject({ url: '/estate/attestation', headers: scoped })).statusCode).toBe(403);
    await a.close();
  });

  it('is refused to a viewer', async () => {
    const a = await authedApp();
    await a.inject({ method: 'POST', url: '/scans', payload: scanPayload('payments') });
    const viewer = await issueToken(a, { name: 'auditor', role: 'viewer' });
    expect((await a.inject({ url: '/estate/attestation', headers: viewer })).statusCode).toBe(403);
    await a.close();
  });
});
