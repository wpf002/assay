import { resolve } from 'node:path';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { scanSource } from '@assay/detect-source';
import { analyzeReachability, assemble } from '@assay/correlate';
import { buildApp } from '../src/app.js';
import { MemoryScanStore } from '../src/store/memory.js';

/**
 * What a caller is owed, independently of which route they came in by.
 *
 * Three properties: a row reports the same arithmetic wherever it is read, an
 * id names exactly one stored thing, and input the API cannot use is answered
 * as the caller's mistake rather than as a server fault.
 */

const FIXTURE = resolve(__dirname, '../../../fixtures/sample-repo');
const T = '2026-08-01T00:00:00.000Z';

interface IngestBody {
  systemName: string;
  detectors: string[];
  policyPackId: string;
  policyPackVersion: string;
  scopeGrantId: null;
  startedAt: string;
  finishedAt: string | null;
  occurrences: Record<string, unknown>[];
  assets: unknown[];
}

async function scanBody(systemName: string, startedAt: string): Promise<IngestBody> {
  const source = await scanSource({ root: FIXTURE, systemId: systemName, collectedAt: T });
  const assembled = assemble(source.findings);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  return {
    systemName,
    detectors: ['detect-source'],
    policyPackId: 'eo-14412',
    policyPackVersion: '1.0.0',
    scopeGrantId: null,
    startedAt,
    finishedAt: startedAt,
    occurrences: reach.occurrences as unknown as Record<string, unknown>[],
    assets: [...assembled.assets],
  };
}

const post = (
  app: FastifyInstance,
  url: string,
  payload: object,
): Promise<LightMyRequestResponse> => app.inject({ method: 'POST', url, payload });
const getJson = async <T>(app: FastifyInstance, url: string): Promise<T> =>
  (await app.inject({ method: 'GET', url })).json<T>();

interface MoscaTerms {
  crqc: { horizonYears: number; slackYears: number; late: boolean };
  regulatory: { slackYears: number; late: boolean };
  bindingConstraint: string;
  x: number;
}
interface Row {
  occurrenceId: string;
  systemId: string;
  slackYears: number;
  late: boolean;
  mosca: MoscaTerms;
}
interface Worklists {
  confidentiality: Row[];
  authenticity: Row[];
  unreached: Row[];
  unanalyzed: Row[];
  hints: Row[];
}
interface Derivation {
  derivations: { mosca: MoscaTerms | null };
}

let app: FastifyInstance;
let scan: string;

beforeAll(async () => {
  app = await buildApp({ store: new MemoryScanStore() });
  const r = await post(app, '/scans', await scanBody('sample', T));
  scan = r.json<{ id: string }>().id;
}, 120_000);

afterAll(async () => {
  await app?.close();
});

describe('a row reads the same wherever it is read', () => {
  it('drills a row down against the clock the estate ranked it at', async () => {
    const estate = await buildApp({ store: new MemoryScanStore() });
    try {
      await post(estate, '/scans', await scanBody('old-sys', '2020-01-01T00:00:00.000Z'));
      await post(estate, '/scans', await scanBody('new-sys', '2030-01-01T00:00:00.000Z'));

      const list = await getJson<{ worklists: Worklists }>(estate, '/estate/worklists');
      const row = list.worklists.confidentiality.find((f) => f.systemId === 'old-sys');
      expect(row).toBeDefined();

      const opened = await getJson<Derivation>(
        estate,
        `/estate/occurrences/${row?.occurrenceId ?? ''}`,
      );
      // The estate ranks every system against the newest scan in it. Ranking
      // the owning scan against its own start instead is what put "overdue"
      // next to a decade of margin on one screen.
      expect(opened.derivations.mosca?.crqc).toEqual(row?.mosca.crqc);
      expect(opened.derivations.mosca?.regulatory).toEqual(row?.mosca.regulatory);
      expect(opened.derivations.mosca?.bindingConstraint).toBe(row?.mosca.bindingConstraint);
    } finally {
      await estate.close();
    }
  }, 120_000);

  it('carries a MOSCA derivation for every row any worklist lists', async () => {
    // Reachability is analyzed per occurrence and partial coverage is normal,
    // so a scan holds analyzed and unanalyzed findings at once.
    const body = await scanBody('mixed', T);
    body.occurrences = body.occurrences.map((o, i) =>
      i % 2 === 0 ? o : { ...o, reachability: null },
    );
    const mixed = await buildApp({ store: new MemoryScanStore() });
    try {
      const posted = await post(mixed, '/scans', body);
      const id = posted.json<{ id: string }>().id;
      const w = await getJson<Worklists>(mixed, `/scans/${id}/worklists?now=${T}`);
      const listed = [w.confidentiality, w.authenticity, w.unreached, w.unanalyzed, w.hints]
        .map((bucket) => bucket[0])
        .filter((f): f is Row => f !== undefined);
      expect(listed.length).toBeGreaterThan(0);

      for (const f of listed) {
        const url = `/scans/${id}/occurrences/${f.occurrenceId}?now=${T}`;
        const d = await getJson<Derivation>(mixed, url);
        expect(d.derivations.mosca).not.toBeNull();
      }
    } finally {
      await mixed.close();
    }
  }, 120_000);

  it('reads an empty secrecyYears as the default rather than as zero', async () => {
    const absent = await getJson<Worklists>(app, `/scans/${scan}/worklists?now=${T}`);
    const id = absent.confidentiality[0]?.occurrenceId ?? '';
    const empty = await getJson<Derivation>(
      app,
      `/scans/${scan}/occurrences/${id}?now=${T}&secrecyYears=`,
    );
    expect(empty.derivations.mosca?.x).toBe(5);
  });
});

describe('an id names one stored thing', () => {
  it('keeps two scans of one system in the same second apart', async () => {
    const store = await buildApp({ store: new MemoryScanStore() });
    try {
      const first = await post(store, '/scans', await scanBody('coll', '2027-01-01T00:00:00.111Z'));
      const second = await post(store, '/scans', await scanBody('coll', '2027-01-01T00:00:00.999Z'));
      const a = first.json<{ id: string }>().id;
      const b = second.json<{ id: string }>().id;

      expect(a).not.toBe(b);
      expect(await getJson<{ id: string }[]>(store, '/scans?system=coll')).toHaveLength(2);
      // The earlier scan is still there, which is what makes a diff possible.
      expect((await store.inject({ method: 'GET', url: `/scans/${a}` })).statusCode).toBe(200);
    } finally {
      await store.close();
    }
  }, 120_000);

  it('keeps two trace uploads covering one window apart', async () => {
    const store = await buildApp({ store: new MemoryScanStore() });
    try {
      const window = {
        from: '2026-08-27T00:00:00.000Z',
        to: '2026-08-28T00:00:00.000Z',
        source: 'tempo',
      };
      const alpha = await post(store, '/traces', {
        ...window,
        spans: [
          { service: 'alpha-root', spanId: 'a1', parentSpanId: '', operation: 'GET /' },
          { service: 'alpha-0', spanId: 'a2', parentSpanId: 'a1', operation: 'work' },
        ],
      });
      const beta = await post(store, '/traces', {
        ...window,
        spans: [
          { service: 'beta-root', spanId: 'b1', parentSpanId: '', operation: 'GET /' },
          { service: 'beta-0', spanId: 'b2', parentSpanId: 'b1', operation: 'work' },
          { service: 'beta-1', spanId: 'b3', parentSpanId: 'b2', operation: 'work' },
        ],
      });
      const alphaId = alpha.json<{ id: string }>().id;
      const betaId = beta.json<{ id: string }>().id;
      expect(alphaId).not.toBe(betaId);

      // The 201 has to describe what the store now holds under that id.
      const stored = await getJson<{ edges: unknown[] }>(store, `/traces/${alphaId}`);
      expect(stored.edges).toHaveLength(alpha.json<{ edges: number }>().edges);
      expect(await getJson<unknown[]>(store, '/traces')).toHaveLength(2);
    } finally {
      await store.close();
    }
  });

  it('gives an OTLP export with no stated window an id of its own', async () => {
    const store = await buildApp({ store: new MemoryScanStore() });
    const otlp = (service: string) => ({
      resourceSpans: [
        {
          resource: { attributes: [{ key: 'service.name', value: { stringValue: service } }] },
          scopeSpans: [{ spans: [{ traceId: 't', spanId: 'o1', name: 'GET /' }] }],
        },
      ],
    });
    try {
      const edge = await post(store, '/traces', otlp('edge'));
      const billing = await post(store, '/traces', otlp('billing'));
      expect(edge.json<{ id: string }>().id).not.toBe(billing.json<{ id: string }>().id);
      expect(await getJson<unknown[]>(store, '/traces')).toHaveLength(2);
    } finally {
      await store.close();
    }
  });

  it('rejects a diff against a scan of another system rather than reporting full churn', async () => {
    const store = await buildApp({ store: new MemoryScanStore() });
    try {
      const other = await post(store, '/scans', await scanBody('other', '2026-07-01T00:00:00.000Z'));
      const mine = await post(store, '/scans', await scanBody('mine', '2026-08-01T00:00:00.000Z'));
      const from = other.json<{ id: string }>().id;
      const to = mine.json<{ id: string }>().id;
      const r = await store.inject({ method: 'GET', url: `/scans/${to}/diff?from=${from}` });
      expect(r.statusCode).toBe(400);
    } finally {
      await store.close();
    }
  }, 120_000);

  it('404s a trace bundle id that resolves to nothing instead of dropping the correlation', async () => {
    const r = await app.inject({ method: 'GET', url: '/estate/worklists?traces=does-not-exist' });
    expect(r.statusCode).toBe(404);
  });
});

describe('bad input is answered as bad input', () => {
  it('400s every query the routes cannot use', async () => {
    const cases = [
      `/scans/${scan}/worklists?secrecyYears=abc`,
      `/scans/${scan}/worklists?secrecyYears=-1`,
      `/scans/${scan}/worklists?now=nope`,
      `/scans/${scan}/worklists?track=BOGUS`,
      `/scans/${scan}/worklists?pack=no-such-pack`,
      `/scans/${scan}/cbom?profile=bogus`,
      `/scans/${scan}/rerank?from=eo-14412`,
      `/scans/${scan}/export/tickets?limit=0`,
      '/estate/worklists?secrecyYears=-1',
    ];
    for (const url of cases) {
      expect((await app.inject({ method: 'GET', url })).statusCode).toBe(400);
    }
  });

  it('holds the rerank route to the same bounds on X as every other route', async () => {
    const r = await app.inject({
      method: 'GET',
      url: `/scans/${scan}/rerank?from=eo-14412&to=eo-14412&secrecyYears=-500`,
    });
    expect(r.statusCode).toBe(400);
  });

  it('rejects a repeated query parameter instead of joining it into a value nobody sent', async () => {
    const w = await getJson<Worklists>(app, `/scans/${scan}/worklists?now=${T}`);
    const id = w.confidentiality[0]?.occurrenceId ?? '';
    const r = await app.inject({
      method: 'GET',
      url: `/estate/occurrences/${id}?pack=eo-14412&pack=nist-ir-8547-draft`,
    });
    expect(r.statusCode).toBe(400);
    expect(r.body).not.toContain('eo-14412,nist-ir-8547-draft');
  });

  it('rejects occurrences no read path could serve, rather than storing them', async () => {
    const shapeless = await post(app, '/scans', {
      systemName: 'junk',
      policyPackId: 'eo-14412',
      policyPackVersion: '1.0.0',
      startedAt: '2026-01-01T00:00:00.000Z',
      occurrences: [{ id: 'x' }],
      assets: [],
    });
    expect(shapeless.statusCode).toBe(400);

    const body = await scanBody('dangling', '2026-01-01T00:00:00.000Z');
    // Occurrence.assetId is a foreign key; an asset the scan never declared is
    // a write-time failure under Postgres and a findings list with nothing
    // behind it everywhere else.
    body.assets = [];
    expect((await post(app, '/scans', body)).statusCode).toBe(400);
  }, 120_000);
});

describe('flags and precision survive the round trip', () => {
  it('turns a flag off when a caller says false', async () => {
    const plain = (await app.inject({ method: 'GET', url: `/scans/${scan}/cbom` })).body;
    const off = (await app.inject({ method: 'GET', url: `/scans/${scan}/cbom?factors=false` })).body;
    const on = (await app.inject({ method: 'GET', url: `/scans/${scan}/cbom?factors=true` })).body;
    expect(off).toBe(plain);
    expect(on).not.toBe(plain);

    const suspectedOff = (
      await app.inject({ method: 'GET', url: `/scans/${scan}/cbom?includeSuspected=false` })
    ).body;
    expect(suspectedOff).toBe(plain);
  });

  it('accepts only the timestamp precision it can give back', async () => {
    const body = await scanBody('precise', '2026-03-01T00:00:00.123456Z');
    const id = (await post(app, '/scans', body)).json<{ id: string }>().id;
    // The scan timestamp goes into the CBOM and into the sha256 that becomes
    // its serial, so a precision the store cannot keep is a document that
    // stops matching itself once it has been through Postgres.
    const stored = await getJson<{ startedAt: string }>(app, `/scans/${id}`);
    expect(stored.startedAt).toBe('2026-03-01T00:00:00.123Z');
    const cbom = await getJson<{ metadata: { timestamp: string } }>(app, `/scans/${id}/cbom`);
    expect(cbom.metadata.timestamp).toBe('2026-03-01T00:00:00.123Z');
  }, 120_000);

  it('reports how many edges a listed bundle has, without the edges', async () => {
    const store = await buildApp({ store: new MemoryScanStore() });
    try {
      await post(store, '/traces', {
        from: '2026-08-27T00:00:00.000Z',
        to: '2026-08-28T00:00:00.000Z',
        source: 'tempo',
        spans: [
          { service: 'gateway', spanId: 'a1', parentSpanId: '', operation: 'POST /v1/pay' },
          { service: 'signing', spanId: 'b1', parentSpanId: 'a1', operation: 'Sign' },
        ],
      });
      const listed = await getJson<{ edgeCount: number; edges?: unknown }[]>(store, '/traces');
      expect(listed[0]?.edgeCount).toBe(1);
      expect(listed[0]?.edges).toBeUndefined();
    } finally {
      await store.close();
    }
  });

  it('bounds the scan list rather than returning every scan ever recorded', async () => {
    const store = await buildApp({ store: new MemoryScanStore() });
    try {
      await post(store, '/scans', await scanBody('many', '2026-01-01T00:00:00.000Z'));
      await post(store, '/scans', await scanBody('many', '2026-02-01T00:00:00.000Z'));
      expect(await getJson<unknown[]>(store, '/scans')).toHaveLength(2);
      expect(await getJson<unknown[]>(store, '/scans?limit=1')).toHaveLength(1);
    } finally {
      await store.close();
    }
  }, 120_000);
});
