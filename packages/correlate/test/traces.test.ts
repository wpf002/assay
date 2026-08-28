import { describe, expect, it } from 'vitest';
import { computeConfidence, makeAsset, type Evidence, type Occurrence } from '@assay/core';
import {
  TraceBundleSchema,
  applyTraceReachability,
  buildServiceGraph,
  reachableServices,
  spansFromOtlp,
} from '../src/index.js';

const ASSET = makeAsset('RSA', { modulusLength: 2048 }, 'DIGITAL_SIGNATURE');

const ev: Evidence = {
  modality: 'SOURCE_AST',
  locator: 'src/sign.ts:12',
  raw: 'x',
  collectedAt: '2026-08-28T00:00:00.000Z',
  collectorVersion: 'test',
};

const occ = (systemId: string, reachable: boolean | null): Occurrence => ({
  id: `occ-${systemId}`,
  assetId: ASSET.id,
  systemId,
  controlClass: 'SELF',
  reachability:
    reachable === null
      ? null
      : {
          reachable,
          via: reachable ? 'ENTRY_POINT' : 'NONE',
          entryPoint: reachable ? 'src/server.ts' : null,
          path: reachable ? [{ module: 'src/server', function: 'handler', fullFilename: 'src/server.ts' }] : [],
          factor: { kind: 'INFERENCE', label: 'static', value: reachable, weight: 1, sources: [] },
        },
  evidence: [ev],
  confidence: computeConfidence([ev]),
});

/** gateway -> payments -> signing, as three services in one trace. */
const bundle = TraceBundleSchema.parse({
  from: '2026-08-27T00:00:00.000Z',
  to: '2026-08-28T00:00:00.000Z',
  source: 'tempo',
  spans: [
    { service: 'gateway', spanId: 'a1', parentSpanId: '', operation: 'POST /v1/payments' },
    { service: 'payments', spanId: 'b1', parentSpanId: 'a1', operation: 'Payments/Create' },
    { service: 'payments', spanId: 'b2', parentSpanId: 'b1', operation: 'db.query' },
    { service: 'signing', spanId: 'c1', parentSpanId: 'b1', operation: 'Signer/Sign' },
    { service: 'signing', spanId: 'c2', parentSpanId: 'b1', operation: 'Signer/Sign' },
    { service: 'reporting', spanId: 'z1', parentSpanId: '', operation: 'cron' },
  ],
});

describe('the service graph', () => {
  const graph = buildServiceGraph(bundle);

  it('records a boundary crossing as an edge', () => {
    expect(graph.edges.map((e) => `${e.from}->${e.to}`)).toEqual([
      'gateway->payments',
      'payments->signing',
    ]);
  });

  it('ignores spans within one service, which static analysis handles better', () => {
    expect(graph.edges.some((e) => e.from === e.to)).toBe(false);
  });

  it('counts how often an edge was observed', () => {
    expect(graph.edges.find((e) => e.to === 'signing')?.observations).toBe(2);
  });

  it('keeps the window, because absence inside it proves nothing', () => {
    expect(graph.window?.from).toBe('2026-08-27T00:00:00.000Z');
    expect(graph.source).toBe('tempo');
  });
});

describe('reaching across the network edge', () => {
  const graph = buildServiceGraph(bundle);

  it('propagates reachability from a service with its own entry point', () => {
    const reached = reachableServices({ rootSystems: ['gateway'], graph });
    expect([...reached.keys()].sort()).toEqual(['gateway', 'payments', 'signing']);
    expect(reached.get('signing')?.hops.map((h) => h.to)).toEqual(['payments', 'signing']);
  });

  it('does not reach a service nothing called', () => {
    expect(reachableServices({ rootSystems: ['gateway'], graph }).has('reporting')).toBe(false);
  });

  it('promotes a signing service that static analysis judged dead', () => {
    // The whole point. A signing service is a library nobody in its own repo
    // calls, and the RSA key every payment depends on lands in "unreached".
    const [promoted] = applyTraceReachability([occ('signing', false)], {
      rootSystems: ['gateway'],
      graph,
    });
    expect(promoted?.reachability?.reachable).toBe(true);
    expect(promoted?.reachability?.via).toBe('TRACE');
  });

  it('ships the cross-service path followed by the in-process one', () => {
    const [promoted] = applyTraceReachability([occ('signing', false)], {
      rootSystems: ['gateway'],
      graph,
    });
    expect(promoted?.reachability?.path.map((f) => f.fullFilename)).toEqual([
      'gateway -> payments',
      'payments -> signing',
    ]);
  });

  it('keeps the static verdict inside the derivation rather than discarding it', () => {
    const [promoted] = applyTraceReachability([occ('signing', false)], {
      rootSystems: ['gateway'],
      graph,
    });
    const s = JSON.stringify(promoted?.reachability?.factor);
    expect(s).toContain('static analysis within signing concluded reachable=false');
  });
});

describe('positive-only: a quiet Tuesday is not dead code', () => {
  const graph = buildServiceGraph(bundle);

  it('never downgrades a service the traces did not touch', () => {
    const before = occ('reporting', true);
    const [after] = applyTraceReachability([before], { rootSystems: ['gateway'], graph });
    expect(after).toBe(before);
  });

  it('leaves an unanalyzed occurrence unanalyzed rather than inventing a verdict', () => {
    const before = occ('reporting', null);
    const [after] = applyTraceReachability([before], { rootSystems: ['gateway'], graph });
    expect(after?.reachability).toBeNull();
  });

  it('states the window as an assumption on every promoted finding', () => {
    const [promoted] = applyTraceReachability([occ('signing', false)], {
      rootSystems: ['gateway'],
      graph,
    });
    const s = JSON.stringify(promoted?.reachability?.factor);
    expect(s).toContain('ASSUMPTION');
    expect(s).toContain('absence in a trace window proves nothing');
    expect(s).toContain('tempo');
  });

  it('does not overwrite a finding already observed on the wire', () => {
    const observed: Occurrence = {
      ...occ('signing', true),
      reachability: {
        reachable: true,
        via: 'OBSERVED',
        entryPoint: 'signing:443',
        path: [],
        factor: { kind: 'EVIDENCE', label: 'handshake', value: true, weight: 1, sources: [] },
      },
    };
    const [after] = applyTraceReachability([observed], { rootSystems: ['gateway'], graph });
    expect(after?.reachability?.via).toBe('OBSERVED');
  });

  it('leaves a root service alone: it was already reachable on its own terms', () => {
    const before = occ('gateway', true);
    const [after] = applyTraceReachability([before], { rootSystems: ['gateway'], graph });
    expect(after).toBe(before);
  });
});

describe('OTLP ingest', () => {
  const payload = {
    resourceSpans: [
      {
        resource: { attributes: [{ key: 'service.name', value: { stringValue: 'gateway' } }] },
        scopeSpans: [{ spans: [{ traceId: 't', spanId: 'a1', name: 'POST /pay' }] }],
      },
      {
        resource: { attributes: [{ key: 'service.name', value: { stringValue: 'signing' } }] },
        scopeSpans: [
          {
            spans: [
              {
                traceId: 't',
                spanId: 'c1',
                parentSpanId: 'a1',
                name: '',
                attributes: [{ key: 'rpc.method', value: { stringValue: 'Sign' } }],
              },
            ],
          },
        ],
      },
    ],
  };

  it('reads the service name from the resource, where OTLP puts it', () => {
    const spans = spansFromOtlp(payload);
    expect(spans.map((s) => s.service).sort()).toEqual(['gateway', 'signing']);
  });

  it('falls back to rpc.method when a span has no name', () => {
    expect(spansFromOtlp(payload).find((s) => s.service === 'signing')?.operation).toBe('Sign');
  });

  it('drops spans with no service, which cannot place an edge', () => {
    const orphan = { resourceSpans: [{ resource: { attributes: [] }, scopeSpans: [{ spans: [{ traceId: 't', spanId: 'x' }] }] }] };
    expect(spansFromOtlp(orphan)).toHaveLength(0);
  });

  it('builds the same graph from OTLP as from normalized input', () => {
    const graph = buildServiceGraph(
      TraceBundleSchema.parse({
        from: '2026-08-27T00:00:00.000Z',
        to: '2026-08-28T00:00:00.000Z',
        spans: spansFromOtlp(payload),
      }),
    );
    expect(graph.edges.map((e) => `${e.from}->${e.to}`)).toEqual(['gateway->signing']);
  });
});
