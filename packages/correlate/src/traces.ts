import { z } from 'zod';
import type { CallFrame, Factor, Occurrence, Reachability } from '@assay/core';

/**
 * Reachability across process boundaries.
 *
 * Static call-graph analysis stops at the network edge. A payments API that
 * calls a signing service over gRPC looks like it does no signing at all, and
 * the signing service looks like a library nobody calls - so the RSA key that
 * every payment depends on lands in "unreached" at both ends. That is the
 * single largest false-negative in the whole tool, and no amount of parsing
 * fixes it, because the edge genuinely does not exist in either codebase.
 *
 * Distributed traces do have it. A parent span in service A with a child span
 * in service B is an observation that A called B, in production, at a known
 * time.
 *
 * ONE PROPERTY GOVERNS THIS FILE: trace evidence is POSITIVE-ONLY. A trace
 * window shows what did happen, never what cannot. A service that was not
 * exercised in the window is not dead code - it is a service nobody called
 * that afternoon. Using trace absence to mark something unreached would
 * retire real work on the strength of a quiet Tuesday, so nothing here ever
 * downgrades a reachability verdict; it can only raise one.
 */

/* ------------------------------------------------------------ OTLP ingest */

const AttributeSchema = z.object({
  key: z.string(),
  value: z
    .object({
      stringValue: z.string().optional(),
      intValue: z.union([z.string(), z.number()]).optional(),
      boolValue: z.boolean().optional(),
    })
    .partial(),
});

const SpanSchema = z.object({
  traceId: z.string(),
  spanId: z.string(),
  parentSpanId: z.string().optional().default(''),
  name: z.string().default(''),
  kind: z.union([z.string(), z.number()]).optional(),
  startTimeUnixNano: z.union([z.string(), z.number()]).optional(),
  attributes: z.array(AttributeSchema).optional().default([]),
});

const ResourceSpansSchema = z.object({
  resource: z
    .object({ attributes: z.array(AttributeSchema).optional().default([]) })
    .optional()
    .default({ attributes: [] }),
  scopeSpans: z
    .array(z.object({ spans: z.array(SpanSchema).optional().default([]) }))
    .optional()
    .default([]),
});

export const OtlpTraceSchema = z.object({
  resourceSpans: z.array(ResourceSpansSchema).default([]),
});

/** Already-normalized input, for anyone whose tracing backend is not OTLP. */
export const SpanRecordSchema = z.object({
  service: z.string().min(1),
  spanId: z.string().min(1),
  parentSpanId: z.string().default(''),
  operation: z.string().default(''),
  observedAt: z.string().optional(),
});
export type SpanRecord = z.infer<typeof SpanRecordSchema>;

export const TraceBundleSchema = z.object({
  /** The window these traces cover. Recorded because absence within it proves nothing. */
  from: z.string().datetime(),
  to: z.string().datetime(),
  source: z.string().default(''),
  spans: z.array(SpanRecordSchema),
});
export type TraceBundle = z.infer<typeof TraceBundleSchema>;

function attribute(attrs: readonly z.infer<typeof AttributeSchema>[], key: string): string | null {
  for (const a of attrs) {
    if (a.key !== key) continue;
    if (a.value.stringValue !== undefined) return a.value.stringValue;
    if (a.value.intValue !== undefined) return String(a.value.intValue);
  }
  return null;
}

/** OTLP JSON -> normalized spans. Service name comes from the resource. */
export function spansFromOtlp(payload: unknown): SpanRecord[] {
  const parsed = OtlpTraceSchema.parse(payload);
  const out: SpanRecord[] = [];

  for (const rs of parsed.resourceSpans) {
    const service = attribute(rs.resource.attributes, 'service.name');
    if (service === null) continue; // a span with no service cannot place an edge
    for (const scope of rs.scopeSpans) {
      for (const span of scope.spans) {
        out.push({
          service,
          spanId: span.spanId,
          parentSpanId: span.parentSpanId,
          operation:
            span.name ||
            attribute(span.attributes, 'rpc.method') ||
            attribute(span.attributes, 'http.route') ||
            '',
        });
      }
    }
  }
  return out;
}

/* -------------------------------------------------------------- service graph */

export interface ServiceEdge {
  readonly from: string;
  readonly to: string;
  /** How many parent/child span pairs supported this edge. */
  readonly observations: number;
  /** A representative operation, for the path a reviewer reads. */
  readonly operation: string;
}

export interface ServiceGraph {
  readonly services: ReadonlySet<string>;
  readonly edges: readonly ServiceEdge[];
  readonly window: { readonly from: string; readonly to: string } | null;
  readonly source: string;
}

export function buildServiceGraph(bundle: TraceBundle): ServiceGraph {
  const byId = new Map(bundle.spans.map((s) => [s.spanId, s]));
  const services = new Set(bundle.spans.map((s) => s.service));
  const edges = new Map<string, ServiceEdge>();

  for (const span of bundle.spans) {
    if (span.parentSpanId === '') continue;
    const parent = byId.get(span.parentSpanId);
    if (parent === undefined) continue;
    // Only a boundary crossing is an edge. Spans within one service are the
    // static analyzer's job and it does that better.
    if (parent.service === span.service) continue;

    const key = `${parent.service}->${span.service}`;
    const existing = edges.get(key);
    edges.set(key, {
      from: parent.service,
      to: span.service,
      observations: (existing?.observations ?? 0) + 1,
      operation: existing?.operation ?? span.operation,
    });
  }

  return {
    services,
    edges: [...edges.values()].sort(
      (a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to),
    ),
    window: { from: bundle.from, to: bundle.to },
    source: bundle.source,
  };
}

/**
 * Services that were called from outside the traced estate.
 *
 * A span with no parent is the top of a trace: something a user, a job or an
 * external system initiated. Those services are reachable by definition, and
 * they are where propagation starts when the scan itself only knows about one
 * repository.
 */
export function traceRoots(graph: ServiceGraph, spans: readonly SpanRecord[]): string[] {
  const known = new Set(spans.map((s) => s.spanId));
  const roots = new Set<string>();
  for (const span of spans) {
    // Parentless, or parented by a span outside this bundle - both mean the
    // call came from somewhere the traces do not cover.
    if (span.parentSpanId === '' || !known.has(span.parentSpanId)) roots.add(span.service);
  }
  return [...roots].filter((s) => graph.services.has(s)).sort();
}

/* ---------------------------------------------------- cross-service reachability */

export interface EstateReachabilityOptions {
  /**
   * Systems already known to be reached in their own right - typically those
   * with a detected HTTP entry point. Traces propagate reachability outward
   * from these.
   */
  readonly rootSystems: readonly string[];
  readonly graph: ServiceGraph;
}

export interface ServicePath {
  readonly service: string;
  readonly hops: readonly ServiceEdge[];
}

/** Shortest call path from any root service to each service traces can reach. */
export function reachableServices(opts: EstateReachabilityOptions): Map<string, ServicePath> {
  const out = new Map<string, ServicePath>();
  const outgoing = new Map<string, ServiceEdge[]>();
  for (const e of opts.graph.edges) {
    const list = outgoing.get(e.from) ?? [];
    list.push(e);
    outgoing.set(e.from, list);
  }

  const queue: ServicePath[] = opts.rootSystems.map((service) => ({ service, hops: [] }));
  for (const root of queue) out.set(root.service, root);

  while (queue.length > 0) {
    const current = queue.shift() as ServicePath;
    for (const edge of outgoing.get(current.service) ?? []) {
      if (out.has(edge.to)) continue;
      const next: ServicePath = { service: edge.to, hops: [...current.hops, edge] };
      out.set(edge.to, next);
      queue.push(next);
    }
  }
  return out;
}

/**
 * Raise reachability for occurrences in services that traces show being called.
 *
 * Only ever raises. An occurrence already reachable keeps its stronger verdict;
 * one that static analysis judged dead is *promoted*, because a trace is an
 * observation and the static verdict was an inference. An occurrence in a
 * service the traces never touched is left exactly as it was.
 */
export function applyTraceReachability(
  occurrences: readonly Occurrence[],
  opts: EstateReachabilityOptions,
): Occurrence[] {
  const reachable = reachableServices(opts);

  return occurrences.map((o) => {
    const path = reachable.get(o.systemId);
    if (path === undefined) return o;
    // A root service was already reachable on its own terms; traces add nothing.
    if (path.hops.length === 0) return o;
    if (o.reachability?.via === 'OBSERVED') return o;

    return { ...o, reachability: traceReachability(o, path, opts.graph) };
  });
}

function traceReachability(
  occurrence: Occurrence,
  path: ServicePath,
  graph: ServiceGraph,
): Reachability {
  const frames: CallFrame[] = path.hops.map((hop) => ({
    module: hop.from,
    function: hop.operation === '' ? 'rpc' : hop.operation,
    fullFilename: `${hop.from} -> ${hop.to}`,
  }));

  const local = occurrence.reachability;
  const localFrames = local?.path ?? [];

  const sources: Factor[] = [
    {
      kind: 'EVIDENCE',
      label: `traced call path ${[path.hops[0]?.from, ...path.hops.map((h) => h.to)].join(' -> ')}`,
      value: path.hops.reduce((n, h) => n + h.observations, 0),
      weight: 1,
      sources: [],
    },
    {
      kind: 'ASSUMPTION',
      // Positive-only, stated. The window is what the claim rests on.
      label:
        `traces cover ${graph.window?.from ?? '?'} to ${graph.window?.to ?? '?'}` +
        (graph.source === '' ? '' : ` from ${graph.source}`) +
        '; a service not exercised in that window is not shown as unreached, because absence in a trace window proves nothing',
      value: true,
      weight: 0,
      sources: [],
    },
  ];
  if (local !== null && local !== undefined) {
    sources.push({
      kind: 'INFERENCE',
      label: `static analysis within ${occurrence.systemId} concluded reachable=${String(local.reachable)}`,
      value: local.reachable,
      weight: 1,
      sources: [local.factor],
    });
  }

  return {
    reachable: true,
    via: 'TRACE',
    entryPoint: path.hops[0]?.from ?? occurrence.systemId,
    path: [...frames, ...localFrames],
    factor: {
      kind: 'INFERENCE',
      label: `reached across ${path.hops.length} service hop(s) observed in production traces`,
      value: true,
      weight: 1,
      sources,
    },
  };
}
