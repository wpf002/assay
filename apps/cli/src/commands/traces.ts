import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  SpanRecordSchema,
  TraceBundleSchema,
  buildServiceGraph,
  spansFromOtlp,
  traceRoots,
  type ServiceGraph,
  type SpanRecord,
} from '@assay/correlate';
import { z } from 'zod';

/**
 * Accept either an OTLP export or a normalized bundle.
 *
 * Nobody's tracing backend agrees on an export format, and requiring one is
 * how a feature that needs a five-minute copy-paste becomes a quarter-long
 * integration project.
 */
export interface LoadedTraces {
  readonly graph: ServiceGraph;
  readonly spans: readonly SpanRecord[];
  readonly roots: readonly string[];
}

export async function loadTraces(path: string): Promise<LoadedTraces> {
  const raw: unknown = JSON.parse(await readFile(resolve(path), 'utf8'));

  let spans: SpanRecord[];
  let from: string;
  let to: string;
  let source: string;

  const bundle = TraceBundleSchema.safeParse(raw);
  if (bundle.success) {
    spans = bundle.data.spans;
    from = bundle.data.from;
    to = bundle.data.to;
    source = bundle.data.source;
  } else {
    // Only an OTLP export may take this branch. OtlpTraceSchema is non-strict
    // and defaults its single field, so every JSON object parses as one and
    // yields no spans at all: without this check a bundle rejected for a bad
    // timestamp is silently re-read as an empty export, the scan loses every
    // cross-service promotion, and nothing is printed to say so.
    if (!isOtlpExport(raw)) {
      throw new Error(
        `${resolve(path)} is not a valid trace bundle: ${bundle.error.issues
          .map((i) => `${i.path.join('.')} ${i.message.toLowerCase()}`)
          .join('; ')}`,
      );
    }
    spans = spansFromOtlp(raw);
    const window = z
      .object({ from: z.string().optional(), to: z.string().optional(), source: z.string().optional() })
      .safeParse(raw);
    // An OTLP dump carries no window of its own. Saying so is better than
    // inventing one, because the window is what a promoted finding rests on.
    from = window.success && window.data.from !== undefined ? window.data.from : 'unstated';
    to = window.success && window.data.to !== undefined ? window.data.to : 'unstated';
    source = window.success && window.data.source !== undefined ? window.data.source : resolve(path);
  }

  // An edge needs a service name at both ends. A file that carries none of
  // them promotes nothing, and reporting that is the only way the operator
  // learns it, since an empty graph prints no trace line at all.
  if (spans.length === 0) {
    throw new Error(`${resolve(path)} carries no spans with a service name`);
  }

  const normalized = spans.map((s) => SpanRecordSchema.parse(s));
  const graph = buildServiceGraph({ from, to, source, spans: normalized });
  return { graph, spans: normalized, roots: traceRoots(graph, normalized) };
}

/** OTLP JSON carries its spans under resourceSpans; a bundle carries `spans`. */
function isOtlpExport(raw: unknown): boolean {
  return typeof raw === 'object' && raw !== null && 'resourceSpans' in raw;
}
