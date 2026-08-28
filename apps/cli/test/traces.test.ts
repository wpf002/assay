import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadTraces } from '../src/commands/traces.js';

/**
 * Trace ingest. A bundle and an OTLP export are told apart on the way in,
 * because OtlpTraceSchema accepts any JSON object and returns no spans - so a
 * bundle that fails validation looks exactly like a successful load of an
 * export that traced nothing.
 */

const BUNDLE = {
  from: '2026-08-27T00:00:00.000Z',
  to: '2026-08-28T00:00:00.000Z',
  source: 'tempo',
  spans: [
    { service: 'gateway', spanId: 'a1', parentSpanId: '', operation: 'POST /v1/payments' },
    { service: 'signer', spanId: 'b1', parentSpanId: 'a1', operation: 'Signer/Sign' },
  ],
};

const OTLP = {
  resourceSpans: [
    {
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'gateway' } }] },
      scopeSpans: [{ spans: [{ traceId: 't', spanId: 'a1', name: 'POST /v1/payments' }] }],
    },
  ],
};

async function write(name: string, body: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'assay-traces-'));
  const path = join(dir, name);
  await writeFile(path, JSON.stringify(body), 'utf8');
  return path;
}

describe('loadTraces', () => {
  it('reads a normalized bundle', async () => {
    const traces = await loadTraces(await write('bundle.json', BUNDLE));
    expect(traces.spans).toHaveLength(2);
    expect(traces.graph.edges.map((e) => `${e.from}->${e.to}`)).toEqual(['gateway->signer']);
  });

  it('reads an OTLP export', async () => {
    const traces = await loadTraces(await write('otlp.json', OTLP));
    expect(traces.spans.map((s) => s.service)).toEqual(['gateway']);
  });

  it('rejects a bundle with a bad window instead of reading it as an empty export', async () => {
    const path = await write('bad-window.json', { ...BUNDLE, from: '2026-08-27' });
    await expect(loadTraces(path)).rejects.toThrow(
      `${resolve(path)} is not a valid trace bundle: from invalid datetime`,
    );
  });

  it('rejects a bundle whose spans are malformed', async () => {
    const path = await write('bad-span.json', { ...BUNDLE, spans: [{ spanId: 'a1' }] });
    await expect(loadTraces(path)).rejects.toThrow('is not a valid trace bundle');
  });

  it('reports an export that carries no span with a service name', async () => {
    const path = await write('anonymous.json', {
      resourceSpans: [
        { resource: { attributes: [] }, scopeSpans: [{ spans: [{ traceId: 't', spanId: 'a1' }] }] },
      ],
    });
    await expect(loadTraces(path)).rejects.toThrow('carries no spans with a service name');
  });
});
