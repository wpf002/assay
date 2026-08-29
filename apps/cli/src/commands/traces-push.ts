import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { requestHeaders } from '../http.js';

/**
 * Ship a trace export to the API.
 *
 * The file goes up as-is and the server derives the graph, so the reduction to
 * edges - and the discarding of every span attribute - happens in exactly one
 * place. Doing it client-side too would be a second implementation of the one
 * privacy property this feature rests on.
 */
export interface TracesPushOptions {
  readonly api: string;
  /** API token. The API has no anonymous access; there is no way to disable that. */
  readonly token?: string;
}

export async function runTracesPush(path: string, options: TracesPushOptions): Promise<void> {
  const headers = requestHeaders(options.api, options.token);
  const payload: unknown = JSON.parse(await readFile(resolve(path), 'utf8'));
  const res = await fetch(`${options.api.replace(/\/$/, '')}/traces`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`trace upload failed: ${res.status} ${await res.text()}`);
  }
  const body = (await res.json()) as {
    id: string;
    spansIngested: number;
    spansStored: number;
    edges: number;
    services: string[];
    rootServices: string[];
  };
  process.stdout.write(
    `uploaded ${body.spansIngested} span(s) as ${body.id}\n` +
      `  ${body.edges} service edge(s) across ${body.services.length} service(s)\n` +
      `  roots: ${body.rootServices.join(', ') || 'none'}\n` +
      `  spans stored: ${body.spansStored} - the graph is kept, the spans are not\n\n` +
      `  ${options.api}/estate/worklists\n` +
      `  ${options.api}/estate/coverage\n`,
  );
}
