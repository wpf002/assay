import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { generateCoverageKeypair, verifyCoverage } from '@assay/coverage';
import type { CoverageReport, SignedCoverage } from '@assay/coverage';
import { requestHeaders } from '../http.js';

/**
 * Fetch and check a coverage attestation.
 *
 * The document exists so an operator can hand somebody a file instead of a
 * screenshot. That only works if the recipient can check it without trusting
 * the sender, which is what `verify` is for - and why it demands the trusted
 * public key rather than using the one packaged with the signature.
 */

export interface CoverageFetchOptions {
  readonly api: string;
  readonly token?: string;
  readonly estate?: boolean;
  readonly out?: string;
}

type Envelope =
  | ({ signed: true } & SignedCoverage)
  | { signed: false; reason: string; digest: string; report: CoverageReport };

export async function runCoverage(scanId: string | undefined, options: CoverageFetchOptions): Promise<void> {
  const headers = requestHeaders(options.api, options.token);
  const base = options.api.replace(/\/$/, '');
  const path =
    options.estate === true || scanId === undefined
      ? '/estate/attestation'
      : `/scans/${encodeURIComponent(scanId)}/coverage`;

  const res = await fetch(`${base}${path}`, { headers });
  if (!res.ok) {
    throw new Error(`coverage failed: ${res.status} ${await res.text()}`);
  }
  const body = (await res.json()) as Envelope;
  const json = `${JSON.stringify(body, null, 2)}\n`;

  if (options.out !== undefined) {
    await writeFile(resolve(options.out), json, 'utf8');
  } else {
    process.stdout.write(json);
  }
  process.stderr.write(summarize(body, options.out));
}

function summarize(body: Envelope, out: string | undefined): string {
  const r = body.report;
  const missing = r.classes.filter((c) => !c.examined);
  const lines = [
    '',
    `${r.subject.kind === 'ESTATE' ? 'Estate' : 'Scan'} ${r.subject.id}`,
    `  examined ${r.summary.classesExamined} of ${r.summary.classesTotal} classes of the estate`,
    ...missing.map((c) => `  not examined: ${c.label} - ${c.remedy}`),
    ...(r.blindSpots.length === 0
      ? []
      : [`  ${r.blindSpots.length} blind spot(s): ${r.blindSpots.map((b) => b.name).join(', ')}`]),
    body.signed
      ? `  signed; digest ${body.digest}`
      : `  UNSIGNED - ${body.reason}`,
    ...(out === undefined ? [] : [`  written to ${out}`]),
    '',
  ];
  return `${lines.join('\n')}\n`;
}

export interface CoverageVerifyOptions {
  readonly key: string;
}

export async function runCoverageVerify(file: string, options: CoverageVerifyOptions): Promise<void> {
  const body = JSON.parse(await readFile(resolve(file), 'utf8')) as Envelope;
  if (body.signed !== true) {
    throw new Error('this attestation is unsigned; there is nothing to verify');
  }
  // The key the reader trusts, not the one in the envelope. Verifying with the
  // packaged key proves only that the file agrees with itself.
  const key = options.key.includes('-----BEGIN')
    ? options.key
    : await readFile(resolve(options.key), 'utf8');

  const verdict = verifyCoverage(body, key);
  if (!verdict.ok) {
    throw new Error(`attestation does not verify: ${verdict.reason}`);
  }
  process.stdout.write(
    `verified against the supplied key\n` +
      `  subject: ${body.report.subject.kind} ${body.report.subject.id}\n` +
      `  generated: ${body.report.generatedAt}\n` +
      `  examined ${body.report.summary.classesExamined} of ${body.report.summary.classesTotal} classes\n` +
      `  digest: ${body.digest}\n`,
  );
}

export async function runCoverageKeygen(options: { out?: string }): Promise<void> {
  const kp = generateCoverageKeypair();
  if (options.out === undefined) {
    process.stdout.write(kp.privateKeyPem);
    process.stdout.write(kp.publicKeyPem);
    return;
  }
  const base = resolve(options.out);
  await writeFile(base, kp.privateKeyPem, { encoding: 'utf8', mode: 0o600 });
  await writeFile(`${base}.pub`, kp.publicKeyPem, 'utf8');
  process.stderr.write(
    `wrote ${base} (private, mode 600) and ${base}.pub\n` +
      `  set ASSAY_COVERAGE_KEY=${base} on the API to sign attestations\n` +
      `  give the .pub to whoever has to check them\n`,
  );
}
