import { readFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import fg from 'fast-glob';
import type { ControlClass, Factor, Finding } from '@assay/core';
import { parseCertificates, type CertificateFacts } from './parse.js';

export * from './parse.js';

export const COLLECTOR_VERSION = 'detect-pki/0.1.0';

export const CERTIFICATE_GLOBS: readonly string[] = [
  '**/*.pem',
  '**/*.crt',
  '**/*.cer',
  '**/*.der',
  '**/*.ca-bundle',
  '**/*.chain',
  '**/fullchain*',
  '**/cacert*',
];

export interface PkiScanOptions {
  readonly root: string;
  readonly systemId: string;
  readonly collectedAt: string;
  readonly ignore?: readonly string[];
  readonly controlClass?: ControlClass;
  readonly maxFileBytes?: number;
}

export interface PkiScanResult {
  readonly findings: readonly Finding[];
  readonly certificates: readonly CertificateFacts[];
  readonly filesScanned: number;
}

export async function scanCertificates(opts: PkiScanOptions): Promise<PkiScanResult> {
  const root = resolve(opts.root);
  const maxBytes = opts.maxFileBytes ?? 1_000_000;
  const files = await fg([...CERTIFICATE_GLOBS], {
    cwd: root,
    ignore: [...(opts.ignore ?? ['**/node_modules/**', '**/.git/**', '**/dist/**'])],
    absolute: true,
    suppressErrors: true,
    followSymbolicLinks: false,
  });

  const certificates: CertificateFacts[] = [];
  let scanned = 0;

  for (const abs of files.sort()) {
    let buf: Buffer;
    try {
      buf = await readFile(abs);
    } catch {
      continue;
    }
    if (buf.byteLength > maxBytes) continue;
    scanned++;
    certificates.push(...parseCertificates(buf, relative(root, abs)));
  }

  return { findings: toFindings(certificates, opts), certificates, filesScanned: scanned };
}

/**
 * Certificates as evidence.
 *
 * Three assets come out of one certificate and they are genuinely different
 * work items: the subject key, the issuer's signature algorithm, and the
 * digest inside that signature. A CA that signs with SHA-1 is the issuer's
 * problem; a 1024-bit subject key is yours. Collapsing them into one row
 * loses the distinction that tells you who has to act.
 */
export function toFindings(
  certificates: readonly CertificateFacts[],
  opts: PkiScanOptions,
): Finding[] {
  const out: Finding[] = [];
  for (const c of certificates) {
    // A leaf you can reissue is SELF. A CA certificate is not: reissuing it
    // means redistributing a trust anchor to every relying party, which is the
    // bilateral problem wearing a different hat.
    const controlClass: ControlClass =
      opts.controlClass ?? (c.isCA ? 'PROTOCOL_BILATERAL' : 'SELF');

    const base = {
      systemId: opts.systemId,
      controlClass,
      collectedAt: opts.collectedAt,
    };
    out.push(finding(base, c, c.publicKey, 'subject public key'));
    out.push(finding(base, c, c.signature, `signature by issuer ${c.issuer}`));
    if (c.signatureDigest !== null) {
      out.push(finding(base, c, c.signatureDigest, 'digest inside the issuer signature'));
    }
  }
  return out;
}

function finding(
  base: { systemId: string; controlClass: ControlClass; collectedAt: string },
  c: CertificateFacts,
  asset: Finding['asset'],
  role: string,
): Finding {
  return {
    asset,
    systemId: base.systemId,
    controlClass: base.controlClass,
    evidence: {
      modality: 'PKI_CERTIFICATE',
      locator: `${c.source}#${c.fingerprintSha256.slice(0, 16)}`,
      raw:
        `${role} :: subject=${c.subject} issuer=${c.issuer} ` +
        `valid=${c.notBefore}..${c.notAfter} ca=${String(c.isCA)} ` +
        `selfSigned=${String(c.selfSigned)}` +
        (c.subjectAltNames.length > 0 ? ` san=${c.subjectAltNames.slice(0, 5).join(',')}` : ''),
      collectedAt: base.collectedAt,
      collectorVersion: COLLECTOR_VERSION,
      occurrence: { location: c.source, symbol: c.subject },
    },
  };
}

/* ------------------------------------------------------- lifetime vs deadline */

export interface LifetimeBreach {
  readonly certificate: CertificateFacts;
  readonly deadlineYear: number;
  readonly notAfterYear: number;
  /** Years the certificate remains valid past the deadline. */
  readonly overhangYears: number;
  readonly factor: Factor;
}

/**
 * A certificate valid past the migration deadline is a finding with a hard
 * date attached, and it is findable today without observing a single
 * handshake. A ten-year CA certificate issued now under RSA-4096 will still be
 * a trusted quantum-vulnerable trust anchor on the day the mandate bites; the
 * work is not "replace it eventually", it is "you cannot let this one expire
 * naturally".
 *
 * Pure: the caller supplies the deadline and the clock.
 */
export function lifetimeBreaches(
  certificates: readonly CertificateFacts[],
  deadlineYear: number | null,
  packLabel: string,
): LifetimeBreach[] {
  if (deadlineYear === null) return [];
  const out: LifetimeBreach[] = [];

  for (const c of certificates) {
    if (!c.publicKey.quantumVulnerable) continue;
    const notAfterYear = decimalYearOf(c.notAfter);
    if (notAfterYear <= deadlineYear) continue;

    const overhangYears = round2(notAfterYear - deadlineYear);
    out.push({
      certificate: c,
      deadlineYear,
      notAfterYear,
      overhangYears,
      factor: {
        kind: 'INFERENCE',
        label: `certificate outlives the migration deadline by ${overhangYears} year(s)`,
        value: overhangYears,
        weight: 1,
        sources: [
          {
            kind: 'EVIDENCE',
            label: `notAfter of ${c.subject} (${c.source})`,
            value: c.notAfter,
            weight: 1,
            sources: [],
          },
          {
            kind: 'POLICY',
            label: `migration deadline @ ${packLabel}`,
            value: deadlineYear,
            weight: 1,
            sources: [],
          },
          {
            kind: 'EVIDENCE',
            label: `subject key is quantum-vulnerable: ${c.publicKey.primitive}`,
            value: true,
            weight: 1,
            sources: [],
          },
        ],
      },
    });
  }
  return out.sort((a, b) => b.overhangYears - a.overhangYears);
}

function decimalYearOf(iso: string): number {
  const d = new Date(iso);
  const year = d.getUTCFullYear();
  const start = Date.UTC(year, 0, 1);
  const end = Date.UTC(year + 1, 0, 1);
  return round2(year + (d.getTime() - start) / (end - start));
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
