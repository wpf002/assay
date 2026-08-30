import { open, readFile } from 'node:fs/promises';
import { basename, relative, resolve } from 'node:path';
import fg from 'fast-glob';
import { makeAsset, type ControlClass, type Finding, type Primitive } from '@assay/core';
import { LOW_SPECIFICITY, findConstants, type ConstantHit } from './constants.js';
import { detectFormat, parseBinary, type BinaryInfo } from './formats/index.js';
import { fingerprintLibraries, matchSymbols, type LibraryFingerprint } from './symbols.js';
import { KEY_ALGORITHM_OIDS, findDerStructures, type DerCandidate } from './der.js';
import { cryptoStrings, extractStrings } from './strings.js';

export * from './constants.js';
export * from './formats/index.js';
export * from './symbols.js';
export * from './der.js';
export * from './strings.js';

export const COLLECTOR_VERSION = 'detect-binary/0.1.0';

/**
 * Binary analysis. Last on purpose.
 *
 * Highest effort, lowest confidence, and shipping it early buries the good
 * signal under noise. Its three modalities differ by an order of magnitude in
 * strength and are kept strictly apart:
 *
 *   BINARY_CONSTANT 0.90 - a fixed byte table that does not occur by accident
 *   BINARY_SYMBOL   0.85 - a relocation the loader had to resolve
 *   BINARY_STRING   0.30 - a sequence of characters
 *
 * The Phase 5 exit gate is that BINARY_STRING never reaches CONFIRMED without
 * independent corroboration, and it needs no special case: 0.30 cannot reach
 * 0.85 by noisy-OR within its own group, however many matches there are.
 */

export interface BinaryScanOptions {
  readonly root: string;
  readonly systemId: string;
  readonly collectedAt: string;
  readonly ignore?: readonly string[];
  readonly include?: readonly string[];
  /** Vendor blobs are the point of this detector, so default to VENDOR_LOCKED. */
  readonly controlClass?: ControlClass;
  readonly maxFileBytes?: number;
}

export interface BinaryReport {
  readonly file: string;
  readonly info: BinaryInfo;
  readonly constants: readonly ConstantHit[];
  readonly der: readonly DerCandidate[];
  readonly libraries: readonly LibraryFingerprint[];
  readonly cryptoStringCount: number;
}

export interface BinaryScanResult {
  readonly findings: readonly Finding[];
  readonly reports: readonly BinaryReport[];
  readonly filesScanned: number;
}

export const DEFAULT_BINARY_GLOBS: readonly string[] = [
  '**/*.so',
  '**/*.so.*',
  '**/*.dylib',
  '**/*.dll',
  '**/*.exe',
  '**/*.node',
  '**/*.a',
  '**/*.bin',
  '**/*.elf',
  '**/*.img',
  '**/*.wasm',
];

/** ELF, Mach-O (32/64, both endiannesses, and the fat header), PE. */
const MAGIC: readonly (readonly number[])[] = [
  [0x7f, 0x45, 0x4c, 0x46], // \x7fELF
  [0xfe, 0xed, 0xfa, 0xce], // Mach-O 32 BE
  [0xfe, 0xed, 0xfa, 0xcf], // Mach-O 64 BE
  [0xce, 0xfa, 0xed, 0xfe], // Mach-O 32 LE
  [0xcf, 0xfa, 0xed, 0xfe], // Mach-O 64 LE
  [0xca, 0xfe, 0xba, 0xbe], // Mach-O universal
  [0x4d, 0x5a], // MZ
];

export function looksExecutable(head: Uint8Array): boolean {
  return MAGIC.some((m) => m.every((byte, i) => head[i] === byte));
}

/** Reads four bytes per candidate, never the whole file. */
async function filterByMagic(paths: readonly string[]): Promise<string[]> {
  const out: string[] = [];
  for (const path of paths) {
    let fh;
    try {
      fh = await open(path, 'r');
      const buf = Buffer.alloc(4);
      const { bytesRead } = await fh.read(buf, 0, 4, 0);
      if (bytesRead === 4 && looksExecutable(buf)) out.push(path);
    } catch {
      /* unreadable is not scannable */
    } finally {
      await fh?.close();
    }
  }
  return out;
}

export async function scanBinaries(opts: BinaryScanOptions): Promise<BinaryScanResult> {
  const root = resolve(opts.root);
  // Firmware images and shipped runtimes are the point of this detector and
  // are routinely over 100 MB - the Node binary itself is. A 64 MB cap
  // silently skipped exactly the files worth scanning.
  const maxBytes = opts.maxFileBytes ?? 512 * 1024 * 1024;
  const ignore = [...(opts.ignore ?? ['**/.git/**'])];
  const globbed = await fg([...(opts.include ?? DEFAULT_BINARY_GLOBS)], {
    cwd: root,
    ignore,
    absolute: true,
    suppressErrors: true,
    followSymbolicLinks: false,
  });

  // Extension globs miss the most common shape a vendor binary actually takes.
  // A shipped agent is /opt/vendor/bin/agent with no extension at all, and
  // every Unix executable is: matching only *.so and *.exe scanned the
  // libraries and skipped the program. So files with no extension are checked
  // by magic number instead - four bytes, on files the globs did not already
  // claim, which is cheap enough to do unconditionally and honest about what
  // it does and does not cover.
  const claimed = new Set(globbed);
  const extensionless = opts.include === undefined
    ? (
        await fg(['**/*'], {
          cwd: root,
          ignore,
          absolute: true,
          suppressErrors: true,
          followSymbolicLinks: false,
          onlyFiles: true,
        })
      ).filter((f) => !claimed.has(f) && !basename(f).includes('.'))
    : [];

  const candidates = [...globbed, ...(await filterByMagic(extensionless))];

  const findings: Finding[] = [];
  const reports: BinaryReport[] = [];
  let scanned = 0;

  for (const abs of candidates.sort()) {
    let data: Buffer;
    try {
      data = await readFile(abs);
    } catch {
      continue;
    }
    if (data.byteLength > maxBytes || data.byteLength < 64) continue;

    const rel = relative(root, abs);
    const report = analyzeBinary(data, rel);
    if (report === null) continue;
    scanned++;
    reports.push(report);
    findings.push(...toFindings(report, opts));
  }

  return { findings, reports, filesScanned: scanned };
}

/** Everything this detector can say about one blob. Pure; no I/O. */
export function analyzeBinary(data: Buffer, file: string): BinaryReport | null {
  const format = detectFormat(data);
  const info = parseBinary(data);
  const strings = extractStrings(data);
  const constants = findConstants(data);
  const der = findDerStructures(data);
  const libraries = fingerprintLibraries(strings.map((s) => s.value));
  const crypto = cryptoStrings(strings);

  // Not an executable and nothing cryptographic in it: not a binary finding.
  if (
    format === 'unknown' &&
    constants.length === 0 &&
    der.length === 0 &&
    libraries.length === 0 &&
    crypto.length === 0
  ) {
    return null;
  }

  return { file, info, constants, der, libraries, cryptoStringCount: crypto.length };
}

function toFindings(report: BinaryReport, opts: BinaryScanOptions): Finding[] {
  const controlClass = opts.controlClass ?? 'VENDOR_LOCKED';
  const out: Finding[] = [];
  const base = { systemId: opts.systemId, controlClass, collectedAt: opts.collectedAt };

  // Constants: byte-exact, and the strongest thing available in a stripped file.
  const bySignature = new Map<string, ConstantHit[]>();
  for (const hit of report.constants) {
    const list = bySignature.get(hit.signature.id) ?? [];
    list.push(hit);
    bySignature.set(hit.signature.id, list);
  }
  for (const [id, hits] of [...bySignature.entries()].sort()) {
    const first = hits[0] as ConstantHit;
    const sig = first.signature;
    // A low-specificity constant is real but cannot stand alone, so it is
    // demoted to the string modality rather than dropped: the observation is
    // preserved and the arithmetic stops it confirming anything.
    const modality = LOW_SPECIFICITY.has(id) ? 'BINARY_STRING' : 'BINARY_CONSTANT';
    out.push({
      asset: makeAsset(sig.primitive, sig.parameters, sig.purpose),
      ...base,
      evidence: {
        modality,
        locator: `${report.file}@0x${first.offset.toString(16)}`,
        raw:
          `constant ${sig.id} at ${hits.length} offset(s) :: ${sig.rationale}` +
          (modality === 'BINARY_STRING' ? ' :: demoted, cannot confirm alone' : ''),
        collectedAt: opts.collectedAt,
        collectorVersion: COLLECTOR_VERSION,
        occurrence: { location: report.file, offset: first.offset, symbol: sig.id },
      },
    });
  }

  // Symbols: a relocation the loader had to resolve.
  for (const m of matchSymbols(report.info.symbols)) {
    out.push({
      asset: makeAsset(m.primitive, m.parameters, m.purpose),
      ...base,
      evidence: {
        modality: 'BINARY_SYMBOL',
        locator: `${report.file}!${m.symbol}`,
        raw: `imported symbol ${m.symbol} :: ${m.rationale} :: ${report.info.format}/${report.info.arch}`,
        collectedAt: opts.collectedAt,
        collectorVersion: COLLECTOR_VERSION,
        occurrence: { location: report.file, symbol: m.symbol },
      },
    });
  }

  // Embedded key material. The existence and the algorithm; never the bytes (I9).
  for (const candidate of report.der) {
    const oid = candidate.algorithmOid;
    const known = oid === null ? undefined : KEY_ALGORITHM_OIDS[oid];
    // A PKCS#1 RSAPrivateKey - openssl genrsa's own output, and what every
    // `BEGIN RSA PRIVATE KEY` file holds - carries no AlgorithmIdentifier, so
    // there is no OID to recognise and the whole finding was being thrown away.
    // The kind is the finding. The OID filter still earns its place for
    // certificates and public keys, where an unrecognised one means noise.
    if (known === undefined && candidate.kind !== 'private-key') continue;
    const note =
      known !== undefined
        ? known.note
        : oid === null
          ? 'no AlgorithmIdentifier in the structure'
          : 'algorithm OID not recognised';
    out.push({
      asset: makeAsset(
        (known?.primitive ?? 'UNKNOWN') as Primitive,
        {},
        candidate.kind === 'certificate' ? 'CERTIFICATE_AUTH' : 'KEY_ESTABLISHMENT',
      ),
      ...base,
      evidence: {
        // A parsed DER structure is a certificate-grade fact even when it is
        // embedded in a binary: the algorithm is stated, not inferred.
        modality: candidate.kind === 'certificate' ? 'PKI_CERTIFICATE' : 'BINARY_CONSTANT',
        locator: `${report.file}@0x${candidate.offset.toString(16)}`,
        raw:
          `embedded ${candidate.kind} (${candidate.length} bytes) algorithm=${oid ?? 'unknown'} ` +
          `(${note})` +
          (candidate.kind === 'private-key'
            ? ' :: existence and algorithm recorded; key material was never read (I9)'
            : ''),
        collectedAt: opts.collectedAt,
        collectorVersion: COLLECTOR_VERSION,
        occurrence: { location: report.file, offset: candidate.offset, symbol: candidate.kind },
      },
    });
  }

  // Library fingerprints. A version is the difference between an upgrade and
  // a procurement problem.
  for (const lib of report.libraries) {
    out.push({
      asset: makeAsset('UNKNOWN', { library: lib.library, version: lib.version ?? 'unknown' }, 'RANDOMNESS'),
      ...base,
      evidence: {
        modality: 'BINARY_STRING',
        locator: `${report.file}#${lib.library}`,
        raw: `library fingerprint ${lib.library} ${lib.version ?? '(version not stated)'} :: ${lib.evidence}`,
        collectedAt: opts.collectedAt,
        collectorVersion: COLLECTOR_VERSION,
        occurrence: { location: report.file, symbol: lib.library },
      },
    });
  }

  return out;
}
