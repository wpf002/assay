/**
 * Embedded DER structures, found by parsing rather than by string matching.
 *
 * An embedded certificate is a pinned trust anchor or a bundled CA, and it is
 * one of the highest-value things in a firmware image: it has a hard expiry,
 * a key algorithm, and usually nobody remembers putting it there. Finding it
 * by looking for "BEGIN CERTIFICATE" misses every DER-encoded one, which is
 * most of them.
 *
 * I9 IS LOAD-BEARING HERE. When a private-key structure is found, this
 * records that one exists, its algorithm and its offset. It never copies the
 * key bytes into a finding, a log line, or a return value, and there is no
 * code path below that could.
 */

export type DerKind = 'certificate' | 'public-key' | 'private-key' | 'unknown';

export interface DerCandidate {
  readonly offset: number;
  readonly length: number;
  readonly kind: DerKind;
  /** Algorithm OID from the AlgorithmIdentifier, where one was reachable. */
  readonly algorithmOid: string | null;
  /** Present for certificates and public keys only. Never for private keys. */
  readonly bytes: Buffer | null;
}

interface TLV {
  readonly tag: number;
  readonly headerLength: number;
  readonly length: number;
  readonly end: number;
}

/** Read a DER tag-length header. Returns null on anything not well-formed. */
function readTlv(data: Buffer, offset: number): TLV | null {
  if (offset + 2 > data.byteLength) return null;
  const tag = data[offset] as number;
  const first = data[offset + 1] as number;

  if (first < 0x80) {
    // A short-form structure that runs past the file is a coincidence too.
    if (offset + 2 + first > data.byteLength) return null;
    return { tag, headerLength: 2, length: first, end: offset + 2 + first };
  }
  // Indefinite length is not valid DER.
  if (first === 0x80) return null;
  const n = first & 0x7f;
  if (n > 4 || offset + 2 + n > data.byteLength) return null;
  let length = 0;
  for (let i = 0; i < n; i++) length = length * 256 + (data[offset + 2 + i] as number);
  // A length that runs past the file is a coincidence, not a structure.
  if (length === 0 || offset + 2 + n + length > data.byteLength) return null;
  return { tag, headerLength: 2 + n, length, end: offset + 2 + n + length };
}

/** Decode an OBJECT IDENTIFIER body into dotted form. */
export function decodeOid(data: Buffer, offset: number, length: number): string | null {
  if (length === 0 || offset + length > data.byteLength) return null;
  const first = data[offset] as number;
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < length; i++) {
    const b = data[offset + i] as number;
    value = value * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

function firstOidWithin(data: Buffer, start: number, end: number, depth = 0): string | null {
  let cursor = start;
  while (cursor < end && depth < 6) {
    const tlv = readTlv(data, cursor);
    if (tlv === null || tlv.end > end) return null;
    const body = cursor + tlv.headerLength;
    if (tlv.tag === 0x06) return decodeOid(data, body, tlv.length);
    // Descend into constructed types (bit 0x20).
    if ((tlv.tag & 0x20) !== 0) {
      const inner = firstOidWithin(data, body, tlv.end, depth + 1);
      if (inner !== null) return inner;
    }
    cursor = tlv.end;
  }
  return null;
}

/**
 * Classify a SEQUENCE by shape.
 *
 *   Certificate        ::= SEQUENCE { tbsCertificate SEQUENCE, ... }
 *   SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }
 *   PrivateKeyInfo     ::= SEQUENCE { version INTEGER 0, algorithm SEQUENCE, key OCTET STRING }
 *   RSAPrivateKey      ::= SEQUENCE { version INTEGER 0, modulus INTEGER, ... }
 */
function classify(data: Buffer, outer: TLV, offset: number): DerKind {
  const body = offset + outer.headerLength;
  const first = readTlv(data, body);
  if (first === null || first.end > outer.end) return 'unknown';

  if (first.tag === 0x30) {
    const second = readTlv(data, first.end);
    if (second === null || second.end > outer.end) return 'unknown';
    // Certificate: tbs SEQUENCE, then signatureAlgorithm SEQUENCE, then BIT STRING.
    if (second.tag === 0x30) {
      const third = readTlv(data, second.end);
      if (third !== null && third.tag === 0x03 && third.end <= outer.end) return 'certificate';
    }
    // SubjectPublicKeyInfo: AlgorithmIdentifier SEQUENCE then BIT STRING.
    if (second.tag === 0x03) return 'public-key';
    return 'unknown';
  }

  if (first.tag === 0x02 && first.length <= 2) {
    const second = readTlv(data, first.end);
    if (second === null || second.end > outer.end) return 'unknown';
    // PKCS#8 PrivateKeyInfo. The trailing OCTET STRING is what makes it one:
    // SEQUENCE{INTEGER, SEQUENCE} on its own is also a v1 TBSCertificate and a
    // CertificationRequestInfo, and "private key in shipped firmware" is far
    // too expensive an alarm to raise on a shape that broad.
    if (second.tag === 0x30) {
      const third = readTlv(data, second.end);
      return third !== null && third.tag === 0x04 && third.end <= outer.end ? 'private-key' : 'unknown';
    }
    // A bare RSAPrivateKey: version, then a modulus too large to be anything else.
    if (second.tag === 0x02 && second.length >= 64) return 'private-key';
  }
  return 'unknown';
}

export interface DerScanOptions {
  readonly minLength?: number;
  readonly maxCandidates?: number;
}

export function findDerStructures(data: Buffer, opts: DerScanOptions = {}): DerCandidate[] {
  const minLength = opts.minLength ?? 64;
  const maxCandidates = opts.maxCandidates ?? 256;
  const out: DerCandidate[] = [];

  for (let i = 0; i + 4 < data.byteLength && out.length < maxCandidates; i++) {
    if (data[i] !== 0x30) continue;
    // Short-form lengths are scanned too. Skipping them excluded every embedded
    // EC public key - a P-256 SubjectPublicKeyInfo is 91 bytes, a P-384 one 120
    // - which is the pinned trust anchor this scanner most wants to find.
    // minLength and classify() carry the noise rejection on their own: over the
    // 120 MB node binary the gate changed neither the candidate count nor the
    // findings, and cost 9 ms.
    const tlv = readTlv(data, i);
    if (tlv === null || tlv.length < minLength) continue;
    const kind = classify(data, tlv, i);
    if (kind === 'unknown') continue;

    const total = tlv.end - i;
    out.push({
      offset: i,
      length: total,
      kind,
      algorithmOid: firstOidWithin(data, i + tlv.headerLength, tlv.end),
      // I9: a private key's bytes are never carried out of this function.
      // Its existence, its algorithm and its offset are the finding.
      bytes: kind === 'private-key' ? null : data.subarray(i, tlv.end),
    });
    i = tlv.end - 1;
  }
  return out;
}

/** Algorithm OIDs seen in embedded key material, for classification. */
export const KEY_ALGORITHM_OIDS: Readonly<Record<string, { primitive: string; note: string }>> = {
  '1.2.840.113549.1.1.1': { primitive: 'RSA', note: 'rsaEncryption' },
  '1.2.840.113549.1.1.11': { primitive: 'RSA', note: 'sha256WithRSAEncryption' },
  '1.2.840.113549.1.1.5': { primitive: 'RSA', note: 'sha1WithRSAEncryption - a signature nobody should still accept' },
  '1.2.840.10045.2.1': { primitive: 'ECDSA', note: 'id-ecPublicKey' },
  '1.2.840.10045.4.3.2': { primitive: 'ECDSA', note: 'ecdsa-with-SHA256' },
  '1.2.840.10040.4.1': { primitive: 'DSA', note: 'id-dsa' },
  '1.3.101.112': { primitive: 'EdDSA', note: 'id-Ed25519' },
  '1.3.101.110': { primitive: 'X25519', note: 'id-X25519' },
  '2.16.840.1.101.3.4.4': { primitive: 'ML-KEM', note: 'ML-KEM' },
  '2.16.840.1.101.3.4.3': { primitive: 'ML-DSA', note: 'ML-DSA' },
};
