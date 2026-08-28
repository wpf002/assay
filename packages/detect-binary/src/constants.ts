import type { Primitive, Purpose } from '@assay/core';

/**
 * Byte-exact algorithm constants.
 *
 * This is the strong half of binary analysis and the reason BINARY_CONSTANT
 * sits at 0.90 while BINARY_STRING sits at 0.30. An AES S-box is 256 specific
 * bytes in a specific order; it survives stripping, it survives symbol
 * removal, and it does not occur by accident. A string that says "AES" occurs
 * in error messages, in test fixtures, and in unrelated English.
 *
 * Every table here is a prefix, not the whole constant. A prefix long enough
 * to be unique is enough to identify, and it keeps the scanner's own binary
 * from being a useful crypto oracle for anyone reading it.
 */

export interface ConstantSignature {
  readonly id: string;
  readonly primitive: Primitive;
  readonly parameters: Readonly<Record<string, string | number>>;
  readonly purpose: Purpose;
  readonly bytes: Uint8Array;
  /** Why this byte sequence identifies this algorithm, for a human reviewing a hit. */
  readonly rationale: string;
  /**
   * Word size, when the constant is a table of integers rather than a byte
   * string. A compiler stores a uint32 table in the target's byte order, so a
   * big-endian-only signature finds SHA-2 on nothing that anyone actually
   * ships. Both orders are searched.
   */
  readonly wordSize?: 4 | 8;
}

const hex = (s: string): Uint8Array =>
  Uint8Array.from((s.replace(/\s+/g, '').match(/.{2}/g) ?? []).map((b) => parseInt(b, 16)));

/** First 32 bytes of the AES forward S-box (FIPS 197, Figure 7). */
const AES_SBOX = hex(`
  637c777bf26b6fc53001672bfed7ab76
  ca82c97dfa5947f0add4a2af9ca472c0
`);

/** First 8 words of the SHA-256 round constants K (FIPS 180-4), big-endian. */
const SHA256_K = hex(`
  428a2f9871374491b5c0fbcfe9b5dba5
  3956c25b59f111f1923f82a4ab1c5ed5
`);

/** First 8 words of the SHA-512 round constants K, big-endian. */
const SHA512_K = hex(`
  428a2f98d728ae227137449123ef65cd
  b5c0fbcfec4d3b2fe9b5dba58189dbbc
`);

/** SHA-1 initial state H0..H4 plus its first round constant. */
const SHA1_H = hex('67452301efcdab8998badcfe10325476c3d2e1f05a827999');

/** MD5 T-table first four entries T[1..4] = floor(2^32 * abs(sin i)), big-endian. */
const MD5_T = hex('d76aa478e8c7b756242070dbc1bdceee');

/** NIST P-256 field prime p, big-endian (SEC 2, secp256r1). */
const P256_PRIME = hex('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff');

/** NIST P-256 curve coefficient b. */
const P256_B = hex('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');

/** NIST P-384 field prime p. */
const P384_PRIME = hex(
  'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
);

/** Curve25519 base point u = 9, as the 32-byte little-endian encoding. */
const X25519_BASEPOINT = hex('0900000000000000000000000000000000000000000000000000000000000000');

/** ChaCha20 "expand 32-byte k" sigma constant. */
const CHACHA_SIGMA = new TextEncoder().encode('expand 32-byte k');

/** DES permuted choice 1, first 16 entries (FIPS 46-3), one byte per bit index. */
const DES_PC1 = hex('39312921191109013a322a221a120a02');

const SPECIFIED: readonly ConstantSignature[] = [
  {
    id: 'aes-sbox',
    primitive: 'AES',
    parameters: {},
    purpose: 'DATA_ENCRYPTION',
    bytes: AES_SBOX,
    rationale: 'AES forward S-box, FIPS 197 Figure 7. A fixed 256-byte permutation; it does not occur by chance.',
  },
  {
    id: 'sha256-k',
    primitive: 'SHA2',
    parameters: { outputLength: 256 },
    purpose: 'INTEGRITY',
    bytes: SHA256_K,
    rationale: 'SHA-256 round constants K[0..7]: cube roots of the first primes, FIPS 180-4.',
    wordSize: 4,
  },
  {
    id: 'sha512-k',
    primitive: 'SHA2',
    parameters: { outputLength: 512 },
    purpose: 'INTEGRITY',
    bytes: SHA512_K,
    rationale: 'SHA-512 round constants K[0..3], 64-bit words, FIPS 180-4.',
    wordSize: 8,
  },
  {
    id: 'sha1-h',
    primitive: 'SHA1',
    parameters: { outputLength: 160 },
    purpose: 'INTEGRITY',
    bytes: SHA1_H,
    rationale: 'SHA-1 initial hash value H0..H4 followed by the first round constant 0x5a827999.',
    wordSize: 4,
  },
  {
    id: 'md5-t',
    primitive: 'MD5',
    parameters: { outputLength: 128 },
    purpose: 'INTEGRITY',
    bytes: MD5_T,
    rationale: 'MD5 T-table T[1..4], derived from abs(sin(i)). Specification (big-endian) word order.',
    wordSize: 4,
  },
  {
    id: 'p256-prime',
    primitive: 'ECDSA',
    parameters: { curve: 'P-256' },
    purpose: 'DIGITAL_SIGNATURE',
    bytes: P256_PRIME,
    rationale: 'secp256r1 field prime. Identifies the curve regardless of which library implements it.',
  },
  {
    id: 'p256-b',
    primitive: 'ECDSA',
    parameters: { curve: 'P-256' },
    purpose: 'DIGITAL_SIGNATURE',
    bytes: P256_B,
    rationale: 'secp256r1 curve coefficient b.',
  },
  {
    id: 'p384-prime',
    primitive: 'ECDSA',
    parameters: { curve: 'P-384' },
    purpose: 'DIGITAL_SIGNATURE',
    bytes: P384_PRIME,
    rationale: 'secp384r1 field prime.',
  },
  {
    id: 'x25519-basepoint',
    primitive: 'X25519',
    parameters: {},
    purpose: 'KEY_ESTABLISHMENT',
    bytes: X25519_BASEPOINT,
    // Deliberately weak on its own: 0x09 followed by 31 zero bytes is a
    // plausible accident in any zero-padded buffer, so this signature is
    // flagged low-specificity and is never reported alone.
    rationale: 'Curve25519 base point u=9. Low specificity: a 0x09 followed by zeroes occurs in padding.',
  },
  {
    id: 'chacha-sigma',
    primitive: 'ChaCha20',
    parameters: { keySize: 256 },
    purpose: 'DATA_ENCRYPTION',
    bytes: CHACHA_SIGMA,
    rationale: 'ChaCha20 sigma constant "expand 32-byte k", RFC 8439.',
  },
  {
    id: 'des-pc1',
    primitive: '3DES',
    parameters: {},
    purpose: 'DATA_ENCRYPTION',
    bytes: DES_PC1,
    rationale:
      'DES permuted choice 1, first 16 entries, FIPS 46-3. Present wherever the key schedule is ' +
      'computed rather than shipped precomputed.',
  },
];

/**
 * Byte-swapped variants of every word-table signature.
 *
 * A uint32 constant table compiles to the target's byte order. arm64 and x86
 * are both little-endian, so a scanner that only knows the specification's
 * big-endian form misses SHA-2 in essentially every binary in existence -
 * which is what the first run against a real binary showed.
 */
function byteSwap(bytes: Uint8Array, wordSize: 4 | 8): Uint8Array {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i + wordSize <= bytes.length; i += wordSize) {
    for (let j = 0; j < wordSize; j++) out[i + j] = bytes[i + wordSize - 1 - j] as number;
  }
  return out;
}

export const CONSTANT_SIGNATURES: readonly ConstantSignature[] = SPECIFIED.flatMap((sig) =>
  sig.wordSize === undefined
    ? [sig]
    : [
        sig,
        {
          ...sig,
          id: `${sig.id}-le`,
          bytes: byteSwap(sig.bytes, sig.wordSize),
          rationale: `${sig.rationale} Little-endian word order, as a compiler emits it.`,
        },
      ],
);

/** Signatures that must never be the sole basis for a finding. */
export const LOW_SPECIFICITY = new Set(['x25519-basepoint']);

export interface ConstantHit {
  readonly signature: ConstantSignature;
  readonly offset: number;
}

/**
 * Boyer-Moore-Horspool over the whole file for each signature.
 *
 * Naive indexOf on a Buffer is already memchr-backed in Node and is faster
 * than a hand-written search here, so this uses it directly and reports every
 * occurrence rather than only the first - a constant appearing forty times is
 * still one observation under I1, but the count is worth showing.
 */
export function findConstants(data: Buffer, maxHitsPerSignature = 8): ConstantHit[] {
  const out: ConstantHit[] = [];
  for (const signature of CONSTANT_SIGNATURES) {
    const needle = Buffer.from(signature.bytes);
    let from = 0;
    let found = 0;
    while (found < maxHitsPerSignature) {
      const at = data.indexOf(needle, from);
      if (at < 0) break;
      out.push({ signature, offset: at });
      from = at + 1;
      found++;
    }
  }
  return out.sort((a, b) => a.offset - b.offset || a.signature.id.localeCompare(b.signature.id));
}
