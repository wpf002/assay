import { canonicalize, sha256Hex } from '../hash/index.js';
import type { CryptoAsset, Primitive, Purpose } from '../types/crypto-asset.js';

/**
 * Asset identity and vulnerability classification. Pure and total: the same
 * (primitive, parameters, purpose) triple always yields the same id, on any
 * runtime, in any key order.
 */

/** Primitives broken outright by Shor. Quantum-vulnerable regardless of size. */
const SHOR_BROKEN: ReadonlySet<Primitive> = new Set<Primitive>([
  'RSA', 'ECDSA', 'ECDH', 'DH', 'DSA', 'EdDSA', 'X25519', 'X448',
]);

/** Standardized post-quantum primitives. */
const PQ_SAFE: ReadonlySet<Primitive> = new Set<Primitive>([
  'ML-KEM', 'ML-DSA', 'SLH-DSA', 'LMS', 'XMSS',
]);

/**
 * Primitives already broken for classical reasons. Flagged too, because a CBOM
 * that reports 3DES as "quantum-safe" is technically correct and useless.
 */
const CLASSICALLY_BROKEN: ReadonlySet<Primitive> = new Set<Primitive>([
  '3DES', 'RC4', 'MD5', 'SHA1',
]);

const NAMED_CURVE_BITS: Readonly<Record<string, number>> = {
  'P-256': 128, 'P-384': 192, 'P-521': 256,
  secp256r1: 128, secp384r1: 192, secp521r1: 256, secp256k1: 128,
  prime256v1: 128, Curve25519: 128, X25519: 128, X448: 224, Ed25519: 128, Ed448: 224,
};

/** NIST SP 800-57 Part 1 Rev 5. Classical strength of a modulus. */
function rsaBits(modulusLength: number): number {
  if (modulusLength >= 15360) return 256;
  if (modulusLength >= 7680) return 192;
  if (modulusLength >= 3072) return 128;
  if (modulusLength >= 2048) return 112;
  if (modulusLength >= 1024) return 80;
  return 0;
}

function paramNumber(
  p: Readonly<Record<string, string | number>>,
  ...keys: string[]
): number | null {
  for (const k of keys) {
    const v = p[k];
    if (typeof v === 'number') return v;
    if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
  }
  return null;
}

export function classicalSecurityBits(
  primitive: Primitive,
  parameters: Readonly<Record<string, string | number>>,
): number | null {
  switch (primitive) {
    case 'RSA':
    case 'DH':
    case 'DSA': {
      const n = paramNumber(parameters, 'modulusLength', 'keySize', 'bits', 'primeLength');
      return n === null ? null : rsaBits(n);
    }
    case 'ECDSA':
    case 'ECDH':
    case 'EdDSA': {
      const curve = parameters['curve'] ?? parameters['namedCurve'];
      if (typeof curve === 'string' && curve in NAMED_CURVE_BITS)
        return NAMED_CURVE_BITS[curve] as number;
      const n = paramNumber(parameters, 'keySize', 'bits');
      return n === null ? null : Math.floor(n / 2);
    }
    case 'X25519':
      return 128;
    case 'X448':
      return 224;
    case 'AES':
    case 'ChaCha20': {
      const n = paramNumber(parameters, 'keySize', 'keyLength', 'bits');
      return n ?? (primitive === 'ChaCha20' ? 256 : null);
    }
    case '3DES':
      return 112;
    case 'RC4':
    case 'SHA1':
    case 'MD5':
      return 0;
    case 'SHA2':
    case 'SHA3': {
      const n = paramNumber(parameters, 'outputLength', 'bits', 'size');
      return n === null ? null : Math.floor(n / 2);
    }
    default:
      return null;
  }
}

/**
 * Quantum vulnerability. Three distinct reasons an asset lands here, and the
 * CBOM must not blur them: Shor-broken asymmetric, Grover-weakened symmetric
 * below 256-bit, and already-broken-classically.
 */
export function isQuantumVulnerable(
  primitive: Primitive,
  parameters: Readonly<Record<string, string | number>>,
): boolean {
  if (PQ_SAFE.has(primitive)) return false;
  if (SHOR_BROKEN.has(primitive)) return true;
  if (CLASSICALLY_BROKEN.has(primitive)) return true;
  const bits = classicalSecurityBits(primitive, parameters);
  if (primitive === 'AES' || primitive === 'ChaCha20') return bits !== null && bits < 256;
  if (primitive === 'SHA2' || primitive === 'SHA3') return bits !== null && bits < 128;
  return false;
}

const OIDS: Readonly<Record<string, string>> = {
  RSA: '1.2.840.113549.1.1.1',
  ECDSA: '1.2.840.10045.2.1',
  DSA: '1.2.840.10040.4.1',
  DH: '1.2.840.113549.1.3.1',
  X25519: '1.3.101.110',
  X448: '1.3.101.111',
  SHA1: '1.3.14.3.2.26',
  MD5: '1.2.840.113549.2.5',
  'ML-KEM': '2.16.840.1.101.3.4.4',
  'ML-DSA': '2.16.840.1.101.3.4.3',
};

/**
 * Deterministic content hash. Parameters are canonicalized, so
 * {curve:'P-256', mode:'x'} and {mode:'x', curve:'P-256'} are one asset.
 */
export function assetId(
  primitive: Primitive,
  parameters: Readonly<Record<string, string | number>>,
  purpose: Purpose,
): string {
  return sha256Hex(canonicalize({ primitive, parameters, purpose })).slice(0, 32);
}

export function makeAsset(
  primitive: Primitive,
  parameters: Readonly<Record<string, string | number>>,
  purpose: Purpose,
  overrides: { readonly nistQuantumSecurityLevel?: number | null } = {},
): CryptoAsset {
  return {
    id: assetId(primitive, parameters, purpose),
    primitive,
    parameters,
    purpose,
    quantumVulnerable: isQuantumVulnerable(primitive, parameters),
    classicalSecurityBits: classicalSecurityBits(primitive, parameters),
    nistQuantumSecurityLevel: overrides.nistQuantumSecurityLevel ?? null,
    oid: OIDS[primitive] ?? null,
  };
}
