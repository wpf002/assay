import type { Factor } from './factor.js';
import type { Modality } from './modality.js';

/**
 * MODEL NOTE: three distinct entities. Collapsing them is why other tools
 * cannot dedupe or explain themselves.
 *   CryptoAsset  - an algorithm + parameters + purpose (the thing to migrate)
 *   Occurrence   - a place it appears (the work item)
 *   Evidence     - why we believe the occurrence is real
 */

export const PRIMITIVES = [
  'RSA', 'ECDSA', 'ECDH', 'DH', 'DSA', 'EdDSA', 'X25519', 'X448',
  'ML-KEM', 'ML-DSA', 'SLH-DSA', 'LMS', 'XMSS',
  'AES', 'ChaCha20', '3DES', 'RC4',
  'SHA1', 'SHA2', 'SHA3', 'MD5',
  'HMAC', 'PBKDF2', 'Argon2', 'scrypt',
  'UNKNOWN',
] as const;
export type Primitive = (typeof PRIMITIVES)[number];

/**
 * Purpose drives the urgency SPLIT (I2). Harvest-now-decrypt-later applies to
 * CONFIDENTIALITY only. A signature forgeable in 2033 is a 2033 problem; a
 * session key recorded today is already compromised.
 *
 * EO 14412 splits its own deadlines the same way: key establishment by
 * 2030-12-31, digital signatures by 2031-12-31. The two tracks are not an
 * Assay idiosyncrasy; they are the regulator's model.
 */
export const PURPOSES = [
  'KEY_ESTABLISHMENT', // confidentiality clock. HNDL applies. EO 14412 deadline 2030-12-31.
  'DATA_ENCRYPTION', // confidentiality clock. HNDL applies.
  'DIGITAL_SIGNATURE', // authenticity clock. HNDL does NOT apply. EO 14412 deadline 2031-12-31.
  'CERTIFICATE_AUTH', // authenticity clock.
  'INTEGRITY',
  'KEY_DERIVATION',
  'RANDOMNESS',
] as const;
export type Purpose = (typeof PURPOSES)[number];

export type UrgencyTrack = 'CONFIDENTIALITY' | 'AUTHENTICITY';

export const HNDL_PURPOSES: ReadonlySet<Purpose> = new Set<Purpose>([
  'KEY_ESTABLISHMENT',
  'DATA_ENCRYPTION',
]);

export function trackFor(purpose: Purpose): UrgencyTrack {
  return HNDL_PURPOSES.has(purpose) ? 'CONFIDENTIALITY' : 'AUTHENTICITY';
}

/** Who can actually change this. Sole driver of migration time Y. */
export const CONTROL_CLASSES = [
  'SELF', // our source, our deploy. days-to-weeks.
  'VENDOR_UPGRADEABLE', // dependency w/ a PQ-capable version available
  'VENDOR_LOCKED', // closed vendor, no PQ roadmap. procurement problem.
  'HARDWARE', // HSM/TPM/smartcard/silicon. replacement cycle.
  'PROTOCOL_BILATERAL', // both endpoints must move together. slowest.
] as const;
export type ControlClass = (typeof CONTROL_CLASSES)[number];

export interface CryptoAsset {
  readonly id: string; // stable content hash of (primitive,params,purpose)
  readonly primitive: Primitive;
  readonly parameters: Readonly<Record<string, string | number>>; // modulusLength, curve, mode
  readonly purpose: Purpose;
  readonly quantumVulnerable: boolean;
  readonly classicalSecurityBits: number | null;
  /** NIST PQC security category 1-5, or null for classical assets. */
  readonly nistQuantumSecurityLevel: number | null;
  /** Dotted OID where one is defined. Emitted into CycloneDX cryptoProperties.oid. */
  readonly oid: string | null;
}

export interface Evidence {
  readonly modality: Modality;
  readonly locator: string; // file:line, host:port, symbol name, cert fingerprint
  readonly raw: string; // the literal observation, for audit
  readonly collectedAt: string; // ISO8601
  readonly collectorVersion: string;
  /**
   * Where this was seen, in CycloneDX evidence.occurrences shape. Populated by
   * source detectors so the export carries a machine-checkable location.
   */
  readonly occurrence?: {
    readonly location: string;
    readonly line?: number;
    readonly offset?: number;
    readonly symbol?: string;
  };
}

/** A single frame of a reachability path. Exported into CycloneDX evidence.callstack. */
export interface CallFrame {
  readonly module: string;
  readonly function: string;
  readonly fullFilename: string;
  readonly line?: number;
  readonly column?: number;
}

/**
 * Reachability. Presence is not exposure (I5). Competitors claim reachability;
 * the differentiator is shipping the PATH, in a field a third party can check.
 */
export interface Reachability {
  readonly reachable: boolean;
  /** The entry point the path starts from, e.g. "http:POST /v1/payments". */
  readonly entryPoint: string | null;
  readonly path: readonly CallFrame[];
  readonly factor: Factor;
}

export interface Occurrence {
  readonly id: string;
  readonly assetId: string;
  readonly systemId: string; // service/repo/host this belongs to
  readonly controlClass: ControlClass;
  /** null = not yet analyzed. Presence != exposure. */
  readonly reachability: Reachability | null;
  readonly evidence: readonly Evidence[];
  readonly confidence: Factor; // derived, provenance-carrying
}
