import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { canonicalize, sha256Hex } from '@assay/core';
import type { CoverageReport } from './report.js';

/**
 * A signed coverage attestation.
 *
 * The point of signing is not secrecy. It is that a screenshot of a dashboard
 * is not an artifact: it cannot be filed, it cannot be re-checked a year later
 * by someone who was not in the room, and it cannot be handed to an auditor who
 * has no reason to trust the person handing it over. A detached Ed25519
 * signature over canonical bytes can be all three.
 *
 * The digest is included in the envelope so a reader can confirm which bytes
 * were signed without re-deriving the canonical form themselves.
 */
export interface SignedCoverage {
  readonly report: CoverageReport;
  readonly digest: string;
  readonly signature: string;
  readonly publicKeyPem: string;
  readonly algorithm: 'ed25519';
}

export interface CoverageKeypair {
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

export function generateCoverageKeypair(): CoverageKeypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** The exact bytes a signature covers. */
export function signingInput(report: CoverageReport): Buffer {
  return Buffer.from(canonicalize(report as never), 'utf8');
}

export function coverageDigest(report: CoverageReport): string {
  return sha256Hex(signingInput(report).toString('utf8'));
}

export function signCoverage(report: CoverageReport, privateKeyPem: string): SignedCoverage {
  const bytes = signingInput(report);
  const key = createPrivateKey(privateKeyPem);
  const pub = createPublicKey(key)
    .export({ type: 'spki', format: 'pem' })
    .toString();
  return {
    report,
    digest: sha256Hex(bytes.toString('utf8')),
    signature: sign(null, bytes, key).toString('base64'),
    publicKeyPem: pub,
    algorithm: 'ed25519',
  };
}

export type CoverageVerdict =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: 'DIGEST_MISMATCH' | 'BAD_SIGNATURE' | 'BAD_KEY' };

/**
 * Verify against a key the reader already trusts, not the one in the envelope.
 *
 * Checking a signature with the public key that travelled beside it proves only
 * that the file is internally consistent, which is a property any forger can
 * arrange. The parameter is required for that reason.
 */
export function verifyCoverage(signed: SignedCoverage, trustedPublicKeyPem: string): CoverageVerdict {
  const bytes = signingInput(signed.report);
  if (sha256Hex(bytes.toString('utf8')) !== signed.digest) {
    return { ok: false, reason: 'DIGEST_MISMATCH' };
  }
  let key;
  try {
    key = createPublicKey(trustedPublicKeyPem);
  } catch {
    return { ok: false, reason: 'BAD_KEY' };
  }
  const good = verify(null, bytes, key, Buffer.from(signed.signature, 'base64'));
  return good ? { ok: true } : { ok: false, reason: 'BAD_SIGNATURE' };
}
