import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { canonicalize } from '@assay/core';

/**
 * Policy pack governance (decision D3).
 *
 * The problem: if every customer authors their own CRQC year, no two rankings
 * are comparable and "we are three years late" means nothing across
 * organizations. The naive fix - forbid local packs - is worse, because an
 * organization with a real reason to disagree simply forks the tool.
 *
 * The split: Z and D are SIGNED and not locally overridable; Y is local by
 * design. A customer knows how long their own migrations take and nobody
 * outside the building does. A vendor's opinion about when a CRQC arrives is
 * a published position that should be attributable to whoever published it.
 *
 * The enforcement is disclosure rather than prohibition. An unsigned or
 * locally-edited horizon still ranks - it just enters the derivation as an
 * ASSUMPTION instead of a POLICY, so every finding produced under it carries
 * the fact that its deadline is not attributable. Non-comparability becomes
 * visible instead of assumed.
 */

export type PackTrust =
  /** Signature verifies against the supplied publisher key. */
  | 'SIGNED'
  /** No signature. A local pack, honestly labelled. */
  | 'UNSIGNED'
  /** A signature is present and does not verify, or no key was supplied to check it. */
  | 'UNTRUSTED';

/**
 * The signed half. Y is excluded on purpose: a customer editing
 * migrationYearsByControl must NOT invalidate the publisher's signature over
 * the horizon, because that is the whole point of the split.
 */
export interface SignedPortion {
  readonly packId: string;
  readonly packVersion: string;
  readonly crqcYear: number;
  readonly deprecateYear: number;
  readonly disallowYear: number;
  readonly regulatoryDeadlines: Readonly<Record<string, number | null>>;
  readonly regulatoryAuthority: string | null;
}

export function signedPortion(pack: SignedPortion): SignedPortion {
  return {
    packId: pack.packId,
    packVersion: pack.packVersion,
    crqcYear: pack.crqcYear,
    deprecateYear: pack.deprecateYear,
    disallowYear: pack.disallowYear,
    regulatoryDeadlines: pack.regulatoryDeadlines,
    regulatoryAuthority: pack.regulatoryAuthority,
  };
}

export function signingInput(pack: SignedPortion): Buffer {
  return Buffer.from(canonicalize(signedPortion(pack) as never), 'utf8');
}

export interface PackKeypair {
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

export function generatePackKeypair(): PackKeypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

export function signPack(pack: SignedPortion, privateKeyPem: string): string {
  return sign(null, signingInput(pack), createPrivateKey(privateKeyPem)).toString('base64');
}

export interface VerifyResult {
  readonly trust: PackTrust;
  readonly reason: string;
}

export function verifyPack(
  pack: SignedPortion & { readonly signature?: string | null },
  publicKeyPem: string | null,
): VerifyResult {
  const signature = pack.signature ?? null;
  if (signature === null || signature === '') {
    return {
      trust: 'UNSIGNED',
      reason: 'no publisher signature; the horizon in this pack is attributable to nobody',
    };
  }
  if (publicKeyPem === null || publicKeyPem === '') {
    return {
      trust: 'UNTRUSTED',
      reason: 'the pack is signed but no publisher key was supplied to check it against',
    };
  }
  let bytes: Buffer;
  try {
    bytes = Buffer.from(signature, 'base64');
    if (bytes.byteLength !== 64) throw new Error('length');
  } catch {
    return { trust: 'UNTRUSTED', reason: 'signature is not a 64-byte Ed25519 signature' };
  }
  try {
    const ok = verify(null, signingInput(pack), createPublicKey(publicKeyPem), bytes);
    return ok
      ? { trust: 'SIGNED', reason: `horizon attributable to the holder of the publisher key` }
      : {
          trust: 'UNTRUSTED',
          // The most likely cause by far, and worth naming: someone edited a
          // deadline. Editing Y would not have done this.
          reason:
            'signature does not verify: the horizon or the regulatory deadlines were edited after signing',
        };
  } catch {
    return { trust: 'UNTRUSTED', reason: 'publisher key is not a usable Ed25519 public key' };
  }
}
