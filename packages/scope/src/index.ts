import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { canonicalize } from '@assay/core';
import { ScopeGrantSchema, payloadOf, type GrantPayload, type ScopeGrant } from './grant.js';
import { matchesTarget, normalizeHost } from './target.js';

export * from './grant.js';
export * from './target.js';

/**
 * THE TYPE-LEVEL GATE.
 *
 * `AuthorizedTarget` is branded and its brand is not exported, so the only way
 * to obtain one is `authorize()`, which throws unless a verified grant covers
 * the host, the port and the current time. Network detectors accept nothing
 * else. An out-of-scope probe is therefore not a runtime check that someone
 * can forget to call - it is a program that does not typecheck.
 *
 * The same shape gates `VerifiedGrant`: a grant that has not been through
 * `verifyGrant` cannot be passed to `authorize`.
 */
declare const AUTHORIZED: unique symbol;
declare const VERIFIED: unique symbol;

export interface VerifiedGrant extends ScopeGrant {
  readonly [VERIFIED]: true;
}

export interface AuthorizedTarget {
  readonly host: string;
  readonly port: number;
  readonly grantId: string;
  readonly [AUTHORIZED]: true;
}

export class ScopeError extends Error {
  constructor(
    message: string,
    readonly code:
      | 'MALFORMED'
      | 'BAD_SIGNATURE'
      | 'NOT_YET_VALID'
      | 'EXPIRED'
      | 'TARGET_OUT_OF_SCOPE'
      | 'PORT_OUT_OF_SCOPE'
      | 'WINDOW_INVALID',
  ) {
    super(message);
    this.name = 'ScopeError';
  }
}

/* ------------------------------------------------------------------ signing */

export interface Keypair {
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

export function generateGrantKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** Canonical bytes over which the signature is computed. */
export function signingInput(payload: GrantPayload): Buffer {
  return Buffer.from(canonicalize(payloadOf(payload) as never), 'utf8');
}

export function signGrant(payload: GrantPayload, privateKeyPem: string): ScopeGrant {
  const key = createPrivateKey(privateKeyPem);
  const signature = sign(null, signingInput(payload), key).toString('base64');
  return { ...payloadOf(payload), signature };
}

/**
 * Verify the detached signature against an operator-supplied public key.
 *
 * The time window is NOT checked here. Verification answers "did the issuer
 * sign this", and `authorize` answers "may I touch this host right now" -
 * collapsing them would make an expired grant indistinguishable from a forged
 * one in the error path, and those are very different incidents.
 */
export function verifyGrant(grant: unknown, publicKeyPem: string): VerifiedGrant {
  const parsed = ScopeGrantSchema.safeParse(grant);
  if (!parsed.success) {
    throw new ScopeError(`grant is malformed: ${parsed.error.issues[0]?.message ?? ''}`, 'MALFORMED');
  }
  const g = parsed.data;

  if (Date.parse(g.notAfter) <= Date.parse(g.notBefore)) {
    throw new ScopeError('grant window ends before it begins', 'WINDOW_INVALID');
  }

  let key;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    throw new ScopeError('verification key is not a usable public key', 'MALFORMED');
  }
  // A key-agreement key (X25519, X448) is a perfectly valid public key that
  // `verify` cannot use: it throws a raw OpenSSL error instead of returning
  // false, so an operator who points --pubkey at the wrong file gets a library
  // message where the code expects a classified one.
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new ScopeError('verification key is not an Ed25519 public key', 'MALFORMED');
  }

  let signatureBytes: Buffer;
  try {
    signatureBytes = Buffer.from(g.signature, 'base64');
    // Buffer.from is lenient with base64; an Ed25519 signature is exactly 64 bytes.
    if (signatureBytes.byteLength !== 64) {
      throw new Error('length');
    }
  } catch {
    throw new ScopeError('signature is not a 64-byte Ed25519 signature', 'BAD_SIGNATURE');
  }

  if (!verify(null, signingInput(g), key, signatureBytes)) {
    throw new ScopeError('signature does not verify under the supplied key', 'BAD_SIGNATURE');
  }
  return g as VerifiedGrant;
}

/* -------------------------------------------------------------- authorizing */

export interface AuthorizeOptions {
  /**
   * Tolerance for clock skew between the issuer and this machine, in seconds.
   * Applied to both ends of the window and capped, because an unbounded skew
   * allowance is an expired grant that still works.
   */
  readonly clockSkewSeconds?: number;
}

export const MAX_CLOCK_SKEW_SECONDS = 300;

export function authorize(
  grant: VerifiedGrant,
  host: string,
  port: number,
  now: Date,
  opts: AuthorizeOptions = {},
): AuthorizedTarget {
  // NaN survives the clamp - Math.max and Math.min both propagate it - and a
  // NaN skew makes both window comparisons below false, so an expired grant
  // authorizes. A mistyped `--clock-skew-seconds 60s` is exactly that value.
  const requestedSkew = opts.clockSkewSeconds ?? 0;
  const skewMs = Number.isFinite(requestedSkew)
    ? Math.min(Math.max(requestedSkew, 0), MAX_CLOCK_SKEW_SECONDS) * 1000
    : 0;
  const t = now.getTime();

  if (t + skewMs < Date.parse(grant.notBefore)) {
    throw new ScopeError(
      `grant ${grant.grantId} is not valid until ${grant.notBefore}`,
      'NOT_YET_VALID',
    );
  }
  if (t - skewMs > Date.parse(grant.notAfter)) {
    throw new ScopeError(`grant ${grant.grantId} expired at ${grant.notAfter}`, 'EXPIRED');
  }

  const h = normalizeHost(host);
  if (!grant.targets.some((target) => matchesTarget(target, h))) {
    throw new ScopeError(
      `${h} is not covered by grant ${grant.grantId} (targets: ${grant.targets.join(', ')})`,
      'TARGET_OUT_OF_SCOPE',
    );
  }
  // An empty port list means any port. A non-empty one is exhaustive: a grant
  // for :443 does not authorize :22 on the same host.
  if (grant.ports.length > 0 && !grant.ports.includes(port)) {
    throw new ScopeError(
      `port ${port} is not covered by grant ${grant.grantId} (ports: ${grant.ports.join(', ')})`,
      'PORT_OUT_OF_SCOPE',
    );
  }

  return { host: h, port, grantId: grant.grantId } as AuthorizedTarget;
}

/** Non-throwing form, for reporting which of a target list is in scope. */
export function isAuthorized(
  grant: VerifiedGrant,
  host: string,
  port: number,
  now: Date,
  opts: AuthorizeOptions = {},
): boolean {
  try {
    authorize(grant, host, port, now, opts);
    return true;
  } catch {
    return false;
  }
}
