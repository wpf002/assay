import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sha256Hex } from '@assay/core';
import type { ScanStore, StoredToken } from './store/types.js';

/**
 * API authentication.
 *
 * The thing this protects is an inventory of an organization's weakest
 * cryptography, which is a map of where to attack it. Until now the API served
 * that to anyone who could reach the port.
 *
 * Three properties the rest of this file exists to hold:
 *
 * 1. The secret is shown once and never stored. What is stored is its
 *    SHA-256. A token table that can be read back is a second copy of the key
 *    to the estate, sitting in the same database as the estate.
 * 2. Comparison is constant-time. Token lookup is by hash so the database does
 *    an indexed read rather than a scan, but the final check still compares
 *    fixed-length digests without early exit.
 * 3. Authorization is deny-by-default. A route with no stated requirement is
 *    unreachable rather than open, and a viewer scoped to two systems sees two
 *    systems in the estate view - not the whole estate with two highlighted.
 */

export const ROLES = ['admin', 'operator', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

/** Ordered by privilege, so a check is a comparison rather than a set of ifs. */
const RANK: Readonly<Record<Role, number>> = { viewer: 0, operator: 1, admin: 2 };

export function atLeast(held: Role, required: Role): boolean {
  return RANK[held] >= RANK[required];
}

export interface Principal {
  readonly tokenId: string;
  readonly name: string;
  readonly role: Role;
  /** Empty means every system. */
  readonly systems: readonly string[];
}

export type AuthFailure =
  | 'MISSING'
  | 'MALFORMED'
  | 'UNKNOWN'
  | 'REVOKED'
  | 'EXPIRED'
  | 'FORBIDDEN'
  | 'OUT_OF_SCOPE';

export class AuthError extends Error {
  constructor(
    readonly reason: AuthFailure,
    message: string,
  ) {
    super(message);
    this.name = 'AuthError';
  }

  /**
   * 401 means "you did not identify yourself"; 403 means "you did, and no".
   *
   * OUT_OF_SCOPE is deliberately neither: it answers 404, identically to a
   * resource that does not exist. Returning 403 with the body "no such scan"
   * masked the message and then undid it with the status line, which is an
   * existence oracle — a scoped token could map every system by probing ids
   * and watching 403 against 404.
   */
  get statusCode(): number {
    if (this.reason === 'OUT_OF_SCOPE') return 404;
    return this.reason === 'FORBIDDEN' ? 403 : 401;
  }
}

/* ------------------------------------------------------------------ minting */

const PREFIX = 'assay';

export interface MintedToken {
  readonly id: string;
  /** Shown once, at creation. Never recoverable. */
  readonly secret: string;
  readonly secretHash: string;
}

export function mintToken(): MintedToken {
  const id = randomBytes(8).toString('hex');
  // 32 bytes of CSPRNG output. base64url so it survives a shell, a header and
  // a copy-paste without re-encoding.
  const secret = randomBytes(32).toString('base64url');
  return { id, secret: `${PREFIX}_${id}_${secret}`, secretHash: sha256Hex(secret) };
}

interface ParsedToken {
  readonly id: string;
  readonly secret: string;
}

/**
 * Split a presented token without leaking whether the id or the secret is wrong.
 *
 * Only the first two separators are separators. base64url's alphabet includes
 * `_`, so splitting on every underscore rejects most valid tokens - and does it
 * intermittently, which is the worst way for an authentication bug to behave.
 */
export function parseToken(presented: string): ParsedToken | null {
  const trimmed = presented.trim();
  const first = trimmed.indexOf('_');
  if (first < 0) return null;
  const second = trimmed.indexOf('_', first + 1);
  if (second < 0) return null;

  const prefix = trimmed.slice(0, first);
  const id = trimmed.slice(first + 1, second);
  const secret = trimmed.slice(second + 1);

  if (prefix !== PREFIX) return null;
  if (!/^[0-9a-f]{16}$/.test(id)) return null;
  if (!/^[A-Za-z0-9_-]{40,}$/.test(secret)) return null;
  return { id, secret };
}

/** Constant-time comparison of two hex digests of known equal length. */
export function digestsMatch(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/* ------------------------------------------------------------- verification */

export interface AuthenticateOptions {
  /** Supplied by the caller so expiry is evaluated against a known clock. */
  readonly now: Date;
}

export async function authenticate(
  store: ScanStore,
  header: string | undefined,
  opts: AuthenticateOptions,
): Promise<Principal> {
  if (header === undefined || header === '') {
    throw new AuthError('MISSING', 'no Authorization header');
  }
  const bearer = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (bearer?.[1] === undefined) {
    throw new AuthError('MALFORMED', 'Authorization must be "Bearer <token>"');
  }
  const parsed = parseToken(bearer[1]);
  if (parsed === null) {
    throw new AuthError('MALFORMED', 'token is not in the expected form');
  }

  const record = await store.findToken(sha256Hex(parsed.secret));
  // A wrong secret and an unknown id are the same answer on purpose.
  if (record === null || !digestsMatch(record.secretHash, sha256Hex(parsed.secret))) {
    throw new AuthError('UNKNOWN', 'token is not recognized');
  }
  if (record.id !== parsed.id) {
    // The id is not a credential, but a mismatch means the presented token was
    // assembled rather than issued.
    throw new AuthError('UNKNOWN', 'token is not recognized');
  }
  if (record.revokedAt !== null) {
    throw new AuthError('REVOKED', `token was revoked at ${record.revokedAt}`);
  }
  if (record.expiresAt !== null && Date.parse(record.expiresAt) <= opts.now.getTime()) {
    throw new AuthError('EXPIRED', `token expired at ${record.expiresAt}`);
  }

  return {
    tokenId: record.id,
    name: record.name,
    role: record.role,
    systems: record.systems,
  };
}

export function requireRole(principal: Principal, required: Role): void {
  if (!atLeast(principal.role, required)) {
    throw new AuthError(
      'FORBIDDEN',
      `this token is a ${principal.role}; the route requires ${required}`,
    );
  }
}

/**
 * A scoped token sees its systems and nothing else.
 *
 * Returning a filtered list rather than throwing is deliberate for collection
 * routes: a viewer scoped to one system asking for the estate should get their
 * system, not an error that tells them how many others exist.
 */
export function visibleTo(principal: Principal, systemName: string): boolean {
  return principal.systems.length === 0 || principal.systems.includes(systemName);
}

export function assertVisible(principal: Principal, systemName: string): void {
  if (!visibleTo(principal, systemName)) {
    // Indistinguishable from "no such scan" in both body and status, so a
    // scoped token cannot enumerate systems by probing ids.
    throw new AuthError('OUT_OF_SCOPE', 'no such scan');
  }
}

/**
 * Writes are scoped too.
 *
 * `visibleTo` reads as a question about reading, and that framing is how the
 * write paths ended up ungated: a scoped operator could post a scan for any
 * system at all. Because the estate view takes the newest scan per system, an
 * empty scan with a future timestamp silently replaced another team's findings
 * for every reader, admins included.
 */
export function assertMayWrite(principal: Principal, systemName: string): void {
  if (!visibleTo(principal, systemName)) {
    throw new AuthError(
      'FORBIDDEN',
      `this token is scoped to ${principal.systems.join(', ')} and cannot write to ${systemName}`,
    );
  }
}

/**
 * A trace bundle names every service in the estate, so uploading one is a
 * whole-estate act. A scoped token has no business performing it.
 */
export function assertUnscoped(principal: Principal, what: string): void {
  if (principal.systems.length > 0) {
    throw new AuthError('FORBIDDEN', `${what} affects the whole estate; this token is scoped`);
  }
}

export type { StoredToken };
