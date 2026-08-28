import { z } from 'zod';

/**
 * A signed authorization to touch a host you did not build.
 *
 * Active probing is a scanning activity. It runs only inside a grant that
 * names the targets and the window, and the grant is passed to detectors as
 * an explicit argument (I8). There is no ambient authority, no default-allow,
 * and no environment variable that quietly turns scanning on.
 *
 * Note what is NOT in this type: a public key. A grant that carried its own
 * verification key would verify against itself, which is not a signature - it
 * is a self-assertion with extra steps. The key comes from the operator, out
 * of band.
 */
export const ScopeGrantSchema = z.object({
  grantId: z.string().min(1),
  issuedBy: z.string().min(1),
  /** CIDR (v4 or v6), exact hostname, or a single-label glob like *.example.com. */
  targets: z.array(z.string().min(1)).min(1),
  /** Empty means any port. A grant for :443 does not authorize :22. */
  ports: z.array(z.number().int().min(1).max(65535)).default([]),
  notBefore: z.string().datetime(),
  notAfter: z.string().datetime(),
  /** Free text recorded in the scan, e.g. a ticket reference. */
  purpose: z.string().default(''),
  /** base64 Ed25519 signature over the canonical form of everything above. */
  signature: z.string().min(1),
});

export type ScopeGrant = z.infer<typeof ScopeGrantSchema>;

/** The signed payload. Excludes the signature itself, by construction. */
export type GrantPayload = Omit<ScopeGrant, 'signature'>;

export function payloadOf(grant: GrantPayload): GrantPayload {
  return {
    grantId: grant.grantId,
    issuedBy: grant.issuedBy,
    targets: [...grant.targets].sort(),
    ports: [...grant.ports].sort((a, b) => a - b),
    notBefore: grant.notBefore,
    notAfter: grant.notAfter,
    purpose: grant.purpose,
  };
}
