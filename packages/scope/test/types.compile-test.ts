/**
 * COMPILE-TIME enforcement of the Phase 2 exit gate.
 *
 * "An out-of-scope probe fails at the type level, not at runtime." These
 * assertions are checked by `tsc` during typecheck, not by vitest: each
 * @ts-expect-error is itself an error if the line it guards ever starts
 * compiling. Deleting the branded types would break the build here.
 */
import {
  authorize,
  generateGrantKeypair,
  signGrant,
  verifyGrant,
  type AuthorizedTarget,
  type ScopeGrant,
  type VerifiedGrant,
} from '../src/index.js';

const keys = generateGrantKeypair();
const raw: ScopeGrant = signGrant(
  {
    grantId: 'g',
    issuedBy: 'x',
    targets: ['api.example.com'],
    ports: [443],
    notBefore: '2026-08-01T00:00:00.000Z',
    notAfter: '2026-09-01T00:00:00.000Z',
    purpose: '',
  },
  keys.privateKeyPem,
);
const verified: VerifiedGrant = verifyGrant(raw, keys.publicKeyPem);

// A signed-but-unverified grant cannot reach authorize(). Signature checking
// is not a step a caller can skip by being in a hurry.
// @ts-expect-error - ScopeGrant is not VerifiedGrant
authorize(raw, 'api.example.com', 443, new Date());

// A plain object cannot impersonate a verified grant.
// @ts-expect-error - object literal is not VerifiedGrant
authorize({ ...raw, targets: ['0.0.0.0/0'] }, 'evil.test', 443, new Date());

// An AuthorizedTarget cannot be constructed by hand; only authorize() mints one.
// @ts-expect-error - missing the unexported brand
const forged: AuthorizedTarget = { host: 'evil.test', port: 443, grantId: 'g' };

// The legitimate path typechecks.
const ok: AuthorizedTarget = authorize(verified, 'api.example.com', 443, new Date());

export { forged, ok };
