import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  MAX_CLOCK_SKEW_SECONDS,
  ScopeError,
  authorize,
  generateGrantKeypair,
  isAuthorized,
  matchesTarget,
  signGrant,
  verifyGrant,
  type GrantPayload,
} from '../src/index.js';

const keys = generateGrantKeypair();
const other = generateGrantKeypair();

const NOW = new Date('2026-08-28T12:00:00.000Z');

const payload = (over: Partial<GrantPayload> = {}): GrantPayload => ({
  grantId: 'grant-1',
  issuedBy: 'security@example.com',
  targets: ['api.example.com', '10.0.0.0/24'],
  ports: [443],
  notBefore: '2026-08-01T00:00:00.000Z',
  notAfter: '2026-09-01T00:00:00.000Z',
  purpose: 'Q3 PQC inventory',
  ...over,
});

const good = () => verifyGrant(signGrant(payload(), keys.privateKeyPem), keys.publicKeyPem);

function code(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return e instanceof ScopeError ? e.code : `UNEXPECTED:${String(e)}`;
  }
  return 'NO_ERROR';
}

describe('signature verification', () => {
  it('accepts a grant signed by the matching key', () => {
    expect(good().grantId).toBe('grant-1');
  });

  it('rejects a grant signed by a different key', () => {
    const g = signGrant(payload(), other.privateKeyPem);
    expect(code(() => verifyGrant(g, keys.publicKeyPem))).toBe('BAD_SIGNATURE');
  });

  it('rejects a grant whose targets were widened after signing', () => {
    const g = signGrant(payload(), keys.privateKeyPem);
    const tampered = { ...g, targets: [...g.targets, '0.0.0.0/0'] };
    expect(code(() => verifyGrant(tampered, keys.publicKeyPem))).toBe('BAD_SIGNATURE');
  });

  it('rejects a grant whose expiry was extended after signing', () => {
    const g = signGrant(payload(), keys.privateKeyPem);
    expect(code(() => verifyGrant({ ...g, notAfter: '2099-01-01T00:00:00.000Z' }, keys.publicKeyPem))).toBe(
      'BAD_SIGNATURE',
    );
  });

  it('rejects a grant whose ports were widened after signing', () => {
    const g = signGrant(payload(), keys.privateKeyPem);
    expect(code(() => verifyGrant({ ...g, ports: [443, 22] }, keys.publicKeyPem))).toBe('BAD_SIGNATURE');
  });

  it('is insensitive to target and port ORDER, which is not security-relevant', () => {
    const a = signGrant(payload({ targets: ['b.example.com', 'a.example.com'], ports: [443, 80] }), keys.privateKeyPem);
    const b = signGrant(payload({ targets: ['a.example.com', 'b.example.com'], ports: [80, 443] }), keys.privateKeyPem);
    expect(a.signature).toBe(b.signature);
  });

  it('rejects a truncated or padded signature rather than letting the library coerce it', () => {
    const g = signGrant(payload(), keys.privateKeyPem);
    expect(code(() => verifyGrant({ ...g, signature: g.signature.slice(0, 40) }, keys.publicKeyPem))).toBe(
      'BAD_SIGNATURE',
    );
    expect(code(() => verifyGrant({ ...g, signature: 'not base64 at all!!' }, keys.publicKeyPem))).toBe(
      'BAD_SIGNATURE',
    );
  });

  it('rejects a malformed grant before touching the crypto', () => {
    expect(code(() => verifyGrant({ grantId: 'x' }, keys.publicKeyPem))).toBe('MALFORMED');
    expect(code(() => verifyGrant(null, keys.publicKeyPem))).toBe('MALFORMED');
  });

  it('rejects an inverted validity window', () => {
    const g = signGrant(
      payload({ notBefore: '2026-09-01T00:00:00.000Z', notAfter: '2026-08-01T00:00:00.000Z' }),
      keys.privateKeyPem,
    );
    expect(code(() => verifyGrant(g, keys.publicKeyPem))).toBe('WINDOW_INVALID');
  });

  it('ignores any public key smuggled into the grant body', () => {
    // A grant that carried its own verification key would verify against
    // itself. Extra fields are stripped by the schema, so they cannot be used.
    const g = signGrant(payload(), other.privateKeyPem);
    const smuggled = { ...g, publicKey: other.publicKeyPem };
    expect(code(() => verifyGrant(smuggled, keys.publicKeyPem))).toBe('BAD_SIGNATURE');
  });

  it('rejects a verification key that is not a key', () => {
    expect(code(() => verifyGrant(signGrant(payload(), keys.privateKeyPem), 'hello'))).toBe('MALFORMED');
  });

  it('classifies a key that cannot verify signatures at all rather than leaking the library error', () => {
    // An X25519 key is a valid public key, so it survives createPublicKey and
    // reaches verify(), which throws instead of returning false.
    const x25519 = generateKeyPairSync('x25519')
      .publicKey.export({ type: 'spki', format: 'pem' })
      .toString();
    expect(code(() => verifyGrant(signGrant(payload(), keys.privateKeyPem), x25519))).toBe('MALFORMED');
  });
});

describe('the time window', () => {
  it('authorizes inside the window', () => {
    expect(authorize(good(), 'api.example.com', 443, NOW).host).toBe('api.example.com');
  });

  it('refuses before it opens and after it closes', () => {
    expect(code(() => authorize(good(), 'api.example.com', 443, new Date('2026-07-31T23:00:00Z')))).toBe(
      'NOT_YET_VALID',
    );
    expect(code(() => authorize(good(), 'api.example.com', 443, new Date('2026-09-02T00:00:00Z')))).toBe(
      'EXPIRED',
    );
  });

  it('allows a bounded clock skew at both ends', () => {
    const justBefore = new Date('2026-07-31T23:59:00.000Z');
    expect(code(() => authorize(good(), 'api.example.com', 443, justBefore))).toBe('NOT_YET_VALID');
    expect(
      authorize(good(), 'api.example.com', 443, justBefore, { clockSkewSeconds: 120 }).port,
    ).toBe(443);
  });

  it('caps the skew allowance, because an unbounded one is an expired grant that still works', () => {
    const wayLate = new Date('2026-09-05T00:00:00.000Z');
    expect(
      code(() =>
        authorize(good(), 'api.example.com', 443, wayLate, { clockSkewSeconds: 10_000_000 }),
      ),
    ).toBe('EXPIRED');
    expect(MAX_CLOCK_SKEW_SECONDS).toBe(300);
  });

  it('ignores a negative skew request', () => {
    expect(
      code(() => authorize(good(), 'api.example.com', 443, NOW, { clockSkewSeconds: -1_000_000 })),
    ).toBe('NO_ERROR');
  });

  it('treats a non-numeric skew request as no skew instead of skipping the window', () => {
    // NaN passes straight through the clamp and makes both window comparisons
    // false, which is an expired grant that still works.
    const wayLate = new Date('2026-09-05T00:00:00.000Z');
    for (const skew of [Number('60s'), Number('abc'), Number.NaN]) {
      expect(code(() => authorize(good(), 'api.example.com', 443, wayLate, { clockSkewSeconds: skew }))).toBe(
        'EXPIRED',
      );
      expect(
        code(() =>
          authorize(good(), 'api.example.com', 443, new Date('2026-07-01T00:00:00.000Z'), {
            clockSkewSeconds: skew,
          }),
        ),
      ).toBe('NOT_YET_VALID');
    }
  });
});

describe('target matching', () => {
  it('matches an exact hostname case-insensitively and ignores a trailing dot', () => {
    expect(matchesTarget('api.example.com', 'API.Example.com.')).toBe(true);
  });

  it('does not let a hostname match a different host that contains it', () => {
    expect(matchesTarget('example.com', 'notexample.com')).toBe(false);
    expect(matchesTarget('example.com', 'example.com.evil.test')).toBe(false);
  });

  it('keeps a glob to a single label', () => {
    expect(matchesTarget('*.example.com', 'api.example.com')).toBe(true);
    expect(matchesTarget('*.example.com', 'example.com')).toBe(false);
    expect(matchesTarget('*.example.com', 'a.b.example.com')).toBe(false);
    expect(matchesTarget('*.example.com', 'api.example.com.evil.test')).toBe(false);
  });

  it('matches inside an IPv4 CIDR and not outside it', () => {
    expect(matchesTarget('10.0.0.0/24', '10.0.0.7')).toBe(true);
    expect(matchesTarget('10.0.0.0/24', '10.0.1.7')).toBe(false);
    expect(matchesTarget('10.0.0.0/31', '10.0.0.1')).toBe(true);
    expect(matchesTarget('10.0.0.0/32', '10.0.0.1')).toBe(false);
  });

  it('rejects malformed addresses rather than coercing them', () => {
    expect(matchesTarget('10.0.0.0/24', '10.0.0.256')).toBe(false);
    expect(matchesTarget('10.0.0.0/24', '10.0.0')).toBe(false);
    expect(matchesTarget('10.0.0.0/33', '10.0.0.1')).toBe(false);
    // Non-canonical octets are rejected: 010.0.0.1 is decimal to some parsers
    // and octal to others, and an ambiguous target is a reviewable-looking
    // allowlist entry that does not mean what it reads as.
    expect(matchesTarget('10.0.0.0/24', '010.0.0.1')).toBe(false);
  });

  it('handles IPv6 CIDRs including :: expansion and non-byte prefixes', () => {
    expect(matchesTarget('2001:db8::/32', '2001:db8:1:2::5')).toBe(true);
    expect(matchesTarget('2001:db8::/32', '2001:db9::1')).toBe(false);
    expect(matchesTarget('2001:db8::/33', '2001:db8:8000::1')).toBe(false);
    expect(matchesTarget('2001:db8::/33', '2001:db8:7fff::1')).toBe(true);
    expect(matchesTarget('::1/128', '[::1]')).toBe(true);
  });

  it('does not match an IPv4 address against an IPv6 CIDR', () => {
    expect(matchesTarget('2001:db8::/32', '10.0.0.1')).toBe(false);
  });

  it('refuses a CIDR with no prefix length rather than reading it as /0', () => {
    for (const target of ['10.0.0.0/', '10.0.0.0/ ', '10.0.0.0/\t', '10.0.0.0/+8', '10.0.0.0/08']) {
      expect(matchesTarget(target, '8.8.8.8')).toBe(false);
      expect(matchesTarget(target, '10.0.0.1')).toBe(false);
    }
    for (const target of ['2001:db8::/', '2001:db8::/ ', '2001:db8::/+8']) {
      expect(matchesTarget(target, '2606:4700::1111')).toBe(false);
      expect(matchesTarget(target, '::1')).toBe(false);
      expect(matchesTarget(target, '::ffff:8.8.8.8')).toBe(false);
      expect(matchesTarget(target, '2001:db8::1')).toBe(false);
    }
    // An explicit /0 still means what it says.
    expect(matchesTarget('0.0.0.0/0', '8.8.8.8')).toBe(true);
    expect(matchesTarget('::/0', '2606:4700::1111')).toBe(true);
  });

  it('refuses a CIDR with a third component rather than dropping it', () => {
    expect(matchesTarget('10.0.0.0/8/32', '10.0.0.1')).toBe(false);
    expect(matchesTarget('2001:db8::/32/128', '2001:db8::1')).toBe(false);
  });

  it('refuses IPv6 literals that no resolver would accept', () => {
    expect(matchesTarget('::/128', ':::')).toBe(false);
    expect(matchesTarget('::1/128', '::1:')).toBe(false);
    expect(matchesTarget('1:2:3:4:5:6:7:8/128', '1:2:3:4:5:6:7::8')).toBe(false);
    expect(matchesTarget('102:304::/32', '1.2.3.4::')).toBe(false);
    expect(matchesTarget('102:304::/32', '1.2.3.4::1')).toBe(false);
    expect(matchesTarget('::/0', '1:2::3:')).toBe(false);
    // The forms that are real addresses still match.
    expect(matchesTarget('::ffff:0:0/96', '::ffff:192.0.2.1')).toBe(true);
    expect(matchesTarget('::/128', '::')).toBe(true);
    expect(matchesTarget('2001:db8::/32', '2001:db8:0:0:0:0:0:1')).toBe(true);
  });
});

describe('port scope', () => {
  it('refuses a port the grant does not name', () => {
    expect(code(() => authorize(good(), 'api.example.com', 22, NOW))).toBe('PORT_OUT_OF_SCOPE');
  });

  it('treats an empty port list as any port', () => {
    const anyPort = verifyGrant(signGrant(payload({ ports: [] }), keys.privateKeyPem), keys.publicKeyPem);
    expect(authorize(anyPort, 'api.example.com', 22, NOW).port).toBe(22);
  });
});

describe('host scope', () => {
  it('refuses a host outside every target', () => {
    expect(code(() => authorize(good(), 'evil.test', 443, NOW))).toBe('TARGET_OUT_OF_SCOPE');
    expect(code(() => authorize(good(), '10.0.1.5', 443, NOW))).toBe('TARGET_OUT_OF_SCOPE');
  });

  it('refuses every host when a signed target lost its prefix length', () => {
    const g = (target: string) =>
      verifyGrant(signGrant(payload({ targets: [target] }), keys.privateKeyPem), keys.publicKeyPem);
    expect(code(() => authorize(g('10.0.0.0/'), '8.8.8.8', 443, NOW))).toBe('TARGET_OUT_OF_SCOPE');
    expect(code(() => authorize(g('2001:db8::/'), '2606:4700::1111', 443, NOW))).toBe(
      'TARGET_OUT_OF_SCOPE',
    );
    // The IPv4-mapped form is how a v6-only typo reaches an IPv4 host.
    expect(code(() => authorize(g('2001:db8::/'), '[::ffff:8.8.8.8]', 443, NOW))).toBe(
      'TARGET_OUT_OF_SCOPE',
    );
  });

  it('reports scope without throwing, for planning a probe list', () => {
    const g = good();
    expect(isAuthorized(g, '10.0.0.9', 443, NOW)).toBe(true);
    expect(isAuthorized(g, '10.0.9.9', 443, NOW)).toBe(false);
  });
});
