import { describe, expect, it } from 'vitest';
import {
  assetFor,
  controlClassFor,
  fromAwsKms,
  fromAzureKeyVault,
  fromGcpKms,
  kmsFindings,
  KeyInventorySchema,
  type KeyRecord,
} from '../src/index.js';

const base: KeyRecord = {
  id: 'k',
  provider: 'imported',
  scope: '',
  region: '',
  keySpec: 'RSA_2048',
  usage: 'ENCRYPT_DECRYPT',
  enabled: true,
  hsmBacked: false,
  rotationEnabled: null,
  createdAt: null,
  description: '',
};

describe('AWS KMS adapter', () => {
  it('normalizes an asymmetric key', () => {
    const r = fromAwsKms(
      {
        KeyId: 'abc',
        Arn: 'arn:aws:kms:us-east-1:1:key/abc',
        KeySpec: 'RSA_4096',
        KeyUsage: 'SIGN_VERIFY',
        Enabled: true,
        Origin: 'AWS_KMS',
      },
      { account: '1', region: 'us-east-1' },
    );
    expect(r.id).toBe('arn:aws:kms:us-east-1:1:key/abc');
    expect(r.usage).toBe('SIGN_VERIFY');
    expect(r.hsmBacked).toBe(false);
  });

  it('treats CloudHSM and external key stores as HSM-backed', () => {
    expect(fromAwsKms({ KeyId: 'a', Origin: 'AWS_CLOUDHSM' }).hsmBacked).toBe(true);
    expect(fromAwsKms({ KeyId: 'a', Origin: 'EXTERNAL_KEY_STORE' }).hsmBacked).toBe(true);
  });

  it('defaults a key with no stated spec to the symmetric default', () => {
    expect(fromAwsKms({ KeyId: 'a' }).keySpec).toBe('SYMMETRIC_DEFAULT');
  });
});

describe('Azure Key Vault adapter', () => {
  it('derives the RSA modulus size from the base64url modulus, which is the only place it appears', () => {
    const n = Buffer.alloc(256).toString('base64url'); // 2048-bit modulus
    const r = fromAzureKeyVault({ key: { kid: 'https://v.vault.azure.net/keys/k/1', kty: 'RSA', n } });
    expect(r.keySpec).toBe('RSA_2048');
  });

  it('reads the -HSM suffix as a hardware statement', () => {
    const r = fromAzureKeyVault({ key: { kid: 'k', kty: 'RSA-HSM', n: Buffer.alloc(384).toString('base64url') } });
    expect(r.hsmBacked).toBe(true);
    expect(r.keySpec).toBe('RSA_3072');
  });

  it('maps key_ops to a usage', () => {
    expect(fromAzureKeyVault({ key: { kid: 'k', kty: 'EC', crv: 'P-256', key_ops: ['sign'] } }).usage).toBe(
      'SIGN_VERIFY',
    );
    expect(
      fromAzureKeyVault({ key: { kid: 'k', kty: 'RSA', key_ops: ['wrapKey'] } }).usage,
    ).toBe('KEY_AGREEMENT');
  });
});

describe('GCP KMS adapter', () => {
  it('pulls project and location out of the resource name', () => {
    const r = fromGcpKms({
      name: 'projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
      algorithm: 'RSA_SIGN_PSS_2048_SHA256',
      protectionLevel: 'HSM',
      state: 'ENABLED',
    });
    expect(r.scope).toBe('p');
    expect(r.region).toBe('europe-west1');
    expect(r.hsmBacked).toBe(true);
    expect(r.usage).toBe('SIGN_VERIFY');
  });

  it('treats a destroyed version as disabled', () => {
    expect(fromGcpKms({ name: 'n', algorithm: 'X', state: 'DESTROYED' }).enabled).toBe(false);
  });
});

describe('spec -> asset', () => {
  it('reads RSA size and padding from any provider spelling', () => {
    expect(assetFor({ ...base, keySpec: 'RSA_2048' })?.parameters['modulusLength']).toBe(2048);
    const gcp = assetFor({ ...base, keySpec: 'RSA_SIGN_PSS_3072_SHA256', usage: 'SIGN_VERIFY' });
    expect(gcp?.primitive).toBe('RSA');
    expect(gcp?.parameters['modulusLength']).toBe(3072);
    expect(gcp?.parameters['padding']).toBe('PSS');
  });

  it('normalizes curve names across providers to one asset', () => {
    const aws = assetFor({ ...base, keySpec: 'ECC_NIST_P256', usage: 'SIGN_VERIFY' });
    const azure = assetFor({ ...base, keySpec: 'EC_P-256', usage: 'SIGN_VERIFY' });
    expect(aws?.parameters['curve']).toBe('P-256');
    // Same curve, same purpose, therefore the same content hash - which is
    // what lets one key inventory dedupe against a certificate and a handshake.
    expect(aws?.id).toBe(azure?.id);
  });

  it('records the symmetric default explicitly, so it can be shown NOT to need migrating', () => {
    const a = assetFor({ ...base, keySpec: 'SYMMETRIC_DEFAULT' });
    expect(a?.primitive).toBe('AES');
    expect(a?.parameters['keySize']).toBe(256);
    expect(a?.quantumVulnerable).toBe(false);
  });

  it('recognizes standardized PQ key specs', () => {
    expect(assetFor({ ...base, keySpec: 'ML_DSA_44', usage: 'SIGN_VERIFY' })?.quantumVulnerable).toBe(false);
  });

  it('returns null rather than guessing at an unknown spec', () => {
    expect(assetFor({ ...base, keySpec: 'SOME_FUTURE_THING' })).toBeNull();
  });
});

describe('control class', () => {
  it('classes an HSM-backed key as HARDWARE - bounded by the appliance, not a code change', () => {
    expect(controlClassFor({ ...base, hsmBacked: true })).toBe('HARDWARE');
  });
  it('classes a software key as vendor-upgradeable', () => {
    expect(controlClassFor(base)).toBe('VENDOR_UPGRADEABLE');
  });
});

describe('findings', () => {
  const inventory = KeyInventorySchema.parse({
    collectedAt: '2026-08-28T00:00:00.000Z',
    source: 'export',
    keys: [
      { id: 'b', keySpec: 'RSA_2048', usage: 'ENCRYPT_DECRYPT', provider: 'aws-kms', hsmBacked: true },
      { id: 'a', keySpec: 'SYMMETRIC_DEFAULT', usage: 'ENCRYPT_DECRYPT', provider: 'aws-kms' },
      { id: 'c', keySpec: 'NOPE', usage: 'UNKNOWN', provider: 'kmip' },
      { id: 'd', keySpec: 'RSA_2048', usage: 'SIGN_VERIFY', provider: 'aws-kms', enabled: false },
    ],
  });

  it('emits CLOUD_KMS_API evidence and states that no key material was read', () => {
    const { findings } = kmsFindings(inventory, { systemId: 's', collectedAt: '2026-08-28T00:00:00.000Z' });
    expect(findings.every((f) => f.evidence.modality === 'CLOUD_KMS_API')).toBe(true);
    expect(findings.every((f) => f.evidence.raw.includes('no key material was read'))).toBe(true);
  });

  it('reports unrecognized specs instead of dropping them silently', () => {
    const { unrecognized } = kmsFindings(inventory, { systemId: 's', collectedAt: '2026-08-28T00:00:00.000Z' });
    expect(unrecognized.map((r) => r.id)).toEqual(['c']);
  });

  it('skips disabled keys unless asked', () => {
    const opts = { systemId: 's', collectedAt: '2026-08-28T00:00:00.000Z' };
    expect(kmsFindings(inventory, opts).findings.map((f) => f.evidence.locator)).toEqual(['a', 'b']);
    expect(
      kmsFindings(inventory, { ...opts, includeDisabled: true }).findings.map((f) => f.evidence.locator),
    ).toEqual(['a', 'b', 'd']);
  });

  it('is order-stable', () => {
    const opts = { systemId: 's', collectedAt: '2026-08-28T00:00:00.000Z' };
    const shuffled = { ...inventory, keys: [...inventory.keys].reverse() };
    expect(JSON.stringify(kmsFindings(shuffled, opts).findings)).toBe(
      JSON.stringify(kmsFindings(inventory, opts).findings),
    );
  });
});
