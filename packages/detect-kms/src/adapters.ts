import type { KeyRecord } from './types.js';

/**
 * Provider response -> normalized KeyRecord.
 *
 * These are pure functions over the shapes each provider's metadata API
 * returns. That is deliberate: translating `RSA_2048` / `RSA-HSM` /
 * `RSA_SIGN_PSS_2048_SHA256` into one asset model is the part that is easy to
 * get subtly wrong, and it is the part that can be tested without credentials.
 * Wiring an SDK call to feed them is a few lines and cannot be verified here,
 * so it is not pretended at - see importInventory for the path that works
 * today, and note it is also the only path available in an air-gapped estate.
 */

/* --------------------------------------------------------------- AWS KMS */

export interface AwsKeyMetadata {
  readonly KeyId: string;
  readonly Arn?: string;
  readonly KeySpec?: string;
  readonly KeyUsage?: string;
  readonly Enabled?: boolean;
  readonly Origin?: string;
  readonly CreationDate?: string;
  readonly Description?: string;
  readonly MultiRegion?: boolean;
}

export function fromAwsKms(
  meta: AwsKeyMetadata,
  ctx: { account?: string; region?: string; rotationEnabled?: boolean | null } = {},
): KeyRecord {
  return {
    id: meta.Arn ?? meta.KeyId,
    provider: 'aws-kms',
    scope: ctx.account ?? '',
    region: ctx.region ?? '',
    keySpec: meta.KeySpec ?? 'SYMMETRIC_DEFAULT',
    usage: awsUsage(meta.KeyUsage),
    enabled: meta.Enabled ?? true,
    // CloudHSM-backed and external-store keys are hardware; the default store
    // is a managed HSM fleet but is not replaceable on a hardware cycle, so it
    // is not classed as HARDWARE.
    hsmBacked: meta.Origin === 'AWS_CLOUDHSM' || meta.Origin === 'EXTERNAL_KEY_STORE',
    rotationEnabled: ctx.rotationEnabled ?? null,
    createdAt: meta.CreationDate ?? null,
    description: meta.Description ?? '',
  };
}

function awsUsage(u: string | undefined): KeyRecord['usage'] {
  switch (u) {
    case 'ENCRYPT_DECRYPT':
      return 'ENCRYPT_DECRYPT';
    case 'SIGN_VERIFY':
      return 'SIGN_VERIFY';
    case 'KEY_AGREEMENT':
      return 'KEY_AGREEMENT';
    case 'GENERATE_VERIFY_MAC':
      return 'GENERATE_VERIFY_MAC';
    default:
      return 'UNKNOWN';
  }
}

/* ------------------------------------------------------- Azure Key Vault */

export interface AzureKeyBundle {
  readonly key: {
    readonly kid: string;
    readonly kty: string;
    readonly crv?: string;
    readonly n?: string;
    readonly key_ops?: readonly string[];
  };
  readonly attributes?: { readonly enabled?: boolean; readonly created?: number };
  readonly tags?: Readonly<Record<string, string>>;
}

export function fromAzureKeyVault(bundle: AzureKeyBundle, ctx: { subscription?: string } = {}): KeyRecord {
  const kty = bundle.key.kty;
  // Azure states RSA size only via the modulus, base64url-encoded. Length in
  // bytes times eight is the modulus size; there is no separate field.
  const modulusBits = bundle.key.n === undefined ? null : base64urlBits(bundle.key.n);
  const keySpec =
    kty.startsWith('RSA')
      ? `RSA_${modulusBits ?? 'unknown'}`
      : kty.startsWith('EC')
        ? `EC_${bundle.key.crv ?? 'unknown'}`
        : kty;

  return {
    id: bundle.key.kid,
    provider: 'azure-key-vault',
    scope: ctx.subscription ?? '',
    region: '',
    keySpec,
    usage: azureUsage(bundle.key.key_ops ?? []),
    enabled: bundle.attributes?.enabled ?? true,
    // The -HSM suffix is Azure stating the key never leaves an HSM.
    hsmBacked: kty.endsWith('-HSM'),
    rotationEnabled: null,
    createdAt:
      bundle.attributes?.created === undefined
        ? null
        : new Date(bundle.attributes.created * 1000).toISOString(),
    description: bundle.tags?.['description'] ?? '',
  };
}

function azureUsage(ops: readonly string[]): KeyRecord['usage'] {
  const set = new Set(ops);
  if (set.has('sign') || set.has('verify')) return 'SIGN_VERIFY';
  if (set.has('wrapKey') || set.has('unwrapKey')) return 'KEY_AGREEMENT';
  if (set.has('encrypt') || set.has('decrypt')) return 'ENCRYPT_DECRYPT';
  return 'UNKNOWN';
}

/**
 * Byte length of a base64 or base64url value, in bits.
 *
 * JWK modulus values are base64url and UNPADDED, so the padded-length formula
 * overstates a 2048-bit modulus as 2052 and the inventory reports a key size
 * that does not exist. Handle both encodings explicitly.
 */
function base64urlBits(b64url: string): number {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0;
  const bytes =
    padding > 0 ? (b64.length / 4) * 3 - padding : Math.floor((b64.length * 3) / 4);
  return bytes * 8;
}

/* ---------------------------------------------------------------- GCP KMS */

export interface GcpCryptoKeyVersion {
  readonly name: string;
  readonly algorithm: string;
  readonly state?: string;
  readonly protectionLevel?: string;
  readonly createTime?: string;
  readonly purpose?: string;
}

export function fromGcpKms(
  v: GcpCryptoKeyVersion,
  ctx: { project?: string; location?: string; rotationEnabled?: boolean | null } = {},
): KeyRecord {
  return {
    id: v.name,
    provider: 'gcp-kms',
    scope: ctx.project ?? projectOf(v.name),
    region: ctx.location ?? locationOf(v.name),
    keySpec: v.algorithm,
    usage: gcpUsage(v.purpose, v.algorithm),
    enabled: v.state === undefined || v.state === 'ENABLED',
    hsmBacked: v.protectionLevel === 'HSM' || v.protectionLevel === 'EXTERNAL_VPC',
    rotationEnabled: ctx.rotationEnabled ?? null,
    createdAt: v.createTime ?? null,
    description: '',
  };
}

function gcpUsage(purpose: string | undefined, algorithm: string): KeyRecord['usage'] {
  if (purpose === 'ASYMMETRIC_SIGN' || algorithm.includes('SIGN')) return 'SIGN_VERIFY';
  if (purpose === 'ASYMMETRIC_DECRYPT' || algorithm.includes('DECRYPT')) return 'ENCRYPT_DECRYPT';
  if (purpose === 'MAC') return 'GENERATE_VERIFY_MAC';
  if (purpose === 'ENCRYPT_DECRYPT') return 'ENCRYPT_DECRYPT';
  return 'UNKNOWN';
}

function projectOf(name: string): string {
  return /projects\/([^/]+)/.exec(name)?.[1] ?? '';
}

function locationOf(name: string): string {
  return /locations\/([^/]+)/.exec(name)?.[1] ?? '';
}
