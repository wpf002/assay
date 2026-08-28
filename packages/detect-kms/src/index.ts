import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  makeAsset,
  normalizeCurve,
  type ControlClass,
  type CryptoAsset,
  type Finding,
  type Purpose,
} from '@assay/core';
import { KeyInventorySchema, type KeyInventory, type KeyRecord } from './types.js';

export * from './types.js';
export * from './adapters.js';

export const COLLECTOR_VERSION = 'detect-kms/0.1.0';

/**
 * Key-store inventory -> findings.
 *
 * The provider names the key spec, so there is nothing to infer and the
 * modality sits at 0.97. What it cannot tell us is whether anything USES the
 * key - an unused RSA key in a vault is still an asset, but it is not the same
 * work item as the one wrapping your database DEKs. That distinction is
 * reachability, and it is Phase 3.
 */

/** Provider spec string -> asset. Every branch is a place a size can be lost. */
export function assetFor(record: KeyRecord): CryptoAsset | null {
  const spec = record.keySpec.toUpperCase();
  const purpose = purposeFor(record);

  // AWS: RSA_2048 / ECC_NIST_P256 / ECC_SECG_P256K1 / SYMMETRIC_DEFAULT / HMAC_256 / ML_DSA_44
  // GCP: RSA_SIGN_PSS_2048_SHA256 / EC_SIGN_P256_SHA256 / GOOGLE_SYMMETRIC_ENCRYPTION
  // Azure (normalized above): RSA_3072 / EC_P-256
  if (spec.includes('ML_DSA') || spec.includes('ML-DSA')) {
    return makeAsset('ML-DSA', { keySpec: record.keySpec }, purpose);
  }
  if (spec.includes('ML_KEM') || spec.includes('ML-KEM')) {
    return makeAsset('ML-KEM', { keySpec: record.keySpec }, purpose);
  }
  if (spec.startsWith('RSA') || spec.includes('_RSA') || spec.includes('RSA_')) {
    const bits = /(\d{3,5})/.exec(spec)?.[1];
    const padding = spec.includes('PSS') ? 'PSS' : spec.includes('OAEP') ? 'OAEP' : undefined;
    return makeAsset(
      'RSA',
      {
        ...(bits === undefined ? {} : { modulusLength: Number(bits) }),
        ...(padding === undefined ? {} : { padding }),
      },
      purpose,
    );
  }
  if (spec.startsWith('EC') || spec.includes('ECC') || spec.includes('EC_')) {
    const raw = /(P-?\d{3}|SECP\d{3}[KR]1|NIST_P\d{3})/.exec(spec)?.[1] ?? '';
    const curve = normalizeCurve(raw.replace('NIST_P', 'P-').replace(/^P(\d)/, 'P-$1'));
    const isAgreement = purpose === 'KEY_ESTABLISHMENT';
    return makeAsset(
      isAgreement ? 'ECDH' : 'ECDSA',
      curve === null ? { keySpec: record.keySpec } : { curve },
      purpose,
    );
  }
  if (spec.includes('HMAC')) {
    const bits = /(\d{3})/.exec(spec)?.[1];
    return makeAsset('HMAC', bits === undefined ? {} : { outputLength: Number(bits) }, 'INTEGRITY');
  }
  if (spec.includes('SYMMETRIC') || spec.includes('AES')) {
    // AWS SYMMETRIC_DEFAULT and Google's symmetric key are both AES-256-GCM.
    // Recording that explicitly matters: at 256 bits it is NOT a migration
    // item, and a CBOM that leaves it as "symmetric" cannot say so.
    const bits = /(\d{3})/.exec(spec)?.[1];
    return makeAsset(
      'AES',
      { keySize: bits === undefined ? 256 : Number(bits), mode: 'GCM' },
      purpose,
    );
  }
  return null;
}

function purposeFor(record: KeyRecord): Purpose {
  switch (record.usage) {
    case 'SIGN_VERIFY':
      return 'DIGITAL_SIGNATURE';
    case 'KEY_AGREEMENT':
      return 'KEY_ESTABLISHMENT';
    case 'GENERATE_VERIFY_MAC':
      return 'INTEGRITY';
    case 'ENCRYPT_DECRYPT':
      // A KMS key that encrypts is almost always wrapping a data key rather
      // than encrypting bulk data, which puts it on the confidentiality track
      // either way.
      return 'KEY_ESTABLISHMENT';
    default:
      return 'DATA_ENCRYPTION';
  }
}

/**
 * An HSM-backed key is HARDWARE: migrating it is bounded by what the appliance
 * firmware supports and when it can be replaced, not by a code change. That is
 * a six-year Y, and it is the single most common reason a migration plan slips.
 */
export function controlClassFor(record: KeyRecord): ControlClass {
  if (record.hsmBacked) return 'HARDWARE';
  return record.provider === 'imported' ? 'VENDOR_UPGRADEABLE' : 'VENDOR_UPGRADEABLE';
}

export interface KmsFindingOptions {
  readonly systemId: string;
  readonly collectedAt: string;
  /** Include keys the provider reports as disabled. Off by default. */
  readonly includeDisabled?: boolean;
}

export function kmsFindings(
  inventory: KeyInventory,
  opts: KmsFindingOptions,
): { findings: Finding[]; unrecognized: KeyRecord[] } {
  const findings: Finding[] = [];
  const unrecognized: KeyRecord[] = [];

  for (const record of [...inventory.keys].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    if (!record.enabled && opts.includeDisabled !== true) continue;
    const asset = assetFor(record);
    if (asset === null) {
      unrecognized.push(record);
      continue;
    }
    findings.push({
      asset,
      systemId: opts.systemId,
      controlClass: controlClassFor(record),
      evidence: {
        modality: 'CLOUD_KMS_API',
        locator: record.id,
        raw:
          `${record.provider} keySpec=${record.keySpec} usage=${record.usage} ` +
          `hsm=${String(record.hsmBacked)} enabled=${String(record.enabled)} ` +
          `rotation=${record.rotationEnabled === null ? 'unknown' : String(record.rotationEnabled)} ` +
          `scope=${record.scope || '-'} region=${record.region || '-'} ` +
          `:: provider-stated key spec; no key material was read (I9)`,
        collectedAt: opts.collectedAt,
        collectorVersion: COLLECTOR_VERSION,
        occurrence: { location: record.id, symbol: record.keySpec },
      },
    });
  }
  return { findings, unrecognized };
}

/**
 * Read a normalized inventory from disk.
 *
 * This is the path that exists today, and in a regulated or air-gapped estate
 * it is the only path that ever will: the customer exports their key listing
 * with credentials Assay never sees, and Assay classifies it. The provider
 * adapters above turn each vendor's native response into this shape.
 */
export async function importInventory(path: string): Promise<KeyInventory> {
  const raw: unknown = JSON.parse(await readFile(resolve(path), 'utf8'));
  return KeyInventorySchema.parse(raw);
}
