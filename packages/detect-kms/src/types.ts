import { z } from 'zod';

/**
 * Normalized key-store inventory.
 *
 * Cloud KMS is the highest-confidence, lowest-effort modality Assay has
 * (CLOUD_KMS_API, ceiling 0.97): the provider states the key spec in an
 * authenticated API response. Nothing is inferred from a call site and no
 * handshake has to be observed. It is also the modality that reaches the part
 * of the estate a repo scan structurally cannot see - the keys that exist
 * without any code referring to them.
 *
 * I9 applies with full force here. This module records that a key EXISTS, its
 * algorithm, its size and where it lives. There is no code path that reads,
 * stores or transmits key material, and the provider adapters below read only
 * metadata endpoints.
 */

export const KeyRecordSchema = z.object({
  /** Provider-native identifier: ARN, resource name, key vault URL, KMIP UID. */
  id: z.string().min(1),
  provider: z.enum(['aws-kms', 'azure-key-vault', 'gcp-kms', 'kmip', 'imported']),
  /** Account, subscription, project or appliance this key lives in. */
  scope: z.string().default(''),
  region: z.string().default(''),
  /** Provider's own spec string, kept verbatim for audit. */
  keySpec: z.string().min(1),
  /** What the provider says the key is for. */
  usage: z.enum(['ENCRYPT_DECRYPT', 'SIGN_VERIFY', 'KEY_AGREEMENT', 'GENERATE_VERIFY_MAC', 'UNKNOWN']),
  enabled: z.boolean().default(true),
  /** True when the provider states the key is HSM-backed. Drives control class. */
  hsmBacked: z.boolean().default(false),
  rotationEnabled: z.boolean().nullable().default(null),
  createdAt: z.string().nullable().default(null),
  description: z.string().default(''),
});

export type KeyRecord = z.infer<typeof KeyRecordSchema>;

export const KeyInventorySchema = z.object({
  collectedAt: z.string(),
  source: z.string().default(''),
  keys: z.array(KeyRecordSchema),
});

export type KeyInventory = z.infer<typeof KeyInventorySchema>;
