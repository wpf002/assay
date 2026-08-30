import { z } from 'zod';

/**
 * A normalized host inventory: what an agent found on a running machine.
 *
 * This is the modality every other one defers to. A configuration file in a
 * repository "may be a template rather than the file a server is running";
 * a dependency "shows what the code COULD do"; a certificate in a tree "is not
 * evidence of what a live endpoint presents". Every one of those caveats is a
 * caveat about not having stood on the machine. HOST_AGENT is standing on the
 * machine, which is why its ceiling is 0.9 and why it sits in
 * DEPLOYMENT_MODALITIES rather than with the capability evidence.
 *
 * Assay does not ship an agent and this file does not collect anything. The
 * customer's existing EDR, CMDB or configuration-management tool already holds
 * this; the adapters turn three common shapes into the one below. That is the
 * same division of labour as detect-kms, and in a regulated estate it is the
 * only division that is ever allowed: the tool that holds the credentials is
 * theirs, and Assay classifies what it exports.
 *
 * I9 holds here as it does everywhere. A host agent can see private keys on
 * disk. Nothing in this package reads key material, and the schema has no field
 * that could carry it: a key is recorded by algorithm, size and path, never by
 * content. `PrivateKeyFileSchema` deliberately has no `pem` field.
 */

/** A crypto library or runtime installed on the host. */
export const HostPackageSchema = z.object({
  name: z.string().min(1),
  version: z.string().default(''),
  /** Where the package manager says it came from. */
  source: z.string().default(''),
});

/**
 * A directive read off the machine, not out of a repository.
 *
 * The same `Ciphers aes128-cbc` line means two different things depending on
 * where it was read: in a repo it is a proposal, here it is the running state.
 */
export const HostConfigSchema = z.object({
  path: z.string().min(1),
  directive: z.string().min(1),
  value: z.string().default(''),
  /** True when the agent confirmed the owning service was running. */
  active: z.boolean().default(true),
});

/** A certificate or host key present on the machine. */
export const HostKeyFileSchema = z.object({
  path: z.string().min(1),
  kind: z.enum(['certificate', 'ssh-host-key', 'public-key', 'private-key']),
  algorithm: z.string().min(1),
  bits: z.number().int().positive().nullable().default(null),
  curve: z.string().default(''),
  subject: z.string().default(''),
  notAfter: z.string().nullable().default(null),
});

/** A listening service and what the agent saw it configured to accept. */
export const HostListenerSchema = z.object({
  port: z.number().int().min(0).max(65535),
  protocol: z.string().default(''),
  service: z.string().default(''),
  /** Cipher suites or KEX algorithms the service is configured to offer. */
  offers: z.array(z.string()).default([]),
});

export const HostSchema = z.object({
  hostId: z.string().min(1),
  hostname: z.string().default(''),
  os: z.string().default(''),
  /** Which system in the estate this host belongs to. */
  systemId: z.string().default(''),
  packages: z.array(HostPackageSchema).default([]),
  configs: z.array(HostConfigSchema).default([]),
  keyFiles: z.array(HostKeyFileSchema).default([]),
  listeners: z.array(HostListenerSchema).default([]),
});

export const HostInventorySchema = z.object({
  collectedAt: z.string(),
  /** The agent that produced this, named so the evidence can be traced back. */
  source: z.string().default(''),
  hosts: z.array(HostSchema),
});

export type HostPackage = z.infer<typeof HostPackageSchema>;
export type HostConfig = z.infer<typeof HostConfigSchema>;
export type HostKeyFile = z.infer<typeof HostKeyFileSchema>;
export type HostListener = z.infer<typeof HostListenerSchema>;
export type Host = z.infer<typeof HostSchema>;
export type HostInventory = z.infer<typeof HostInventorySchema>;
