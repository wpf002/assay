import { z } from 'zod';
import { CONTROL_CLASSES, PRIMITIVES, PURPOSES } from '@assay/core';

/**
 * Vendor attestation.
 *
 * `VENDOR_LOCKED` and `HARDWARE` are the classes that actually blow a
 * migration timeline, and no amount of scanning resolves them: the source is
 * not yours, the appliance does not answer questions, and the only party who
 * knows when post-quantum support lands is the vendor.
 *
 * What is captured here is a CLAIM, and it is treated as one - ingested at the
 * ASSERTED modality with its 0.40 ceiling, which cannot confirm anything on
 * its own. Its value is not evidence. Its value is the DATE: a vendor's stated
 * availability is a far better Y than a class average, and comparing that date
 * against the deadline turns "we are waiting on the vendor" into a dated
 * procurement finding you can put in a contract.
 */

export const CryptoClaimSchema = z.object({
  primitive: z.enum(PRIMITIVES),
  parameters: z.record(z.union([z.string(), z.number()])).default({}),
  purpose: z.enum(PURPOSES),
  /** Where in the product this is used, in the vendor's own words. */
  component: z.string().default(''),
  /** The vendor says this is configurable or removable without a new release. */
  configurable: z.boolean().default(false),
});
export type CryptoClaim = z.infer<typeof CryptoClaimSchema>;

export const RoadmapSchema = z.object({
  /**
   * When post-quantum support becomes available, as the vendor states it.
   * A date, or an explicit refusal. "We are evaluating" is not a date and
   * must be recorded as `none` rather than dressed up as one.
   */
  status: z.enum(['available', 'committed', 'evaluating', 'none']),
  availableFrom: z.string().datetime().nullable().default(null),
  /** Algorithms the vendor commits to supporting. */
  algorithms: z.array(z.enum(PRIMITIVES)).default([]),
  /** Whether the customer must also upgrade hardware to get it. */
  requiresHardwareReplacement: z.boolean().default(false),
  notes: z.string().default(''),
});
export type Roadmap = z.infer<typeof RoadmapSchema>;

export const VendorAttestationSchema = z.object({
  schema: z.literal('assay.attestation/v1'),
  vendor: z.string().min(1),
  product: z.string().min(1),
  version: z.string().min(1),
  /** The system in the customer's estate this attestation covers. */
  systemId: z.string().min(1),
  controlClass: z.enum(CONTROL_CLASSES).default('VENDOR_LOCKED'),
  /** Who at the vendor signed this, and when. Both are auditable. */
  attestedBy: z.string().min(1),
  attestedAt: z.string().datetime(),
  /**
   * A questionnaire response with no expiry is a claim about a product that
   * has shipped four releases since. Required, like a suppression.
   */
  validUntil: z.string().datetime(),
  claims: z.array(CryptoClaimSchema),
  roadmap: RoadmapSchema,
  /** Free-form reference: a ticket, a contract clause, an email thread. */
  reference: z.string().default(''),
});
export type VendorAttestation = z.infer<typeof VendorAttestationSchema>;
