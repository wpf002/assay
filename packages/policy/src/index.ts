import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { MoscaPolicy } from '@assay/core';
import { verifyPack, type PackTrust } from './signing.js';

export * from './signing.js';

/**
 * Deadline policy is versioned data, never constants (I4).
 *
 * CNSA 2.0, NIST IR 8547 and EU financial-sector timelines disagree and move,
 * and as of EO 14412 there is now a hard US regulatory date that has nothing
 * to do with any of them. Hardcoding a year makes the tool silently wrong on a
 * schedule; every ranked finding records the pack version that produced it, so
 * a re-rank under a new pack is a diff rather than a rewrite.
 */
export const PolicyPackSchema = z.object({
  packId: z.string().min(1),
  packVersion: z.string().min(1),
  title: z.string().optional(),
  note: z.string().optional(),
  crqcYear: z.number(),
  deprecateYear: z.number(),
  disallowYear: z.number(),
  regulatoryDeadlines: z.object({
    CONFIDENTIALITY: z.number().nullable(),
    AUTHENTICITY: z.number().nullable(),
  }),
  regulatoryAuthority: z.string().nullable(),
  migrationYearsByControl: z.object({
    SELF: z.number().positive(),
    VENDOR_UPGRADEABLE: z.number().positive(),
    VENDOR_LOCKED: z.number().positive(),
    HARDWARE: z.number().positive(),
    PROTOCOL_BILATERAL: z.number().positive(),
  }),
  sources: z.array(z.string()).default([]),
  caveats: z.array(z.string()).default([]),
  /**
   * Publisher signature over the horizon and the regulatory deadlines only
   * (decision D3). Editing migrationYearsByControl locally does NOT
   * invalidate it: Y is the customer's business and Z is the publisher's.
   */
  signature: z.string().nullable().default(null),
});

export type PolicyPack = z.infer<typeof PolicyPackSchema> &
  MoscaPolicy & {
    readonly trust: PackTrust;
    readonly trustReason: string;
  };

export interface LoadOptions {
  /**
   * Publisher key. Without it a signed pack cannot be distinguished from a
   * forged one, so it is reported UNTRUSTED rather than assumed good.
   */
  readonly publisherKeyPem?: string | null;
  /** Refuse to load anything that is not SIGNED. For a regulated deployment. */
  readonly requireSigned?: boolean;
}

const PACKS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'packs');

export function parsePack(json: unknown, opts: LoadOptions = {}): PolicyPack {
  const parsed = PolicyPackSchema.parse(json);
  // `undefined` means "use the shipped publisher key"; an explicit `null`
  // means "check against nothing", which is how a caller asks what a pack
  // looks like without any trust anchor at all.
  const key = 'publisherKeyPem' in opts ? (opts.publisherKeyPem ?? null) : defaultPublisherKey();
  const { trust, reason } = verifyPack(parsed, key);
  if (opts.requireSigned === true && trust !== 'SIGNED') {
    throw new Error(`policy pack ${parsed.packId} is ${trust}: ${reason}`);
  }
  return { ...parsed, trust, trustReason: reason } as PolicyPack;
}

const PUBLISHER_KEY_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'keys',
  'assay-packs.pub.pem',
);

/**
 * The key the shipped packs were signed with, distributed alongside them.
 *
 * This is deliberately not a trust anchor in any strong sense - it ships in
 * the same repository as the packs, so it proves the packs were not edited
 * after publication, not that the publisher is trustworthy. An organization
 * with its own view supplies its own key.
 */
function defaultPublisherKey(): string | null {
  try {
    return readFileSync(PUBLISHER_KEY_PATH, 'utf8');
  } catch {
    return null;
  }
}

export function listPacks(): string[] {
  return readdirSync(PACKS_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''))
    .sort();
}

export function loadPack(packId: string, opts: LoadOptions = {}): PolicyPack {
  const file = join(PACKS_DIR, `${packId}.json`);
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    throw new Error(`unknown policy pack "${packId}". available: ${listPacks().join(', ')}`);
  }
  const pack = parsePack(JSON.parse(raw), opts);
  if (pack.packId !== packId) {
    throw new Error(`policy pack file ${packId}.json declares packId "${pack.packId}"`);
  }
  return pack;
}

export const DEFAULT_PACK_ID = 'eo-14412';

/**
 * Decimal year from a date. Callers pass this into scoreMosca so the engine
 * itself never reads a clock.
 */
export function decimalYear(d: Date): number {
  const year = d.getUTCFullYear();
  const start = Date.UTC(year, 0, 1);
  const end = Date.UTC(year + 1, 0, 1);
  return Math.round((year + (d.getTime() - start) / (end - start)) * 1e4) / 1e4;
}
