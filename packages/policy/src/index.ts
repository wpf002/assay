import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { MoscaPolicy } from '@assay/core';

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
});

export type PolicyPack = z.infer<typeof PolicyPackSchema> & MoscaPolicy;

const PACKS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'packs');

export function parsePack(json: unknown): PolicyPack {
  return PolicyPackSchema.parse(json) as PolicyPack;
}

export function listPacks(): string[] {
  return readdirSync(PACKS_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''))
    .sort();
}

export function loadPack(packId: string): PolicyPack {
  const file = join(PACKS_DIR, `${packId}.json`);
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    throw new Error(`unknown policy pack "${packId}". available: ${listPacks().join(', ')}`);
  }
  const pack = parsePack(JSON.parse(raw));
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
