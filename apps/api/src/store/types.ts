import { z } from 'zod';
import type { CryptoAsset, Occurrence } from '@assay/core';

/**
 * Persistence boundary.
 *
 * The API is written against this interface rather than against Prisma so the
 * route logic can be tested without a database, and so a customer who cannot
 * run Postgres inside their perimeter is not locked out of the product.
 */

export const IngestSchema = z.object({
  systemName: z.string().min(1),
  detectors: z.array(z.string()).default([]),
  policyPackId: z.string().min(1),
  policyPackVersion: z.string().min(1),
  /** Required for any scan that used a network detector; recorded for audit (I8). */
  scopeGrantId: z.string().nullable().default(null),
  startedAt: z.string().datetime(),
  finishedAt: z.string().datetime().nullable().default(null),
  // Occurrences and assets are passed through as produced by @assay/core. They
  // are validated structurally rather than re-derived: re-deriving confidence
  // server-side would let the API and the CLI disagree, and the whole claim is
  // that the same evidence yields the same answer everywhere.
  occurrences: z.array(z.unknown()),
  assets: z.array(z.unknown()),
});

export type IngestBody = z.infer<typeof IngestSchema>;

export interface StoredScan {
  readonly id: string;
  readonly systemName: string;
  readonly startedAt: string;
  readonly finishedAt: string | null;
  readonly detectors: readonly string[];
  readonly policyPackId: string;
  readonly policyPackVersion: string;
  readonly scopeGrantId: string | null;
  readonly occurrences: readonly Occurrence[];
  readonly assets: readonly CryptoAsset[];
}

export interface ScanSummary {
  readonly id: string;
  readonly systemName: string;
  readonly startedAt: string;
  readonly policyPackId: string;
  readonly policyPackVersion: string;
  readonly occurrenceCount: number;
  readonly assetCount: number;
  readonly detectors: readonly string[];
}

/**
 * A trace bundle, reduced to its service graph.
 *
 * Spans are ingested and discarded; only edges are kept. A span carries
 * request attributes, user identifiers and sometimes payload fragments, and
 * knowing that the payments API calls the signing service requires none of
 * that. Persisting raw spans would make this tool a second copy of the most
 * sensitive telemetry an organization has, for no analytical gain.
 */
export interface StoredTraceBundle {
  readonly id: string;
  readonly source: string;
  readonly windowFrom: string;
  readonly windowTo: string;
  readonly ingestedAt: string;
  readonly spanCount: number;
  readonly rootServices: readonly string[];
  readonly edges: readonly {
    readonly from: string;
    readonly to: string;
    readonly observations: number;
    readonly operation: string;
  }[];
}

export interface ScanStore {
  readonly kind: 'memory' | 'prisma';
  put(scan: StoredScan): Promise<void>;
  list(systemName?: string): Promise<ScanSummary[]>;
  get(id: string): Promise<StoredScan | null>;
  /** The two most recent scans of a system, newest first. The default diff. */
  recent(systemName: string, limit: number): Promise<StoredScan[]>;
  /** The most recent scan of every system. The estate as it currently stands. */
  latestPerSystem(): Promise<StoredScan[]>;

  putTraces(bundle: StoredTraceBundle): Promise<void>;
  listTraces(): Promise<Omit<StoredTraceBundle, 'edges'>[]>;
  getTraces(id: string): Promise<StoredTraceBundle | null>;
  /** Newest bundle, for `?traces=latest`. */
  latestTraces(): Promise<StoredTraceBundle | null>;

  close(): Promise<void>;
}

export function summarize(scan: StoredScan): ScanSummary {
  return {
    id: scan.id,
    systemName: scan.systemName,
    startedAt: scan.startedAt,
    policyPackId: scan.policyPackId,
    policyPackVersion: scan.policyPackVersion,
    occurrenceCount: scan.occurrences.length,
    assetCount: scan.assets.length,
    detectors: scan.detectors,
  };
}
