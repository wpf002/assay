import { z } from 'zod';
import { CONTROL_CLASSES, MODALITIES, PRIMITIVES, PURPOSES } from '@assay/core';
import type { CryptoAsset, Occurrence } from '@assay/core';

/**
 * Persistence boundary.
 *
 * The API is written against this interface rather than against Prisma so the
 * route logic can be tested without a database, and so a customer who cannot
 * run Postgres inside their perimeter is not locked out of the product.
 */

/**
 * Timestamps are normalized to millisecond resolution on the way in.
 *
 * The Postgres store funnels every timestamp through a JS Date, which has no
 * finer resolution, so a scan ingested at microsecond precision comes back
 * shorter than it went in. That would be invisible bookkeeping if the scan
 * timestamp did not end up inside the CBOM and inside the sha256 that becomes
 * its serial number: the same scan would re-export under a different serial
 * once it had been through Postgres, which is precisely the byte-identity the
 * exporter claims. Truncating once, here, is what keeps the two stores
 * returning the same document.
 */
function storableIso(value: string): string {
  return new Date(value).toISOString();
}

/**
 * The Factor tree, checked for shape only.
 *
 * Recursive, so it needs the lazy self-reference and a loose annotation to
 * break the inference cycle. Unknown keys are kept rather than stripped: this
 * is @assay/core's data structure, and validation here must not quietly delete
 * a field a newer core added.
 */
const FactorSchema: z.ZodTypeAny = z.lazy(() =>
  z
    .object({
      kind: z.enum(['EVIDENCE', 'INFERENCE', 'POLICY', 'ASSUMPTION']),
      label: z.string(),
      value: z.union([z.number(), z.string(), z.boolean()]),
      weight: z.number(),
      sources: z.array(FactorSchema),
    })
    .passthrough(),
);

const EvidenceSchema = z
  .object({
    modality: z.enum(MODALITIES),
    locator: z.string(),
    raw: z.string(),
    collectedAt: z.string().datetime().transform(storableIso),
    collectorVersion: z.string(),
    occurrence: z
      .object({
        location: z.string(),
        line: z.number().optional(),
        offset: z.number().optional(),
        symbol: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

const CallFrameSchema = z
  .object({
    module: z.string(),
    function: z.string(),
    fullFilename: z.string(),
    line: z.number().optional(),
    column: z.number().optional(),
  })
  .passthrough();

const OccurrenceSchema = z
  .object({
    id: z.string().min(1),
    assetId: z.string().min(1),
    systemId: z.string().min(1),
    controlClass: z.enum(CONTROL_CLASSES),
    /** null = not yet analyzed. Presence != exposure (I5). */
    reachability: z
      .object({
        reachable: z.boolean(),
        via: z.enum([
          'OBSERVED',
          'ENTRY_POINT',
          'DEPLOYED_CONFIG',
          'LIBRARY_SURFACE',
          'TRACE',
          'NONE',
        ]),
        entryPoint: z.string().nullable(),
        path: z.array(CallFrameSchema),
        factor: FactorSchema,
      })
      .passthrough()
      .nullable(),
    evidence: z.array(EvidenceSchema),
    confidence: FactorSchema,
  })
  .passthrough();

const CryptoAssetSchema = z
  .object({
    id: z.string().min(1),
    primitive: z.enum(PRIMITIVES),
    parameters: z.record(z.union([z.string(), z.number()])),
    purpose: z.enum(PURPOSES),
    quantumVulnerable: z.boolean(),
    classicalSecurityBits: z.number().nullable(),
    nistQuantumSecurityLevel: z.number().nullable(),
    oid: z.string().nullable(),
  })
  .passthrough();

export const IngestSchema = z
  .object({
    systemName: z.string().min(1),
    detectors: z.array(z.string()).default([]),
    policyPackId: z.string().min(1),
    policyPackVersion: z.string().min(1),
    /** Required for any scan that used a network detector; recorded for audit (I8). */
    scopeGrantId: z.string().nullable().default(null),
    startedAt: z.string().datetime().transform(storableIso),
    finishedAt: z
      .string()
      .datetime()
      .nullable()
      .default(null)
      .transform((v) => (v === null ? null : storableIso(v))),
    // Occurrences and assets are validated structurally and stored as produced
    // by @assay/core. Structurally, because confidence is NOT re-derived
    // server-side: a second implementation is a second chance for the API and
    // the CLI to disagree about the same evidence. Structurally at all,
    // because a body that only the write path can read is not stored data - an
    // occurrence with no confidence Factor is accepted with a 201 and then
    // fails every export, drill-down and divergence read of that scan.
    occurrences: z.array(OccurrenceSchema),
    assets: z.array(CryptoAssetSchema),
  })
  .superRefine((body, ctx) => {
    // Occurrence.assetId is a foreign key to CryptoAsset in Postgres, so a
    // dangling reference is a write-time 500 there and a findings list with no
    // asset behind it everywhere else.
    const declared = new Set(body.assets.map((a) => a.id));
    for (const [i, o] of body.occurrences.entries()) {
      if (declared.has(o.assetId)) continue;
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['occurrences', i, 'assetId'],
        message: `no asset "${o.assetId}" in this scan`,
      });
    }
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

/**
 * What `GET /traces` returns: the bundle without its edges, plus how many
 * there are. Declared rather than left to each store, because a field one
 * backend returns and the other does not is a client that works under
 * `assay serve --ephemeral` and renders undefined in production.
 */
export type TraceBundleSummary = Omit<StoredTraceBundle, 'edges'> & {
  readonly edgeCount: number;
};

export interface StoredToken {
  readonly id: string;
  readonly secretHash: string;
  readonly name: string;
  readonly role: 'admin' | 'operator' | 'viewer';
  /** Systems this token may read. Empty means every system. */
  readonly systems: readonly string[];
  readonly createdAt: string;
  readonly createdBy: string;
  readonly lastUsedAt: string | null;
  readonly expiresAt: string | null;
  readonly revokedAt: string | null;
}

/** A token as it may be shown after creation: never including the secret. */
export type TokenSummary = Omit<StoredToken, 'secretHash'>;

export interface AuditEvent {
  readonly id: string;
  readonly at: string;
  readonly tokenId: string | null;
  readonly tokenName: string;
  readonly role: string;
  readonly method: string;
  readonly route: string;
  readonly resource: string | null;
  readonly statusCode: number;
  readonly remoteAddr: string;
}

/**
 * "Who exported the CBOM last March" has to be answerable. Newest-N alone made
 * the trail unqueryable the moment it grew, and left the tokenId index unused.
 */
export interface AuditQuery {
  readonly limit: number;
  readonly before?: string | undefined;
  readonly since?: string | undefined;
  readonly tokenId?: string | undefined;
}

export interface ScanStore {
  readonly kind: 'memory' | 'prisma';
  put(scan: StoredScan): Promise<void>;
  /** Newest first. The limit is required: no read path here is unbounded. */
  list(systemName: string | undefined, limit: number): Promise<ScanSummary[]>;
  get(id: string): Promise<StoredScan | null>;
  /** The two most recent scans of a system, newest first. The default diff. */
  recent(systemName: string, limit: number): Promise<StoredScan[]>;
  /** The most recent scan of every system. The estate as it currently stands. */
  latestPerSystem(): Promise<StoredScan[]>;
  /**
   * The names alone, for callers that need the estate's shape and not its
   * findings. Hydrating every occurrence and every evidence row of every
   * system to build a list of strings is the difference between one query and
   * millions of rows.
   */
  latestSystemNames(): Promise<string[]>;

  /** Lookup is by hash so the database does an indexed read, not a scan. */
  findToken(secretHash: string): Promise<StoredToken | null>;
  putToken(token: StoredToken): Promise<void>;
  listTokens(): Promise<TokenSummary[]>;
  revokeToken(id: string, at: string): Promise<boolean>;
  touchToken(id: string, at: string): Promise<void>;
  /**
   * Tokens that can still authenticate. Counting revoked and expired ones
   * meant the bootstrap never re-armed, so losing the last working token
   * locked the API out permanently with rows still in the table.
   */
  countUsableTokens(now: string): Promise<number>;

  appendAudit(event: AuditEvent): Promise<void>;
  listAudit(query: AuditQuery): Promise<AuditEvent[]>;

  putTraces(bundle: StoredTraceBundle): Promise<void>;
  listTraces(): Promise<TraceBundleSummary[]>;
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
