import { Prisma, PrismaClient } from '@prisma/client';
import { gate, type CallFrame, type CryptoAsset, type Factor, type Occurrence } from '@assay/core';
import {
  summarize,
  type AuditEvent,
  type AuditQuery,
  type StoredToken,
  type TokenSummary,
  type ScanStore,
  type ScanSummary,
  type StoredScan,
  type StoredTraceBundle,
  type TraceBundleSummary,
} from './types.js';

/**
 * Postgres-backed store.
 *
 * Two things this deliberately does NOT do:
 *
 * 1. It does not recompute confidence or ranking on read. The Factor tree is
 *    stored verbatim and returned verbatim. If the server re-derived it, the
 *    API and the CLI could disagree about the same evidence, and the entire
 *    reproducibility claim would be a claim about one code path rather than
 *    about the tool.
 * 2. It does not upsert occurrences across scans. An occurrence id is stable
 *    by construction, but each scan owns its own row - otherwise the previous
 *    scan's state is destroyed by the next one and a diff becomes impossible.
 */
export class PrismaScanStore implements ScanStore {
  readonly kind = 'prisma' as const;

  constructor(private readonly prisma: PrismaClient) {}

  static fromUrl(url: string): PrismaScanStore {
    return new PrismaScanStore(
      new PrismaClient({
        datasources: { db: { url } },
        // An ingest writes one row per occurrence and one per evidence item
        // inside a single transaction. Prisma's five-second default aborts a
        // realistically sized scan halfway and reports it as a server error.
        transactionOptions: { maxWait: 10_000, timeout: 120_000 },
      }),
    );
  }

  async put(scan: StoredScan): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const system = await tx.system.upsert({
        where: { name_kind: { name: scan.systemName, kind: 'repo' } },
        create: { name: scan.systemName, kind: 'repo' },
        update: {},
      });

      for (const asset of scan.assets) {
        await tx.cryptoAsset.upsert({
          where: { id: asset.id },
          create: {
            id: asset.id,
            primitive: asset.primitive,
            parameters: asset.parameters as object,
            purpose: asset.purpose,
            quantumVulnerable: asset.quantumVulnerable,
            classicalSecurityBits: asset.classicalSecurityBits,
            nistQuantumSecurityLevel: asset.nistQuantumSecurityLevel,
            oid: asset.oid,
          },
          update: {},
        });
      }

      await tx.scan.create({
        data: {
          id: scan.id,
          systemName: scan.systemName,
          startedAt: new Date(scan.startedAt),
          finishedAt: scan.finishedAt === null ? null : new Date(scan.finishedAt),
          detectors: [...scan.detectors],
          policyPackId: scan.policyPackId,
          policyPackVersion: scan.policyPackVersion,
          scopeGrantId: scan.scopeGrantId,
        },
      });

      // The assets the scan DECLARED, which is not the same set as the assets
      // its occurrences reference: an inventory entry with no work item behind
      // it has no occurrence to be recovered from.
      await tx.scanAsset.createMany({
        data: scan.assets.map((a) => ({ scanId: scan.id, assetId: a.id })),
        skipDuplicates: true,
      });

      for (const o of scan.occurrences) {
        const g = gate(o);
        await tx.occurrence.create({
          data: {
            // Scoped to the scan so two scans can hold the same work item.
            id: `${scan.id}:${o.id}`,
            assetId: o.assetId,
            systemId: system.id,
            // The occurrence's own logical system. It is part of the content
            // hash that makes the id stable, and trace correlation matches
            // trace service names against it, so it cannot be reconstructed
            // from the scan's system name.
            systemKey: o.systemId,
            controlClass: o.controlClass,
            reachable: o.reachability?.reachable ?? null,
            reachVia: o.reachability?.via ?? null,
            reachEntryPoint: o.reachability?.entryPoint ?? null,
            // Prisma distinguishes SQL NULL from JSON null; DbNull is what
            // "this scan did not analyze reachability" means.
            reachPath: (o.reachability?.path ?? Prisma.DbNull) as unknown as Prisma.InputJsonValue,
            reachFactor: (o.reachability?.factor ?? Prisma.DbNull) as unknown as Prisma.InputJsonValue,
            confidence: Number(o.confidence.value),
            confidenceFactor: o.confidence as unknown as object,
            assertionLevel: g.assertionLevel,
            downgradeReason: g.downgradeReason,
            scanId: scan.id,
            evidence: {
              create: o.evidence.map((e) => ({
                modality: e.modality,
                locator: e.locator,
                raw: e.raw,
                collectedAt: new Date(e.collectedAt),
                collectorVersion: e.collectorVersion,
                location: e.occurrence?.location ?? null,
                line: e.occurrence?.line ?? null,
                offset: e.occurrence?.offset ?? null,
                symbol: e.occurrence?.symbol ?? null,
              })),
            },
          },
        });
      }
    });
  }

  async list(systemName: string | undefined, limit: number): Promise<ScanSummary[]> {
    const rows = await this.prisma.scan.findMany({
      where: systemName === undefined ? {} : { systemName },
      orderBy: { startedAt: 'desc' },
      take: limit,
      // Counted in the database. Selecting an assetId per occurrence of every
      // scan ever recorded, to arrive at two numbers, is the same query at
      // estate scale as loading the estate.
      include: { _count: { select: { occurrences: true, assets: true } } },
    });
    return rows.map((r) => ({
      id: r.id,
      systemName: r.systemName,
      startedAt: r.startedAt.toISOString(),
      policyPackId: r.policyPackId,
      policyPackVersion: r.policyPackVersion,
      occurrenceCount: r._count.occurrences,
      assetCount: r._count.assets,
      detectors: r.detectors,
    }));
  }

  async get(id: string): Promise<StoredScan | null> {
    const row = await this.prisma.scan.findUnique({ where: { id }, include: FULL_SCAN });
    return row === null ? null : hydrate(row);
  }

  async recent(systemName: string, limit: number): Promise<StoredScan[]> {
    const rows = await this.prisma.scan.findMany({
      where: { systemName },
      orderBy: { startedAt: 'desc' },
      take: limit,
      include: FULL_SCAN,
    });
    return rows.map(hydrate);
  }

  async latestPerSystem(): Promise<StoredScan[]> {
    const newest = await this.prisma.scan.findMany({
      distinct: ['systemName'],
      orderBy: [{ systemName: 'asc' }, { startedAt: 'desc' }],
      select: { id: true },
    });
    if (newest.length === 0) return [];
    // One query for the whole estate rather than one per system: fanning the
    // hydration out with Promise.all saturates the connection pool long before
    // it runs out of memory, and every estate route goes through here.
    const rows = await this.prisma.scan.findMany({
      where: { id: { in: newest.map((r) => r.id) } },
      orderBy: { systemName: 'asc' },
      include: FULL_SCAN,
    });
    return rows.map(hydrate);
  }

  async latestSystemNames(): Promise<string[]> {
    const rows = await this.prisma.scan.findMany({
      distinct: ['systemName'],
      orderBy: { systemName: 'asc' },
      select: { systemName: true },
    });
    return rows.map((r) => r.systemName);
  }

  async findToken(secretHash: string): Promise<StoredToken | null> {
    const row = await this.prisma.apiToken.findUnique({ where: { secretHash } });
    return row === null ? null : hydrateToken(row);
  }

  async putToken(token: StoredToken): Promise<void> {
    await this.prisma.apiToken.create({
      data: {
        id: token.id,
        secretHash: token.secretHash,
        name: token.name,
        role: token.role,
        systems: [...token.systems],
        createdAt: new Date(token.createdAt),
        createdBy: token.createdBy,
        lastUsedAt: token.lastUsedAt === null ? null : new Date(token.lastUsedAt),
        expiresAt: token.expiresAt === null ? null : new Date(token.expiresAt),
        revokedAt: token.revokedAt === null ? null : new Date(token.revokedAt),
      },
    });
  }

  async listTokens(): Promise<TokenSummary[]> {
    const rows = await this.prisma.apiToken.findMany({ orderBy: { createdAt: 'asc' } });
    // The hash is dropped here rather than at the route, so no caller can
    // reach it by forgetting to strip it.
    return rows.map((r) => {
      const { secretHash, ...rest } = hydrateToken(r);
      void secretHash;
      return rest;
    });
  }

  async revokeToken(id: string, at: string): Promise<boolean> {
    const { count } = await this.prisma.apiToken.updateMany({
      where: { id, revokedAt: null },
      data: { revokedAt: new Date(at) },
    });
    return count > 0;
  }

  async touchToken(id: string, at: string): Promise<void> {
    await this.prisma.apiToken.updateMany({ where: { id }, data: { lastUsedAt: new Date(at) } });
  }

  async countUsableTokens(now: string): Promise<number> {
    return this.prisma.apiToken.count({
      where: {
        revokedAt: null,
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date(now) } }],
      },
    });
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    await this.prisma.auditEvent.create({
      data: {
        id: event.id,
        at: new Date(event.at),
        tokenId: event.tokenId,
        tokenName: event.tokenName,
        role: event.role,
        method: event.method,
        route: event.route,
        resource: event.resource,
        statusCode: event.statusCode,
        remoteAddr: event.remoteAddr,
      },
    });
  }

  async listAudit(query: AuditQuery): Promise<AuditEvent[]> {
    const rows = await this.prisma.auditEvent.findMany({
      where: {
        ...(query.tokenId === undefined ? {} : { tokenId: query.tokenId }),
        ...(query.since === undefined && query.before === undefined
          ? {}
          : {
              at: {
                ...(query.since === undefined ? {} : { gte: new Date(query.since) }),
                ...(query.before === undefined ? {} : { lt: new Date(query.before) }),
              },
            }),
      },
      orderBy: { at: 'desc' },
      take: query.limit,
    });
    return rows.map((r) => ({
      id: r.id,
      at: r.at.toISOString(),
      tokenId: r.tokenId,
      tokenName: r.tokenName,
      role: r.role,
      method: r.method,
      route: r.route,
      resource: r.resource,
      statusCode: r.statusCode,
      remoteAddr: r.remoteAddr,
    }));
  }

  async putTraces(bundle: StoredTraceBundle): Promise<void> {
    await this.prisma.traceBundle.upsert({
      where: { id: bundle.id },
      create: {
        id: bundle.id,
        source: bundle.source,
        windowFrom: new Date(bundle.windowFrom),
        windowTo: new Date(bundle.windowTo),
        ingestedAt: new Date(bundle.ingestedAt),
        spanCount: bundle.spanCount,
        rootServices: [...bundle.rootServices],
        // Only the edges. The spans were discarded at ingest and there is no
        // column here that could hold them.
        edges: {
          create: bundle.edges.map((e) => ({
            fromService: e.from,
            toService: e.to,
            observations: e.observations,
            operation: e.operation,
          })),
        },
      },
      update: {},
    });
  }

  async listTraces(): Promise<TraceBundleSummary[]> {
    const rows = await this.prisma.traceBundle.findMany({
      orderBy: { ingestedAt: 'desc' },
      include: { _count: { select: { edges: true } } },
    });
    return rows.map((r) => ({
      id: r.id,
      source: r.source,
      windowFrom: r.windowFrom.toISOString(),
      windowTo: r.windowTo.toISOString(),
      ingestedAt: r.ingestedAt.toISOString(),
      spanCount: r.spanCount,
      rootServices: r.rootServices,
      edgeCount: r._count.edges,
    }));
  }

  async getTraces(id: string): Promise<StoredTraceBundle | null> {
    const row = await this.prisma.traceBundle.findUnique({ where: { id }, include: { edges: true } });
    return row === null ? null : hydrateTraces(row);
  }

  async latestTraces(): Promise<StoredTraceBundle | null> {
    const row = await this.prisma.traceBundle.findFirst({
      orderBy: { ingestedAt: 'desc' },
      include: { edges: true },
    });
    return row === null ? null : hydrateTraces(row);
  }

  async close(): Promise<void> {
    await this.prisma.$disconnect();
  }
}

/**
 * Everything a StoredScan is made of. The declared assets are joined
 * separately from the occurrences because the two sets are not the same.
 */
const FULL_SCAN = {
  occurrences: { include: { evidence: true, asset: true } },
  assets: { include: { asset: true } },
} as const;

type AssetRow = {
  id: string;
  primitive: string;
  parameters: unknown;
  purpose: string;
  quantumVulnerable: boolean;
  classicalSecurityBits: number | null;
  nistQuantumSecurityLevel: number | null;
  oid: string | null;
};

type ScanRow = Awaited<ReturnType<PrismaClient['scan']['findUnique']>> & {
  assets: { asset: AssetRow }[];
  occurrences: {
    id: string;
    assetId: string;
    systemId: string;
    systemKey: string;
    controlClass: string;
    reachable: boolean | null;
    reachVia: string | null;
    reachEntryPoint: string | null;
    reachPath: unknown;
    reachFactor: unknown;
    confidenceFactor: unknown;
    asset: AssetRow;
    evidence: {
      modality: string;
      locator: string;
      raw: string;
      collectedAt: Date;
      collectorVersion: string;
      location: string | null;
      line: number | null;
      offset: number | null;
      symbol: string | null;
    }[];
  }[];
};

function asset(a: AssetRow): CryptoAsset {
  return {
    id: a.id,
    primitive: a.primitive as CryptoAsset['primitive'],
    parameters: a.parameters as CryptoAsset['parameters'],
    purpose: a.purpose as CryptoAsset['purpose'],
    quantumVulnerable: a.quantumVulnerable,
    classicalSecurityBits: a.classicalSecurityBits,
    nistQuantumSecurityLevel: a.nistQuantumSecurityLevel,
    oid: a.oid,
  };
}

function hydrate(row: NonNullable<ScanRow>): StoredScan {
  const assets = new Map<string, CryptoAsset>();
  const occurrences: Occurrence[] = [];

  // The declared set first. Scans written before ScanAsset existed have only
  // the assets their occurrences reference, which the loop below still adds.
  for (const link of row.assets) assets.set(link.asset.id, asset(link.asset));

  for (const o of row.occurrences) {
    assets.set(o.asset.id, asset(o.asset));

    occurrences.push({
      // Strip the scan prefix: the caller works with stable work-item ids.
      id: o.id.includes(':') ? (o.id.split(':').slice(1).join(':') as string) : o.id,
      assetId: o.assetId,
      systemId: o.systemKey,
      controlClass: o.controlClass as Occurrence['controlClass'],
      reachability:
        o.reachable === null
          ? null
          : {
              reachable: o.reachable,
              via: (o.reachVia ?? 'NONE') as NonNullable<Occurrence['reachability']>['via'],
              entryPoint: o.reachEntryPoint,
              path: (o.reachPath ?? []) as CallFrame[],
              factor: o.reachFactor as Factor,
            },
      evidence: o.evidence
        .map((e) => ({
          modality: e.modality as Occurrence['evidence'][number]['modality'],
          locator: e.locator,
          raw: e.raw,
          collectedAt: e.collectedAt.toISOString(),
          collectorVersion: e.collectorVersion,
          ...(e.location === null
            ? {}
            : {
                occurrence: {
                  location: e.location,
                  ...(e.line === null ? {} : { line: e.line }),
                  ...(e.offset === null ? {} : { offset: e.offset }),
                  ...(e.symbol === null ? {} : { symbol: e.symbol }),
                },
              }),
        }))
        // Row order out of Postgres is not guaranteed. Sorting on read is what
        // keeps a re-export byte-identical to the original scan.
        .sort((a, b) =>
          a.modality !== b.modality
            ? a.modality.localeCompare(b.modality)
            : a.locator !== b.locator
              ? a.locator.localeCompare(b.locator)
              : a.raw.localeCompare(b.raw),
        ),
      confidence: o.confidenceFactor as Factor,
    });
  }

  return {
    id: row.id,
    systemName: row.systemName,
    startedAt: row.startedAt.toISOString(),
    finishedAt: row.finishedAt?.toISOString() ?? null,
    detectors: row.detectors,
    policyPackId: row.policyPackId,
    policyPackVersion: row.policyPackVersion,
    scopeGrantId: row.scopeGrantId,
    occurrences: occurrences.sort((a, b) => a.id.localeCompare(b.id)),
    assets: [...assets.values()].sort((a, b) => a.id.localeCompare(b.id)),
  };
}

interface TokenRow {
  id: string;
  secretHash: string;
  name: string;
  role: string;
  systems: string[];
  createdAt: Date;
  createdBy: string;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
}

function hydrateToken(row: TokenRow): StoredToken {
  return {
    id: row.id,
    secretHash: row.secretHash,
    name: row.name,
    role: row.role as StoredToken['role'],
    systems: row.systems,
    createdAt: row.createdAt.toISOString(),
    createdBy: row.createdBy,
    lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
    expiresAt: row.expiresAt?.toISOString() ?? null,
    revokedAt: row.revokedAt?.toISOString() ?? null,
  };
}

interface TraceRow {
  id: string;
  source: string;
  windowFrom: Date;
  windowTo: Date;
  ingestedAt: Date;
  spanCount: number;
  rootServices: string[];
  edges: { fromService: string; toService: string; observations: number; operation: string }[];
}

function hydrateTraces(row: TraceRow): StoredTraceBundle {
  return {
    id: row.id,
    source: row.source,
    windowFrom: row.windowFrom.toISOString(),
    windowTo: row.windowTo.toISOString(),
    ingestedAt: row.ingestedAt.toISOString(),
    spanCount: row.spanCount,
    rootServices: row.rootServices,
    edges: row.edges
      .map((e) => ({
        from: e.fromService,
        to: e.toService,
        observations: e.observations,
        operation: e.operation,
      }))
      .sort((a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to)),
  };
}

export { summarize };
