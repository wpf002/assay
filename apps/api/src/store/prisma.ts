import { Prisma, PrismaClient } from '@prisma/client';
import { gate, type CallFrame, type CryptoAsset, type Factor, type Occurrence } from '@assay/core';
import {
  summarize,
  type ScanStore,
  type ScanSummary,
  type StoredScan,
  type StoredTraceBundle,
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
    return new PrismaScanStore(new PrismaClient({ datasources: { db: { url } } }));
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

      for (const o of scan.occurrences) {
        const g = gate(o);
        await tx.occurrence.create({
          data: {
            // Scoped to the scan so two scans can hold the same work item.
            id: `${scan.id}:${o.id}`,
            assetId: o.assetId,
            systemId: system.id,
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

  async list(systemName?: string): Promise<ScanSummary[]> {
    const rows = await this.prisma.scan.findMany({
      where: systemName === undefined ? {} : { systemName },
      orderBy: { startedAt: 'desc' },
      include: {
        _count: { select: { occurrences: true } },
        // Distinct assets per scan, without loading every occurrence.
        occurrences: { select: { assetId: true }, distinct: ['assetId'] },
      },
    });
    return rows.map((r) => ({
      id: r.id,
      systemName: r.systemName,
      startedAt: r.startedAt.toISOString(),
      policyPackId: r.policyPackId,
      policyPackVersion: r.policyPackVersion,
      occurrenceCount: r._count.occurrences,
      assetCount: r.occurrences.length,
      detectors: r.detectors,
    }));
  }

  async get(id: string): Promise<StoredScan | null> {
    const row = await this.prisma.scan.findUnique({
      where: { id },
      include: { occurrences: { include: { evidence: true, asset: true } } },
    });
    return row === null ? null : hydrate(row);
  }

  async recent(systemName: string, limit: number): Promise<StoredScan[]> {
    const rows = await this.prisma.scan.findMany({
      where: { systemName },
      orderBy: { startedAt: 'desc' },
      take: limit,
      include: { occurrences: { include: { evidence: true, asset: true } } },
    });
    return rows.map(hydrate);
  }

  async latestPerSystem(): Promise<StoredScan[]> {
    const newest = await this.prisma.scan.findMany({
      distinct: ['systemName'],
      orderBy: [{ systemName: 'asc' }, { startedAt: 'desc' }],
      select: { id: true },
    });
    const scans = await Promise.all(newest.map((r) => this.get(r.id)));
    return scans.filter((s): s is StoredScan => s !== null);
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

  async listTraces(): Promise<Omit<StoredTraceBundle, 'edges'>[]> {
    const rows = await this.prisma.traceBundle.findMany({ orderBy: { ingestedAt: 'desc' } });
    return rows.map((r) => ({
      id: r.id,
      source: r.source,
      windowFrom: r.windowFrom.toISOString(),
      windowTo: r.windowTo.toISOString(),
      ingestedAt: r.ingestedAt.toISOString(),
      spanCount: r.spanCount,
      rootServices: r.rootServices,
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

type ScanRow = Awaited<ReturnType<PrismaClient['scan']['findUnique']>> & {
  occurrences: {
    id: string;
    assetId: string;
    systemId: string;
    controlClass: string;
    reachable: boolean | null;
    reachVia: string | null;
    reachEntryPoint: string | null;
    reachPath: unknown;
    reachFactor: unknown;
    confidenceFactor: unknown;
    asset: {
      id: string;
      primitive: string;
      parameters: unknown;
      purpose: string;
      quantumVulnerable: boolean;
      classicalSecurityBits: number | null;
      nistQuantumSecurityLevel: number | null;
      oid: string | null;
    };
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

function hydrate(row: NonNullable<ScanRow>): StoredScan {
  const assets = new Map<string, CryptoAsset>();
  const occurrences: Occurrence[] = [];

  for (const o of row.occurrences) {
    assets.set(o.asset.id, {
      id: o.asset.id,
      primitive: o.asset.primitive as CryptoAsset['primitive'],
      parameters: o.asset.parameters as CryptoAsset['parameters'],
      purpose: o.asset.purpose as CryptoAsset['purpose'],
      quantumVulnerable: o.asset.quantumVulnerable,
      classicalSecurityBits: o.asset.classicalSecurityBits,
      nistQuantumSecurityLevel: o.asset.nistQuantumSecurityLevel,
      oid: o.asset.oid,
    });

    occurrences.push({
      // Strip the scan prefix: the caller works with stable work-item ids.
      id: o.id.includes(':') ? (o.id.split(':').slice(1).join(':') as string) : o.id,
      assetId: o.assetId,
      systemId: row.systemName,
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
