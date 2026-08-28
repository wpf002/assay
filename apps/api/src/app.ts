import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import Fastify, { type FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  diffScans,
  explain,
  blockers,
  citations,
  derivationDepth,
  gate,
  rank,
  toCycloneDX,
  divergencesOf,
  type CryptoAsset,
  type ExportProfile,
  type Occurrence,
  type Worklists,
} from './deps.js';
import { IngestSchema, summarize, type ScanStore, type StoredScan } from './store/types.js';
import { DEFAULT_PACK_ID, decimalYear, listPacks, loadPack } from '@assay/policy';

/**
 * The API exists to make the derivation clickable.
 *
 * Two design choices carry most of the weight:
 *
 * - Ranking is computed ON READ, from stored evidence, with the policy pack as
 *   a query parameter. That is what makes the pack switcher a live control
 *   rather than a re-scan: the evidence does not change when the deadline
 *   does, only the arithmetic over it. Storing a ranked worklist would freeze
 *   an answer whose inputs are explicitly versioned data (I4).
 * - Confidence is NOT recomputed on read. It is stored verbatim and returned
 *   verbatim, because the claim is that the same evidence yields the same
 *   answer everywhere, and a second implementation is a second chance to
 *   disagree with the CLI.
 */

export interface AppOptions {
  readonly store: ScanStore;
  readonly logger?: boolean;
}

const RankQuery = z.object({
  pack: z.string().default(DEFAULT_PACK_ID),
  secrecyYears: z.coerce.number().min(0).max(100).default(5),
  now: z.string().datetime().optional(),
  track: z.enum(['CONFIDENTIALITY', 'AUTHENTICITY']).optional(),
});

export async function buildApp(opts: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: opts.logger ?? false });
  const store = opts.store;

  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, { origin: true });

  app.get('/health', async () => ({ ok: true, store: store.kind }));

  app.get('/policy-packs', async () =>
    listPacks().map((id) => {
      const p = loadPack(id);
      return {
        packId: p.packId,
        packVersion: p.packVersion,
        title: p.title ?? p.packId,
        crqcYear: p.crqcYear,
        regulatoryDeadlines: p.regulatoryDeadlines,
        regulatoryAuthority: p.regulatoryAuthority,
        migrationYearsByControl: p.migrationYearsByControl,
        // Shipped figures are inputs, not truth claims, and the UI says so.
        caveats: p.caveats,
        sources: p.sources,
      };
    }),
  );

  app.post('/scans', async (request, reply) => {
    const parsed = IngestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: 'invalid scan', issues: parsed.error.issues });
    }
    const body = parsed.data;
    const scan: StoredScan = {
      id: scanId(body.systemName, body.startedAt),
      systemName: body.systemName,
      startedAt: body.startedAt,
      finishedAt: body.finishedAt,
      detectors: body.detectors,
      policyPackId: body.policyPackId,
      policyPackVersion: body.policyPackVersion,
      scopeGrantId: body.scopeGrantId,
      occurrences: body.occurrences as Occurrence[],
      assets: body.assets as CryptoAsset[],
    };
    await store.put(scan);
    return reply.code(201).send(summarize(scan));
  });

  app.get('/scans', async (request) => {
    const q = z.object({ system: z.string().optional() }).parse(request.query);
    return store.list(q.system);
  });

  app.get('/scans/:id', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    return { ...summarize(scan), assets: scan.assets, occurrenceIds: scan.occurrences.map((o) => o.id) };
  });

  /** The two worklists, ranked live under whichever pack was asked for. */
  app.get('/scans/:id/worklists', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    const q = RankQuery.parse(request.query);
    const worklists = rankScan(scan, q);
    if (q.track === undefined) return worklists;
    return q.track === 'CONFIDENTIALITY'
      ? { ...worklists, authenticity: [] }
      : { ...worklists, confidentiality: [] };
  });

  /**
   * Re-rank under a different pack and report which rows moved.
   *
   * This is the answer to "whose deadline are we using". Changing the pack
   * changes the arithmetic and nothing else, so every difference here is
   * attributable to policy rather than to the estate.
   */
  app.get('/scans/:id/rerank', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    const q = z
      .object({
        from: z.string().default(DEFAULT_PACK_ID),
        to: z.string(),
        secrecyYears: z.coerce.number().default(5),
        now: z.string().datetime().optional(),
      })
      .parse(request.query);

    const before = rankScan(scan, { ...q, pack: q.from });
    const after = rankScan(scan, { ...q, pack: q.to });
    return {
      from: q.from,
      to: q.to,
      headline: { before: before.headline, after: after.headline },
      moved: movedRows(before, after),
    };
  });

  /** Everything needed to walk one finding to raw evidence. */
  app.get('/scans/:id/occurrences/:occId', async (request, reply) => {
    const params = request.params as { id: string; occId: string };
    const scan = await store.get(params.id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    const occurrence = scan.occurrences.find((o) => o.id === params.occId);
    if (occurrence === undefined) return reply.code(404).send({ error: 'no such occurrence' });

    const q = RankQuery.parse(request.query);
    const asset = scan.assets.find((a) => a.id === occurrence.assetId) ?? null;
    const ranked = rankScan(scan, q);
    const row = [...ranked.confidentiality, ...ranked.authenticity, ...ranked.unreached, ...ranked.hints]
      .find((f) => f.occurrenceId === occurrence.id);
    const g = gate(occurrence);

    return {
      occurrence: { ...occurrence, confidence: Number(occurrence.confidence.value) },
      asset,
      assertionLevel: g.assertionLevel,
      downgradeReason: g.downgradeReason,
      blockedBy: blockers(occurrence.confidence),
      evidence: occurrence.evidence,
      derivations: {
        confidence: {
          tree: explain(occurrence.confidence, 'confidence'),
          depth: derivationDepth(occurrence.confidence),
          citations: citations(occurrence.confidence).length,
        },
        mosca:
          row === undefined
            ? null
            : {
                tree: explain(row.mosca.factor, 'mosca'),
                depth: derivationDepth(row.mosca.factor),
                bindingConstraint: row.bindingConstraint,
              },
        reachability:
          occurrence.reachability === null
            ? null
            : {
                tree: explain(occurrence.reachability.factor, 'reachability'),
                via: occurrence.reachability.via,
                entryPoint: occurrence.reachability.entryPoint,
                path: occurrence.reachability.path,
              },
      },
    };
  });

  app.get('/scans/:id/cbom', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    const q = z
      .object({
        profile: z.enum(['cyclonedx-1.7', 'cyclonedx-1.6', 'cisa-min-elements']).default('cyclonedx-1.7'),
        includeSuspected: z.coerce.boolean().default(false),
        factors: z.coerce.boolean().default(false),
      })
      .parse(request.query);

    return toCycloneDX(scan.occurrences, scan.assets, {
      profile: q.profile as ExportProfile,
      policyPackId: scan.policyPackId,
      policyPackVersion: scan.policyPackVersion,
      // The scan's own timestamp, not the request's: a CBOM re-exported
      // tomorrow must be byte-identical to the one exported today.
      timestamp: scan.startedAt,
      toolVersion: '0.1.0',
      includeSuspected: q.includeSuspected,
      includeFactorTrees: q.factors,
    });
  });

  app.get('/scans/:id/diff', async (request, reply) => {
    const params = request.params as { id: string };
    const current = await store.get(params.id);
    if (current === null) return reply.code(404).send({ error: 'no such scan' });
    const q = z.object({ from: z.string().optional() }).parse(request.query);

    let previous: StoredScan | null;
    if (q.from !== undefined) {
      previous = await store.get(q.from);
    } else {
      const recent = await store.recent(current.systemName, 10);
      previous = recent.find((s) => s.startedAt < current.startedAt) ?? null;
    }
    if (previous === null) {
      return reply.code(404).send({ error: 'no earlier scan of this system to diff against' });
    }
    return diffScans(toSnapshot(previous), toSnapshot(current));
  });

  app.get('/scans/:id/divergences', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    return divergencesOf(scan.occurrences, scan.assets);
  });

  /**
   * Ticket payloads. A worklist that cannot leave the tool does not get
   * worked, and every competitor ships this for exactly that reason.
   */
  app.get('/scans/:id/export/tickets', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    const q = RankQuery.extend({ limit: z.coerce.number().min(1).max(200).default(25) }).parse(
      request.query,
    );
    const ranked = rankScan(scan, q);

    return [...ranked.confidentiality, ...ranked.authenticity]
      .filter((f) => f.assertionLevel === 'CONFIRMED')
      .slice(0, q.limit)
      .map((f) => ({
        summary: `Migrate ${f.assetName} in ${f.systemId} (${f.track.toLowerCase()}, ${
          f.late ? 'overdue' : `${f.slackYears.toFixed(1)}y slack`
        })`,
        // No priority field. Slack is the priority, and it carries its
        // derivation; a P1/P2 label would be the heuristic severity score this
        // project exists to avoid.
        labels: ['pqc', `track:${f.track.toLowerCase()}`, `control:${f.controlClass.toLowerCase()}`],
        fields: {
          system: f.systemId,
          asset: f.assetName,
          purpose: f.purpose,
          controlClass: f.controlClass,
          slackYears: f.slackYears,
          bindingConstraint: f.bindingConstraint,
          reachedVia: f.reachedVia,
          assertionLevel: f.assertionLevel,
          confidence: f.confidence,
          policyPack: `${ranked.policyPackId}@${ranked.policyPackVersion}`,
        },
        description: describe(f, scan),
      }));
  });

  return app;
}

/* -------------------------------------------------------------------- utils */

function rankScan(scan: StoredScan, q: z.infer<typeof RankQuery>): Worklists {
  const pack = loadPack(q.pack);
  const now = q.now === undefined ? new Date(scan.startedAt) : new Date(q.now);
  return rank(scan.occurrences, scan.assets, {
    policy: pack,
    currentYear: decimalYear(now),
    secrecyLifetime: () => ({ years: q.secrecyYears, assumed: true }),
  });
}

function toSnapshot(scan: StoredScan) {
  return {
    scanId: scan.id,
    takenAt: scan.startedAt,
    policyPackId: scan.policyPackId,
    policyPackVersion: scan.policyPackVersion,
    occurrences: scan.occurrences,
    assets: scan.assets,
  };
}

function movedRows(before: Worklists, after: Worklists) {
  const index = (w: Worklists) =>
    new Map([...w.confidentiality, ...w.authenticity].map((f) => [f.occurrenceId, f]));
  const b = index(before);
  const a = index(after);
  const moved: unknown[] = [];

  for (const [id, rowAfter] of a) {
    const rowBefore = b.get(id);
    if (rowBefore === undefined) continue;
    if (
      rowBefore.slackYears === rowAfter.slackYears &&
      rowBefore.bindingConstraint === rowAfter.bindingConstraint
    ) {
      continue;
    }
    moved.push({
      occurrenceId: id,
      assetName: rowAfter.assetName,
      systemId: rowAfter.systemId,
      slackYears: { before: rowBefore.slackYears, after: rowAfter.slackYears },
      bindingConstraint: { before: rowBefore.bindingConstraint, after: rowAfter.bindingConstraint },
      late: { before: rowBefore.late, after: rowAfter.late },
    });
  }
  return moved;
}

function describe(f: Worklists['confidentiality'][number], scan: StoredScan): string {
  const o = scan.occurrences.find((x) => x.id === f.occurrenceId);
  const lines = [
    `${f.assetName} is used for ${f.purpose} in ${f.systemId}.`,
    '',
    `Urgency track: ${f.track}. Binding constraint: ${f.bindingConstraint}. Slack: ${f.slackYears} years.`,
    `Control class ${f.controlClass} implies ${f.mosca.y} years to migrate.`,
    `Reachability: ${f.reachedVia}.`,
    `Assertion: ${f.assertionLevel} at confidence ${f.confidence}.`,
    '',
    'Evidence:',
    ...(o?.evidence ?? []).slice(0, 20).map((e) => `  - [${e.modality}] ${e.locator}`),
  ];
  if ((o?.evidence.length ?? 0) > 20) lines.push(`  ... and ${(o?.evidence.length ?? 0) - 20} more`);
  return lines.join('\n');
}

function scanId(systemName: string, startedAt: string): string {
  const slug = systemName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  return `${slug}-${startedAt.replace(/[-:.TZ]/g, '').slice(0, 14)}`;
}
