import { createHash, randomUUID } from 'node:crypto';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import Fastify, { type FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  SpanRecordSchema,
  TraceBundleSchema,
  applyTraceReachability,
  buildServiceGraph,
  spansFromOtlp,
  traceRoots,
  computeConfidenceBreakdown,
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
  type Factor,
  type Occurrence,
  type Reachability,
  type Worklists,
} from './deps.js';
import {
  AuthError,
  assertMayWrite,
  assertUnscoped,
  assertVisible,
  authenticate,
  mintToken,
  requireRole,
  visibleTo,
  type Principal,
  type Role,
} from './auth.js';
import {
  IngestSchema,
  summarize,
  type ScanStore,
  type StoredScan,
  type StoredTraceBundle,
  type StoredToken,
} from './store/types.js';
import type { ServiceGraph, SpanRecord } from './deps.js';
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
  /** Supplied so token expiry and audit timestamps are testable. */
  readonly clock?: () => Date;
}

/**
 * Mint the first admin token.
 *
 * Called at startup when the token table is empty, and by tests. The secret is
 * returned once and never recoverable; an operator who loses it mints another
 * and revokes this one.
 */
export async function bootstrapAdminToken(
  store: ScanStore,
  name = 'bootstrap',
  now = new Date(),
): Promise<{ token: string; id: string }> {
  const minted = mintToken();
  await store.putToken({
    id: minted.id,
    secretHash: minted.secretHash,
    name,
    role: 'admin',
    systems: [],
    createdAt: now.toISOString(),
    createdBy: 'bootstrap',
    lastUsedAt: null,
    expiresAt: null,
    revokedAt: null,
  });
  return { token: minted.secret, id: minted.id };
}

/** Routes reachable without a token. Deliberately a closed list. */
const PUBLIC_ROUTES = new Set(['/health']);

declare module 'fastify' {
  interface FastifyRequest {
    principal?: Principal;
  }
}

/**
 * An unknown pack id is bad input, not a server fault. `loadPack` throws a
 * bare Error, which Fastify has no choice but to report as a 500, so the id is
 * checked here where it can be a 400 naming the same packs loadPack would.
 */
const PackId = z.string().refine(
  (id) => listPacks().includes(id),
  (id) => ({ message: `unknown policy pack "${id}". available: ${listPacks().join(', ')}` }),
);

/**
 * X, the operator-supplied secrecy lifetime.
 *
 * An empty query value is a missing value, not zero. `Number('')` is 0 and
 * passes `min(0)`, so `?secrecyYears=` silently replaced the documented
 * default with an assertion that nothing this system protects needs to stay
 * secret for a single year - and it flips the binding constraint.
 */
const SecrecyYears = z.preprocess(
  (v) => (v === '' ? undefined : v),
  z.coerce.number().min(0).max(100).default(5),
);

/**
 * A boolean query flag.
 *
 * `z.coerce.boolean()` is `Boolean(value)`, and every non-empty query string
 * is truthy - including "false". A caller who asks a CBOM to exclude SUSPECTED
 * findings has to actually get a CBOM without them.
 */
const QueryFlag = z
  .enum(['true', 'false', '1', '0', ''])
  .transform((v) => v === 'true' || v === '1')
  .default('false');

const RankQuery = z.object({
  pack: PackId.default(DEFAULT_PACK_ID),
  secrecyYears: SecrecyYears,
  now: z.string().datetime().optional(),
  track: z.enum(['CONFIDENTIALITY', 'AUTHENTICITY']).optional(),
});

/** The estate is ranked against a trace bundle; the default is the newest one. */
const EstateQuery = RankQuery.extend({ traces: z.string().default('latest') });

export async function buildApp(opts: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: opts.logger ?? false });
  const store = opts.store;

  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, { origin: true });

  /**
   * A rejected query is the caller's fault, not ours.
   *
   * A ZodError carries no statusCode, so Fastify's default handler reports
   * every malformed query parameter as a 500: it pages whoever is on call, it
   * pollutes the error budget, and it tells the caller to retry a request that
   * can never succeed. The POST routes already answer 400 by hand; this is the
   * same contract for the routes that parse with `.parse`.
   */
  /**
   * OUT_OF_SCOPE says nothing about itself.
   *
   * The status was changed to 404 so a scoped token could not tell "not yours"
   * from "not there" - and then the body handed back `reason: "OUT_OF_SCOPE"`,
   * which is the same oracle one field lower. The reason code is genuinely
   * useful for every other failure, so it survives everywhere else.
   */
  function authBody(e: AuthError): { error: string; reason?: string } {
    return e.reason === 'OUT_OF_SCOPE'
      ? { error: e.message }
      : { error: e.message, reason: e.reason };
  }

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof AuthError) {
      return reply.code(error.statusCode).send(authBody(error));
    }
    if (error instanceof z.ZodError) {
      return reply.code(400).send({ error: 'invalid query', issues: error.issues });
    }
    return reply.send(error);
  });

  const clock = opts.clock ?? (() => new Date());

  /**
   * Authentication runs before every handler, and the allow-list is the only
   * way past it. A route added tomorrow is protected by default rather than
   * open by default, which is the failure mode this whole phase exists to fix.
   */
  app.addHook('onRequest', async (request, reply) => {
    if (PUBLIC_ROUTES.has(request.url.split('?')[0] ?? '')) return;
    try {
      const principal = await authenticate(store, request.headers.authorization, { now: clock() });
      request.principal = principal;
      // Fire-and-forget: a slow write here would sit in front of every request,
      // and last-used is a convenience, not the audit trail.
      void store.touchToken(principal.tokenId, clock().toISOString()).catch(() => undefined);
    } catch (e) {
      if (!(e instanceof AuthError)) throw e;
      await reply.code(e.statusCode).send(authBody(e));
    }
  });

  /**
   * Who read what. Written for reads as much as writes - exfiltrating an
   * inventory is a read, and "we do not keep that" is not an answer to the
   * customer's auditor.
   */
  app.addHook('onResponse', async (request, reply) => {
    if (PUBLIC_ROUTES.has(request.url.split('?')[0] ?? '')) return;
    const p = request.principal;
    await store
      .appendAudit({
        // request.id is a per-process counter that restarts at 1, so pairing
        // it with a timestamp collided across restarts and dropped rows.
        id: randomUUID(),
        at: clock().toISOString(),
        tokenId: p?.tokenId ?? null,
        tokenName: p?.name ?? '(unauthenticated)',
        role: p?.role ?? '-',
        method: request.method,
        route: request.routeOptions.url ?? request.url,
        resource: resourceOf(request.params),
        statusCode: reply.statusCode,
        remoteAddr: request.ip,
      })
      .catch((e: unknown) => {
        // The audit trail is the thing a customer's own auditor asks for.
        // Losing a row silently means the answer to "who read this" is quietly
        // wrong rather than visibly broken.
        request.log.error({ err: e, route: request.routeOptions.url }, 'audit write failed');
      });
  });

  app.get('/health', async () => ({ ok: true, store: store.kind }));

  /* ------------------------------------------------------------------ tokens */

  app.post('/tokens', async (request, reply) => {
    const principal = must(request);
    requireRole(principal, 'admin');
    const body = z
      .object({
        name: z.string().min(1),
        role: z.enum(['admin', 'operator', 'viewer']),
        systems: z.array(z.string()).default([]),
        // Normalized to the same canonical UTC form the stores use, so that
        // an offset-bearing timestamp does not compare as a different instant
        // in memory than it does after a round-trip through Postgres.
        expiresAt: z
          .string()
          .datetime()
          .transform((v) => new Date(v).toISOString())
          .nullable()
          .default(null),
      })
      .safeParse(request.body);
    if (!body.success) {
      return reply.code(400).send({ error: 'invalid token request', issues: body.error.issues });
    }

    const minted = mintToken();
    const record: StoredToken = {
      id: minted.id,
      secretHash: minted.secretHash,
      name: body.data.name,
      role: body.data.role as Role,
      systems: body.data.systems,
      createdAt: clock().toISOString(),
      createdBy: principal.name,
      lastUsedAt: null,
      expiresAt: body.data.expiresAt,
      revokedAt: null,
    };
    await store.putToken(record);

    // The only time the secret exists outside the caller's memory.
    return reply.code(201).send({
      id: record.id,
      token: minted.secret,
      name: record.name,
      role: record.role,
      systems: record.systems,
      expiresAt: record.expiresAt,
      note: 'this secret is shown once and is not recoverable',
    });
  });

  app.get('/tokens', async (request) => {
    requireRole(must(request), 'admin');
    return store.listTokens();
  });

  app.delete('/tokens/:id', async (request, reply) => {
    requireRole(must(request), 'admin');
    const { id } = request.params as { id: string };
    const revoked = await store.revokeToken(id, clock().toISOString());
    return revoked
      ? reply.code(204).send()
      : reply.code(404).send({ error: 'no such active token' });
  });

  app.get('/audit', async (request) => {
    requireRole(must(request), 'admin');
    const q = z
      .object({
        limit: z.coerce.number().min(1).max(1000).default(100),
        // `before` pages backwards through the trail; without it the answer to
        // "who exported this in March" was unreachable past the newest 1000.
        before: z.string().datetime().optional(),
        since: z.string().datetime().optional(),
        tokenId: z.string().optional(),
      })
      .parse(request.query);
    return store.listAudit(q);
  });

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
        // D3: a horizon nobody signed still ranks, and the UI says so.
        trust: p.trust,
        trustReason: p.trustReason,
        // Shipped figures are inputs, not truth claims, and the UI says so.
        caveats: p.caveats,
        sources: p.sources,
      };
    }),
  );

  app.post('/scans', async (request, reply) => {
    const principal = must(request);
    requireRole(principal, 'operator');
    const parsed = IngestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: 'invalid scan', issues: parsed.error.issues });
    }
    const body = parsed.data;
    assertMayWrite(principal, body.systemName);
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
    const principal = must(request);
    const q = z
      .object({
        system: z.string().optional(),
        limit: z.coerce.number().min(1).max(500).default(100),
      })
      .parse(request.query);
    const scans = await store.list(q.system, q.limit);
    return scans.filter((s) => visibleTo(principal, s.systemName));
  });

  app.get('/scans/:id', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    assertVisible(must(request), scan.systemName);
    return { ...summarize(scan), assets: scan.assets, occurrenceIds: scan.occurrences.map((o) => o.id) };
  });

  /** The two worklists, ranked live under whichever pack was asked for. */
  app.get('/scans/:id/worklists', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    assertVisible(must(request), scan.systemName);
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
    assertVisible(must(request), scan.systemName);
    // Derived from RankQuery rather than redeclared, so the one endpoint whose
    // job is attributing differences to policy cannot be handed an X the rest
    // of the API rejects.
    const q = RankQuery.omit({ pack: true, track: true })
      .extend({ from: PackId.default(DEFAULT_PACK_ID), to: PackId })
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
    assertVisible(must(request), scan.systemName);
    const occurrence = scan.occurrences.find((o) => o.id === params.occId);
    if (occurrence === undefined) return reply.code(404).send({ error: 'no such occurrence' });

    const q = RankQuery.parse(request.query);
    return derivation(occurrence, scan.assets, rankScan(scan, q), q.pack, must(request));
  });

  /**
   * The same drill-down, addressed estate-wide.
   *
   * The estate view has no single scan to query - it is the newest scan of
   * every system merged - so a row opened there had nowhere to send its
   * request. Occurrence ids are stable content hashes, so the lookup is just
   * "find it across the current estate".
   *
   * It ranks the whole estate, exactly as /estate/worklists does, rather than
   * ranking the owning scan alone. Those are two different sums: the estate
   * clock is the newest scan of any system, not this scan's own start, and
   * reachability here is the trace-correlated one. Ranking the owner by itself
   * is how a row could read "overdue by five years" in the list and "eleven
   * years of margin" when it was clicked.
   */
  app.get('/estate/occurrences/:occId', async (request, reply) => {
    const { occId } = request.params as { occId: string };
    const principal = must(request);
    const q = EstateQuery.parse(request.query);
    const scans = (await store.latestPerSystem()).filter((s) => visibleTo(principal, s.systemName));
    if (scans.length === 0) {
      return reply.code(404).send({ error: 'no such occurrence in the estate' });
    }
    const bundle = await resolveTraces(store, q.traces);
    if (bundle === null && q.traces !== 'latest') {
      return reply.code(404).send({ error: 'no such trace bundle' });
    }

    const estate = rankEstate(scans, bundle, q);
    const occurrence = estate.occurrences.find((o) => o.id === occId);
    if (occurrence === undefined) {
      return reply.code(404).send({ error: 'no such occurrence in the estate' });
    }
    return derivation(occurrence, estate.assets, estate.worklists, q.pack, principal);
  });

  app.get('/scans/:id/cbom', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    assertVisible(must(request), scan.systemName);
    const q = z
      .object({
        profile: z.enum(['cyclonedx-1.7', 'cyclonedx-1.6', 'cisa-min-elements']).default('cyclonedx-1.7'),
        includeSuspected: QueryFlag,
        factors: QueryFlag,
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
    assertVisible(must(request), current.systemName);
    const q = z.object({ from: z.string().optional() }).parse(request.query);

    let previous: StoredScan | null;
    if (q.from !== undefined) {
      previous = await store.get(q.from);
      // Scope first. "That scan is of a different system" is a true statement
      // about a scan the caller is not allowed to know exists.
      if (previous !== null) assertVisible(must(request), previous.systemName);
      // Occurrence ids are content hashes of (system, asset, control class),
      // so two systems share none of them and the diff degenerates into every
      // row appearing and every row disappearing - a changelog of nothing,
      // presented as a regression report. The default branch is scoped to the
      // system and ordered by construction; an explicit `from` has to be too.
      if (previous !== null && previous.systemName !== current.systemName) {
        return reply.code(400).send({ error: 'that scan is of a different system' });
      }
      if (previous !== null && previous.startedAt >= current.startedAt) {
        return reply.code(400).send({ error: 'that scan is not earlier than this one' });
      }
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
    assertVisible(must(request), scan.systemName);
    return divergencesOf(scan.occurrences, scan.assets);
  });

  /**
   * Ticket payloads. A worklist that cannot leave the tool does not get
   * worked, and every competitor ships this for exactly that reason.
   */
  app.get('/scans/:id/export/tickets', async (request, reply) => {
    const scan = await store.get((request.params as { id: string }).id);
    if (scan === null) return reply.code(404).send({ error: 'no such scan' });
    assertVisible(must(request), scan.systemName);
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

  /* ------------------------------------------------------------------ traces */

  /**
   * Ingest a trace export and keep only the service graph.
   *
   * Accepts OTLP JSON or a normalized bundle, because no two tracing backends
   * agree on an export format and requiring one turns a five-minute
   * copy-paste into a quarter-long integration.
   */
  app.post('/traces', async (request, reply) => {
    const principal = must(request);
    requireRole(principal, 'operator');
    assertUnscoped(principal, 'uploading traces');
    const body = request.body;
    let spans: SpanRecord[];
    let from = 'unstated';
    let to = 'unstated';
    let source = 'upload';

    const bundle = TraceBundleSchema.safeParse(body);
    if (bundle.success) {
      spans = bundle.data.spans;
      from = bundle.data.from;
      to = bundle.data.to;
      source = bundle.data.source === '' ? 'upload' : bundle.data.source;
    } else {
      try {
        spans = spansFromOtlp(body).map((s) => SpanRecordSchema.parse(s));
      } catch (e) {
        return reply.code(400).send({
          error: 'not a trace bundle or an OTLP export',
          detail: e instanceof Error ? e.message : String(e),
        });
      }
    }
    if (spans.length === 0) {
      return reply.code(400).send({ error: 'no spans with a service name' });
    }

    const graph = buildServiceGraph({ from, to, source, spans });
    const derived: Omit<StoredTraceBundle, 'id'> = {
      source,
      // A window is needed to store the bundle; "unstated" is preserved in the
      // source string rather than silently becoming now().
      windowFrom: isoOr(from, request),
      windowTo: isoOr(to, request),
      ingestedAt: new Date().toISOString(),
      spanCount: spans.length,
      rootServices: traceRoots(graph, spans),
      edges: graph.edges.map((e) => ({
        from: e.from,
        to: e.to,
        observations: e.observations,
        operation: e.operation,
      })),
    };
    const stored: StoredTraceBundle = { id: traceId(from, derived), ...derived };
    await store.putTraces(stored);

    return reply.code(201).send({
      id: stored.id,
      spansIngested: stored.spanCount,
      // Said out loud in the response: the spans are gone.
      spansStored: 0,
      edges: stored.edges.length,
      services: [...graph.services].sort(),
      rootServices: stored.rootServices,
      note: 'spans were discarded after deriving the service graph; only edges are persisted',
    });
  });

  // A trace bundle names every service in the estate, including ones a scoped
  // token cannot otherwise see, so it is not viewer-readable.
  app.get('/traces', async (request) => {
    // A bundle is a list of every service in the estate and who calls whom.
    // Role alone was not enough: a scoped operator could read the whole graph.
    const principal = must(request);
    requireRole(principal, 'operator');
    assertUnscoped(principal, 'the trace inventory');
    return store.listTraces();
  });

  app.get('/traces/:id', async (request, reply) => {
    const principal = must(request);
    requireRole(principal, 'operator');
    assertUnscoped(principal, 'a trace bundle');
    const bundle = await store.getTraces((request.params as { id: string }).id);
    return bundle === null ? reply.code(404).send({ error: 'no such trace bundle' }) : bundle;
  });

  /* ------------------------------------------------------------------ estate */

  /**
   * Every system at once, ranked together, with cross-service reachability.
   *
   * This is the form that matters. A signing service scanned on its own looks
   * like a library nobody calls; the same scan correlated against traces of
   * the estate shows the RSA key that every payment depends on.
   */
  app.get('/estate/worklists', async (request, reply) => {
    const principal = must(request);
    const q = EstateQuery.parse(request.query);
    const scans = (await store.latestPerSystem()).filter((s) => visibleTo(principal, s.systemName));
    if (scans.length === 0) return reply.code(404).send({ error: 'no scans' });

    const bundle = await resolveTraces(store, q.traces);
    // An id that resolves to nothing is a typo or a bundle that has been
    // replaced, and answering it with the un-correlated estate says the
    // signing service is a library nobody calls - the exact reading this
    // endpoint exists to prevent. `latest` against a store with no traces is
    // the one honest null: nothing was uploaded to correlate against.
    if (bundle === null && q.traces !== 'latest') {
      return reply.code(404).send({ error: 'no such trace bundle' });
    }
    const estate = rankEstate(scans, bundle, q);

    return {
      systems: scans.map((s) => ({ systemName: s.systemName, scanId: s.id, startedAt: s.startedAt })),
      traces:
        bundle === null
          ? null
          : {
              id: bundle.id,
              source: bundle.source,
              window: { from: bundle.windowFrom, to: bundle.windowTo },
              edges: bundle.edges.length,
              // The root list is drawn from the whole estate, so a scoped
              // token would otherwise read service names it cannot see.
              rootServices: bundle.rootServices.filter((name) => visibleTo(principal, name)),
            },
      promotedBySystem: bundle === null ? [] : promotedSystems(estate.merged, estate.occurrences),
      worklists: estate.worklists,
    };
  });

  /**
   * Which services the traces show, and which of them have never been scanned.
   *
   * The blind-spot list. A service that calls you and has no CBOM is a hole in
   * the inventory that no amount of scanning your own repositories will close.
   */
  app.get('/estate/coverage', async (request, reply) => {
    // Derived entirely from a trace bundle, which names every service in the
    // estate. Gating /traces and leaving this open re-served exactly the data
    // that gate withholds.
    const principal = must(request);
    requireRole(principal, 'operator');
    assertUnscoped(principal, 'the coverage report');
    const q = z.object({ traces: z.string().default('latest') }).parse(request.query);
    const bundle = await resolveTraces(store, q.traces);
    if (bundle === null) return reply.code(404).send({ error: 'no trace bundle' });

    const scanned = new Set(await store.latestSystemNames());
    const services = new Set<string>();
    for (const e of bundle.edges) {
      services.add(e.from);
      services.add(e.to);
    }
    for (const r of bundle.rootServices) services.add(r);

    const unscanned = [...services].filter((s) => !scanned.has(s)).sort();
    return {
      tracesId: bundle.id,
      window: { from: bundle.windowFrom, to: bundle.windowTo },
      servicesObserved: [...services].sort(),
      scanned: [...services].filter((s) => scanned.has(s)).sort(),
      unscanned,
      scannedWithoutTraffic: [...scanned].filter((s) => !services.has(s)).sort(),
      note:
        unscanned.length === 0
          ? 'every service observed in the traces has a scan'
          : `${unscanned.length} service(s) participate in traced calls and have no CBOM; scanning your own repositories will not close this`,
    };
  });

  return app;
}

/**
 * The principal, which the onRequest hook has already established.
 *
 * Reaching a handler without one would mean the hook was bypassed, so this
 * throws rather than returning a permissive default: a missing principal is a
 * bug in the wiring, and the safe reading of that bug is "no".
 */
function must(request: { principal?: Principal }): Principal {
  if (request.principal === undefined) {
    throw new AuthError('MISSING', 'unauthenticated request reached a guarded handler');
  }
  return request.principal;
}

function resourceOf(params: unknown): string | null {
  if (typeof params !== 'object' || params === null) return null;
  const p = params as Record<string, unknown>;
  const id = p['id'] ?? p['occId'] ?? p['bundleId'];
  return typeof id === 'string' ? id : null;
}

/* --------------------------------------------------------------- estate utils */

async function resolveTraces(store: ScanStore, id: string): Promise<StoredTraceBundle | null> {
  return id === 'latest' ? store.latestTraces() : store.getTraces(id);
}

interface RankedEstate {
  /** The merged estate before trace promotion, for reporting what moved. */
  readonly merged: readonly Occurrence[];
  readonly occurrences: readonly Occurrence[];
  readonly assets: readonly CryptoAsset[];
  readonly worklists: Worklists;
}

/**
 * The estate as one ranked unit.
 *
 * Both estate routes go through here so the list and the drill-down of a row
 * in it cannot disagree. The clock is the newest scan in the estate rather
 * than each scan's own start: ranking a 2020 scan against 2020 and the estate
 * against 2030 gives the same finding two different deadlines, and the row the
 * whole product exists to make clickable would contradict itself when clicked.
 */
function rankEstate(
  scans: readonly StoredScan[],
  bundle: StoredTraceBundle | null,
  q: z.infer<typeof EstateQuery>,
): RankedEstate {
  const merged = mergeScans(scans);
  const promoted =
    bundle === null
      ? merged.occurrences
      : applyTraceReachability(merged.occurrences, {
          rootSystems: [...bundle.rootServices, ...selfReachableSystems(merged.occurrences)],
          graph: graphOf(bundle),
        });
  const now = q.now === undefined ? new Date(newestStart(scans)) : new Date(q.now);

  return {
    merged: merged.occurrences,
    occurrences: promoted,
    assets: merged.assets,
    worklists: rank(promoted, merged.assets, {
      policy: loadPack(q.pack),
      currentYear: decimalYear(now),
      secrecyLifetime: () => ({ years: q.secrecyYears, assumed: true }),
    }),
  };
}

function graphOf(bundle: StoredTraceBundle): ServiceGraph {
  const services = new Set<string>(bundle.rootServices);
  for (const e of bundle.edges) {
    services.add(e.from);
    services.add(e.to);
  }
  return {
    services,
    edges: bundle.edges.map((e) => ({ ...e })),
    window: { from: bundle.windowFrom, to: bundle.windowTo },
    source: bundle.source,
  };
}

function mergeScans(scans: readonly StoredScan[]): {
  occurrences: Occurrence[];
  assets: CryptoAsset[];
} {
  const assets = new Map<string, CryptoAsset>();
  const occurrences: Occurrence[] = [];
  for (const scan of scans) {
    for (const a of scan.assets) assets.set(a.id, a);
    // Occurrence ids are content hashes of (system, asset, control class), so
    // two systems using the same asset stay two work items, as they should.
    occurrences.push(...scan.occurrences);
  }
  return {
    occurrences: occurrences.sort((a, b) => a.id.localeCompare(b.id)),
    assets: [...assets.values()].sort((a, b) => a.id.localeCompare(b.id)),
  };
}

/** Systems reachable on their own terms, which is where trace propagation starts. */
function selfReachableSystems(occurrences: readonly Occurrence[]): string[] {
  const roots = new Set<string>();
  for (const o of occurrences) {
    const via = o.reachability?.via;
    if (via === 'ENTRY_POINT' || via === 'DEPLOYED_CONFIG' || via === 'OBSERVED') {
      roots.add(o.systemId);
    }
  }
  return [...roots].sort();
}

function promotedSystems(
  before: readonly Occurrence[],
  after: readonly Occurrence[],
): { systemId: string; occurrences: number }[] {
  const beforeById = new Map(before.map((o) => [o.id, o]));
  const counts = new Map<string, number>();
  for (const o of after) {
    if (o.reachability?.via !== 'TRACE') continue;
    if (beforeById.get(o.id)?.reachability?.via === 'TRACE') continue;
    counts.set(o.systemId, (counts.get(o.systemId) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([systemId, occurrences]) => ({ systemId, occurrences }))
    .sort((a, b) => b.occurrences - a.occurrences);
}

function newestStart(scans: readonly StoredScan[]): string {
  return scans.reduce((a, s) => (s.startedAt > a ? s.startedAt : a), scans[0]?.startedAt ?? '');
}

function isoOr(value: string, request: { id?: unknown }): string {
  void request;
  const t = Date.parse(value);
  return Number.isFinite(t) ? new Date(t).toISOString() : new Date(0).toISOString();
}

/**
 * A bundle id has to separate two uploads a human would call the same one.
 *
 * The window stamp alone could not: a full-precision ISO `from` supplies more
 * digits than the stamp holds, so `to` and the span count never reached the
 * id and every bundle a backend uploaded for one window collapsed onto a
 * single id - and an OTLP export, whose window is "unstated", collapsed onto
 * source plus span count. One of the two bundles was then unrecoverable, and
 * which one depended on the store: memory overwrites, Postgres upserts and
 * keeps the first while the 201 describes the second.
 *
 * So the derived graph is hashed in behind the readable stamp. Re-uploading
 * the same export still lands on the same id, which is what makes putTraces an
 * idempotent upsert rather than a destructive one.
 */
function traceId(statedFrom: string, bundle: Omit<StoredTraceBundle, 'id'>): string {
  const slug = bundle.source
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 24);
  // The stated window rather than the stored one, so an OTLP export says
  // "unstated" instead of claiming it covers 1970.
  const stamp = statedFrom.replace(/[^0-9]/g, '').slice(0, 14) || 'unstated';
  const digest = createHash('sha256')
    .update(
      JSON.stringify([
        bundle.source,
        bundle.windowFrom,
        bundle.windowTo,
        bundle.spanCount,
        bundle.rootServices,
        bundle.edges,
      ]),
    )
    .digest('hex')
    .slice(0, 12);
  return `${slug || 'traces'}-${stamp}-${digest}`;
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

/**
 * One finding, walked from its ranked row down to raw evidence.
 *
 * Shared by the per-scan and the estate drill-down so there is exactly one
 * implementation of the derivation response. The worklists are passed in
 * rather than computed here because who ranked them, and against which clock
 * and which reachability, is the caller's decision.
 */
/**
 * Hide the names of services a scoped token cannot see.
 *
 * Trace-derived reachability is built out of service names: the frames are
 * `payments -> treasury`, the entry point is the first hop, and the evidence
 * label spells the whole path out. So the drill-down handed a viewer scoped to
 * one system a partial map of the estate around it - the same names /traces
 * refuses to serve them.
 *
 * The path is trimmed to the part inside scope rather than dropped: knowing
 * that a call arrives from somewhere is the point of the finding, and the hop
 * count is kept so the derivation still adds up.
 */
function scrub(label: string, hidden: readonly string[]): string {
  let out = label;
  for (const name of hidden) out = out.split(name).join('(out of scope)');
  return out;
}

function redactFactor(factor: Factor, hidden: readonly string[]): Factor {
  if (hidden.length === 0) return factor;
  return {
    ...factor,
    label: scrub(factor.label, hidden),
    sources: factor.sources.map((f) => redactFactor(f, hidden)),
  };
}

/**
 * The reachability a given caller is allowed to read.
 *
 * Redaction has to happen before the occurrence is echoed, not only inside the
 * derivations block: the response repeats the raw occurrence at the top, and
 * that copy carried the entry point, the frames and the "traced call path
 * a -> b -> c" evidence label in full.
 */
function redactReachability(
  principal: Principal,
  reach: Reachability,
  hidden: readonly string[],
): Reachability & { hopsOutOfScope: number } {
  const path = reach.path.filter((f) => frameVisible(principal, f));
  return {
    ...reach,
    entryPoint:
      reach.entryPoint !== null && !visibleTo(principal, reach.entryPoint) ? null : reach.entryPoint,
    path,
    factor: redactFactor(reach.factor, hidden),
    /** Hops through services this token cannot see: counted, not named. */
    hopsOutOfScope: reach.path.length - path.length,
  };
}

function derivation(
  occurrence: Occurrence,
  assets: readonly CryptoAsset[],
  ranked: Worklists,
  packId: string,
  principal: Principal,
) {
  const asset = assets.find((a) => a.id === occurrence.assetId) ?? null;
  const pack = loadPack(packId);
  // Every bucket rank() can return. A row missing from this list reports no
  // MOSCA derivation at all, which reads as "there is no deadline" rather than
  // "we did not look here".
  const row = [
    ...ranked.confidentiality,
    ...ranked.authenticity,
    ...ranked.unreached,
    ...ranked.unanalyzed,
    ...ranked.hints,
  ].find((f) => f.occurrenceId === occurrence.id);
  const g = gate(occurrence);
  const raw = occurrence.reachability;
  // Only the names actually present in this derivation, so the substitution
  // does not have to walk the estate.
  const hiddenServices =
    raw === null
      ? []
      : [
          ...new Set(
            [raw.entryPoint, ...raw.path.flatMap((f) => [f.module, ...f.fullFilename.split(' -> ')])]
              .filter((n): n is string => typeof n === 'string' && n !== '')
              .filter((n) => !visibleTo(principal, n)),
          ),
        ];
  const reach = raw === null ? null : redactReachability(principal, raw, hiddenServices);

  return {
    occurrence: {
      ...occurrence,
      reachability: reach,
      confidence: Number(occurrence.confidence.value),
    },
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
        // Structured, so the UI can explain the ceilings in words instead of
        // parsing them back out of a label string.
        value: Number(occurrence.confidence.value),
        groups: computeConfidenceBreakdown(occurrence.evidence).groups,
      },
      mosca:
        row === undefined
          ? null
          : {
              tree: explain(row.mosca.factor, 'mosca'),
              depth: derivationDepth(row.mosca.factor),
              bindingConstraint: row.bindingConstraint,
              x: row.mosca.x,
              y: row.mosca.y,
              crqc: row.mosca.crqc,
              regulatory: row.mosca.regulatory,
              controlClass: row.controlClass,
              track: row.track,
              policy: {
                packId: ranked.policyPackId,
                packVersion: ranked.policyPackVersion,
                crqcYear: pack.crqcYear,
                authority: pack.regulatoryAuthority,
              },
            },
      reachability:
        reach === null
          ? null
          : {
              tree: explain(reach.factor, 'reachability'),
              via: reach.via,
              entryPoint: reach.entryPoint,
              path: reach.path,
              hopsOutOfScope: reach.hopsOutOfScope,
            },
    },
  };
}

/** A trace frame is `from -> to`; both ends must be in scope to be shown. */
function frameVisible(principal: Principal, frame: { module: string; fullFilename: string }): boolean {
  if (principal.systems.length === 0) return true;
  return [frame.module, ...frame.fullFilename.split(' -> ')]
    .map((n) => n.trim())
    .filter((n) => n !== '')
    .every((n) => visibleTo(principal, n));
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

/**
 * Readable, and never shared by two scans.
 *
 * The readable half is lossy in both directions: the stamp truncates at whole
 * seconds while an ingest may carry milliseconds, and the slug collapses
 * "a-b", "a_b" and "A B" to one string. Two distinct scans landing on one id
 * meant the memory store silently dropped the earlier one and Postgres
 * rejected the write as a duplicate key - and `assay push` twice in one second
 * is enough to reach it. The exact inputs are hashed in behind the stamp so
 * the id stays deterministic without pretending the stamp is unique.
 */
function scanId(systemName: string, startedAt: string): string {
  const slug = systemName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const stamp = startedAt.replace(/[-:.TZ]/g, '').slice(0, 14);
  const digest = createHash('sha256')
    .update(`${systemName}\u0000${startedAt}`)
    .digest('hex')
    .slice(0, 8);
  return `${slug || 'scan'}-${stamp}-${digest}`;
}
