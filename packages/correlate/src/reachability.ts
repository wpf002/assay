import type { CallFrame, Evidence, Occurrence, Reachability, ReachabilityVia } from '@assay/core';
import type { ModuleGraph, ModuleNode } from '@assay/detect-source';

/**
 * Presence is not exposure (I5).
 *
 * RSA in a test fixture and RSA on the payment API key exchange are not the
 * same work item. This decides which is which, and - more importantly - ships
 * the path, so a reviewer can check the answer instead of trusting it.
 *
 * Three states, never two:
 *   true   - a path exists from a detected entry point
 *   false  - analyzed, and no path exists
 *   null   - not analyzable by this method
 * Collapsing null into false would silently retire real work; collapsing it
 * into true would put every test fixture back on the CISO's page.
 */

export interface ReachabilityOptions {
  /** Extra entry files, e.g. from a framework manifest the heuristics miss. */
  readonly extraEntryPoints?: readonly string[];
  /**
   * Treat a file with no detected entry point anywhere in the tree as reached.
   * A library has no server to start; refusing to analyze it is honest, and
   * pretending everything in it is dead is not.
   */
  readonly assumeLibraryReachable?: boolean;
}

export interface ReachabilityAnalysis {
  readonly occurrences: readonly Occurrence[];
  readonly entryPoints: readonly string[];
  readonly reachableFiles: ReadonlySet<string>;
  readonly analyzed: boolean;
}

const SOURCE_MODALITIES = new Set(['SOURCE_AST', 'SOURCE_CONFIG']);
const CONFIG_FIXTURE = /(^|\/)(examples?|samples?|templates?|docs?|tests?|__tests__|fixtures?)(\/|$)/i;

function isConfigFixture(path: string): boolean {
  return CONFIG_FIXTURE.test(path.replace(/\\/g, '/'));
}
const LIVE_MODALITIES = new Set(['NETWORK_ACTIVE', 'NETWORK_PASSIVE']);

export function analyzeReachability(
  occurrences: readonly Occurrence[],
  graph: ModuleGraph,
  opts: ReachabilityOptions = {},
): ReachabilityAnalysis {
  const entryPoints = [
    ...new Set([
      ...[...graph.nodes.values()].filter((n) => n.entryKind !== null && !n.isTest).map((n) => n.file),
      // A published package's declared entry is an entry point. A library has
      // no server to start, and treating its public surface as dead code
      // marks the whole package unreached - which is the error that retires
      // real work rather than the one that adds noise.
      ...graph.packageEntries.filter((f) => !graph.nodes.get(f)?.isTest),
      ...(opts.extraEntryPoints ?? []),
    ]),
  ].sort();

  const { reachable, predecessor } = walk(graph, entryPoints);
  // With no entry point anywhere, the import graph says nothing. Reporting
  // every finding as dead code would be worse than reporting that we did not
  // look, so the whole analysis is marked unperformed.
  const analyzed = entryPoints.length > 0 || opts.assumeLibraryReachable === true;

  return {
    entryPoints,
    reachableFiles: reachable,
    analyzed,
    occurrences: occurrences.map((o) =>
      analyzed ? { ...o, reachability: reachabilityOf(o, graph, reachable, predecessor, opts) } : o,
    ),
  };
}

function reachabilityOf(
  occurrence: Occurrence,
  graph: ModuleGraph,
  reachable: ReadonlySet<string>,
  predecessor: ReadonlyMap<string, string>,
  opts: ReachabilityOptions,
): Reachability | null {
  // A negotiated handshake is not an inference about whether code runs - it is
  // an observation that it already did.
  const live = occurrence.evidence.find((e) => LIVE_MODALITIES.has(e.modality));
  if (live !== undefined) {
    return {
      reachable: true,
      via: 'OBSERVED',
      entryPoint: live.locator,
      path: [],
      factor: {
        kind: 'EVIDENCE',
        label: `observed on the wire at ${live.locator}`,
        value: true,
        weight: 1,
        sources: [],
      },
    };
  }

  // Deployed configuration is deployed. An nginx cipher list is not imported
  // by anything and never will be, so judging it with an import graph marks
  // the entire TLS edge as dead code - which is exactly backwards, since it is
  // the part of the estate that is definitely serving traffic.
  const config = occurrence.evidence.find(
    (e) => e.modality === 'SOURCE_CONFIG' && !isConfigFixture(e.occurrence?.location ?? ''),
  );
  if (config !== undefined) {
    return {
      reachable: true,
      via: 'DEPLOYED_CONFIG',
      entryPoint: config.occurrence?.location ?? config.locator,
      path: [],
      factor: {
        kind: 'INFERENCE',
        label: `deployed configuration at ${config.locator}`,
        value: true,
        weight: 1,
        sources: [
          {
            kind: 'ASSUMPTION',
            label:
              'a configuration file in the tree is assumed to describe a running deployment; it could be a template or an example',
            value: true,
            weight: 0,
            sources: [],
          },
        ],
      },
    };
  }

  const sourceEvidence = occurrence.evidence.filter(
    (e) => SOURCE_MODALITIES.has(e.modality) && e.occurrence !== undefined,
  );
  // Certificates on disk, managed keys and manifest entries have no call site,
  // so this method cannot speak to them.
  if (sourceEvidence.length === 0) return null;

  let best: { evidence: Evidence; path: CallFrame[]; entry: string } | null = null;
  const deadReasons: string[] = [];

  for (const e of sourceEvidence) {
    const file = e.occurrence?.location as string;
    const node = graph.nodes.get(file);
    if (node?.isTest === true) {
      deadReasons.push(`${file} is a test path`);
      continue;
    }
    if (!reachable.has(file)) {
      deadReasons.push(`${file} is not imported from any entry point`);
      continue;
    }
    if (node !== undefined && !isLocallyLive(node, e)) {
      deadReasons.push(`${file}: enclosing function is not exported or called from one`);
      continue;
    }
    const path = pathTo(file, predecessor, graph, e);
    const entry = path[0]?.fullFilename ?? file;
    if (best === null || path.length < best.path.length) best = { evidence: e, path, entry };
  }

  if (best === null) {
    // No static path - but a module inside a published package is reachable by
    // that package's consumers, whose code is not in this tree. Django loads
    // its password hashers from a dotted string in settings; n8n's nodes are
    // discovered at runtime. Calling those dead code would retire real work,
    // and calling them entry-point-reachable would be a lie. They are a third
    // thing, and the ranking is told which.
    const surface = sourceEvidence.find((e) => {
      const file = e.occurrence?.location as string;
      const node = graph.nodes.get(file);
      return node !== undefined && !node.isTest && inPublishedSurface(file, graph);
    });
    if (surface !== undefined) {
      const file = surface.occurrence?.location as string;
      return {
        reachable: true,
        via: 'LIBRARY_SURFACE',
        entryPoint: packageDirOf(file, graph) || '<root package>',
        path: [],
        factor: {
          kind: 'INFERENCE',
          label: `inside the published surface of ${packageDirOf(file, graph) || 'this package'}`,
          value: true,
          weight: 1,
          sources: [
            {
              kind: 'EVIDENCE',
              label: `call site ${surface.locator}`,
              value: surface.raw.slice(0, 160),
              weight: 1,
              sources: [],
            },
            {
              kind: 'ASSUMPTION',
              label:
                'no static path from an entry point in this tree; treated as reachable because the module is published and its consumers are not in scope',
              value: true,
              weight: 0,
              sources: [],
            },
          ],
        },
      };
    }

    return {
      reachable: false,
      via: 'NONE',
      entryPoint: null,
      path: [],
      factor: {
        kind: 'INFERENCE',
        label: 'no path from any entry point',
        value: false,
        weight: 1,
        sources: [...new Set(deadReasons)].sort().map((r) => ({
          kind: 'EVIDENCE' as const,
          label: r,
          value: false,
          weight: 1,
          sources: [],
        })),
      },
    };
  }

  return {
    reachable: true,
    via: 'ENTRY_POINT',
    entryPoint: best.entry,
    path: best.path,
    factor: {
      kind: 'INFERENCE',
      label: `reached from ${best.entry} in ${best.path.length} module hop(s)`,
      value: true,
      weight: 1,
      sources: [
        {
          kind: 'EVIDENCE',
          label: `call site ${best.evidence.locator}`,
          value: best.evidence.raw.slice(0, 160),
          weight: 1,
          sources: [],
        },
        {
          kind: 'ASSUMPTION',
          // Stated, not buried. Without type information an import edge cannot
          // be narrowed to the functions actually called, so this direction of
          // the analysis over-approximates - and the ranking must not treat it
          // as a verified fact.
          label:
            'module-level import reachability over-approximates: importing a module does not prove every function in it is called',
          value: true,
          weight: 0,
          sources: [],
        },
      ],
    },
  };
}

/**
 * Within-file liveness. A crypto call inside a helper nobody exports or calls
 * is dead even when the file itself is imported - which is most of what an
 * import-only analysis gets wrong.
 */
function isLocallyLive(node: ModuleNode, evidence: Evidence): boolean {
  const symbol = evidence.occurrence?.symbol ?? '';
  const chain = symbol.split(' > ').slice(0, -1).filter(Boolean);
  if (chain.length === 0) return true; // module top level runs on import

  const holder = chain[0] as string;
  if (node.exported.has(holder)) return true;

  const seen = new Set<string>();
  const queue = [...node.exported];
  while (queue.length > 0) {
    const fn = queue.pop() as string;
    if (seen.has(fn)) continue;
    seen.add(fn);
    if (fn === holder) return true;
    for (const callee of node.callEdges.get(fn) ?? []) queue.push(callee);
  }
  return false;
}

/* --------------------------------------------------------------- graph walk */

const EXTENSIONS = [
  '.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.java', '.rs', '.cs', '.c', '.cc', '.cpp', '.h', '.hpp',
];

function resolve(spec: string, graph: ModuleGraph): string | null {
  if (graph.nodes.has(spec)) return spec;
  // NodeNext TypeScript imports './keys.js' and means './keys.ts'. Resolving
  // only the literal specifier makes every modern TS service look like it
  // imports nothing, and therefore look entirely dead.
  const rewritten = spec.replace(/\.(js|mjs|cjs)$/, '');
  if (rewritten !== spec) {
    for (const ext of EXTENSIONS) {
      if (graph.nodes.has(rewritten + ext)) return rewritten + ext;
    }
  }
  for (const ext of EXTENSIONS) {
    if (graph.nodes.has(spec + ext)) return spec + ext;
  }
  for (const ext of EXTENSIONS) {
    if (graph.nodes.has(`${spec}/index${ext}`)) return `${spec}/index${ext}`;
  }
  if (graph.nodes.has(`${spec}/__init__.py`)) return `${spec}/__init__.py`;
  return null;
}

/**
 * Non-relative specifiers that are nonetheless inside this tree.
 *
 * Three kinds, and missing any of them collapses the graph:
 *   - workspace packages: `@acme/core`, resolved by longest-prefix name match
 *   - Python absolute modules: `django.utils.crypto` -> django/utils/crypto.py
 *   - TypeScript path aliases: `@/encryption/cipher`, which live in tsconfig
 *     and cannot be resolved without it
 *
 * The alias case is handled by unique-suffix match rather than by reading
 * tsconfig: an alias is accepted only when exactly one file in the tree ends
 * with that path, preferring one inside the importing package. That is a
 * heuristic and it is stated as one - but the alternative, following only
 * relative imports, reported 983 of n8n's 19,747 files as reachable and
 * retired most of its production crypto as dead code.
 */
function resolveNonRelative(spec: string, from: ModuleNode, graph: ModuleGraph): string | null {
  const workspace = resolveWorkspace(spec, graph);
  if (workspace !== null) return workspace;
  if (from.lang === 'python') return resolvePythonModule(spec, graph);
  return resolveAlias(spec, from, graph);
}

/** `django.utils.crypto` -> `django/utils/crypto.py` or its package __init__. */
function resolvePythonModule(spec: string, graph: ModuleGraph): string | null {
  if (!spec.includes('.') || spec.startsWith('.')) return null;
  const asPath = spec.replace(/\./g, '/');
  if (graph.nodes.has(`${asPath}.py`)) return `${asPath}.py`;
  if (graph.nodes.has(`${asPath}/__init__.py`)) return `${asPath}/__init__.py`;
  // The importable root may sit below the scan root (src/ layouts).
  const suffix = suffixMatch(`${asPath}.py`, graph) ?? suffixMatch(`${asPath}/__init__.py`, graph);
  return suffix;
}

/** `@/x/y`, `~/x/y`, `#internal/x` and bare `src/x/y`, via unique suffix. */
function resolveAlias(spec: string, from: ModuleNode, graph: ModuleGraph): string | null {
  const stripped = spec.replace(/^[@~#]\//, '').replace(/^[@~#]/, '');
  // A scoped package name that did not match a workspace is a real dependency.
  if (spec.startsWith('@') && spec.includes('/') && !spec.startsWith('@/')) return null;
  if (stripped === '' || !/[/]/.test(stripped)) return null;

  const packageDir = packageDirOf(from.file, graph);
  return suffixMatch(stripped, graph, packageDir);
}

/**
 * A file whose path ends with `suffix`, uniquely. Preference is given to the
 * importing package, because two packages in a monorepo routinely contain
 * `src/utils/index.ts` and picking the wrong one invents an edge.
 */
function suffixMatch(suffix: string, graph: ModuleGraph, preferDir?: string): string | null {
  const candidates: string[] = [];
  const tails = [suffix, ...EXTENSIONS.map((e) => suffix + e), ...EXTENSIONS.map((e) => `${suffix}/index${e}`)];

  for (const file of graph.nodes.keys()) {
    for (const tail of tails) {
      if (file === tail || file.endsWith(`/${tail}`)) {
        candidates.push(file);
        break;
      }
    }
  }
  if (candidates.length === 0) return null;
  if (candidates.length === 1) return candidates[0] as string;

  if (preferDir !== undefined && preferDir !== '') {
    const local = candidates.filter((c) => c.startsWith(`${preferDir}/`));
    if (local.length === 1) return local[0] as string;
  }
  // Ambiguous. Inventing an edge is worse than missing one here, because a
  // wrong edge marks unrelated code reachable and puts it on the worklist.
  return null;
}

/**
 * Is this file part of something the repo publishes?
 *
 * Anything under a package directory that is not a test, example, script or
 * tool. With no package manifests at all the whole tree is treated as the
 * surface, which is the right answer for a single-package library.
 */
function inPublishedSurface(file: string, graph: ModuleGraph): boolean {
  if (/(^|\/)(examples?|samples?|scripts?|tools?|benchmarks?|docs?)(\/|$)/i.test(file)) return false;
  for (const dir of graph.publishedDirs) {
    if (dir === '' || file.startsWith(`${dir}/`)) return true;
  }
  return false;
}

function packageDirOf(file: string, graph: ModuleGraph): string {
  let best = '';
  for (const dir of graph.packages.values()) {
    if (dir !== '' && file.startsWith(`${dir}/`) && dir.length > best.length) best = dir;
  }
  return best;
}

function resolveWorkspace(spec: string, graph: ModuleGraph): string | null {
  let bestName: string | null = null;
  for (const name of graph.packages.keys()) {
    if (spec !== name && !spec.startsWith(`${name}/`)) continue;
    if (bestName === null || name.length > bestName.length) bestName = name;
  }
  if (bestName === null) return null;
  const dir = graph.packages.get(bestName) as string;
  const subpath = spec.slice(bestName.length).replace(/^\//, '');
  const joined = [dir, subpath].filter(Boolean).join('/');
  return joined === '' ? '.' : joined;
}

function walk(
  graph: ModuleGraph,
  entryPoints: readonly string[],
): { reachable: Set<string>; predecessor: Map<string, string> } {
  const reachable = new Set<string>(entryPoints);
  const predecessor = new Map<string, string>();
  const queue = [...entryPoints];

  while (queue.length > 0) {
    const file = queue.shift() as string;
    const node = graph.nodes.get(file);
    if (node === undefined) continue;
    const specs = [
      ...node.localImports,
      // Workspace imports look external but are not. Resolving them is what
      // gives a monorepo any edges at all.
      ...node.externalImports
        .map((spec) => resolveNonRelative(spec, node, graph))
        .filter((s): s is string => s !== null),
    ];
    for (const spec of specs) {
      const target = resolve(spec, graph);
      if (target === null || reachable.has(target)) continue;
      reachable.add(target);
      predecessor.set(target, file);
      queue.push(target);
    }
  }
  return { reachable, predecessor };
}

function pathTo(
  file: string,
  predecessor: ReadonlyMap<string, string>,
  graph: ModuleGraph,
  evidence: Evidence,
): CallFrame[] {
  const chain: string[] = [file];
  const seen = new Set<string>([file]);
  let cursor = predecessor.get(file);
  while (cursor !== undefined && !seen.has(cursor)) {
    chain.unshift(cursor);
    seen.add(cursor);
    cursor = predecessor.get(cursor);
  }

  const symbol = evidence.occurrence?.symbol ?? '';
  const functions = symbol.split(' > ').filter(Boolean);

  return chain.map((f, i) => {
    const isLast = i === chain.length - 1;
    const node = graph.nodes.get(f);
    return {
      module: f.replace(/\.[^/.]+$/, ''),
      function: isLast ? (functions[functions.length - 1] ?? '<module>') : (node?.entryKind ?? 'imports'),
      fullFilename: f,
      ...(isLast && evidence.occurrence?.line !== undefined ? { line: evidence.occurrence.line } : {}),
    } satisfies CallFrame;
  });
}
