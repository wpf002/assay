import { canonicalize, sha256Hex } from '../hash/index.js';
import { computeConfidenceBreakdown } from '../confidence/index.js';
import { isTainted, assumptions, trace, type Factor } from '../types/factor.js';
import type { CryptoAsset, Evidence, Occurrence, Primitive, Purpose } from '../types/crypto-asset.js';
import type { Modality } from '../types/modality.js';

/**
 * CycloneDX cryptographic-asset export.
 *
 * EXPORT GATE (I6): an occurrence may only be emitted at CONFIRMED when its
 * confidence Factor tree is untainted (no ASSUMPTION node anywhere in the
 * dependency path) AND clears the threshold. Everything else downgrades to
 * OBSERVED or SUSPECTED. A guess never launders itself into a fact by passing
 * through a serializer.
 *
 * The BINARY_STRING rule needs no special case here: its 0.30 ceiling makes it
 * arithmetically incapable of reaching 0.85 without independent corroboration.
 * The invariant is enforced by the algebra, not by a check that can be forgotten.
 */
export type AssertionLevel = 'CONFIRMED' | 'OBSERVED' | 'SUSPECTED';

export const CONFIRM_THRESHOLD = 0.85;
export const OBSERVE_THRESHOLD = 0.5;

/**
 * Export profiles. ECMA-424 2nd edition (Dec 2025) standardizes CycloneDX 1.7;
 * 1.6 is kept for consumers that lag. `cisa-min-elements` is a placeholder for
 * the minimum-elements guidance EO 14412 sec. 5(d) directs CISA to publish
 * ~2026-12-20; it currently emits 1.7 and flags itself as provisional rather
 * than pretending to a schema nobody has seen.
 */
export type ExportProfile = 'cyclonedx-1.7' | 'cyclonedx-1.6' | 'cisa-min-elements';

export interface CbomExportOptions {
  readonly profile?: ExportProfile;
  readonly confirmThreshold?: number;
  readonly includeSuspected?: boolean;
  readonly policyPackId: string;
  readonly policyPackVersion: string;
  /** ISO8601. Supplied by the caller; core reads no clock (I7). */
  readonly timestamp: string;
  readonly toolVersion: string;
  /** Emit the full recursive Factor tree as assay: properties. Large but auditable. */
  readonly includeFactorTrees?: boolean;
}

export interface GatedOccurrence {
  readonly occurrence: Occurrence;
  readonly confidence: number;
  readonly assertionLevel: AssertionLevel;
  /** Present when the level was capped below what the number alone would allow. */
  readonly downgradeReason: string | null;
}

/** The gate, exposed on its own so the API and UI can explain a downgrade. */
export function gate(occurrence: Occurrence, confirmThreshold = CONFIRM_THRESHOLD): GatedOccurrence {
  const confidence = Number(occurrence.confidence.value);
  const tainted = isTainted(occurrence.confidence);

  if (tainted) {
    const names = assumptions(occurrence.confidence).map((a) => a.label);
    return {
      occurrence,
      confidence,
      assertionLevel: confidence >= OBSERVE_THRESHOLD ? 'OBSERVED' : 'SUSPECTED',
      downgradeReason: `provenance tainted by ${names.length} assumption(s): ${names.join('; ')}`,
    };
  }
  if (confidence >= confirmThreshold) {
    return { occurrence, confidence, assertionLevel: 'CONFIRMED', downgradeReason: null };
  }
  return {
    occurrence,
    confidence,
    assertionLevel: confidence >= OBSERVE_THRESHOLD ? 'OBSERVED' : 'SUSPECTED',
    downgradeReason: `confidence ${confidence} below confirm threshold ${confirmThreshold}`,
  };
}

/* ------------------------------------------------------------ CycloneDX maps */

const PRIMITIVE_KIND: Readonly<Record<Primitive, string>> = {
  RSA: 'pke', ECDSA: 'signature', ECDH: 'key-agree', DH: 'key-agree', DSA: 'signature',
  EdDSA: 'signature', X25519: 'key-agree', X448: 'key-agree',
  'ML-KEM': 'kem', 'ML-DSA': 'signature', 'SLH-DSA': 'signature', LMS: 'signature', XMSS: 'signature',
  AES: 'block-cipher', ChaCha20: 'stream-cipher', '3DES': 'block-cipher', RC4: 'stream-cipher',
  SHA1: 'hash', SHA2: 'hash', SHA3: 'hash', MD5: 'hash',
  HMAC: 'mac', PBKDF2: 'kdf', Argon2: 'kdf', scrypt: 'kdf',
  UNKNOWN: 'unknown',
};

const PURPOSE_FUNCTIONS: Readonly<Record<Purpose, readonly string[]>> = {
  KEY_ESTABLISHMENT: ['keygen', 'encapsulate', 'decapsulate'],
  DATA_ENCRYPTION: ['encrypt', 'decrypt'],
  DIGITAL_SIGNATURE: ['sign', 'verify'],
  CERTIFICATE_AUTH: ['sign', 'verify'],
  INTEGRITY: ['digest', 'tag'],
  KEY_DERIVATION: ['keyderive'],
  RANDOMNESS: ['generate'],
};

/**
 * CycloneDX evidence.identity.methods[].technique has six values and no notion
 * of a per-technique ceiling. Assay's thirteen modalities do not survive the
 * round trip, so the lossy mapping is recorded here in one place and the real
 * modality is carried alongside in an assay: property.
 */
const TECHNIQUE_OF: Readonly<Record<Modality, string>> = {
  SOURCE_AST: 'source-code-analysis',
  SOURCE_CONFIG: 'source-code-analysis',
  DEPENDENCY: 'manifest-analysis',
  BINARY_SYMBOL: 'binary-analysis',
  BINARY_CONSTANT: 'binary-analysis',
  BINARY_STRING: 'binary-analysis',
  HOST_AGENT: 'filename',
  RUNTIME_HOOK: 'instrumentation',
  NETWORK_ACTIVE: 'dynamic-analysis',
  NETWORK_PASSIVE: 'dynamic-analysis',
  PKI_CERTIFICATE: 'certificate',
  CLOUD_KMS_API: 'attestation',
  ASSERTED: 'attestation',
};

/* ------------------------------------------------------------------ exporter */

export interface CbomDocument {
  readonly bomFormat: 'CycloneDX';
  readonly specVersion: string;
  readonly serialNumber: string;
  readonly version: number;
  readonly metadata: unknown;
  readonly components: readonly unknown[];
  readonly dependencies: readonly unknown[];
  readonly properties: readonly unknown[];
}

export function toCycloneDX(
  occurrences: readonly Occurrence[],
  assets: readonly CryptoAsset[],
  opts: CbomExportOptions,
): CbomDocument {
  const profile = opts.profile ?? 'cyclonedx-1.7';
  const specVersion = profile === 'cyclonedx-1.6' ? '1.6' : '1.7';
  const threshold = opts.confirmThreshold ?? CONFIRM_THRESHOLD;
  const includeSuspected = opts.includeSuspected ?? false;

  const assetById = new Map(assets.map((a) => [a.id, a]));

  const gated = occurrences
    .map((o) => gate(o, threshold))
    .filter((g) => includeSuspected || g.assertionLevel !== 'SUSPECTED')
    .sort((a, b) => cmp(a.occurrence.id, b.occurrence.id));

  // One component per distinct asset; occurrences fold in as evidence.
  const byAsset = new Map<string, GatedOccurrence[]>();
  for (const g of gated) {
    const list = byAsset.get(g.occurrence.assetId);
    if (list) list.push(g);
    else byAsset.set(g.occurrence.assetId, [g]);
  }

  const components = [...byAsset.entries()]
    .sort((a, b) => cmp(a[0], b[0]))
    .map(([assetId, gs]) => component(assetById.get(assetId), assetId, gs, opts));

  const dependencies = [...byAsset.keys()].sort(cmp).map((id) => ({
    ref: `crypto:${id}`,
    // A dependency manifest says a library IMPLEMENTS an algorithm. It does not
    // say the application USES it. Assay never emits `uses` from manifest
    // evidence alone; that distinction is decision D1 made machine-readable.
    dependsOn: [],
  }));

  const body = {
    bomFormat: 'CycloneDX' as const,
    specVersion,
    version: 1,
    metadata: {
      timestamp: opts.timestamp,
      tools: {
        components: [
          { type: 'application', name: 'assay', version: opts.toolVersion, publisher: 'Assay' },
        ],
      },
      properties: [
        prop('assay:policyPack', `${opts.policyPackId}@${opts.policyPackVersion}`),
        prop('assay:exportProfile', profile),
        prop('assay:confirmThreshold', String(threshold)),
        ...(profile === 'cisa-min-elements'
          ? [
              prop(
                'assay:profileStatus',
                'PROVISIONAL - CISA minimum elements per EO 14412 sec. 5(d) not yet published; emitting CycloneDX 1.7',
              ),
            ]
          : []),
      ],
    },
    components,
    dependencies,
    properties: [
      prop('assay:confirmed', String(count(gated, 'CONFIRMED'))),
      prop('assay:observed', String(count(gated, 'OBSERVED'))),
      prop('assay:suspected', String(count(gated, 'SUSPECTED'))),
    ],
  };

  // Deterministic serial number: same evidence set, same document, same urn.
  // A random uuid here would quietly break the reproducibility claim.
  const digest = sha256Hex(canonicalize(body as never));
  const serialNumber = `urn:uuid:${digest.slice(0, 8)}-${digest.slice(8, 12)}-${digest.slice(
    12,
    16,
  )}-${digest.slice(16, 20)}-${digest.slice(20, 32)}`;

  return { ...body, serialNumber };
}

function component(
  asset: CryptoAsset | undefined,
  assetId: string,
  gs: readonly GatedOccurrence[],
  opts: CbomExportOptions,
): unknown {
  const best = gs.reduce((a, b) => (b.confidence > a.confidence ? b : a));
  const allEvidence = gs.flatMap((g) => g.occurrence.evidence);
  const breakdown = computeConfidenceBreakdown(allEvidence);

  const occurrences = allEvidence
    .filter((e) => e.occurrence !== undefined)
    .map((e) => {
      const o = e.occurrence as NonNullable<Evidence['occurrence']>;
      return clean({
        'bom-ref': `occ:${sha256Hex(canonicalize({ ...o } as never)).slice(0, 16)}`,
        location: o.location,
        line: o.line,
        offset: o.offset,
        symbol: o.symbol,
        additionalContext: e.raw.slice(0, 200),
      });
    })
    .sort((a, b) => cmp(canonicalize(a as never), canonicalize(b as never)));

  // Reachability paths ride in evidence.callstack. Every competitor claims
  // reachability; shipping the path in a standard field is what makes the
  // claim checkable by someone who does not trust us.
  // Only when there is an actual path. A `callstack: { frames: [] }` is noise
  // that reads as "we traced this" when we did not - config and network
  // evidence are reached without any call path existing to show.
  const reached = gs.find(
    (g) => g.occurrence.reachability?.reachable === true && g.occurrence.reachability.path.length > 0,
  );
  const callstack =
    reached && reached.occurrence.reachability
      ? {
          frames: reached.occurrence.reachability.path.map((f) =>
            clean({
              module: f.module,
              function: f.function,
              fullFilename: f.fullFilename,
              line: f.line,
              column: f.column,
            }),
          ),
        }
      : undefined;

  return clean({
    type: 'cryptographic-asset',
    'bom-ref': `crypto:${assetId}`,
    name: asset ? assetName(asset) : assetId,
    cryptoProperties: asset
      ? clean({
          assetType: 'algorithm',
          algorithmProperties: clean({
            primitive: PRIMITIVE_KIND[asset.primitive],
            parameterSetIdentifier: paramSet(asset),
            curve: typeof asset.parameters['curve'] === 'string' ? asset.parameters['curve'] : undefined,
            executionEnvironment: 'unknown',
            implementationPlatform: 'unknown',
            cryptoFunctions: PURPOSE_FUNCTIONS[asset.purpose],
            classicalSecurityLevel: asset.classicalSecurityBits ?? undefined,
            nistQuantumSecurityLevel: asset.nistQuantumSecurityLevel ?? undefined,
          }),
          oid: asset.oid ?? undefined,
        })
      : undefined,
    evidence: clean({
      identity: {
        field: 'name',
        // CycloneDX confidence is an integer 0-100 with no ceiling discipline.
        // The number is faithful; the derivation behind it has no home in the
        // schema and travels in assay: properties below.
        confidence: Math.round(breakdown.value * 100),
        concludedValue: asset ? assetName(asset) : assetId,
        methods: breakdown.groups.map((g) => ({
          technique: TECHNIQUE_OF[g.contributing],
          confidence: Math.round(g.ceiling * 100),
          value: `${g.contributing}: ${g.tallies.reduce((n, t) => n + t.count, 0)} observation(s), ${
            g.suppressed
          } suppressed as same-group repetition`,
        })),
      },
      occurrences: occurrences.length > 0 ? occurrences : undefined,
      callstack,
    }),
    properties: [
      prop('assay:assertionLevel', best.assertionLevel),
      prop('assay:confidence', String(breakdown.value)),
      prop('assay:quantumVulnerable', String(asset?.quantumVulnerable ?? 'unknown')),
      prop('assay:purpose', asset?.purpose ?? 'unknown'),
      prop('assay:urgencyTrack', asset ? track(asset.purpose) : 'unknown'),
      prop('assay:occurrenceCount', String(gs.length)),
      prop('assay:controlClasses', unique(gs.map((g) => g.occurrence.controlClass)).join(',')),
      prop(
        'assay:reachable',
        gs.some((g) => g.occurrence.reachability?.reachable === true)
          ? 'true'
          : gs.every((g) => g.occurrence.reachability === null)
            ? 'unanalyzed'
            : 'false',
      ),
      ...(best.downgradeReason ? [prop('assay:downgradeReason', best.downgradeReason)] : []),
      ...(opts.includeFactorTrees
        ? [prop('assay:factor', trace(breakdown.factor).join('\n'))]
        : []),
    ],
  });
}

/* -------------------------------------------------------------------- helpers */

function assetName(a: CryptoAsset): string {
  const parts = Object.entries(a.parameters)
    .sort(([x], [y]) => cmp(x, y))
    .map(([k, v]) => `${k}=${String(v)}`);
  return parts.length > 0 ? `${a.primitive}(${parts.join(',')})` : a.primitive;
}

function paramSet(a: CryptoAsset): string | undefined {
  const n = a.parameters['modulusLength'] ?? a.parameters['keySize'] ?? a.parameters['curve'];
  return n === undefined ? undefined : String(n);
}

function track(p: Purpose): string {
  return p === 'KEY_ESTABLISHMENT' || p === 'DATA_ENCRYPTION' ? 'CONFIDENTIALITY' : 'AUTHENTICITY';
}

function prop(name: string, value: string): { name: string; value: string } {
  return { name, value };
}

function count(gs: readonly GatedOccurrence[], level: AssertionLevel): number {
  return gs.filter((g) => g.assertionLevel === level).length;
}

function unique(xs: readonly string[]): string[] {
  return [...new Set(xs)].sort(cmp);
}

/** Drop undefined keys so canonicalization and byte-equality stay stable. */
function clean<T extends Record<string, unknown>>(o: T): T {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(o).sort()) {
    if (o[k] !== undefined) out[k] = o[k];
  }
  return out as T;
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export type { Factor };
