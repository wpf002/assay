/**
 * Single import surface for engine functions, so a route file cannot quietly
 * start depending on something that does I/O.
 */
export {
  computeConfidenceBreakdown,
  MODALITY_CEILING,
  diffScans,
  explain,
  blockers,
  citations,
  derivationDepth,
  gate,
  rank,
  toCycloneDX,
} from '@assay/core';
export type {
  Factor,
  CryptoAsset,
  ExportProfile,
  Occurrence,
  Reachability,
  RankedFinding,
  ScanSnapshot,
  Worklists,
} from '@assay/core';
export {
  divergences as divergencesOf,
  applyTraceReachability,
  buildServiceGraph,
  spansFromOtlp,
  traceRoots,
  SpanRecordSchema,
  TraceBundleSchema,
} from '@assay/correlate';
export type { ServiceGraph, SpanRecord } from '@assay/correlate';

export {
  CLASSES,
  ESTATE_CLASSES,
  coverageReport,
  coverageDigest,
  signCoverage,
  verifyCoverage,
} from '@assay/coverage';
export type { BlindSpot, CoverageReport, EstateClass, SignedCoverage } from '@assay/coverage';
