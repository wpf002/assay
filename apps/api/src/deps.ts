/**
 * Single import surface for engine functions, so a route file cannot quietly
 * start depending on something that does I/O.
 */
export {
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
  CryptoAsset,
  ExportProfile,
  Occurrence,
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
