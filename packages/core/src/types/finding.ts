import type { ControlClass, CryptoAsset, Evidence } from './crypto-asset.js';

/**
 * A single observation, already classified. Detectors emit these; correlation
 * folds them into Occurrences. Keeping the detector output flat is what lets
 * `@assay/core` stay pure: a detector does I/O and returns data, and every
 * judgement about what the data means happens downstream in a pure function.
 */
export interface Finding {
  readonly asset: CryptoAsset;
  readonly systemId: string;
  readonly controlClass: ControlClass;
  readonly evidence: Evidence;
}
