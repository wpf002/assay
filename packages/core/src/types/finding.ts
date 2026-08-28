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
  /**
   * Detector-supplied caveats that taint this observation's provenance.
   *
   * Not "we are unsure the code is there" - the AST saw it. These are claims
   * the detector had to take on trust to classify it, such as Python's
   * `usedforsecurity=False`, where the developer asserts the digest is not
   * security-relevant and nothing in the source can verify that. Under I6 such
   * a finding can be OBSERVED but never CONFIRMED, which keeps it in the
   * inventory and out of the worklist.
   */
  readonly assumptions?: readonly string[];
}
