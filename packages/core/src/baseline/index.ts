import { z } from 'zod';
import type { RankedFinding, Worklists } from '../rank/index.js';

/**
 * The CI gate.
 *
 * Failing a build on the *existing* estate is useless - every repo fails on
 * day one and the check gets disabled by Friday. The gate fails on what is
 * NEW relative to a baseline, which is the only version of this that survives
 * contact with a real team.
 *
 * A suppression MUST carry an expiry. A suppression that never expires is a
 * lie: it says "we accept this" when it means "we forgot about this". The
 * schema will not parse one without a date, and the gate reports expiry as a
 * distinct outcome so a lapsed acceptance surfaces as a decision to remake
 * rather than as a mysterious new finding.
 */

export const MAX_SUPPRESSION_DAYS = 365;

export const SuppressionSchema = z.object({
  occurrenceId: z.string().min(1),
  /** Why this is acceptable. Not optional: an unexplained suppression is a hole. */
  reason: z.string().min(10, 'a suppression needs a reason someone can evaluate later'),
  /** Who accepted the risk. Auditable, and it names whoever must renew it. */
  approvedBy: z.string().min(1),
  expiresAt: z.string().datetime(),
});
export type Suppression = z.infer<typeof SuppressionSchema>;

export const BaselineSchema = z.object({
  version: z.literal(1),
  createdAt: z.string().datetime(),
  systemName: z.string().min(1),
  policyPackId: z.string().min(1),
  policyPackVersion: z.string().min(1),
  /**
   * Work items that existed when the baseline was taken. Stable occurrence ids
   * are what make this a set of accepted facts rather than a fingerprint that
   * invalidates on every refactor.
   */
  accepted: z.array(z.string()),
  suppressions: z.array(SuppressionSchema).default([]),
});
export type Baseline = z.infer<typeof BaselineSchema>;

export interface GateOptions {
  /** Supplied by the caller; the engine reads no clock (I7). */
  readonly now: Date;
  /** Fail on findings that are reachable but only via a published surface. */
  readonly includeLibrarySurface?: boolean;
}

export interface GateResult {
  readonly passed: boolean;
  /** New, confirmed, reachable, quantum-vulnerable work. The failure condition. */
  readonly introduced: readonly RankedFinding[];
  /** Suppressed and still within its window. */
  readonly suppressed: readonly { readonly finding: RankedFinding; readonly suppression: Suppression }[];
  /** Suppressions whose window has closed. A decision to remake, not a surprise. */
  readonly expired: readonly Suppression[];
  /** Suppressions naming work items that no longer exist. Housekeeping. */
  readonly stale: readonly Suppression[];
  /** Baseline entries no longer present - candidates for removal. */
  readonly resolved: readonly string[];
  readonly summary: string;
}

/**
 * Only CONFIRMED, reachable, quantum-vulnerable findings can fail a build.
 *
 * Each qualifier removes a category of false alarm that would otherwise get
 * the check switched off: OBSERVED evidence is not certain enough to block a
 * merge; an unreached finding is not exposure; a quantum-safe asset is
 * inventory. `rank` has already excluded the last of those.
 */
export function isBlocking(f: RankedFinding, opts: GateOptions): boolean {
  if (f.assertionLevel !== 'CONFIRMED') return false;
  if (f.reachable !== true) return false;
  if (f.reachedVia === 'LIBRARY_SURFACE' && opts.includeLibrarySurface !== true) return false;
  return true;
}

export function evaluateGate(
  worklists: Worklists,
  baseline: Baseline | null,
  opts: GateOptions,
): GateResult {
  const all = [...worklists.confidentiality, ...worklists.authenticity];
  const accepted = new Set(baseline?.accepted ?? []);
  const now = opts.now.getTime();

  const live = new Map<string, Suppression>();
  const expired: Suppression[] = [];
  const stale: Suppression[] = [];
  const present = new Set(all.map((f) => f.occurrenceId));

  for (const s of baseline?.suppressions ?? []) {
    if (Date.parse(s.expiresAt) <= now) {
      expired.push(s);
      continue;
    }
    if (!present.has(s.occurrenceId)) {
      stale.push(s);
      continue;
    }
    live.set(s.occurrenceId, s);
  }

  const blocking = all.filter((f) => isBlocking(f, opts));
  const suppressed: { finding: RankedFinding; suppression: Suppression }[] = [];
  const introduced: RankedFinding[] = [];

  for (const f of blocking) {
    const suppression = live.get(f.occurrenceId);
    if (suppression !== undefined) {
      suppressed.push({ finding: f, suppression });
      continue;
    }
    if (accepted.has(f.occurrenceId)) continue;
    introduced.push(f);
  }

  const resolved = [...accepted].filter((id) => !present.has(id)).sort();
  const passed = introduced.length === 0;

  return {
    passed,
    introduced: introduced.sort((a, b) => a.slackYears - b.slackYears),
    suppressed,
    expired: expired.sort((a, b) => a.expiresAt.localeCompare(b.expiresAt)),
    stale,
    resolved,
    summary: summarize(introduced, expired, suppressed.length, resolved.length, baseline),
  };
}

function summarize(
  introduced: readonly RankedFinding[],
  expired: readonly Suppression[],
  suppressedCount: number,
  resolvedCount: number,
  baseline: Baseline | null,
): string {
  const parts: string[] = [];
  if (baseline === null) {
    parts.push('no baseline: every confirmed reachable finding counts as new');
  }
  parts.push(
    introduced.length === 0
      ? 'no new confirmed, reachable, quantum-vulnerable work'
      : `${introduced.length} new confirmed, reachable, quantum-vulnerable work item(s)`,
  );
  if (expired.length > 0) {
    parts.push(
      `${expired.length} suppression(s) have expired and no longer apply - renew or fix, but decide`,
    );
  }
  if (suppressedCount > 0) parts.push(`${suppressedCount} suppressed and still in date`);
  if (resolvedCount > 0) parts.push(`${resolvedCount} baseline entr(ies) no longer present`);
  return parts.join('; ');
}

/** A baseline that accepts everything currently confirmed and reachable. */
export function makeBaseline(
  worklists: Worklists,
  meta: { systemName: string; createdAt: string },
  opts: GateOptions,
  carryOver: readonly Suppression[] = [],
): Baseline {
  const all = [...worklists.confidentiality, ...worklists.authenticity];
  return {
    version: 1,
    createdAt: meta.createdAt,
    systemName: meta.systemName,
    policyPackId: worklists.policyPackId,
    policyPackVersion: worklists.policyPackVersion,
    accepted: all
      .filter((f) => isBlocking(f, opts))
      .map((f) => f.occurrenceId)
      .sort(),
    // Expired suppressions are dropped rather than silently renewed: rolling
    // one forward on a baseline update is how a temporary exception becomes
    // permanent without anyone deciding to make it so.
    suppressions: carryOver
      .filter((s) => Date.parse(s.expiresAt) > opts.now.getTime())
      .sort((a, b) => a.occurrenceId.localeCompare(b.occurrenceId)),
  };
}

/** Validate a suppression at creation time, where the mistake is cheap to fix. */
export function validateSuppression(input: unknown, now: Date): Suppression {
  const s = SuppressionSchema.parse(input);
  const days = (Date.parse(s.expiresAt) - now.getTime()) / 86_400_000;
  if (days <= 0) throw new Error('a suppression that is already expired accepts nothing');
  if (days > MAX_SUPPRESSION_DAYS) {
    throw new Error(
      `a suppression may not run longer than ${MAX_SUPPRESSION_DAYS} days; ` +
        'anything longer is a decision to never fix it, and should be recorded as one',
    );
  }
  return s;
}
