import type { Factor } from '../types/factor.js';
import { trackFor, type ControlClass, type Purpose, type UrgencyTrack } from '../types/crypto-asset.js';

/**
 * Ranking. Two constraints, whichever binds first.
 *
 * 1. PHYSICS - Mosca's inequality.  X + Y > Z  =>  already late.
 *      X = years the data must remain confidential (0 on the authenticity track)
 *      Y = years to complete migration, derived from ControlClass
 *      Z = years until a cryptographically relevant quantum computer
 *
 * 2. REGULATION - a fixed completion date.  Y > (D - now)  =>  already late.
 *      X does not appear. A regulator setting 2030-12-31 does not care how long
 *      your data stays secret; you must be migrated by the date either way.
 *
 * EO 14412 (signed 2026-06-22) sets D = 2030-12-31 for key establishment and
 * 2031-12-31 for digital signatures. For anyone in federal or contractor scope
 * that lands 4-5 years ahead of any credible CRQC horizon, which makes the
 * regulatory term the binding one and the physics term the backstop. Ranking on
 * the CRQC year alone - as this project originally did, and as most of the
 * field still does - understates urgency by roughly half a decade.
 *
 * Both are computed. `bindingConstraint` names which one produced the answer,
 * because "we are late because of the EO" and "we are late because of Shor" are
 * different conversations with different people.
 */

export interface MoscaPolicy {
  readonly packId: string;
  readonly packVersion: string;
  /**
   * Whether the horizon in this pack is attributable to a publisher
   * (decision D3). An unsigned or edited horizon still ranks, but it enters
   * the derivation as an ASSUMPTION rather than a POLICY, so a reader can see
   * that this finding is not comparable with one ranked under a signed pack.
   */
  readonly trust?: 'SIGNED' | 'UNSIGNED' | 'UNTRUSTED';
  /** Decimal year at which a CRQC is assumed to exist. Policy input, not a truth claim. */
  readonly crqcYear: number;
  readonly deprecateYear: number;
  readonly disallowYear: number;
  /** Completion deadlines by track, as decimal years. null = this pack asserts none. */
  readonly regulatoryDeadlines: Readonly<Record<UrgencyTrack, number | null>>;
  /** Citation for the deadline, e.g. "EO 14412 sec. 4(b)(i)". Rendered in the derivation. */
  readonly regulatoryAuthority: string | null;
  readonly migrationYearsByControl: Readonly<Record<ControlClass, number>>;
}

export interface MoscaInput {
  readonly purpose: Purpose;
  readonly controlClass: ControlClass;
  /** Years the data must stay confidential. Ignored on the authenticity track. */
  readonly secrecyLifetimeYears: number;
  /**
   * True when secrecyLifetimeYears came from an operator rather than from a
   * data-classification source. Marks X as an ASSUMPTION in the ranking tree.
   *
   * Note this does NOT downgrade the assertion level: I6 gates export tier on
   * the CONFIDENCE tree, which answers "is this crypto really here". Whether
   * the estate guessed its own retention policy is a separate question, and
   * conflating them would make every ranked finding unconfirmable.
   */
  readonly secrecyLifetimeAssumed?: boolean;
  /** Decimal year, supplied by the caller. Core reads no clock (I7). */
  readonly currentYear: number;
  readonly policy: MoscaPolicy;
  /**
   * Y, overridden by something the estate actually knows.
   *
   * The policy default is a class average: VENDOR_LOCKED means "four years,
   * probably". When a vendor states a date - "PQ support in 2029Q2" - that is
   * a better Y for this specific product, and it is the term the whole ranking
   * turns on. It arrives with its own provenance, and an unverified vendor
   * claim taints the ranking derivation accordingly.
   */
  readonly migrationYearsOverride?: {
    readonly years: number;
    readonly label: string;
    readonly kind: Factor['kind'];
  };
}

export interface ConstraintResult {
  readonly horizonYears: number;
  readonly slackYears: number;
  readonly late: boolean;
}

export interface MoscaResult {
  readonly urgencyTrack: UrgencyTrack;
  readonly x: number;
  readonly y: number;
  readonly crqc: ConstraintResult;
  readonly regulatory: (ConstraintResult & { readonly deadlineYear: number }) | null;
  readonly bindingConstraint: 'CRQC' | 'REGULATORY';
  /** Slack under the binding constraint. Negative => already late. */
  readonly slackYears: number;
  readonly late: boolean;
  readonly factor: Factor;
}

const leaf = (kind: Factor['kind'], label: string, value: number | string): Factor => ({
  kind,
  label,
  value,
  weight: 1,
  sources: [],
});

export function scoreMosca(input: MoscaInput): MoscaResult {
  const { purpose, controlClass, secrecyLifetimeYears, currentYear, policy } = input;
  const track = trackFor(purpose);

  // Authenticity is not retroactively breakable: a signature forgeable in 2033
  // is a 2033 problem. X collapses to zero rather than to the archive lifetime.
  const x = track === 'CONFIDENTIALITY' ? secrecyLifetimeYears : 0;
  const override = input.migrationYearsOverride;
  const y = override?.years ?? policy.migrationYearsByControl[controlClass];

  const zCrqc = round2(policy.crqcYear - currentYear);
  const crqc: ConstraintResult = {
    horizonYears: zCrqc,
    slackYears: round2(zCrqc - (x + y)),
    late: zCrqc - (x + y) < 0,
  };

  const deadlineYear = policy.regulatoryDeadlines[track];
  const regulatory =
    deadlineYear === null
      ? null
      : {
          deadlineYear,
          horizonYears: round2(deadlineYear - currentYear),
          slackYears: round2(deadlineYear - currentYear - y),
          late: deadlineYear - currentYear - y < 0,
        };

  const bindingConstraint: MoscaResult['bindingConstraint'] =
    regulatory !== null && regulatory.slackYears <= crqc.slackYears ? 'REGULATORY' : 'CRQC';
  const binding = bindingConstraint === 'REGULATORY' ? (regulatory as ConstraintResult) : crqc;

  const xFactor: Factor = input.secrecyLifetimeAssumed
    ? leaf(
        'ASSUMPTION',
        `X secrecy lifetime (${track}) - operator-supplied, unverified`,
        x,
      )
    : leaf('INFERENCE', `X secrecy lifetime (${track})`, x);

  const yFactor =
    override === undefined
      ? leaf(
          'POLICY',
          `Y migration years [${controlClass}] @ ${policy.packId}@${policy.packVersion}`,
          y,
        )
      : {
          kind: override.kind,
          label: `Y migration years [${controlClass}] overridden: ${override.label}`,
          value: y,
          weight: 1,
          sources: [
            leaf(
              'POLICY',
              `class default would have been ${policy.migrationYearsByControl[controlClass]} @ ${policy.packId}@${policy.packVersion}`,
              policy.migrationYearsByControl[controlClass],
            ),
          ],
        };

  // A horizon nobody signed is an opinion, and the tree says so.
  const horizonKind: Factor['kind'] =
    policy.trust === undefined || policy.trust === 'SIGNED' ? 'POLICY' : 'ASSUMPTION';
  const trustSuffix =
    horizonKind === 'POLICY' ? '' : ` [${policy.trust ?? 'UNSIGNED'}: horizon not attributable]`;

  const crqcFactor: Factor = {
    kind: 'INFERENCE',
    label: 'slack under CRQC horizon (Z - (X + Y))',
    value: crqc.slackYears,
    weight: 1,
    sources: [
      xFactor,
      yFactor,
      leaf(
        horizonKind,
        `Z CRQC year ${policy.crqcYear} @ ${policy.packId}@${policy.packVersion}${trustSuffix}`,
        zCrqc,
      ),
    ],
  };

  const sources: Factor[] = [crqcFactor];
  if (regulatory !== null) {
    sources.push({
      kind: 'INFERENCE',
      label: 'slack under regulatory deadline (D - now - Y); X does not apply to a fixed date',
      value: regulatory.slackYears,
      weight: 1,
      sources: [
        yFactor,
        leaf(
          horizonKind,
          `D deadline ${regulatory.deadlineYear} for ${track} per ${
            policy.regulatoryAuthority ?? 'unattributed policy'
          } @ ${policy.packId}@${policy.packVersion}${trustSuffix}`,
          regulatory.horizonYears,
        ),
      ],
    });
  }

  return {
    urgencyTrack: track,
    x,
    y,
    crqc,
    regulatory,
    bindingConstraint,
    slackYears: binding.slackYears,
    late: binding.late,
    factor: {
      kind: 'INFERENCE',
      label: `mosca slack (${track}), binding constraint: ${bindingConstraint}`,
      value: binding.slackYears,
      weight: 1,
      sources,
    },
  };
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
