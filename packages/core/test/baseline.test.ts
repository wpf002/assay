import { describe, expect, it } from 'vitest';
import {
  BaselineSchema,
  MAX_SUPPRESSION_DAYS,
  computeConfidence,
  evaluateGate,
  makeBaseline,
  makeAsset,
  rank,
  validateSuppression,
  type Evidence,
  type Modality,
  type MoscaPolicy,
  type Occurrence,
  type Suppression,
} from '../src/index.js';

const POLICY: MoscaPolicy = {
  packId: 'eo-14412',
  packVersion: '1.0.0',
  crqcYear: 2035,
  deprecateYear: 2030,
  disallowYear: 2035,
  regulatoryDeadlines: { CONFIDENTIALITY: 2031, AUTHENTICITY: 2032 },
  regulatoryAuthority: 'EO 14412 sec. 4',
  migrationYearsByControl: { SELF: 0.5, VENDOR_UPGRADEABLE: 1.5, VENDOR_LOCKED: 4, HARDWARE: 6, PROTOCOL_BILATERAL: 5 },
};

const KEX = makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT');
const SAFE = makeAsset('ML-KEM', { parameterSet: '768' }, 'KEY_ESTABLISHMENT');

const NOW = new Date('2026-08-28T00:00:00.000Z');

const ev = (modality: Modality): Evidence => ({
  modality,
  locator: 'a.ts:1',
  raw: 'x',
  collectedAt: NOW.toISOString(),
  collectorVersion: 'test',
});

const occ = (
  id: string,
  opts: {
    modalities?: Modality[];
    reachable?: boolean | null;
    via?: NonNullable<Occurrence['reachability']>['via'];
    assetId?: string;
  } = {},
): Occurrence => {
  const evidence = (opts.modalities ?? ['SOURCE_AST']).map(ev);
  const reachable = opts.reachable ?? true;
  return {
    id,
    assetId: opts.assetId ?? KEX.id,
    systemId: 'svc',
    controlClass: 'SELF',
    reachability:
      opts.reachable === null
        ? null
        : {
            reachable,
            via: opts.via ?? (reachable ? 'ENTRY_POINT' : 'NONE'),
            entryPoint: reachable ? 'src/server.ts' : null,
            path: [],
            factor: { kind: 'INFERENCE', label: 'r', value: reachable, weight: 1, sources: [] },
          },
    evidence,
    confidence: computeConfidence(evidence),
  };
};

const worklistsOf = (occurrences: Occurrence[]) =>
  rank(occurrences, [KEX, SAFE], {
    policy: POLICY,
    currentYear: 2026.66,
    secrecyLifetime: () => ({ years: 5, assumed: false }),
  });

const GATE = { now: NOW };

describe('what can fail a build', () => {
  it('fails on a new confirmed, reachable, quantum-vulnerable finding', () => {
    const r = evaluateGate(worklistsOf([occ('new')]), null, GATE);
    expect(r.passed).toBe(false);
    expect(r.introduced).toHaveLength(1);
  });

  it('does not fail on evidence that is merely OBSERVED', () => {
    // Not certain enough to block a merge. Blocking on it is how the check
    // gets switched off.
    const r = evaluateGate(worklistsOf([occ('weak', { modalities: ['NETWORK_PASSIVE'] })]), null, GATE);
    expect(r.passed).toBe(true);
  });

  it('does not fail on an unreached finding', () => {
    expect(evaluateGate(worklistsOf([occ('dead', { reachable: false })]), null, GATE).passed).toBe(true);
  });

  it('does not fail on a quantum-safe asset', () => {
    expect(evaluateGate(worklistsOf([occ('pq', { assetId: SAFE.id })]), null, GATE).passed).toBe(true);
  });

  it('does not fail on published-surface reachability unless asked', () => {
    const w = worklistsOf([occ('lib', { via: 'LIBRARY_SURFACE' })]);
    expect(evaluateGate(w, null, GATE).passed).toBe(true);
    expect(evaluateGate(w, null, { ...GATE, includeLibrarySurface: true }).passed).toBe(false);
  });
});

describe('the baseline is what makes this survivable', () => {
  it('passes on an estate that was already there', () => {
    const w = worklistsOf([occ('existing')]);
    const baseline = makeBaseline(w, { systemName: 'svc', createdAt: NOW.toISOString() }, GATE);
    expect(baseline.accepted).toEqual(['existing']);
    expect(evaluateGate(w, baseline, GATE).passed).toBe(true);
  });

  it('still fails when something new arrives alongside the accepted estate', () => {
    const before = worklistsOf([occ('existing')]);
    const baseline = makeBaseline(before, { systemName: 'svc', createdAt: NOW.toISOString() }, GATE);
    const after = worklistsOf([occ('existing'), occ('brand-new')]);
    const r = evaluateGate(after, baseline, GATE);
    expect(r.passed).toBe(false);
    expect(r.introduced.map((f) => f.occurrenceId)).toEqual(['brand-new']);
  });

  it('does not report a live acceptance as resolved because the finding is unreached today', () => {
    // Presence in the estate and presence in the worklist are different
    // predicates. Telling the operator to prune both is how the risk acceptance
    // and its approver disappear, and the next scan that finds the occurrence
    // reachable again fails the build on it as newly introduced.
    const live: Suppression = {
      occurrenceId: 'dormant',
      reason: 'vendor appliance, replacement scheduled for Q1',
      approvedBy: 'ciso@example.com',
      expiresAt: '2026-12-01T00:00:00.000Z',
    };
    const w = worklistsOf([occ('dormant', { reachable: false })]);
    const baseline = {
      ...makeBaseline(w, { systemName: 'svc', createdAt: NOW.toISOString() }, GATE),
      accepted: ['dormant'],
      suppressions: [live],
    };
    const r = evaluateGate(w, baseline, GATE);
    expect(w.unreached.map((f) => f.occurrenceId)).toEqual(['dormant']);
    expect(r.stale).toEqual([]);
    expect(r.resolved).toEqual([]);
  });

  it('reports baseline entries that are gone, so the file can shrink', () => {
    const before = worklistsOf([occ('a'), occ('b')]);
    const baseline = makeBaseline(before, { systemName: 'svc', createdAt: NOW.toISOString() }, GATE);
    const r = evaluateGate(worklistsOf([occ('a')]), baseline, GATE);
    expect(r.resolved).toEqual(['b']);
  });
});

describe('a suppression that never expires is a lie', () => {
  const live: Suppression = {
    occurrenceId: 'risky',
    reason: 'vendor appliance, replacement scheduled for Q1',
    approvedBy: 'ciso@example.com',
    expiresAt: '2026-12-01T00:00:00.000Z',
  };

  it('refuses to parse a suppression with no expiry', () => {
    const { expiresAt, ...noExpiry } = live;
    expect(expiresAt).toBeTruthy();
    expect(BaselineSchema.safeParse({
      version: 1,
      createdAt: NOW.toISOString(),
      systemName: 's',
      policyPackId: 'p',
      policyPackVersion: '1',
      accepted: [],
      suppressions: [noExpiry],
    }).success).toBe(false);
  });

  it('refuses a suppression with no reason anyone could evaluate later', () => {
    expect(() => validateSuppression({ ...live, reason: 'ok' }, NOW)).toThrow();
  });

  it('refuses one that outlives a year', () => {
    expect(() =>
      validateSuppression({ ...live, expiresAt: '2030-01-01T00:00:00.000Z' }, NOW),
    ).toThrow(new RegExp(String(MAX_SUPPRESSION_DAYS)));
  });

  it('refuses one that is already expired', () => {
    expect(() => validateSuppression({ ...live, expiresAt: '2026-01-01T00:00:00.000Z' }, NOW)).toThrow();
  });

  it('suppresses while in date', () => {
    const w = worklistsOf([occ('risky')]);
    const baseline = { ...makeBaseline(w, { systemName: 'svc', createdAt: NOW.toISOString() }, GATE), accepted: [], suppressions: [live] };
    const r = evaluateGate(w, baseline, GATE);
    expect(r.passed).toBe(true);
    expect(r.suppressed[0]?.suppression.approvedBy).toBe('ciso@example.com');
  });

  it('fails once the window closes, and says the suppression expired', () => {
    const w = worklistsOf([occ('risky')]);
    const baseline = {
      ...makeBaseline(w, { systemName: 'svc', createdAt: NOW.toISOString() }, GATE),
      accepted: [],
      suppressions: [{ ...live, expiresAt: '2026-08-01T00:00:00.000Z' }],
    };
    const r = evaluateGate(w, baseline, GATE);
    expect(r.passed).toBe(false);
    expect(r.expired).toHaveLength(1);
    // The distinction matters: this is a lapsed decision, not a new finding.
    expect(r.summary).toContain('expired');
  });

  it('reports a suppression whose work item no longer exists', () => {
    const w = worklistsOf([occ('other')]);
    const baseline = {
      ...makeBaseline(w, { systemName: 'svc', createdAt: NOW.toISOString() }, GATE),
      suppressions: [live],
    };
    expect(evaluateGate(w, baseline, GATE).stale.map((s) => s.occurrenceId)).toEqual(['risky']);
  });

  it('never rolls an expired suppression forward on a baseline update', () => {
    // Renewing silently is how a temporary exception becomes permanent
    // without anyone deciding to make it so.
    const w = worklistsOf([occ('risky')]);
    const updated = makeBaseline(w, { systemName: 'svc', createdAt: NOW.toISOString() }, GATE, [
      { ...live, expiresAt: '2026-08-01T00:00:00.000Z' },
      live,
    ]);
    expect(updated.suppressions).toHaveLength(1);
    expect(updated.suppressions[0]?.expiresAt).toBe(live.expiresAt);
  });
});
