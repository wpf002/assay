import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Coverage as CoveragePanel } from '@/components/Coverage';
import { Masthead } from '@/components/Masthead';
import { CONTROL, actionNext, duration } from '@/lib/format';
import {
  ESTATE_SCAN,
  Unauthorized,
  getCoverage,
  getEstate,
  getRerank,
  getTickets,
  getWorklists,
  type Coverage,
  type PolicyPack,
  type RankedFinding,
  type ScanSummary,
  type Worklists,
} from '@/lib/api';

/**
 * A labelled control. Native selects and number inputs render with the
 * operating system's own chrome, which on a dark surface looks like a browser
 * dialog someone left open. The label also removes the need to explain what
 * each dropdown is by padding its options with prose.
 */
function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}

/**
 * A number input with its own steppers.
 *
 * The native spinner cannot be themed - it is drawn by the platform, sits in
 * its own tiny hit area, and is the one control on the page that looks like it
 * belongs to a different application.
 */
function Stepper({
  value,
  min,
  max,
  onChange,
}: {
  value: number;
  min: number;
  max: number;
  onChange: (n: number) => void;
}) {
  const clamp = (n: number): number => Math.min(max, Math.max(min, n));
  return (
    <span className="stepper">
      <input
        type="number"
        inputMode="numeric"
        value={value}
        min={min}
        max={max}
        onChange={(e) => onChange(clamp(Number(e.target.value)))}
      />
      <span className="unit">years</span>
      <span className="arrows">
        <button type="button" aria-label="Increase" onClick={() => onChange(clamp(value + 1))}>
          <svg viewBox="0 0 10 6" aria-hidden="true">
            <path d="M1 5L5 1l4 4" />
          </svg>
        </button>
        <button type="button" aria-label="Decrease" onClick={() => onChange(clamp(value - 1))}>
          <svg viewBox="0 0 10 6" aria-hidden="true">
            <path d="M1 1l4 4 4-4" />
          </svg>
        </button>
      </span>
    </span>
  );
}

/** Sentinel for the estate view: every system at once, correlated by traces. */
const ESTATE = ESTATE_SCAN;
import { Worklist } from './Worklist';
import { domainYears } from './Timeline';

/**
 * The screen nobody else builds.
 *
 * Two ranked worklists that are never merged, one derived headline number, and
 * a policy pack switcher that re-ranks live and marks every row that moved.
 * Changing the pack changes the arithmetic and nothing else, so a moved row is
 * attributable to policy rather than to the estate - which turns the argument
 * about whose deadline applies into a control instead of a footnote.
 */
/**
 * The two dates the active pack actually sets, and how long is left.
 *
 * These were reachable only by reading a dropdown option label and a caveat
 * paragraph at the bottom of the page. They are the reason anyone is on this
 * screen, so they sit above the findings, with the authority that imposes them
 * printed underneath rather than three screens away.
 */
function DeadlineBand({
  pack,
  currentYear,
  counts,
}: {
  pack: PolicyPack;
  currentYear: number;
  /** Confirmed rows and confirmed-overdue rows, per track. Never pooled. */
  counts: Record<Track, { confirmed: number; late: number }>;
}) {
  const rows: { k: string; year: number; track: Track }[] = [];
  const c = pack.regulatoryDeadlines.CONFIDENTIALITY;
  const a = pack.regulatoryDeadlines.AUTHENTICITY;
  if (typeof c === 'number')
    rows.push({ k: 'Key Exchange And Encryption', year: c, track: 'CONFIDENTIALITY' });
  if (typeof a === 'number')
    rows.push({ k: 'Signatures And Certificates', year: a, track: 'AUTHENTICITY' });

  return (
    <div className="band">
      <span className="band-label">Deadlines In This Pack</span>
      {rows.length === 0 ? (
        <p className="band-source">
          This pack sets no regulatory deadline. Every date below comes from its assumed quantum
          horizon of {pack.crqcYear}.
        </p>
      ) : (
        <>
          {rows.map((r) => (
            <span className="band-row" key={r.k}>
              <span className="k">{r.k}</span>
              <span className="d">{Math.floor(r.year) - 1}-12-31</span>
              <span className="r">{remaining(r.year, currentYear)}</span>
              {/* Counted per track and over confirmed rows only. One pooled
                  figure here would re-merge exactly what the two tracks exist
                  to keep apart, and would disagree with the numerator beside
                  it, which counts confirmed rows too. */}
              <span className={`n ${counts[r.track].late > 0 ? 'late' : ''}`}>
                {counts[r.track].late} of {counts[r.track].confirmed} confirmed overdue
              </span>
            </span>
          ))}
          {pack.regulatoryAuthority !== null && (
            <p className="band-source">{pack.regulatoryAuthority}</p>
          )}
        </>
      )}
    </div>
  );
}

/**
 * Time to a deadline, against the engine's own clock rather than the browser's.
 *
 * currentYear is the decimal year the ranking was computed at, so the band and
 * the rows cannot disagree about what day it is.
 */
function remaining(deadlineYear: number, currentYear: number): string {
  const total = deadlineYear - currentYear;
  const abs = Math.abs(total);
  let years = Math.floor(abs);
  let months = Math.round((abs - years) * 12);
  if (months === 12) {
    years += 1;
    months = 0;
  }
  if (years === 0 && months === 0) return total < 0 ? 'Past' : 'Less than a month left';
  const parts = [
    years === 0 ? '' : `${years} year${years === 1 ? '' : 's'}`,
    months === 0 ? '' : `${months} month${months === 1 ? '' : 's'}`,
  ].filter((x) => x !== '');
  return `${parts.join(', ')}${total < 0 ? ' past' : ' left'}`;
}

type Track = RankedFinding['track'];

/** Confirmed, and confirmed-and-overdue, for one track. */
function tally(rs: readonly RankedFinding[]): { confirmed: number; late: number } {
  const confirmed = rs.filter((f) => f.assertionLevel === 'CONFIRMED');
  return { confirmed: confirmed.length, late: confirmed.filter((f) => f.late).length };
}

/** Everything this scan turned up, across all four buckets the endpoint returns. */
function found(w: Worklists): number {
  return (
    w.confidentiality.length + w.authenticity.length + w.unreached.length + w.hints.length
  );
}

/**
 * How the four buckets add up, so the reader can see that the two lists below
 * are not the whole scan. A clause is dropped rather than printed as zero.
 */
function receiptTail(w: Worklists): string {
  const onLists = w.confidentiality.length + w.authenticity.length;
  const clauses = [
    onLists === 0 ? '' : `${onLists} on the worklists below`,
    w.unreached.length === 0 ? '' : `${w.unreached.length} that nothing serving traffic calls`,
    w.hints.length === 0 ? '' : `${w.hints.length} with evidence too weak to call a work item`,
  ].filter((x) => x !== '');
  return clauses.length === 0 ? '.' : `: ${clauses.join(', ')}.`;
}

/** The rows a control-class filter leaves visible. */
function visible(findings: RankedFinding[], controlFilter: string | null): RankedFinding[] {
  return controlFilter === null ? findings : findings.filter((f) => f.controlClass === controlFilter);
}

export function Dashboard({
  scans,
  packs,
  initialPack,
  onSignOut,
  onTokenRejected,
}: {
  scans: ScanSummary[];
  packs: PolicyPack[];
  initialPack: string;
  onSignOut: () => void;
  /** A token revoked mid-session is a sign-in problem, not an outage. */
  onTokenRejected: () => void;
}) {
  // Default to the estate once there is more than one system: a per-scan view
  // of a signing service is exactly the answer that misses the point.
  const [scanId, setScanId] = useState(
    new Set(scans.map((s) => s.systemName)).size > 1 ? ESTATE : (scans[0]?.id ?? ''),
  );
  const [pack, setPack] = useState(initialPack);
  const [secrecyYears, setSecrecyYears] = useState(5);
  const [worklists, setWorklists] = useState<Worklists | null>(null);
  const [estate, setEstate] = useState<{
    systems: number;
    /** The most recent scan across the estate, so the receipt can date itself. */
    newest: string;
    promoted: { systemId: string; occurrences: number }[];
    traceWindow: string | null;
  } | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [coverageError, setCoverageError] = useState<string | null>(null);
  const [moved, setMoved] = useState<Map<string, { before: number; after: number }>>(new Map());
  const [error, setError] = useState<string | null>(null);
  const [comparePack, setComparePack] = useState<string>('');
  /** Set by the What To Do Next strip; filters both worklists to one control class. */
  const [controlFilter, setControlFilter] = useState<string | null>(null);

  useEffect(() => {
    if (scanId === '') return;
    let cancelled = false;
    setError(null);
    // Everything below is derived from the controls that just moved. Holding
    // the previous selection's rows on screen while the new ones load - and
    // permanently if the fetch fails - is the one thing this page must not do,
    // since a difference is only attributable to policy if the numbers under
    // the labels were computed from them.
    setWorklists(null);
    setEstate(null);
    setCoverage(null);
    setCoverageError(null);
    setControlFilter(null);

    if (scanId === ESTATE) {
      Promise.all([
        getEstate(pack, secrecyYears),
        // A failure here is not "there is nothing unscanned" - dropping the
        // warning silently is the one way this panel can be actively wrong.
        getCoverage().then(
          (c) => ({ ok: true as const, c }),
          (err: unknown) => ({ ok: false as const, err }),
        ),
      ])
        .then(([e, cov]) => {
          if (cancelled) return;
          setWorklists(e.worklists);
          setEstate({
            systems: e.systems.length,
            newest: e.systems.reduce((a, b) => (b.startedAt > a ? b.startedAt : a), '').slice(0, 10),
            promoted: e.promotedBySystem,
            traceWindow:
              e.traces === null
                ? null
                : `${e.traces.window.from.slice(0, 10)} to ${e.traces.window.to.slice(0, 10)} from ${e.traces.source}`,
          });
          if (cov.ok) {
            setCoverage(cov.c);
            setCoverageError(null);
          } else if (cov.err instanceof Unauthorized) {
            // Coverage needs an unscoped operator; a viewer simply cannot see it.
            setCoverage(null);
            setCoverageError(
              'This token cannot read the coverage report. It needs an unscoped operator token.',
            );
          } else {
            setCoverage(null);
            setCoverageError(
              `Coverage did not load (${cov.err instanceof Error ? cov.err.message : String(cov.err)}). Services with no scan at all are missing from the lists below.`,
            );
          }
        })
        .catch((err: unknown) => {
          if (cancelled) return;
          if (err instanceof Unauthorized) return onTokenRejected();
          setError(err instanceof Error ? err.message : String(err));
        });
      return () => {
        cancelled = true;
      };
    }

    getWorklists(scanId, pack, secrecyYears)
      .then((w) => {
        if (!cancelled) setWorklists(w);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof Unauthorized) return onTokenRejected();
        setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, pack, secrecyYears]);

  useEffect(() => {
    if (scanId === '' || scanId === ESTATE || comparePack === '' || comparePack === pack) {
      setMoved(new Map());
      return;
    }
    let cancelled = false;
    getRerank(scanId, comparePack, pack, secrecyYears)
      .then((r) => {
        if (cancelled) return;
        setMoved(new Map(r.moved.map((m) => [m.occurrenceId, m.slackYears])));
      })
      .catch(() => setMoved(new Map()));
    return () => {
      cancelled = true;
    };
  }, [scanId, pack, comparePack, secrecyYears]);

  const activePack = useMemo(() => packs.find((p) => p.packId === pack) ?? null, [packs, pack]);
  const comparePackTitle = useMemo(
    () => packs.find((p) => p.packId === comparePack)?.title ?? null,
    [packs, comparePack],
  );

  /**
   * Everything the verdict block and the What To Do Next strip count.
   *
   * Only the two worklists: unreached and hints are deliberately excluded from
   * every figure at the top of the page, the same way rank() excludes them from
   * the headline. Counting them here would make the strip disagree with the
   * sentence above it.
   */
  const rows = useMemo(
    () => (worklists === null ? [] : [...worklists.confidentiality, ...worklists.authenticity]),
    [worklists],
  );
  const observedOnly = rows.filter((f) => f.assertionLevel !== 'CONFIRMED').length;
  const overdueByControl = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of rows) {
      if (!f.late || f.assertionLevel !== 'CONFIRMED') continue;
      m.set(f.controlClass, (m.get(f.controlClass) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [rows]);

  /**
   * One x-axis for the whole page. The two worklists sit side by side, so
   * per-track domains would stand two differently scaled rulers next to each
   * other and invite exactly the comparison they cannot support.
   */
  const domain = useMemo(() => domainYears(rows), [rows]);
  const trackCounts = useMemo(
    () => ({
      CONFIDENTIALITY: tally(worklists?.confidentiality ?? []),
      AUTHENTICITY: tally(worklists?.authenticity ?? []),
    }),
    [worklists],
  );

  const selectedScan = scans.find((s) => s.id === scanId) ?? null;

  async function exportTickets() {
    try {
      const data = await getTickets(scanId, pack, secrecyYears);
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
      );
      const a = document.createElement('a');
      a.href = url;
      a.download = `assay-tickets-${scanId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      if (e instanceof Unauthorized) return onTokenRejected();
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  if (scans.length === 0) {
    return (
      <div className="wrap">
        <header className="top">
          <div className="top-title">
            <Masthead />
            <button type="button" className="ghost" onClick={onSignOut}>
              Sign Out
            </button>
          </div>
        </header>
        <p className="aside">
          No scans yet. Run <code>assay push &lt;path&gt;</code> to scan a repository and send the
          evidence here.
        </p>
      </div>
    );
  }

  return (
    <div className="wrap">
      <header className="top">
        <div className="top-title">
          <Masthead>
            {worklists !== null && (
              <p className="receipt">
                {scanId === ESTATE && estate !== null
                  ? `Read ${estate.systems} system${estate.systems === 1 ? '' : 's'}, most recently on ${estate.newest}. `
                  : selectedScan === null
                    ? ''
                    : `Read ${selectedScan.systemName}, scanned ${selectedScan.startedAt.slice(0, 10)}. `}
                {found(worklists)} uses of cryptography a quantum computer breaks
                {receiptTail(worklists)}
              </p>
            )}
          </Masthead>
          <button type="button" className="ghost" onClick={onSignOut}>
            Sign Out
          </button>
        </div>

        {/* Named, because every figure on the page is a function of these four
            and a reader who does not know that reads the numbers as measured. */}
        <div className="controls-group">
          <span className="controls-label">Ranking Inputs</span>
          <div className="controls">
            <Field label="Scope">
              <select value={scanId} onChange={(e) => setScanId(e.target.value)} aria-label="Scope">
                {/* The code says estate throughout: ESTATE_SCAN, /estate/*, rankEstate. */}
                <option value={ESTATE}>All Systems</option>
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.systemName}, scanned {s.startedAt.slice(0, 10)}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Policy Pack">
              <select
                value={pack}
                onChange={(e) => setPack(e.target.value)}
                aria-label="Policy Pack"
              >
                {packs.map((p) => (
                  <option key={p.packId} value={p.packId}>
                    {p.title}
                    {p.trust === 'SIGNED' ? '' : p.trust === 'UNSIGNED' ? ' (Unsigned)' : ' (Untrusted)'}
                  </option>
                ))}
              </select>
            </Field>

            <Field label="Compare With">
              <select
                value={comparePack}
                onChange={(e) => setComparePack(e.target.value)}
                aria-label="Compare With"
              >
                <option value="">No Comparison</option>
                {packs
                  .filter((p) => p.packId !== pack)
                  .map((p) => (
                    <option key={p.packId} value={p.packId}>
                      {p.title}
                    </option>
                  ))}
              </select>
            </Field>

            <Field label="Secrecy Lifetime">
              <Stepper value={secrecyYears} min={0} max={50} onChange={setSecrecyYears} />
            </Field>
          </div>
          <p className="controls-note">
            Every number below is computed from these. Change one and the page recomputes.
          </p>
        </div>
      </header>

      {error !== null && <p className="aside">Cannot reach the API: {error}</p>}

      {worklists === null && error === null && <p className="aside">Loading the worklists.</p>}

      {worklists !== null && (
        <>
          {/* One instrument cluster: the computed conclusion on the left, the
              reference table it is measured against on the right. They were two
              stacked full-width slabs wearing the identical costume, which is
              what a verdict and a lookup table look like when layout is asked
              to say nothing and colour is left to arbitrate. */}
          <div className="readout">
            {/* The numeral is lifted out of the sentence so it can hang in the
                margin. Set inline at 34px inside a 16.5px line box it was 1.47x
                its own leading and could only read as a mistake. */}
            <div className={`headline ${worklists.headline.numerator > 0 ? 'late' : ''}`}>
              {worklists.headline.denominator > 0 && worklists.headline.numerator > 0 && (
                <span className="big">{worklists.headline.numerator}</span>
              )}
              <p className="verdict">
                {worklists.headline.denominator === 0
                  ? 'Nothing on these worklists is confirmed yet.'
                  : worklists.headline.numerator === 0
                    ? `None of the ${worklists.headline.denominator} confirmed uses of breakable cryptography are overdue yet.`
                    : `of ${worklists.headline.denominator} confirmed uses of breakable cryptography are already overdue for replacement.`}
              </p>
              {worklists.headline.denominator > 0 && (
                <p className="defines">
                  Confirmed means the evidence carries no assumption in it and clears the confidence
                  bar. Overdue means starting today does not finish the replacement before the date
                  that binds it, and on the key exchange list the secrecy lifetime is part of that
                  date.
                </p>
              )}
              {observedOnly > 0 && (
                <p className="excluded">
                  {observedOnly} further row{observedOnly === 1 ? ' is' : 's are'} listed below as
                  observed, not confirmed. They are not counted here, because that evidence is not
                  certain enough to commit to.
                </p>
              )}
            </div>

            {activePack !== null && (
              <DeadlineBand
                pack={activePack}
                currentYear={worklists.currentYear}
                counts={trackCounts}
              />
            )}
          </div>

          {overdueByControl.length > 0 && (
            <section className="next">
              <h2>What To Do Next</h2>
              <div className="groups">
                {overdueByControl.map(([cc, n]) => {
                  const y = activePack?.migrationYearsByControl[cc];
                  return (
                    <button
                      key={cc}
                      type="button"
                      aria-pressed={controlFilter === cc}
                      onClick={() => setControlFilter(controlFilter === cc ? null : cc)}
                    >
                      <span className="cc">{CONTROL[cc] ?? cc}</span>
                      <span className="n">{n} overdue</span>
                      <span className="clause">
                        {y === undefined ? '' : `${duration(y)} to replace under this pack. `}
                        {actionNext(cc)}
                      </span>
                    </button>
                  );
                })}
              </div>
              {controlFilter !== null && (
                <div className="filter-row">
                  <button type="button" className="ghost" onClick={() => setControlFilter(null)}>
                    Clear Filter
                  </button>
                  <span className="filter-note">
                    Showing every item controlled by {CONTROL[controlFilter] ?? controlFilter}, not
                    only the overdue ones.
                  </span>
                </div>
              )}
            </section>
          )}

          <div className="tracks-head">
            <div className="export">
              <button
                type="button"
                className="ghost"
                disabled={scanId === ESTATE}
                title={
                  scanId === ESTATE
                    ? 'Ticket export runs on one system. Pick a system in Scope.'
                    : ''
                }
                onClick={() => void exportTickets()}
              >
                Export Tickets
              </button>
              <span className="export-note">
                {scanId === ESTATE
                  ? 'Ticket export runs on one system. Pick a system in Scope.'
                  : 'Confirmed items only, up to 200, ranked as shown.'}
              </span>
            </div>
          </div>

          <div className="tracks">
            <Worklist
              kicker="Confidentiality Track"
              title="Key Exchange And Encryption"
              subtitle="Traffic captured today can be decrypted once a quantum computer exists. This clock has already started."
              findings={visible(worklists.confidentiality, controlFilter)}
              scanId={scanId}
              pack={pack}
              moved={moved}
              secrecyYears={secrecyYears}
              showSystem={estate !== null}
              crqcYear={activePack?.crqcYear ?? null}
              compareTitle={comparePackTitle}
              domain={domain}
            />
            <Worklist
              kicker="Authenticity Track"
              title="Signatures And Certificates"
              subtitle="Nothing is at risk until a quantum computer exists. After that, anything signed with this can be forged."
              findings={visible(worklists.authenticity, controlFilter)}
              scanId={scanId}
              pack={pack}
              moved={moved}
              secrecyYears={secrecyYears}
              showSystem={estate !== null}
              crqcYear={activePack?.crqcYear ?? null}
              compareTitle={comparePackTitle}
              domain={domain}
            />
          </div>

          {estate !== null && estate.promoted.length > 0 && (
            <p className="aside">
              <strong>Found through traces:</strong>{' '}
              {estate.promoted.map((p) => `${p.systemId} (${p.occurrences})`).join(', ')}. A
              repository scan alone would have missed these, because the caller is a different
              service.
            </p>
          )}

          {coverageError !== null && <p className="aside">{coverageError}</p>}
          {coverage !== null && coverage.unscanned.length > 0 && (
            <p className="caveat caveat-warn">
              <strong>Never scanned:</strong> {coverage.unscanned.join(', ')}. Seen in live
              traffic, with no inventory of any kind.
            </p>
          )}

          <CoveragePanel scanId={scanId} />

          {/* Four unrelated notes that used to stack down the left margin with
              the right half of the screen empty. One band, in columns. */}
          <div className="footnotes">
            <details className="notes" open>
              <summary>
                Not Counted Above ({worklists.unreached.length} unreachable,{' '}
                {worklists.hints.length} library hints)
              </summary>
              <p>
                <strong>Unreachable.</strong> Found in the code, but nothing that serves traffic
                calls it. Test fixtures and dead modules land here.
              </p>
              <p>
                <strong>Library hints.</strong> A dependency that <em>can</em> do this, with no
                call site found. Somewhere to go looking, not a work item.
              </p>
            </details>

            {activePack !== null && activePack.trust !== 'SIGNED' && (
              <p className="caveat" style={{ color: 'var(--policy)' }}>
                <span className="footnote-title">Unsigned Pack</span>
                This pack is {activePack.trust.toLowerCase()}: {activePack.trustReason}. The
                arithmetic is unchanged, but do not compare these dates with a ranking produced
                under a signed pack.
              </p>
            )}

            {/* Shipped figures are inputs, not truth claims. The reader of a
                deadline the whole ranking turns on is the one who needs to know
                what its publisher was unsure about. */}
            {activePack !== null && activePack.caveats.length > 0 && (
              <div className="caveat">
                <span className="footnote-title">What This Pack Is Unsure Of</span>
                {activePack.caveats.map((c) => (
                  <p key={c}>{c}</p>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
