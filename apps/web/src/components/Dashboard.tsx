import { useEffect, useMemo, useState } from 'react';
import {
  ESTATE_SCAN,
  getCoverage,
  getEstate,
  getRerank,
  getWorklists,
  type Coverage,
  type PolicyPack,
  type ScanSummary,
  type Worklists,
} from '@/lib/api';

/** Sentinel for the estate view: every system at once, correlated by traces. */
const ESTATE = ESTATE_SCAN;
import { Worklist } from './Worklist';

/**
 * The screen nobody else builds.
 *
 * Two ranked worklists that are never merged, one derived headline number, and
 * a policy pack switcher that re-ranks live and marks every row that moved.
 * Changing the pack changes the arithmetic and nothing else, so a moved row is
 * attributable to policy rather than to the estate - which turns the argument
 * about whose deadline applies into a control instead of a footnote.
 */
export function Dashboard({
  scans,
  packs,
  initialPack,
}: {
  scans: ScanSummary[];
  packs: PolicyPack[];
  initialPack: string;
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
    promoted: { systemId: string; occurrences: number }[];
    traceWindow: string | null;
  } | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [moved, setMoved] = useState<Map<string, { before: number; after: number }>>(new Map());
  const [error, setError] = useState<string | null>(null);
  const [comparePack, setComparePack] = useState<string>('');

  useEffect(() => {
    if (scanId === '') return;
    let cancelled = false;
    setError(null);

    if (scanId === ESTATE) {
      Promise.all([getEstate(pack, secrecyYears), getCoverage().catch(() => null)])
        .then(([e, c]) => {
          if (cancelled) return;
          setWorklists(e.worklists);
          setEstate({
            systems: e.systems.length,
            promoted: e.promotedBySystem,
            traceWindow:
              e.traces === null
                ? null
                : `${e.traces.window.from.slice(0, 10)} to ${e.traces.window.to.slice(0, 10)} from ${e.traces.source}`,
          });
          setCoverage(c);
        })
        .catch((err: unknown) => {
          if (!cancelled) setError(err instanceof Error ? err.message : String(err));
        });
      return () => {
        cancelled = true;
      };
    }

    setEstate(null);
    setCoverage(null);
    getWorklists(scanId, pack, secrecyYears)
      .then((w) => {
        if (!cancelled) setWorklists(w);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
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
    getRerank(scanId, comparePack, pack)
      .then((r) => {
        if (cancelled) return;
        setMoved(new Map(r.moved.map((m) => [m.occurrenceId, m.slackYears])));
      })
      .catch(() => setMoved(new Map()));
    return () => {
      cancelled = true;
    };
  }, [scanId, pack, comparePack]);

  const activePack = useMemo(() => packs.find((p) => p.packId === pack) ?? null, [packs, pack]);

  if (scans.length === 0) {
    return (
      <div className="wrap">
        <header className="top">
          <h1>assay</h1>
        </header>
        <p className="aside">
          No scans yet. Run <code>pnpm assay scan &lt;path&gt;</code> and POST the result to the API,
          or start the API with an in-memory store and ingest one.
        </p>
      </div>
    );
  }

  return (
    <div className="wrap">
      <header className="top">
        <h1>assay</h1>

        <div className="controls">
          <select value={scanId} onChange={(e) => setScanId(e.target.value)} aria-label="Scan">
            <option value={ESTATE}>Estate — every system, correlated by traces</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.systemName} · {s.startedAt.slice(0, 10)}
              </option>
            ))}
          </select>

          <select value={pack} onChange={(e) => setPack(e.target.value)} aria-label="Policy pack">
            {packs.map((p) => (
              <option key={p.packId} value={p.packId}>
                {p.title}
                {p.trust === 'SIGNED' ? '' : ` (${p.trust.toLowerCase()})`}
              </option>
            ))}
          </select>

          <select
            value={comparePack}
            onChange={(e) => setComparePack(e.target.value)}
            aria-label="Compare against"
          >
            <option value="">Compare against…</option>
            {packs
              .filter((p) => p.packId !== pack)
              .map((p) => (
                <option key={p.packId} value={p.packId}>
                  vs {p.title}
                </option>
              ))}
          </select>

          <label className="sub">
            Secrecy{' '}
            <input
              type="number"
              min={0}
              max={50}
              value={secrecyYears}
              onChange={(e) => setSecrecyYears(Number(e.target.value))}
              style={{ width: '64px' }}
            />
            y
          </label>
        </div>
      </header>

      {error !== null && <p className="aside">could not reach the API: {error}</p>}

      {worklists !== null && (
        <>
          <div className="headline">
            <div className={`big ${worklists.headline.numerator > 0 ? 'late' : ''}`}>
              {worklists.headline.numerator}
            </div>
            <div className="label">
              <strong>
                of {worklists.headline.denominator} work items are already overdue.
              </strong>
              <br />
              Every item below is cryptography a quantum computer breaks, running in code you
              reach. Each one shows who has to change it and by when. Click any row for the
              evidence behind it.
            </div>
          </div>

          <div className="tracks">
            <Worklist
              title="Confidentiality"
              subtitle="Traffic recorded today can be decrypted later. This clock has already started."
              findings={worklists.confidentiality}
              scanId={scanId}
              pack={pack}
              moved={moved}
              showSystem={estate !== null}
            />
            <Worklist
              title="Authenticity"
              subtitle="Nothing is at risk until a quantum computer exists. Then forgery is."
              findings={worklists.authenticity}
              scanId={scanId}
              pack={pack}
              moved={moved}
              showSystem={estate !== null}
            />
          </div>

          {estate !== null && estate.promoted.length > 0 && (
            <p className="aside">
              <strong>Found via traces:</strong>{' '}
              {estate.promoted.map((p) => `${p.systemId} (${p.occurrences})`).join(', ')}. Reading
              those repositories alone would have missed this — the caller is a different service.
            </p>
          )}

          {coverage !== null && coverage.unscanned.length > 0 && (
            <p className="caveat warn">
              <strong>Never scanned:</strong> {coverage.unscanned.join(', ')}. These services take
              part in live calls and you have no inventory for them.
            </p>
          )}

          <details className="notes">
            <summary>
              Not shown: {worklists.unreached.length} unreachable, {worklists.hints.length} library
              hints
              {worklists.unanalyzed.length > 0 ? `, ${worklists.unanalyzed.length} untraceable` : ''}
            </summary>
            <p>
              <strong>Unreachable</strong> — found in the code, but nothing that serves traffic
              calls it. Test fixtures and dead modules live here.
            </p>
            <p>
              <strong>Library hints</strong> — a dependency that <em>can</em> do this, with no call
              site found. A search hint, not a work item.
            </p>
            {worklists.unanalyzed.length > 0 && (
              <p>
                <strong>Untraceable</strong> — certificates and managed keys have no call site to
                follow. Not looked at is not the same as not reached.
              </p>
            )}
          </details>

          {activePack !== null && activePack.trust !== 'SIGNED' && (
            <p className="caveat" style={{ color: 'var(--late)' }}>
              This pack&rsquo;s horizon is {activePack.trust.toLowerCase()}: {activePack.trustReason}.
              The arithmetic is unchanged, but these slack figures are not comparable with a
              ranking produced under a signed pack.
            </p>
          )}

          {activePack !== null && activePack.caveats.length > 0 && (
            <p className="caveat">
              <strong>Deadline source:</strong>{' '}
              {activePack.regulatoryAuthority ?? 'this pack sets no regulatory deadline.'}
            </p>
          )}
        </>
      )}
    </div>
  );
}
