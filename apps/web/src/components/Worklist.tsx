import { useCallback, useEffect, useState } from 'react';
import { getDerivation, type Derivation, type RankedFinding } from '@/lib/api';
import { Timeline } from './Timeline';
import { Tree } from './Tree';

/**
 * One of the two worklists. Never both.
 *
 * Every number on a row is clickable and opens its own derivation. That is the
 * whole product: not a dashboard that tells you the estate is 62% ready, but a
 * page where the reason for each figure is three clicks away and ends at a
 * file and a line number.
 */
export function Worklist({
  title,
  subtitle,
  findings,
  scanId,
  pack,
  moved,
}: {
  title: string;
  subtitle: string;
  findings: RankedFinding[];
  scanId: string;
  pack: string;
  moved: Map<string, { before: number; after: number }>;
}) {
  const [open, setOpen] = useState<string | null>(null);

  return (
    <div className="track">
      <h2>
        {title} <small>{subtitle}</small>
      </h2>
      {findings.length === 0 ? (
        <div className="empty">Nothing on this track.</div>
      ) : (
        findings.map((f) => (
          <Row
            key={f.occurrenceId}
            f={f}
            scanId={scanId}
            pack={pack}
            moved={moved.get(f.occurrenceId)}
            open={open === f.occurrenceId}
            onToggle={() => setOpen(open === f.occurrenceId ? null : f.occurrenceId)}
          />
        ))
      )}
    </div>
  );
}

function Row({
  f,
  scanId,
  pack,
  moved,
  open,
  onToggle,
}: {
  f: RankedFinding;
  scanId: string;
  pack: string;
  moved: { before: number; after: number } | undefined;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <div className="row" role="button" aria-expanded={open} onClick={onToggle}>
        <div className={`slack ${f.late ? 'late' : ''}`}>
          {f.slackYears >= 0 ? '+' : ''}
          {f.slackYears.toFixed(1)}y
        </div>
        <div>
          <div className="name">{f.assetName}</div>
          <div className="meta">
            <span className={`chip ${f.assertionLevel.toLowerCase()}`}>{f.assertionLevel}</span>
            <span className="chip">{f.controlClass}</span>
            <span className="chip">{f.purpose}</span>
            <span className="chip">{f.bindingConstraint === 'REGULATORY' ? 'deadline' : 'crqc'}</span>
            {f.reachedVia !== 'UNANALYZED' && <span className="chip">{via(f.reachedVia)}</span>}
            {moved !== undefined && (
              <span className="moved">
                {moved.before.toFixed(1)} → {moved.after.toFixed(1)} under this pack
              </span>
            )}
          </div>
        </div>
        <Timeline f={f} />
      </div>
      {open && <Detail scanId={scanId} occId={f.occurrenceId} pack={pack} />}
    </>
  );
}

function via(v: string): string {
  switch (v) {
    case 'OBSERVED':
      return 'seen on the wire';
    case 'ENTRY_POINT':
      return 'reached from an entry point';
    case 'DEPLOYED_CONFIG':
      return 'deployed config';
    case 'LIBRARY_SURFACE':
      return 'published surface';
    default:
      return v.toLowerCase();
  }
}

function Detail({ scanId, occId, pack }: { scanId: string; occId: string; pack: string }) {
  const [data, setData] = useState<Derivation | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await getDerivation(scanId, occId, pack));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [scanId, occId, pack]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error !== null) return <div className="panel">could not load the derivation: {error}</div>;
  if (data === null) return <div className="panel">loading the derivation…</div>;

  const d = data.derivations;
  return (
    <div className="panel">
      {d.mosca !== null && (
        <section>
          <h3>Why this number</h3>
          <Tree node={d.mosca.tree} />
        </section>
      )}

      <section>
        <h3>Why we believe it</h3>
        <Tree node={d.confidence.tree} />
        {data.downgradeReason !== null && (
          <div className="caveat">
            Not CONFIRMED: {data.downgradeReason}
            {data.blockedBy.length > 0 && ` — ${data.blockedBy.join('; ')}`}
          </div>
        )}
      </section>

      {d.reachability !== null && (
        <section>
          <h3>Why it is exposed</h3>
          <Tree node={d.reachability.tree} />
          {d.reachability.path.length > 0 && (
            <div className="caveat">
              {d.reachability.path.map((p) => `${p.fullFilename}${p.line ? `:${p.line}` : ''}`).join('  →  ')}
            </div>
          )}
        </section>
      )}

      <section>
        <h3>Raw evidence ({data.evidence.length})</h3>
        <table className="evidence">
          <tbody>
            {data.evidence.slice(0, 40).map((e, i) => (
              <tr key={`${e.locator}-${i}`}>
                <td className="mod">{e.modality}</td>
                <td className="mod">{e.locator}</td>
                <td>{e.raw.slice(0, 180)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.evidence.length > 40 && (
          <div className="caveat">
            {data.evidence.length - 40} further observations of the same work item, folded in.
          </div>
        )}
      </section>
    </div>
  );
}
