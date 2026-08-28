import { useCallback, useEffect, useState } from 'react';
import { getDerivation, type Derivation, type RankedFinding } from '@/lib/api';
import {
  ASSERTION,
  PURPOSE,
  WHERE,
  action,
  actionDetail,
  assetLabel,
  driver,
  due,
} from '@/lib/format';
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
  showSystem,
}: {
  title: string;
  subtitle: string;
  findings: RankedFinding[];
  scanId: string;
  pack: string;
  moved: Map<string, { before: number; after: number }>;
  /**
   * Estate-wide, the same asset legitimately appears once per system and the
   * rows are otherwise identical. Without the system name the list reads as
   * duplicates of one finding rather than as separate work items.
   */
  showSystem: boolean;
}) {
  const [open, setOpen] = useState<string | null>(null);

  return (
    <div className="track">
      <h2>
        {title} <span className="count">{findings.length}</span>
        <small>{subtitle}</small>
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
            showSystem={showSystem}
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
  showSystem,
  open,
  onToggle,
}: {
  f: RankedFinding;
  scanId: string;
  pack: string;
  moved: { before: number; after: number } | undefined;
  showSystem: boolean;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <div className="row" role="button" aria-expanded={open} onClick={onToggle}>
        <div className={`slack ${f.late ? 'late' : ''}`}>{f.late ? 'Overdue' : ''}</div>

        <div>
          <div className="name">
            {assetLabel(f)}
            <span className="dim"> · {PURPOSE[f.purpose] ?? f.purpose}</span>
          </div>

          <div className="meta">
            {showSystem && <strong>{f.systemId}</strong>}
            {showSystem && ' · '}
            <span className="act">{action(f)}</span>
            {WHERE[f.reachedVia] !== undefined && WHERE[f.reachedVia] !== '' && (
              <> · {WHERE[f.reachedVia]}</>
            )}
            {f.assertionLevel !== 'CONFIRMED' && (
              <> · {ASSERTION[f.assertionLevel] ?? f.assertionLevel} only</>
            )}
            {moved !== undefined && (
              <span className="moved">
                {' '}
                · was {moved.before.toFixed(1)}y under the other pack
              </span>
            )}
          </div>

        </div>

        <div className="whenwrap">
          <div className={`when ${f.late ? 'late' : ''}`}>{due(f)}</div>
          <div className="driver">{driver(f)}</div>
          <Timeline f={f} />
        </div>
      </div>
      {open && <Detail scanId={scanId} occId={f.occurrenceId} pack={pack} finding={f} />}
    </>
  );
}


function Detail({
  scanId,
  occId,
  pack,
  finding,
}: {
  scanId: string;
  occId: string;
  pack: string;
  finding: RankedFinding;
}) {
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
      {actionDetail(finding) !== '' && (
        <section>
          <h3>What to do</h3>
          <p className="prose">{actionDetail(finding)}</p>
        </section>
      )}

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
