import { useCallback, useEffect, useState } from 'react';
import { getDerivation, type Derivation, type RankedFinding } from '@/lib/api';
import {
  ASSERTION,
  MODALITY,
  PURPOSE,
  WHERE,
  action,
  actionDetail,
  assetLabel,
  driver,
  due,
  whyThisDate,
  whyWeBelieve,
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
  secrecyYears,
  showSystem,
}: {
  title: string;
  subtitle: string;
  findings: RankedFinding[];
  scanId: string;
  pack: string;
  moved: Map<string, { before: number; after: number }>;
  /** X, as the rows were ranked. The derivation panel has to be asked for the same one. */
  secrecyYears: number;
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
            secrecyYears={secrecyYears}
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
  secrecyYears,
  showSystem,
  open,
  onToggle,
}: {
  f: RankedFinding;
  scanId: string;
  pack: string;
  moved: { before: number; after: number } | undefined;
  secrecyYears: number;
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
      {open && (
        <Detail
          scanId={scanId}
          occId={f.occurrenceId}
          pack={pack}
          secrecyYears={secrecyYears}
          finding={f}
        />
      )}
    </>
  );
}


function Detail({
  scanId,
  occId,
  pack,
  secrecyYears,
  finding,
}: {
  scanId: string;
  occId: string;
  pack: string;
  secrecyYears: number;
  finding: RankedFinding;
}) {
  const [data, setData] = useState<Derivation | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    // Both are reset on every run: an error left over from a failed fetch
    // renders instead of the derivation that has since loaded, and the
    // previous pack's reasoning under the new pack's name is a wrong answer
    // stated with full confidence.
    setError(null);
    setData(null);
    try {
      setData(await getDerivation(scanId, occId, pack, secrecyYears));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [scanId, occId, pack, secrecyYears]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error !== null) return <div className="panel">Could not load the evidence: {error}</div>;
  if (data === null) return <div className="panel">Loading…</div>;

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
          <h3>Why this date</h3>
          {whyThisDate(d.mosca).map((line) => (
            <p className="prose" key={line}>
              {line}
            </p>
          ))}
          <p className="prose dim">
            Deadline from {d.mosca.policy.packId}
            {d.mosca.policy.authority === null ? '' : ` · ${d.mosca.policy.authority}`}
          </p>
          <details>
            <summary>Show the arithmetic</summary>
            <Tree node={d.mosca.tree} />
          </details>
        </section>
      )}

      <section>
        <h3>How sure we are</h3>
        {whyWeBelieve(d.confidence.value, d.confidence.groups).map((line) => (
          <p className="prose" key={line}>
            {line}
          </p>
        ))}
        {data.downgradeReason !== null && (
          <p className="prose warn">
            Not confirmed: {data.downgradeReason}
            {data.blockedBy.length > 0 && ` — ${data.blockedBy.join('; ')}`}
          </p>
        )}
        {d.confidence.groups.length > 0 && (
          <table className="sure">
            <tbody>
              {d.confidence.groups.flatMap((g) =>
                g.tallies.map((t) => (
                  <tr key={`${g.contributing}-${t.modality}`} className={t.modality === g.contributing ? 'counted' : 'ignored'}>
                    <td>{MODALITY[t.modality] ?? t.modality}</td>
                    <td className="num">{t.count === 1 ? 'once' : `${t.count} times`}</td>
                    <td className="num">up to {Math.round(t.ceiling * 100)}%</td>
                    <td>{t.modality === g.contributing ? 'counted' : 'already covered'}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        )}
        <details>
          <summary>Show the full derivation</summary>
          <Tree node={d.confidence.tree} />
        </details>
      </section>

      {d.reachability !== null && (
        <section>
          <h3>Where it runs</h3>
          <p className="prose">
            {d.reachability.path.length > 0
              ? 'Traced from an entry point:'
              : (WHERE[d.reachability.via] ?? d.reachability.via) +
                (d.reachability.entryPoint === null ? '.' : ` — ${d.reachability.entryPoint}.`)}
          </p>
          {d.reachability.path.length > 0 && (
            <p className="prose path">
              {d.reachability.path
                .map((p) => `${p.fullFilename}${p.line === undefined ? '' : `:${p.line}`}`)
                .join('  →  ')}
            </p>
          )}
          <details>
            <summary>Show the full derivation</summary>
            <Tree node={d.reachability.tree} />
          </details>
        </section>
      )}

      <section>
        <h3>Where we found it · {data.evidence.length}</h3>
        <table className="evidence">
          <tbody>
            {data.evidence.slice(0, 40).map((e, i) => (
              <tr key={`${e.locator}-${i}`}>
                <td className="mod">{MODALITY[e.modality] ?? e.modality}</td>
                <td className="loc">{e.locator}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.evidence.length > 40 && (
          <p className="prose dim">
            and {data.evidence.length - 40} more places, all of them the same work item.
          </p>
        )}
      </section>
    </div>
  );
}
