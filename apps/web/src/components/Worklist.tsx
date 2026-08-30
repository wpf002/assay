import { useCallback, useEffect, useState, type CSSProperties } from 'react';
import { getDerivation, type Derivation, type RankedFinding } from '@/lib/api';
import {
  CONTROL,
  MODALITY,
  PURPOSE,
  WHERE,
  actionDetail,
  assetLabel,
  driver,
  due,
  duration,
  whyThisDate,
  whyWeBelieve,
} from '@/lib/format';
import { PackageChart, TimelineAxis } from './Timeline';
import { Tree } from './Tree';

/**
 * A run of consecutive rows that share every figure the head of the list would
 * print for them.
 *
 * Slack, lateness, the binding constraint and both Mosca terms are pure
 * functions of (track, control class): slack is strictly decreasing in Y and Y
 * comes from the control class, so the ranking's slack-ascending order already
 * arrives grouped. The key carries every value the package head asserts, so a
 * package cannot state something untrue of a row inside it - if the data ever
 * varies, the run simply breaks and a second package is emitted. Grouping by
 * run rather than by map is what keeps the list in strict rank order.
 */
interface Package {
  key: string;
  rep: RankedFinding;
  rows: RankedFinding[];
}

function packages(findings: readonly RankedFinding[]): Package[] {
  const out: Package[] = [];
  for (const f of findings) {
    const key = [
      f.controlClass,
      f.late,
      f.slackYears,
      f.bindingConstraint,
      f.mosca.x,
      f.mosca.y,
    ].join('|');
    const last = out[out.length - 1];
    if (last !== undefined && last.key === key) last.rows.push(f);
    else out.push({ key, rep: f, rows: [f] });
  }
  return out;
}

/**
 * One of the two worklists. Never both.
 *
 * Every number on a row is clickable and opens its own derivation. That is the
 * whole product: not a dashboard that tells you the estate is 62% ready, but a
 * page where the reason for each figure is three clicks away and ends at a
 * file and a line number.
 *
 * The list is drawn as work packages rather than as flat rows. The date, the
 * verdict, the action and the chart were identical for every row of a control
 * class and were being restated once per row; said once at the head of the
 * package, across the full width of the column, they are an argument, and the
 * rows underneath are free to carry only what actually differs between them.
 */
export function Worklist({
  kicker,
  title,
  subtitle,
  findings,
  scanId,
  pack,
  moved,
  secrecyYears,
  showSystem,
  crqcYear,
  compareTitle,
  domain,
}: {
  /** Which of the two Mosca tracks this is. The title is what the track holds. */
  kicker: string;
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
  /** The active pack's horizon, so a row can print the year rather than the word. */
  crqcYear: number | null;
  /** Named on a moved row, because "the other pack" is not a pack anyone can look up. */
  compareTitle: string | null;
  /**
   * The shared x-axis, in years, computed once across BOTH tracks. The two
   * lists sit side by side, so they have to be one ruler; per-track domains
   * would put two differently scaled charts next to each other and invite
   * exactly the comparison they cannot support.
   */
  domain: number;
}) {
  const [open, setOpen] = useState<string | null>(null);

  return (
    <div className="track">
      <h2>
        <span className="kicker">{kicker}</span>
        {title} <span className="count">{findings.length} items</span>
        <small>{subtitle}</small>
      </h2>
      {findings.length === 0 ? (
        <div className="empty">No work items on this list.</div>
      ) : (
        <>
          <TimelineAxis first={findings[0]} domain={domain} crqcYear={crqcYear} />
          {packages(findings).map((p, i) => (
            <section
              className="pkg"
              key={`${p.key}-${i}`}
              data-late={p.rep.late ? '' : undefined}
            >
              <div className="pkg-head">
                <div className="pkg-id">
                  <span className="pkg-kind">
                    {duration(p.rep.mosca.y)} to replace · {driver(p.rep, crqcYear ?? undefined)}
                  </span>
                  <h3 className="pkg-name">
                    {CONTROL[p.rep.controlClass] ?? p.rep.controlClass}
                  </h3>
                  <span className="pkg-n">
                    {p.rows.length} item{p.rows.length === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="pkg-when">
                  <span className={`chip ${p.rep.late ? 'late' : ''}`}>
                    {p.rep.late ? 'Overdue' : 'In Time'}
                  </span>
                  <span className={`when ${p.rep.late ? 'late' : ''}`}>{due(p.rep)}</span>
                </div>
              </div>

              <PackageChart f={p.rep} domain={domain} />

              <div className="pkg-rows">
                {p.rows.map((f) => (
                  <Row
                    key={f.occurrenceId}
                    f={f}
                    scanId={scanId}
                    pack={pack}
                    moved={moved.get(f.occurrenceId)}
                    secrecyYears={secrecyYears}
                    showSystem={showSystem}
                    compareTitle={compareTitle}
                    open={open === f.occurrenceId}
                    onToggle={() => setOpen(open === f.occurrenceId ? null : f.occurrenceId)}
                  />
                ))}
              </div>
            </section>
          ))}
        </>
      )}
    </div>
  );
}

/**
 * One occurrence, carrying only what varies inside its package.
 *
 * The date, the Overdue chip, the binding deadline and the chart have all
 * moved up to the package head, where they are stated once instead of once per
 * row. What is left is the asset, where it runs, whether the evidence was
 * confirmed, and how sure we are - and that last figure is the only number
 * that changes row to row, so it gets the list's one numeric column.
 */
function Row({
  f,
  scanId,
  pack,
  moved,
  secrecyYears,
  showSystem,
  compareTitle,
  open,
  onToggle,
}: {
  f: RankedFinding;
  scanId: string;
  pack: string;
  moved: { before: number; after: number } | undefined;
  secrecyYears: number;
  showSystem: boolean;
  compareTitle: string | null;
  open: boolean;
  onToggle: () => void;
}) {
  // Banded to five points. The underlying figure is a noisy-OR estimate over
  // per-modality ceilings; printing it to the whole percent claims a
  // resolution the arithmetic does not have.
  const sure = Math.round(f.confidence * 20) * 5;

  return (
    <>
      <div className="row" role="button" aria-expanded={open} onClick={onToggle}>
        <div className="id">
          <div className="name">
            {assetLabel(f)}
            <span className="dim"> · {PURPOSE[f.purpose] ?? f.purpose}</span>
          </div>

          <div className="meta">
            {showSystem && <strong>{f.systemId}</strong>}
            {showSystem && ' · '}
            <span className="act">{WHERE[f.reachedVia] ?? f.reachedVia}</span>
            {f.assertionLevel !== 'CONFIRMED' && <> · Observed, not confirmed</>}
            {moved !== undefined && (
              <span className="moved">
                {' '}
                · was {Math.abs(moved.before).toFixed(1)} years{' '}
                {moved.before < 0 ? 'late' : 'to spare'}
                {compareTitle === null ? ' under the other pack' : ` under ${compareTitle}`}
              </span>
            )}
          </div>
        </div>

        <div className="conf">{sure}% sure</div>

        <div className="chev" aria-hidden="true">
          {open ? '▾' : '▸'}
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
  if (data === null) return <div className="panel">Loading the evidence.</div>;

  const d = data.derivations;
  return (
    <div className="panel">
      {actionDetail(finding) !== '' && (
        <section>
          <h3>What To Do</h3>
          <p className="prose">{actionDetail(finding)}</p>
        </section>
      )}

      {d.mosca !== null && (
        <section>
          <h3>Why This Date</h3>
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
            <summary>Show The Arithmetic</summary>
            <Tree node={d.mosca.tree} />
          </details>
        </section>
      )}

      <section>
        <h3>How Sure We Are</h3>
        {whyWeBelieve(d.confidence.value, d.confidence.groups).map((line) => (
          <p className="prose" key={line}>
            {line}
          </p>
        ))}
        {data.downgradeReason !== null && (
          <p className="prose warn">
            Not confirmed: {data.downgradeReason}.
            {data.blockedBy.length > 0 && ` Blocked by: ${data.blockedBy.join('; ')}.`}
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
                    {/* The ceiling as a length, drawn as a cap and not as a
                        contribution: a modality that was already counted gets
                        the same bar hollow, because it added nothing. A dimmed
                        solid bar would read as "contributed a little", which is
                        the one place on this page where a picture could lie
                        about the arithmetic. */}
                    <td
                      className="ceil"
                      style={{ '--w': `${Math.round(t.ceiling * 100)}%` } as CSSProperties}
                    >
                      <span>
                        up to {Math.round(t.ceiling * 100)}%
                        {t.modality === g.contributing ? '' : ' · already counted'}
                      </span>
                    </td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        )}
        <details>
          <summary>Show The Full Derivation</summary>
          <Tree node={d.confidence.tree} />
        </details>
      </section>

      {d.reachability !== null && (
        <section>
          <h3>Where It Runs</h3>
          <p className="prose">
            {d.reachability.path.length > 0
              ? 'Traced from an entry point:'
              : (WHERE[d.reachability.via] ?? d.reachability.via) +
                (d.reachability.entryPoint === null
                  ? '.'
                  : `. Entry point: ${d.reachability.entryPoint}.`)}
          </p>
          {d.reachability.path.length > 0 && (
            <p className="prose path">
              {d.reachability.path
                .map((p) => `${p.fullFilename}${p.line === undefined ? '' : `:${p.line}`}`)
                .join('  →  ')}
            </p>
          )}
          <details>
            <summary>Show The Full Derivation</summary>
            <Tree node={d.reachability.tree} />
          </details>
        </section>
      )}

      <section>
        <h3>Where We Found It · {data.evidence.length}</h3>
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
            And {data.evidence.length - 40} more places. All of them are the same work item.
          </p>
        )}
      </section>
    </div>
  );
}
