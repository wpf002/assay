import type { RankedFinding } from '@/lib/api';

/**
 * The one picture on this page, and what it deliberately is not.
 *
 * Not a pooled readiness percentage, not a sunburst, not a severity heat-map.
 * COMPETITIVE.md section 5 rejects all three by name: the first because EO
 * 14412 sets two deadlines a year apart, the second because it optimises for
 * "look at the estate" rather than "what do I do Monday", the third because it
 * is severity with no arithmetic behind it. Not a confidence trend line
 * either - the API serves no series. Every mark below is a field the API
 * already sends, so the next pass does not re-propose any of them.
 *
 * What it is: a bar from today through the year the replacement finishes, with
 * a thinner tail for how long the data stays sensitive after that, against two
 * vertical rules - the regulatory deadline and the quantum horizon. The
 * segment lying past the binding rule is drawn in the overdue colour and four
 * pixels taller, so lateness is a length sticking out past a line rather than
 * a hue you have to have been told about.
 */

/**
 * One horizon for the whole page.
 *
 * Computed once across both tracks, because the two lists sit side by side and
 * a reader will compare across them. Per-row horizons - what this file used to
 * do - meant a longer bar could stand for less time.
 */
export function domainYears(rows: readonly RankedFinding[]): number {
  let t = 6;
  for (const f of rows) {
    t = Math.max(
      t,
      f.mosca.x + f.mosca.y,
      f.mosca.crqc.horizonYears,
      f.mosca.regulatory?.horizonYears ?? 0,
    );
  }
  return Math.ceil(t);
}

/** A year, as a percentage of the shared horizon. The bars and the rules that
 *  judge them are both positioned from this, off the same box, so they cannot
 *  drift apart at any container width. */
export const pct = (years: number, domain: number): string =>
  `${((Math.min(domain, Math.max(0, years)) / domain) * 100).toFixed(3)}%`;

/** Which constraint this is judged by, and what is measured against it. */
function bindingOf(f: RankedFinding): { at: number; reach: number } {
  return f.bindingConstraint === 'REGULATORY' && f.mosca.regulatory !== null
    ? { at: f.mosca.regulatory.horizonYears, reach: f.mosca.y }
    : { at: f.mosca.crqc.horizonYears, reach: f.mosca.x + f.mosca.y };
}

function label(f: RankedFinding): string {
  const work = `${f.mosca.y} year${f.mosca.y === 1 ? '' : 's'} of work`;
  const tail = f.mosca.x > 0 ? `, then ${f.mosca.x} years the data stays sensitive` : '';
  return `${work}${tail}, against a deadline it ${f.late ? 'misses' : 'meets'}`;
}

/**
 * The chart, drawn once per work package rather than once per row.
 *
 * X, Y, both horizons and the binding constraint are constant within a
 * (track, control class) run - slack is a strictly decreasing function of Y
 * and Y comes from the control class - so a per-row chart drew at most five
 * distinct pictures, each of them four or five times over, in a column too
 * narrow for any of them to be read.
 */
export function PackageChart({ f, domain }: { f: RankedFinding; domain: number }) {
  const { x, y, crqc, regulatory } = f.mosca;
  const b = bindingOf(f);
  return (
    <div className="chart" role="img" aria-label={label(f)}>
      {x > 0 && (
        <span className="bar-tail" style={{ left: pct(y, domain), width: pct(x, domain) }} />
      )}
      <span className="bar-work" style={{ width: pct(y, domain) }} />
      {f.late && (
        <span
          className="bar-over"
          style={{ left: pct(b.at, domain), width: pct(b.reach - b.at, domain) }}
        />
      )}
      {regulatory !== null && (
        <span
          className="rule"
          data-kind="reg"
          data-strong={f.bindingConstraint === 'REGULATORY' ? '' : undefined}
          style={{ left: pct(regulatory.horizonYears, domain) }}
        />
      )}
      <span
        className="rule"
        data-kind="crqc"
        data-strong={f.bindingConstraint === 'CRQC' ? '' : undefined}
        style={{ left: pct(crqc.horizonYears, domain) }}
      />
    </div>
  );
}

/**
 * The scale, drawn once per list on the same full-width box every chart uses,
 * so a tick and a bar at the same year land on the same pixel with no shared
 * column token to keep in lockstep.
 *
 * Both deadlines are read off the track's own first row rather than off the
 * pack, because scoreMosca resolves regulatoryDeadlines[track] per finding: a
 * pack-level list would draw the signature deadline through the key exchange
 * list, which is the one pooling error this product cannot make.
 */
export function TimelineAxis({
  first,
  domain,
  crqcYear,
}: {
  first: RankedFinding | undefined;
  domain: number;
  crqcYear: number | null;
}) {
  if (first === undefined) return null;
  const { crqc, regulatory } = first.mosca;
  const atEnd = (crqc.horizonYears / domain) * 100 > 88;
  return (
    <div className="axis">
      <span className="axis-title">Replacement Window Against The Deadline</span>
      <div className="axis-scale">
        <span className="tick start">Today</span>
        {regulatory !== null && (
          <span
            className={`tick ${first.bindingConstraint === 'REGULATORY' ? 'binding' : ''}`}
            style={{ left: pct(regulatory.horizonYears, domain) }}
          >
            {Math.floor(regulatory.deadlineYear) - 1}
          </span>
        )}
        <span
          className={`tick ${atEnd ? 'end' : ''} ${first.bindingConstraint === 'CRQC' ? 'binding' : ''}`}
          style={{ left: pct(crqc.horizonYears, domain) }}
        >
          {crqcYear === null ? 'Quantum' : `Quantum ${crqcYear}`}
        </span>
      </div>
    </div>
  );
}
