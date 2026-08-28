import type { RankedFinding } from '@/lib/api';

/**
 * Migration window against the deadline.
 *
 * A sunburst tells you what the estate contains. This tells you whether you
 * will finish in time, which is the only question a procurement conversation
 * is actually about. The bar runs from today through the projected completion
 * date implied by the control class; the marker is the binding deadline.
 */
export function Timeline({ f }: { f: RankedFinding }) {
  const horizon = Math.max(
    f.mosca.crqc.horizonYears,
    f.mosca.regulatory?.horizonYears ?? 0,
    f.mosca.x + f.mosca.y,
    1,
  );
  const W = 190;
  const H = 22;
  const pad = 2;
  const scale = (years: number) => pad + (Math.max(0, years) / horizon) * (W - pad * 2);

  const workEnd = scale(f.mosca.y);
  const secrecyEnd = scale(f.mosca.x + f.mosca.y);
  const regulatory = f.mosca.regulatory === null ? null : scale(f.mosca.regulatory.horizonYears);
  const crqc = scale(f.mosca.crqc.horizonYears);

  return (
    <svg className="timeline" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="migration window">
      <line x1={pad} y1={H / 2} x2={W - pad} y2={H / 2} stroke="#232a33" strokeWidth="1" />
      {/* X: the window a recorded session stays sensitive. Zero on the
          authenticity track, where it simply does not render. */}
      {f.mosca.x > 0 && (
        <rect x={workEnd} y={H / 2 - 3} width={Math.max(0, secrecyEnd - workEnd)} height="6" fill="#2a3340" />
      )}
      {/* Y: the migration itself. */}
      <rect x={pad} y={H / 2 - 5} width={Math.max(1, workEnd - pad)} height="10" rx="2" fill={f.late ? '#7a2f2a' : '#2f4a44'} />
      {regulatory !== null && (
        <line
          x1={regulatory}
          y1={2}
          x2={regulatory}
          y2={H - 2}
          stroke={f.bindingConstraint === 'REGULATORY' ? '#ff6b5e' : '#e5b567'}
          strokeWidth="2"
        />
      )}
      <line
        x1={crqc}
        y1={4}
        x2={crqc}
        y2={H - 4}
        stroke={f.bindingConstraint === 'CRQC' ? '#ff6b5e' : '#4a5568'}
        strokeWidth="2"
        strokeDasharray="2 2"
      />
    </svg>
  );
}
