import { useEffect, useState, type ReactNode } from 'react';
import { Unauthorized, getAttestation, type Attestation } from '@/lib/api';

/**
 * What Assay did not look at.
 *
 * Every other panel on this page answers "what did you find". This one answers
 * the question a person has to answer before they can sign anything: what
 * fraction of my estate does this cover. A dashboard that only shows findings
 * reads as an inventory, and one repository scanned out of a hundred looks
 * identical to a hundred - which is the failure this panel exists to prevent.
 *
 * So it leads with the unexamined classes, not the examined ones.
 */
/**
 * The remedies and caveats are written once and read in two places: a terminal,
 * where `assay probe` is already the right thing to print, and this table,
 * where a literal backtick is just a typo on screen. Rendering them here rather
 * than keeping two copies of every sentence in the engine.
 */
function withCode(text: string): ReactNode[] {
  return text.split(/`([^`]+)`/g).map((part, i) =>
    i % 2 === 1 ? <code key={i}>{part}</code> : <span key={i}>{part}</span>,
  );
}

export function Coverage({ scanId }: { scanId: string }) {
  const [state, setState] = useState<
    { status: 'loading' } | { status: 'error'; message: string } | { status: 'ready'; a: Attestation }
  >({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    setState({ status: 'loading' });
    getAttestation(scanId)
      .then((a) => {
        if (!cancelled) setState({ status: 'ready', a });
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setState({
          status: 'error',
          message:
            e instanceof Unauthorized
              ? 'This token cannot read the coverage attestation. It needs an unscoped operator token.'
              : e instanceof Error
                ? e.message
                : String(e),
        });
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  if (state.status === 'loading') return <p className="aside">Checking coverage.</p>;
  if (state.status === 'error') return <p className="aside">{state.message}</p>;

  const { report, signed } = state.a;
  const missed = report.classes.filter((c) => !c.examined);
  const seen = report.classes.filter((c) => c.examined);

  return (
    <section className="coverage">
      <div className="coverage-head">
        <h2>What We Did Not Look At</h2>
        <span className="coverage-count">
          {missed.length > 0
            ? `${missed.length} of ${report.summary.classesTotal} classes never examined`
            : `All ${report.summary.classesTotal} classes examined`}
        </span>
      </div>

      <p className="coverage-sub">
        Findings only mean something next to what was never examined. These are the classes this
        scan did not cover, and what each one would take.
      </p>

      <p className="coverage-statement">{report.summary.statement}</p>

      {report.blindSpots.length > 0 && (
        <p className="caveat caveat-warn">
          <strong>No inventory at all:</strong> {report.blindSpots.map((b) => b.name).join(', ')}.
          Observed in live traffic with nothing scanned. Scanning your own repositories will not
          close this.
        </p>
      )}

      <table className="coverage-table">
        <tbody>
          {missed.map((c) => (
            <tr key={c.id} className="miss">
              <th scope="row">{c.label}</th>
              <td className="verdict">Not examined</td>
              <td className="detail">{withCode(c.remedy)}</td>
            </tr>
          ))}
          {seen.map((c) => (
            <tr key={c.id}>
              <th scope="row">{c.label}</th>
              <td className="verdict ok">
                {c.occurrences} item{c.occurrences === 1 ? '' : 's'}
              </td>
              <td className="detail">{withCode(c.caveat)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <details className="notes">
        <summary>What This Does Not Claim</summary>
        <ul>
          {report.notAsserted.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      </details>

      <p className="caveat">
        {signed ? (
          <>
            Signed. Digest <code>{state.a.digest.slice(0, 16)}</code>. Verify it with{' '}
            <code>assay coverage verify</code>.
          </>
        ) : (
          <>
            Unsigned. This server holds no signing key, so nobody outside the tool can verify this
            report. Run <code>assay coverage keygen</code> and set <code>ASSAY_COVERAGE_KEY</code>{' '}
            to sign it.
          </>
        )}
      </p>
    </section>
  );
}
