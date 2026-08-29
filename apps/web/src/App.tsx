import { useEffect, useState } from 'react';
import { Dashboard } from '@/components/Dashboard';
import {
  Unauthorized,
  clearToken,
  getPacks,
  getScans,
  getToken,
  setToken,
  storageAvailable,
  type PolicyPack,
  type ScanSummary,
} from '@/lib/api';

export function App() {
  const [state, setState] = useState<
    | { status: 'loading' }
    | { status: 'unauthorized'; rejected: boolean }
    | { status: 'error'; message: string }
    | { status: 'ready'; scans: ScanSummary[]; packs: PolicyPack[] }
  >({ status: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    if (getToken() === null) {
      setState({ status: 'unauthorized', rejected: false });
      return;
    }
    setState({ status: 'loading' });
    Promise.all([getScans(), getPacks()])
      .then(([scans, packs]) => {
        if (!cancelled) setState({ status: 'ready', scans, packs });
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        // A rejected token is not an outage; asking again is the useful answer.
        if (e instanceof Unauthorized) {
          clearToken();
          setState({ status: 'unauthorized', rejected: true });
          return;
        }
        setState({ status: 'error', message: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  if (state.status === 'loading') {
    return (
      <div className="wrap">
        <header className="top">
          <h1>Assay</h1>
        </header>
        <p className="aside">loading…</p>
      </div>
    );
  }

  if (state.status === 'unauthorized') {
    return (
      <div className="wrap">
        <header className="top">
          <h1>Assay</h1>
        </header>
        <form
          className="signin"
          onSubmit={(e) => {
            e.preventDefault();
            const value = new FormData(e.currentTarget).get('token');
            if (typeof value === 'string' && value.trim() !== '') {
              setToken(value);
              setAttempt((n) => n + 1);
            }
          }}
        >
          <label className="field">
            <span className="field-label">API token</span>
            <input name="token" type="password" autoComplete="off" placeholder="assay_…" />
          </label>
          <button type="submit">Open</button>
          {state.rejected && (
            <p className="caveat caveat-warn">
              That token was refused. It may have been revoked, expired, or issued by a different
              API. Paste a current one.
            </p>
          )}
          {!storageAvailable() && (
            <p className="caveat caveat-warn">
              This browser is blocking local storage, so the token cannot be kept and this form will
              ask again on every load. Allow site data for this origin, or use a normal window.
            </p>
          )}
          <p className="caveat">
            The API prints one on first start. It is kept in this browser only and sent to nothing
            but the API.
          </p>
        </form>
      </div>
    );
  }

  if (state.status === 'error') {
    return (
      <div className="wrap">
        <header className="top">
          <h1>Assay</h1>
        </header>
        <p className="aside">
          The API is not reachable ({state.message}). Start it with{' '}
          <code>pnpm --filter @assay/api dev</code>.
        </p>
      </div>
    );
  }

  return (
    <Dashboard
      scans={state.scans}
      packs={state.packs}
      initialPack={state.packs[0]?.packId ?? 'eo-14412'}
      onSignOut={() => {
        clearToken();
        setState({ status: 'unauthorized', rejected: false });
      }}
      onTokenRejected={() => {
        clearToken();
        setState({ status: 'unauthorized', rejected: true });
      }}
    />
  );
}
