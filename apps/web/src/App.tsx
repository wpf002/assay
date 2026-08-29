import { useEffect, useState } from 'react';
import { Dashboard } from '@/components/Dashboard';
import { Masthead } from '@/components/Masthead';
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
          <Masthead />
        </header>
        <p className="aside">Loading scans.</p>
      </div>
    );
  }

  if (state.status === 'unauthorized') {
    return (
      <div className="wrap">
        <header className="top">
          <Masthead />
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
            <span className="field-label">API Token</span>
            <input name="token" type="password" autoComplete="off" placeholder="assay_…" />
          </label>
          <button type="submit">Sign In</button>
          {state.rejected && (
            <p className="caveat caveat-warn">
              That token was refused. It may be revoked, expired, or issued by a different API.
              Paste a current one.
            </p>
          )}
          {!storageAvailable() && (
            <p className="caveat caveat-warn">
              This browser blocks local storage, so the token cannot be kept and this form will ask
              for it again on every load. Allow site data for this origin, or use a normal window.
            </p>
          )}
          <p className="caveat">
            The API prints a token the first time it starts. It is kept in this browser and sent
            only to the API.
          </p>
        </form>
      </div>
    );
  }

  if (state.status === 'error') {
    return (
      <div className="wrap">
        <header className="top">
          <Masthead />
        </header>
        <p className="aside">
          Cannot reach the API ({state.message}). Start it with{' '}
          <code>pnpm --filter @assay/api dev</code>, then reload.
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
