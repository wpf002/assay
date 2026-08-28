import { useEffect, useState } from 'react';
import { Dashboard } from '@/components/Dashboard';
import { getPacks, getScans, type PolicyPack, type ScanSummary } from '@/lib/api';

export function App() {
  const [state, setState] = useState<
    { status: 'loading' } | { status: 'error'; message: string } | { status: 'ready'; scans: ScanSummary[]; packs: PolicyPack[] }
  >({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    Promise.all([getScans(), getPacks()])
      .then(([scans, packs]) => {
        if (!cancelled) setState({ status: 'ready', scans, packs });
      })
      .catch((e: unknown) => {
        if (!cancelled) setState({ status: 'error', message: e instanceof Error ? e.message : String(e) });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.status === 'loading') {
    return (
      <div className="wrap">
        <header className="top">
          <h1>assay</h1>
        </header>
        <p className="aside">loading…</p>
      </div>
    );
  }

  if (state.status === 'error') {
    return (
      <div className="wrap">
        <header className="top">
          <h1>assay</h1>
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
    />
  );
}
