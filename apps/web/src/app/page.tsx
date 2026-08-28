import { Dashboard } from '@/components/Dashboard';
import { getPacks, getScans, type PolicyPack, type ScanSummary } from '@/lib/api';

export const dynamic = 'force-dynamic';

export default async function Page() {
  let scans: ScanSummary[] = [];
  let packs: PolicyPack[] = [];
  let error: string | null = null;

  try {
    [scans, packs] = await Promise.all([getScans(), getPacks()]);
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  if (error !== null) {
    return (
      <div className="wrap">
        <header className="top">
          <h1>assay</h1>
        </header>
        <p className="aside">
          The API is not reachable ({error}). Start it with <code>pnpm --filter @assay/api dev</code>.
        </p>
      </div>
    );
  }

  return <Dashboard scans={scans} packs={packs} initialPack={packs[0]?.packId ?? 'eo-14412'} />;
}
