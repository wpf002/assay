import {
  summarize,
  type ScanStore,
  type ScanSummary,
  type StoredScan,
  type StoredTraceBundle,
} from './types.js';

/** Process-local store. Used by tests and by `assay serve --ephemeral`. */
export class MemoryScanStore implements ScanStore {
  readonly kind = 'memory' as const;
  private readonly scans = new Map<string, StoredScan>();
  private readonly traces = new Map<string, StoredTraceBundle>();

  async put(scan: StoredScan): Promise<void> {
    this.scans.set(scan.id, scan);
  }

  async list(systemName?: string): Promise<ScanSummary[]> {
    return [...this.scans.values()]
      .filter((s) => systemName === undefined || s.systemName === systemName)
      .sort(byNewest)
      .map(summarize);
  }

  async get(id: string): Promise<StoredScan | null> {
    return this.scans.get(id) ?? null;
  }

  async recent(systemName: string, limit: number): Promise<StoredScan[]> {
    return [...this.scans.values()]
      .filter((s) => s.systemName === systemName)
      .sort(byNewest)
      .slice(0, limit);
  }

  async latestPerSystem(): Promise<StoredScan[]> {
    const newest = new Map<string, StoredScan>();
    for (const scan of [...this.scans.values()].sort(byNewest)) {
      if (!newest.has(scan.systemName)) newest.set(scan.systemName, scan);
    }
    return [...newest.values()].sort((a, b) => a.systemName.localeCompare(b.systemName));
  }

  async putTraces(bundle: StoredTraceBundle): Promise<void> {
    this.traces.set(bundle.id, bundle);
  }

  async listTraces(): Promise<Omit<StoredTraceBundle, 'edges'>[]> {
    return [...this.traces.values()]
      .sort((a, b) => b.ingestedAt.localeCompare(a.ingestedAt))
      .map(({ edges, ...rest }) => ({ ...rest, edgeCount: edges.length }) as never);
  }

  async getTraces(id: string): Promise<StoredTraceBundle | null> {
    return this.traces.get(id) ?? null;
  }

  async latestTraces(): Promise<StoredTraceBundle | null> {
    return (
      [...this.traces.values()].sort((a, b) => b.ingestedAt.localeCompare(a.ingestedAt))[0] ?? null
    );
  }

  async close(): Promise<void> {
    this.scans.clear();
    this.traces.clear();
  }
}

function byNewest(a: StoredScan, b: StoredScan): number {
  return b.startedAt.localeCompare(a.startedAt);
}
