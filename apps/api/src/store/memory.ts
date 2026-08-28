import { summarize, type ScanStore, type ScanSummary, type StoredScan } from './types.js';

/** Process-local store. Used by tests and by `assay serve --ephemeral`. */
export class MemoryScanStore implements ScanStore {
  readonly kind = 'memory' as const;
  private readonly scans = new Map<string, StoredScan>();

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

  async close(): Promise<void> {
    this.scans.clear();
  }
}

function byNewest(a: StoredScan, b: StoredScan): number {
  return b.startedAt.localeCompare(a.startedAt);
}
