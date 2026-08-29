import {
  summarize,
  type AuditEvent,
  type AuditQuery,
  type StoredToken,
  type TokenSummary,
  type ScanStore,
  type ScanSummary,
  type StoredScan,
  type StoredTraceBundle,
  type TraceBundleSummary,
} from './types.js';

/** Process-local store. Used by tests and by `assay serve --ephemeral`. */
export class MemoryScanStore implements ScanStore {
  readonly kind = 'memory' as const;
  private readonly scans = new Map<string, StoredScan>();
  private readonly traces = new Map<string, StoredTraceBundle>();
  private readonly tokens = new Map<string, StoredToken>();
  private readonly audit: AuditEvent[] = [];

  async put(scan: StoredScan): Promise<void> {
    this.scans.set(scan.id, scan);
  }

  async list(systemName: string | undefined, limit: number): Promise<ScanSummary[]> {
    return [...this.scans.values()]
      .filter((s) => systemName === undefined || s.systemName === systemName)
      .sort(byNewest)
      .slice(0, limit)
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

  async latestSystemNames(): Promise<string[]> {
    return [...new Set([...this.scans.values()].map((s) => s.systemName))].sort();
  }

  async findToken(secretHash: string): Promise<StoredToken | null> {
    for (const t of this.tokens.values()) {
      if (t.secretHash === secretHash) return t;
    }
    return null;
  }

  async putToken(token: StoredToken): Promise<void> {
    this.tokens.set(token.id, token);
  }

  async listTokens(): Promise<TokenSummary[]> {
    return [...this.tokens.values()]
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .map(({ secretHash, ...rest }) => {
        void secretHash;
        return rest;
      });
  }

  async revokeToken(id: string, at: string): Promise<boolean> {
    const token = this.tokens.get(id);
    if (token === undefined || token.revokedAt !== null) return false;
    this.tokens.set(id, { ...token, revokedAt: at });
    return true;
  }

  async touchToken(id: string, at: string): Promise<void> {
    const token = this.tokens.get(id);
    if (token !== undefined) this.tokens.set(id, { ...token, lastUsedAt: at });
  }

  async countUsableTokens(now: string): Promise<number> {
    return [...this.tokens.values()].filter(
      (t) => t.revokedAt === null && (t.expiresAt === null || t.expiresAt > now),
    ).length;
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    this.audit.push(event);
  }

  async listAudit(query: AuditQuery): Promise<AuditEvent[]> {
    return this.audit
      .filter((e) => query.tokenId === undefined || e.tokenId === query.tokenId)
      .filter((e) => query.since === undefined || e.at >= query.since)
      .filter((e) => query.before === undefined || e.at < query.before)
      .sort((a, b) => b.at.localeCompare(a.at))
      .slice(0, query.limit);
  }

  async putTraces(bundle: StoredTraceBundle): Promise<void> {
    this.traces.set(bundle.id, bundle);
  }

  async listTraces(): Promise<TraceBundleSummary[]> {
    return [...this.traces.values()]
      .sort((a, b) => b.ingestedAt.localeCompare(a.ingestedAt))
      .map(({ edges, ...rest }) => ({ ...rest, edgeCount: edges.length }));
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
    this.tokens.clear();
    this.audit.length = 0;
  }
}

function byNewest(a: StoredScan, b: StoredScan): number {
  return b.startedAt.localeCompare(a.startedAt);
}
