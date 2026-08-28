/**
 * Thin API client. Every fetch is uncached: the whole point of the policy pack
 * switcher is that the numbers move when the policy does, and a cached
 * worklist would silently show yesterday's deadline.
 */
export const API = process.env['NEXT_PUBLIC_ASSAY_API'] ?? 'http://localhost:3001';

export interface ScanSummary {
  id: string;
  systemName: string;
  startedAt: string;
  policyPackId: string;
  policyPackVersion: string;
  occurrenceCount: number;
  assetCount: number;
  detectors: string[];
}

export interface RankedFinding {
  occurrenceId: string;
  assetId: string;
  systemId: string;
  assetName: string;
  purpose: string;
  controlClass: string;
  track: 'CONFIDENTIALITY' | 'AUTHENTICITY';
  assertionLevel: 'CONFIRMED' | 'OBSERVED' | 'SUSPECTED';
  confidence: number;
  slackYears: number;
  late: boolean;
  bindingConstraint: 'CRQC' | 'REGULATORY';
  reachable: boolean | null;
  reachedVia: string;
  mosca: {
    x: number;
    y: number;
    crqc: { horizonYears: number; slackYears: number; late: boolean };
    regulatory: { deadlineYear: number; horizonYears: number; slackYears: number; late: boolean } | null;
  };
}

export interface Worklists {
  policyPackId: string;
  policyPackVersion: string;
  currentYear: number;
  confidentiality: RankedFinding[];
  authenticity: RankedFinding[];
  unreached: RankedFinding[];
  unanalyzed: RankedFinding[];
  hints: RankedFinding[];
  headline: { label: string; value: number; numerator: number; denominator: number };
}

export interface PolicyPack {
  packId: string;
  packVersion: string;
  title: string;
  crqcYear: number;
  regulatoryDeadlines: { CONFIDENTIALITY: number | null; AUTHENTICITY: number | null };
  regulatoryAuthority: string | null;
  caveats: string[];
}

export interface ExplainNode {
  id: string;
  kind: 'EVIDENCE' | 'INFERENCE' | 'POLICY' | 'ASSUMPTION';
  label: string;
  value: number | string | boolean;
  depth: number;
  tainted: boolean;
  isEvidence: boolean;
  children: ExplainNode[];
}

export interface Derivation {
  asset: { primitive: string; parameters: Record<string, string | number>; purpose: string } | null;
  assertionLevel: string;
  downgradeReason: string | null;
  blockedBy: string[];
  evidence: { modality: string; locator: string; raw: string; collectedAt: string }[];
  derivations: {
    confidence: { tree: ExplainNode; depth: number; citations: number };
    mosca: { tree: ExplainNode; depth: number; bindingConstraint: string } | null;
    reachability: {
      tree: ExplainNode;
      via: string;
      entryPoint: string | null;
      path: { module: string; function: string; fullFilename: string; line?: number }[];
    } | null;
  };
}

export interface RerankResult {
  from: string;
  to: string;
  headline: { before: { value: number }; after: { value: number } };
  moved: {
    occurrenceId: string;
    assetName: string;
    slackYears: { before: number; after: number };
    bindingConstraint: { before: string; after: string };
    late: { before: boolean; after: boolean };
  }[];
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return (await res.json()) as T;
}

export const getScans = (): Promise<ScanSummary[]> => get('/scans');
export const getPacks = (): Promise<PolicyPack[]> => get('/policy-packs');
export const getWorklists = (scanId: string, pack: string, secrecyYears: number): Promise<Worklists> =>
  get(`/scans/${scanId}/worklists?pack=${encodeURIComponent(pack)}&secrecyYears=${secrecyYears}`);
export const getDerivation = (scanId: string, occId: string, pack: string): Promise<Derivation> =>
  get(`/scans/${scanId}/occurrences/${encodeURIComponent(occId)}?pack=${encodeURIComponent(pack)}`);
export const getRerank = (scanId: string, from: string, to: string): Promise<RerankResult> =>
  get(`/scans/${scanId}/rerank?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
