/**
 * Thin API client. Every fetch is uncached: the whole point of the policy pack
 * switcher is that the numbers move when the policy does, and a cached
 * worklist would silently show yesterday's deadline.
 */
/**
 * Empty by default: the dev server proxies /api to the API, and a production
 * build is served from the same origin as it. Nothing about the deployment is
 * baked into the bundle, so one build works against localhost, staging, or an
 * air-gapped internal host.
 */
export const API = import.meta.env['VITE_ASSAY_API'] ?? '/api';

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
  trust: 'SIGNED' | 'UNSIGNED' | 'UNTRUSTED';
  trustReason: string;
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
    confidence: {
      tree: ExplainNode;
      depth: number;
      citations: number;
      value: number;
      groups: {
        index: number;
        contributing: string;
        ceiling: number;
        tallies: { modality: string; count: number; ceiling: number }[];
        suppressed: number;
      }[];
    };
    mosca: {
      tree: ExplainNode;
      depth: number;
      bindingConstraint: 'CRQC' | 'REGULATORY';
      x: number;
      y: number;
      crqc: { horizonYears: number; slackYears: number; late: boolean };
      regulatory: { deadlineYear: number; horizonYears: number; slackYears: number; late: boolean } | null;
      controlClass: string;
      track: string;
      policy: { packId: string; packVersion: string; crqcYear: number; authority: string | null };
    } | null;
    reachability: {
      tree: ExplainNode;
      via: string;
      entryPoint: string | null;
      path: { module: string; function: string; fullFilename: string; line?: number }[];
    } | null;
  };
}

export interface EstateResult {
  systems: { systemName: string; scanId: string; startedAt: string }[];
  traces: {
    id: string;
    source: string;
    window: { from: string; to: string };
    edges: number;
    rootServices: string[];
  } | null;
  promotedBySystem: { systemId: string; occurrences: number }[];
  worklists: Worklists;
}

export interface Coverage {
  servicesObserved: string[];
  scanned: string[];
  unscanned: string[];
  note: string;
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

const TOKEN_KEY = 'assay.token';

/**
 * The token lives in this browser and nowhere else.
 *
 * The API has no anonymous access, so the dashboard needs a credential. It is
 * held in localStorage rather than a cookie because there is no session
 * endpoint to set one, and it is never sent anywhere but the configured API.
 */
export function getToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    window.localStorage.setItem(TOKEN_KEY, token.trim());
  } catch {
    /* handled by storageAvailable(); see below */
  }
}

/**
 * Whether a token can be kept at all.
 *
 * With storage blocked - private mode in some browsers, or a third-party-cookie
 * policy - setToken silently did nothing and getToken kept returning null, so
 * the sign-in form accepted a correct token and immediately asked for it again,
 * forever, with no indication why. Better to say so.
 */
export function storageAvailable(): boolean {
  try {
    const probe = `${TOKEN_KEY}.probe`;
    window.localStorage.setItem(probe, '1');
    window.localStorage.removeItem(probe);
    return true;
  } catch {
    return false;
  }
}

export function clearToken(): void {
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* nothing to clear */
  }
}

export class Unauthorized extends Error {}

async function get<T>(path: string): Promise<T> {
  const token = getToken();
  const res = await fetch(`${API}${path}`, {
    cache: 'no-store',
    headers: token === null ? {} : { authorization: `Bearer ${token}` },
  });
  if (res.status === 401 || res.status === 403) {
    throw new Unauthorized(`${path} -> ${res.status}`);
  }
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return (await res.json()) as T;
}

export const getScans = (): Promise<ScanSummary[]> => get('/scans');
export const getPacks = (): Promise<PolicyPack[]> => get('/policy-packs');
export const getWorklists = (scanId: string, pack: string, secrecyYears: number): Promise<Worklists> =>
  get(`/scans/${scanId}/worklists?pack=${encodeURIComponent(pack)}&secrecyYears=${secrecyYears}`);
export const ESTATE_SCAN = '__estate__';

/**
 * secrecyYears is not optional here. The panel is the derivation of the number
 * on the row it was opened from, and the route defaults X to 5 when it is not
 * sent - so omitting it re-ranks the finding under a different X and the two
 * views disagree about whether the item is overdue at all.
 */
export const getDerivation = (
  scanId: string,
  occId: string,
  pack: string,
  secrecyYears: number,
): Promise<Derivation> =>
  get(
    `${scanId === ESTATE_SCAN ? '/estate' : `/scans/${scanId}`}/occurrences/` +
      `${encodeURIComponent(occId)}?pack=${encodeURIComponent(pack)}&secrecyYears=${secrecyYears}`,
  );
export const getEstate = (pack: string, secrecyYears: number): Promise<EstateResult> =>
  get(`/estate/worklists?pack=${encodeURIComponent(pack)}&secrecyYears=${secrecyYears}`);
export const getCoverage = (): Promise<Coverage> => get('/estate/coverage');
/** Both sides are ranked at the operator's X, or the comparison is not like-for-like. */
export const getRerank = (
  scanId: string,
  from: string,
  to: string,
  secrecyYears: number,
): Promise<RerankResult> =>
  get(
    `/scans/${scanId}/rerank?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}` +
      `&secrecyYears=${secrecyYears}`,
  );
