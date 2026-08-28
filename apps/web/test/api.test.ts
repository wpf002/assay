import { afterEach, describe, expect, it, vi } from 'vitest';
import { API, ESTATE_SCAN, getDerivation, getEstate, getRerank, getWorklists } from '../src/lib/api';

/**
 * What the client actually asks for. Every ranking parameter the page holds
 * has to appear in every request that ranks, because the routes default the
 * ones they are not sent and answer confidently under a different X.
 */

const requested: string[] = [];

const stubFetch = (): void => {
  vi.stubGlobal('fetch', (url: string) => {
    requested.push(url);
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response);
  });
};

afterEach(() => {
  vi.unstubAllGlobals();
  requested.length = 0;
});

const asked = async (call: Promise<unknown>): Promise<URL> => {
  await call;
  return new URL(requested[0] ?? '', 'http://localhost');
};

describe('the ranking parameters the client sends', () => {
  it('ranks the derivation panel at the same secrecy lifetime as the row', async () => {
    stubFetch();
    const url = await asked(getDerivation('scan-1', 'occ 1', 'eo-14412', 20));
    expect(url.pathname).toBe(`${API}/scans/scan-1/occurrences/occ%201`);
    expect(url.searchParams.get('pack')).toBe('eo-14412');
    expect(url.searchParams.get('secrecyYears')).toBe('20');
  });

  it('asks the estate for a derivation the same way', async () => {
    stubFetch();
    const url = await asked(getDerivation(ESTATE_SCAN, 'occ-1', 'eo-14412', 20));
    expect(url.pathname).toBe(`${API}/estate/occurrences/occ-1`);
    expect(url.searchParams.get('secrecyYears')).toBe('20');
  });

  it('compares two packs at one secrecy lifetime, so the difference is the policy', async () => {
    stubFetch();
    const url = await asked(getRerank('scan-1', 'nist-ir-8547-draft', 'eo-14412', 20));
    expect(url.pathname).toBe(`${API}/scans/scan-1/rerank`);
    expect(url.searchParams.get('from')).toBe('nist-ir-8547-draft');
    expect(url.searchParams.get('to')).toBe('eo-14412');
    expect(url.searchParams.get('secrecyYears')).toBe('20');
  });

  it('sends the pack and the secrecy lifetime with both worklist requests', async () => {
    stubFetch();
    const scan = await asked(getWorklists('scan-1', 'eo-14412', 20));
    expect(scan.searchParams.get('secrecyYears')).toBe('20');
    requested.length = 0;
    const estate = await asked(getEstate('eo-14412', 20));
    expect(estate.searchParams.get('secrecyYears')).toBe('20');
  });

  it('reports the path and the status when a request fails', async () => {
    vi.stubGlobal('fetch', () => Promise.resolve({ ok: false, status: 500 } as Response));
    await expect(getWorklists('scan-1', 'eo-14412', 5)).rejects.toThrow(
      '/scans/scan-1/worklists?pack=eo-14412&secrecyYears=5 -> 500',
    );
  });
});
