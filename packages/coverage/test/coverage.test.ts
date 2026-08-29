import { describe, expect, it } from 'vitest';
import { MODALITIES, type Modality, type Occurrence } from '@assay/core';
import {
  CLASSES,
  ESTATE_CLASSES,
  UNCLASSIFIED_MODALITIES,
  classesFor,
  classOf,
  coverageReport,
  coverageDigest,
  generateCoverageKeypair,
  signCoverage,
  verifyCoverage,
  type CoverageInput,
} from '../src/index.js';

const occ = (id: string, modalities: Modality[], systemId = 'payments'): Occurrence => ({
  id,
  assetId: `asset-${id}`,
  systemId,
  controlClass: 'PROTOCOL_BILATERAL',
  reachability: null,
  evidence: modalities.map((m, i) => ({
    modality: m,
    locator: `src/x.ts:${i}`,
    raw: 'x',
    collectedAt: '2026-08-01T00:00:00.000Z',
    collectorVersion: 'test/0.1.0',
    occurrence: { location: 'src/x.ts', line: i },
  })),
  confidence: { kind: 'EVIDENCE', label: 'e', value: 0.9, weight: 1, sources: [] },
});

const input = (occurrences: Occurrence[], over: Partial<CoverageInput> = {}): CoverageInput => ({
  subject: { kind: 'SCAN', id: 'scan-1', systems: ['payments'] },
  generatedAt: '2026-08-28T00:00:00.000Z',
  policy: { packId: 'eo-14412', packVersion: '1.0.0' },
  detectors: ['detect-source'],
  occurrences,
  assets: [],
  ...over,
});

describe('the class taxonomy is total', () => {
  it('gives every modality at least one class', () => {
    // A modality that speaks for no class would vanish from every report -
    // silently, and in exactly the direction that flatters the tool.
    expect(UNCLASSIFIED_MODALITIES).toEqual([]);
  });

  it('names every declared class exactly once', () => {
    expect(CLASSES.map((c) => c.id).sort()).toEqual([...ESTATE_CLASSES].sort());
    expect(new Set(CLASSES.map((c) => c.id)).size).toBe(CLASSES.length);
  });

  it('uses only real modalities', () => {
    for (const c of CLASSES) {
      for (const m of c.modalities) expect(MODALITIES).toContain(m);
    }
  });

  it('gives every class a remedy and a caveat, because "not examined" has to be actionable', () => {
    for (const c of CLASSES) {
      expect(c.remedy.length).toBeGreaterThan(10);
      expect(c.caveat.length).toBeGreaterThan(10);
    }
  });

  it('maps a modality to every class that can see it, not just the first', () => {
    expect(classesFor('HOST_AGENT')).toEqual(['DEPLOYED_CONFIG', 'HOSTS']);
    expect(classesFor('ASSERTED')).toEqual(['APPLIANCES', 'THIRD_PARTY_SAAS']);
  });

  it('throws on a class that does not exist', () => {
    // @ts-expect-error deliberately invalid
    expect(() => classOf('NOPE')).toThrow(/unknown estate class/);
  });
});

describe('examined means evidence, not intent', () => {
  it('does not mark a class examined because a detector ran', () => {
    // The detector list is what was invoked. Coverage is what was seen. A
    // source scan that found nothing has not examined the appliances.
    const r = coverageReport(input([], { detectors: ['detect-source', 'detect-pki', 'detect-kms'] }));
    expect(r.classes.every((c) => !c.examined)).toBe(true);
    expect(r.summary.classesExamined).toBe(0);
  });

  it('marks exactly the classes the evidence speaks for', () => {
    const r = coverageReport(input([occ('a', ['SOURCE_AST']), occ('b', ['PKI_CERTIFICATE'])]));
    const yes = r.classes.filter((c) => c.examined).map((c) => c.id);
    expect(yes).toEqual(['APPLICATION_SOURCE', 'CERTIFICATES']);
  });

  it('counts one occurrence into every class its modalities reach', () => {
    const r = coverageReport(input([occ('a', ['HOST_AGENT'])]));
    const config = r.classes.find((c) => c.id === 'DEPLOYED_CONFIG');
    const hosts = r.classes.find((c) => c.id === 'HOSTS');
    expect(config?.occurrences).toBe(1);
    expect(hosts?.occurrences).toBe(1);
  });

  it('does not double-count an occurrence with two modalities in one class', () => {
    const r = coverageReport(input([occ('a', ['BINARY_SYMBOL', 'BINARY_STRING'])]));
    const bin = r.classes.find((c) => c.id === 'VENDOR_BINARIES');
    expect(bin?.occurrences).toBe(1);
    expect(bin?.modalitiesUsed).toEqual(['BINARY_STRING', 'BINARY_SYMBOL']);
  });

  it('reports which systems contributed to a class', () => {
    const r = coverageReport(
      input([occ('a', ['SOURCE_AST'], 'treasury'), occ('b', ['SOURCE_AST'], 'payments')], {
        subject: { kind: 'ESTATE', id: 'estate', systems: ['treasury', 'payments'] },
      }),
    );
    expect(r.classes.find((c) => c.id === 'APPLICATION_SOURCE')?.systems).toEqual([
      'payments',
      'treasury',
    ]);
  });
});

describe('the summary leads with what was missed', () => {
  it('names the unexamined classes rather than a reassuring fraction', () => {
    const r = coverageReport(input([occ('a', ['SOURCE_AST'])]));
    expect(r.summary.statement).toContain('no evidence was gathered for 9 of 10 classes');
    expect(r.summary.statement).toContain('Managed keys (KMS, HSM, KMIP)');
    expect(r.summary.statement).toContain('not about what exists');
  });

  it('counts blind spots into the sentence', () => {
    const r = coverageReport(
      input([occ('a', ['SOURCE_AST'])], {
        blindSpots: [
          { name: 'hsm-broker', kind: 'SERVICE', observedBy: 'tempo', why: 'no scan' },
          { name: 'edge-lb', kind: 'HOST', observedBy: 'tempo', why: 'no scan' },
        ],
      }),
    );
    expect(r.summary.statement).toContain('2 service(s) or host(s) were observed');
    expect(r.blindSpots.map((b) => b.name)).toEqual(['edge-lb', 'hsm-broker']);
  });

  it('says so plainly when nothing was missed', () => {
    const all = MODALITIES.map((m, i) => occ(`o${i}`, [m]));
    const r = coverageReport(input(all));
    expect(r.summary.classesExamined).toBe(r.summary.classesTotal);
    expect(r.summary.statement).toContain('every class of the estate produced evidence');
  });
});

describe('what the report refuses to let a reader infer', () => {
  it('states it, every time, in the document itself', () => {
    const r = coverageReport(input([occ('a', ['SOURCE_AST'])]));
    expect(r.notAsserted.length).toBeGreaterThanOrEqual(5);
    expect(r.notAsserted.join(' ')).toContain('Presence is not exposure');
    expect(r.notAsserted.join(' ')).toContain('completely inventoried');
  });

  it('keeps the caveat on a class that WAS examined', () => {
    // The caveat is not an excuse for an empty row; it is the limit of the
    // claim being made by a full one.
    const r = coverageReport(input([occ('a', ['DEPENDENCY'])]));
    const deps = r.classes.find((c) => c.id === 'DEPENDENCIES');
    expect(deps?.examined).toBe(true);
    expect(deps?.caveat).toContain('never what it does');
  });
});

describe('the report is a signable artifact', () => {
  it('is byte-identical for identical input, which is what makes a signature mean anything', () => {
    const a = coverageReport(input([occ('a', ['SOURCE_AST'])]));
    const b = coverageReport(input([occ('a', ['SOURCE_AST'])]));
    expect(coverageDigest(a)).toBe(coverageDigest(b));
  });

  it('does not depend on the order evidence arrived in', () => {
    const a = coverageReport(input([occ('a', ['SOURCE_AST']), occ('b', ['PKI_CERTIFICATE'])]));
    const b = coverageReport(input([occ('a', ['SOURCE_AST']), occ('b', ['PKI_CERTIFICATE'])]));
    expect(coverageDigest(a)).toBe(coverageDigest(b));
  });

  it('changes digest when coverage changes', () => {
    const a = coverageReport(input([occ('a', ['SOURCE_AST'])]));
    const b = coverageReport(input([occ('a', ['SOURCE_AST']), occ('b', ['CLOUD_KMS_API'])]));
    expect(coverageDigest(a)).not.toBe(coverageDigest(b));
  });

  it('verifies under the issuer key', () => {
    const kp = generateCoverageKeypair();
    const signed = signCoverage(coverageReport(input([occ('a', ['SOURCE_AST'])])), kp.privateKeyPem);
    expect(verifyCoverage(signed, kp.publicKeyPem)).toEqual({ ok: true });
  });

  it('fails under a different key', () => {
    const kp = generateCoverageKeypair();
    const other = generateCoverageKeypair();
    const signed = signCoverage(coverageReport(input([occ('a', ['SOURCE_AST'])])), kp.privateKeyPem);
    expect(verifyCoverage(signed, other.publicKeyPem)).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
  });

  it('catches a report edited after signing', () => {
    const kp = generateCoverageKeypair();
    const signed = signCoverage(coverageReport(input([occ('a', ['SOURCE_AST'])])), kp.privateKeyPem);
    const tampered = {
      ...signed,
      report: {
        ...signed.report,
        classes: signed.report.classes.map((c) => ({ ...c, examined: true })),
      },
    };
    // Claiming every class was examined is the edit someone would actually
    // make, so it is the one the digest has to catch.
    expect(verifyCoverage(tampered, kp.publicKeyPem)).toEqual({ ok: false, reason: 'DIGEST_MISMATCH' });
  });

  it('rejects a key that is not a key', () => {
    const kp = generateCoverageKeypair();
    const signed = signCoverage(coverageReport(input([])), kp.privateKeyPem);
    expect(verifyCoverage(signed, 'not a pem')).toEqual({ ok: false, reason: 'BAD_KEY' });
  });

  it('will not accept the envelope vouching for itself', () => {
    // Verifying with the key that travelled beside the signature proves only
    // internal consistency, which any forger can arrange. The API makes the
    // trusted key a required argument so that mistake cannot be made silently.
    const kp = generateCoverageKeypair();
    const forger = generateCoverageKeypair();
    const real = signCoverage(coverageReport(input([occ('a', ['SOURCE_AST'])])), kp.privateKeyPem);
    const forged = signCoverage(
      { ...real.report, summary: { ...real.report.summary, classesExamined: 10 } },
      forger.privateKeyPem,
    );
    expect(verifyCoverage(forged, forged.publicKeyPem)).toEqual({ ok: true });
    expect(verifyCoverage(forged, kp.publicKeyPem)).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
  });
});
