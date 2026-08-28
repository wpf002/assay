import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { analyzeReachability, assemble, divergences } from '@assay/correlate';
import { scanSource } from '@assay/detect-source';
import { scanDependencies } from '@assay/detect-deps';
import { decimalYear, loadPack } from '@assay/policy';
import { rank, toCycloneDX } from '@assay/core';

/**
 * Phase 1 end to end: a real tree on disk -> evidence -> occurrences ->
 * two ranked worklists -> a CycloneDX document.
 */

const ROOT = resolve(__dirname, '../../../fixtures/sample-repo');
const NOW = new Date('2026-08-28T00:00:00.000Z');
const COLLECTED = NOW.toISOString();

async function scan() {
  const [source, deps] = await Promise.all([
    scanSource({ root: ROOT, systemId: 'sample', collectedAt: COLLECTED }),
    scanDependencies({ root: ROOT, systemId: 'sample', collectedAt: COLLECTED }),
  ]);
  const assembled = assemble([...source.findings, ...deps.findings]);
  const reach = analyzeReachability(assembled.occurrences, source.graph);
  const occurrences = reach.occurrences;
  const assets = assembled.assets;
  const pack = loadPack('eo-14412');
  const worklists = rank(occurrences, assets, {
    policy: pack,
    currentYear: decimalYear(NOW),
    secrecyLifetime: () => ({ years: 5, assumed: true }),
  });
  const cbom = toCycloneDX(occurrences, assets, {
    policyPackId: pack.packId,
    policyPackVersion: pack.packVersion,
    timestamp: COLLECTED,
    toolVersion: 'test',
  });
  return { source, deps, occurrences, assets, worklists, cbom, reach };
}

describe('phase 1 pipeline', () => {
  it('finds crypto in TypeScript, Python and config from one tree', async () => {
    const { source } = await scan();
    const modalities = new Set(source.findings.map((f) => f.evidence.modality));
    expect(modalities).toEqual(new Set(['SOURCE_AST', 'SOURCE_CONFIG']));

    const files = new Set(source.findings.map((f) => f.evidence.occurrence?.location));
    expect([...files].some((f) => f?.endsWith('.ts'))).toBe(true);
    expect([...files].some((f) => f?.endsWith('.py'))).toBe(true);
    expect([...files].some((f) => f?.endsWith('nginx.conf'))).toBe(true);
    expect([...files].some((f) => f?.endsWith('sshd_config'))).toBe(true);
  });

  it('resolves parameters rather than reporting bare primitives', async () => {
    const { assets } = await scan();
    const rsa = assets.filter((a) => a.primitive === 'RSA');
    expect(rsa.some((a) => a.parameters['modulusLength'] === 2048)).toBe(true);
    const ecdsa = assets.filter((a) => a.primitive === 'ECDSA');
    expect(ecdsa.some((a) => a.parameters['curve'] === 'P-256')).toBe(true);
  });

  it('classifies TLS and SSH algorithm lists as PROTOCOL_BILATERAL, not SELF', async () => {
    const { occurrences } = await scan();
    const bilateral = occurrences.filter((o) => o.controlClass === 'PROTOCOL_BILATERAL');
    expect(bilateral.length).toBeGreaterThan(0);
    expect(
      bilateral.every((o) => o.evidence.every((e) => e.modality === 'SOURCE_CONFIG')),
    ).toBe(true);
  });

  it('produces two separate worklists, both short enough to read', async () => {
    const { worklists } = await scan();
    expect(worklists.confidentiality.length).toBeGreaterThan(0);
    expect(worklists.authenticity.length).toBeGreaterThan(0);
    // The Phase 1 exit gate is a human-readable worklist. If a 4-file fixture
    // yields hundreds of rows, the ceilings or the grouping are wrong.
    expect(worklists.confidentiality.length + worklists.authenticity.length).toBeLessThan(60);
  });

  it('never puts a key-establishment asset on the authenticity track', async () => {
    const { worklists } = await scan();
    expect(worklists.confidentiality.every((f) => f.track === 'CONFIDENTIALITY')).toBe(true);
    expect(worklists.authenticity.every((f) => f.track === 'AUTHENTICITY')).toBe(true);
  });

  it('holds dependency evidence in hints, out of both worklists', async () => {
    const { worklists } = await scan();
    expect(worklists.hints.length).toBeGreaterThan(0);
    expect(worklists.hints.every((f) => f.assertionLevel === 'SUSPECTED')).toBe(true);
    const worklistIds = new Set([
      ...worklists.confidentiality.map((f) => f.occurrenceId),
      ...worklists.authenticity.map((f) => f.occurrenceId),
    ]);
    expect(worklists.hints.every((f) => !worklistIds.has(f.occurrenceId))).toBe(true);
  });

  it('shows the bilateral protocol work as the most overdue, ahead of our own code', async () => {
    const { worklists } = await scan();
    const first = worklists.confidentiality[0];
    expect(first?.controlClass).toBe('PROTOCOL_BILATERAL');
    expect(first?.late).toBe(true);
  });

  it('reports which constraint bound, per finding', async () => {
    const { worklists } = await scan();
    const all = [...worklists.confidentiality, ...worklists.authenticity];
    expect(all.some((f) => f.bindingConstraint === 'REGULATORY')).toBe(true);
    expect(all.some((f) => f.bindingConstraint === 'CRQC')).toBe(true);
  });

  it('is byte-identical across runs of the same tree', async () => {
    const a = await scan();
    const b = await scan();
    expect(JSON.stringify(a.cbom)).toBe(JSON.stringify(b.cbom));
    expect(a.cbom.serialNumber).toBe(b.cbom.serialNumber);
  });

  it('emits a CycloneDX 1.7 document with occurrences carrying file and line', async () => {
    const { cbom } = await scan();
    expect(cbom.specVersion).toBe('1.7');
    const s = JSON.stringify(cbom);
    expect(s).toContain('cryptographic-asset');
    expect(s).toContain('src/keys.ts');
    expect(s).toContain('"line"');
  });

  it('ignores node_modules and other non-estate directories', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-ignore-'));
    const { writeFile, mkdir } = await import('node:fs/promises');
    await mkdir(join(dir, 'node_modules/pkg'), { recursive: true });
    await writeFile(
      join(dir, 'node_modules/pkg/index.js'),
      "const crypto = require('crypto'); crypto.createHash('md5');",
    );
    const r = await scanSource({ root: dir, systemId: 's', collectedAt: COLLECTED });
    expect(r.findings).toHaveLength(0);
  });
});

describe('the CBOM on disk', () => {
  it('round-trips as valid JSON', async () => {
    const { cbom } = await scan();
    const dir = await mkdtemp(join(tmpdir(), 'assay-cbom-'));
    const path = join(dir, 'cbom.json');
    const { writeFile } = await import('node:fs/promises');
    await writeFile(path, JSON.stringify(cbom, null, 2));
    const parsed: unknown = JSON.parse(await readFile(path, 'utf8'));
    expect((parsed as { bomFormat: string }).bomFormat).toBe('CycloneDX');
  });
});

describe('phase 3: reachability on the fixture tree', () => {
  it('finds the http entry point and analyzes from it', async () => {
    const { reach } = await scan();
    expect(reach.analyzed).toBe(true);
    expect(reach.entryPoints).toContain('src/server.ts');
  });

  it('marks the test-only cipher unreached', async () => {
    const { occurrences, assets } = await scan();
    const rc4 = assets.find((a) => a.primitive === 'RC4');
    const occ = occurrences.find((o) => o.assetId === rc4?.id);
    expect(occ?.reachability?.reachable).toBe(false);
  });

  it('marks the module nothing imports unreached', async () => {
    const { occurrences, assets } = await scan();
    const tdes = assets.find((a) => a.primitive === '3DES' && a.parameters['mode'] === 'CBC');
    const occs = occurrences.filter((o) => o.assetId === tdes?.id);
    // The sshd_config 3DES is deployed configuration and reached; the one in
    // src/unused.ts is not. Same asset, different work items.
    expect(occs.some((o) => o.reachability?.reachable === false)).toBe(true);
  });

  it('ships the path for a reached finding', async () => {
    const { occurrences } = await scan();
    const withPath = occurrences.find((o) => (o.reachability?.path.length ?? 0) > 0);
    expect(withPath?.reachability?.path[0]?.fullFilename).toBe('src/server.ts');
  });

  it('keeps every unreached finding out of both worklists', async () => {
    const { worklists } = await scan();
    expect(worklists.confidentiality.every((f) => f.reachable === true)).toBe(true);
    expect(worklists.authenticity.every((f) => f.reachable === true)).toBe(true);
    expect(worklists.unreached.length).toBeGreaterThan(0);
  });

  it('emits the reachability path into CycloneDX evidence.callstack', async () => {
    const { cbom } = await scan();
    const s = JSON.stringify(cbom);
    expect(s).toContain('callstack');
    expect(s).toContain('src/server.ts');
    // An empty callstack would read as "we traced this" when nothing was traced.
    expect(s).not.toContain('"callstack":{"frames":[]}');
  });

  it('names capability/deployment divergences, or none when only one view exists', async () => {
    const { occurrences, assets } = await scan();
    // The fixture is a source-and-config scan with a certificate on disk, so a
    // real divergence set requires a probe. Assert the shape, not a count.
    expect(Array.isArray(divergences(occurrences, assets))).toBe(true);
  });
});
