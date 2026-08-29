import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { coverageReport, generateCoverageKeypair, signCoverage } from '@assay/coverage';
import { runCoverageKeygen, runCoverageVerify } from '../src/commands/coverage.js';

const report = () =>
  coverageReport({
    subject: { kind: 'SCAN', id: 'scan-1', systems: ['payments'] },
    generatedAt: '2026-08-28T00:00:00.000Z',
    policy: { packId: 'eo-14412', packVersion: '1.0.0' },
    detectors: ['detect-source'],
    occurrences: [],
    assets: [],
  });

const out: string[] = [];
const write = vi.spyOn(process.stdout, 'write').mockImplementation((c) => {
  out.push(String(c));
  return true;
});
const errWrite = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

afterEach(() => {
  out.length = 0;
});

describe('verifying an attestation someone handed you', () => {
  it('accepts one signed by the key you trust', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-cov-'));
    const kp = generateCoverageKeypair();
    const file = join(dir, 'attestation.json');
    await writeFile(file, JSON.stringify({ signed: true, ...signCoverage(report(), kp.privateKeyPem) }));

    await runCoverageVerify(file, { key: kp.publicKeyPem });
    expect(out.join('')).toContain('verified against the supplied key');
  });

  it('reads the key from a file as well as inline', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-cov-'));
    const kp = generateCoverageKeypair();
    const file = join(dir, 'attestation.json');
    const keyFile = join(dir, 'key.pub');
    await writeFile(file, JSON.stringify({ signed: true, ...signCoverage(report(), kp.privateKeyPem) }));
    await writeFile(keyFile, kp.publicKeyPem);

    await runCoverageVerify(file, { key: keyFile });
    expect(out.join('')).toContain('verified');
  });

  it('rejects one signed by somebody else', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-cov-'));
    const kp = generateCoverageKeypair();
    const forger = generateCoverageKeypair();
    const file = join(dir, 'attestation.json');
    await writeFile(
      file,
      JSON.stringify({ signed: true, ...signCoverage(report(), forger.privateKeyPem) }),
    );

    // The forged envelope carries the forger's public key and is internally
    // consistent. It fails here only because the reader supplies their own.
    await expect(runCoverageVerify(file, { key: kp.publicKeyPem })).rejects.toThrow(/BAD_SIGNATURE/);
  });

  it('rejects one edited after signing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-cov-'));
    const kp = generateCoverageKeypair();
    const signed = signCoverage(report(), kp.privateKeyPem);
    const file = join(dir, 'attestation.json');
    await writeFile(
      file,
      JSON.stringify({
        signed: true,
        ...signed,
        report: {
          ...signed.report,
          summary: { ...signed.report.summary, classesExamined: 10 },
        },
      }),
    );
    await expect(runCoverageVerify(file, { key: kp.publicKeyPem })).rejects.toThrow(/DIGEST_MISMATCH/);
  });

  it('refuses to pretend an unsigned attestation was verified', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-cov-'));
    const file = join(dir, 'attestation.json');
    await writeFile(file, JSON.stringify({ signed: false, reason: 'no key', digest: 'x', report: report() }));
    await expect(runCoverageVerify(file, { key: 'x' })).rejects.toThrow(/unsigned/);
  });
});

describe('keygen', () => {
  it('writes the private key readable only by its owner', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-cov-'));
    const key = join(dir, 'coverage.key');
    await runCoverageKeygen({ out: key });

    const { stat } = await import('node:fs/promises');
    expect((await stat(key)).mode & 0o777).toBe(0o600);
    expect(await readFile(key, 'utf8')).toContain('BEGIN PRIVATE KEY');
    expect(await readFile(`${key}.pub`, 'utf8')).toContain('BEGIN PUBLIC KEY');
  });

  it('prints both keys when no path is given', async () => {
    await runCoverageKeygen({});
    expect(out.join('')).toContain('BEGIN PRIVATE KEY');
    expect(out.join('')).toContain('BEGIN PUBLIC KEY');
  });
});

write.mockRestore;
errWrite.mockRestore;
