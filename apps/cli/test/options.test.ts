import { existsSync } from 'node:fs';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { generateGrantKeypair, signGrant } from '@assay/scope';
import { runProbe } from '../src/commands/probe.js';
import { runScan } from '../src/commands/scan.js';
import { dateOption, nowOption, numberOption } from '../src/options.js';

/**
 * Flag parsing. commander hands every option through as a string, and the
 * failures that matter are the ones where a bad string becomes NaN and then
 * quietly wins every comparison it takes part in.
 */

const empty = (): Promise<string> => mkdtemp(join(tmpdir(), 'assay-options-'));

describe('option parsing', () => {
  it('names the flag and the value it rejects', () => {
    expect(() => numberOption('--secrecy-years', 'abc')).toThrow('--secrecy-years is not a number: abc');
    expect(() => dateOption('--now', '2026-13-45')).toThrow('--now is not a date: 2026-13-45');
  });

  it('rejects a number outside the bounds the flag documents', () => {
    expect(() => numberOption('--secrecy-years', '-1', { min: 0, max: 100 })).toThrow(
      '--secrecy-years must be at least 0: -1',
    );
    expect(() => numberOption('--secrecy-years', '500', { min: 0, max: 100 })).toThrow(
      '--secrecy-years must be at most 100: 500',
    );
    expect(numberOption('--secrecy-years', '5', { min: 0, max: 100 })).toBe(5);
  });

  it('reads the clock rather than a date when --now is not given', () => {
    expect(nowOption(undefined).getTime()).toBeGreaterThan(0);
  });
});

describe('assay probe', () => {
  it('refuses a clock skew that is not a number instead of probing on an expired grant', async () => {
    const dir = await empty();
    const { publicKeyPem, privateKeyPem } = generateGrantKeypair();
    const grant = signGrant(
      {
        grantId: 'g1',
        issuedBy: 'test',
        targets: ['127.0.0.1'],
        ports: [1],
        notBefore: '2020-01-01T00:00:00.000Z',
        notAfter: '2020-01-02T00:00:00.000Z',
        purpose: 'regression',
      },
      privateKeyPem,
    );
    await writeFile(join(dir, 'grant.json'), JSON.stringify(grant), 'utf8');
    await writeFile(join(dir, 'key.pem'), publicKeyPem, 'utf8');

    await expect(
      runProbe(['127.0.0.1:1'], {
        grant: join(dir, 'grant.json'),
        pubkey: join(dir, 'key.pem'),
        policy: 'eo-14412',
        out: join(dir, 'cbom.json'),
        profile: 'cyclonedx-1.7',
        secrecyYears: '5',
        timeoutMs: '200',
        clockSkewSeconds: 'abc',
        now: '2026-08-28T00:00:00.000Z',
      }),
    ).rejects.toThrow('--clock-skew-seconds is not a number: abc');

    // Nothing below the gate may run: a NaN skew fails both window
    // comparisons, which accepts a grant that expired six years ago.
    expect(existsSync(join(dir, 'cbom.json'))).toBe(false);
  });
});

describe('assay scan', () => {
  const options = (dir: string) => ({
    policy: 'eo-14412',
    out: join(dir, 'cbom.json'),
    profile: 'cyclonedx-1.7',
    secrecyYears: '5',
    binaries: false,
  });

  it('refuses a secrecy lifetime that is not a number instead of ranking everything at NaN', async () => {
    const dir = await empty();
    await expect(runScan(dir, { ...options(dir), secrecyYears: 'abc' })).rejects.toThrow(
      '--secrecy-years is not a number: abc',
    );
    expect(existsSync(join(dir, 'cbom.json'))).toBe(false);
  });

  it('names --now when its value is not a date', async () => {
    const dir = await empty();
    await expect(runScan(dir, { ...options(dir), now: '2026-13-45' })).rejects.toThrow(
      '--now is not a date: 2026-13-45',
    );
  });
});
