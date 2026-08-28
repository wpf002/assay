import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scoreMosca } from '@assay/core';
import {
  PolicyPackSchema,
  generatePackKeypair,
  listPacks,
  loadPack,
  parsePack,
  signPack,
  verifyPack,
} from '../src/index.js';

const PUBLIC_KEY = readFileSync(resolve(__dirname, '../keys/assay-packs.pub.pem'), 'utf8');
const raw = (id: string): Record<string, unknown> =>
  JSON.parse(readFileSync(resolve(__dirname, `../packs/${id}.json`), 'utf8')) as Record<string, unknown>;

describe('the shipped packs are attributable', () => {
  it('signs every pack in the box', () => {
    for (const id of listPacks()) {
      expect(loadPack(id).trust).toBe('SIGNED');
    }
  });

  it('covers the pack version, so a revision cannot be swapped in under an old signature', () => {
    const pack = { ...raw('eo-14412'), packVersion: '9.9.9' };
    expect(parsePack(pack, { publisherKeyPem: PUBLIC_KEY }).trust).toBe('UNTRUSTED');
  });
});

describe('D3: Z is signed, Y is local', () => {
  it('does NOT invalidate the signature when a customer edits their own migration times', () => {
    // The whole point of the split. An organization knows how long its own
    // migrations take; nobody outside the building does.
    const pack = raw('eo-14412');
    const local = {
      ...pack,
      migrationYearsByControl: {
        ...(pack['migrationYearsByControl'] as Record<string, number>),
        VENDOR_LOCKED: 7,
      },
    };
    const loaded = parsePack(local, { publisherKeyPem: PUBLIC_KEY });
    expect(loaded.trust).toBe('SIGNED');
    expect(loaded.migrationYearsByControl.VENDOR_LOCKED).toBe(7);
  });

  it('DOES invalidate it when the horizon is edited', () => {
    const loaded = parsePack({ ...raw('eo-14412'), crqcYear: 2045 }, { publisherKeyPem: PUBLIC_KEY });
    expect(loaded.trust).toBe('UNTRUSTED');
    expect(loaded.trustReason).toContain('edited after signing');
  });

  it('DOES invalidate it when a regulatory deadline is moved', () => {
    const moved = {
      ...raw('eo-14412'),
      regulatoryDeadlines: { CONFIDENTIALITY: 2040, AUTHENTICITY: 2041 },
    };
    expect(parsePack(moved, { publisherKeyPem: PUBLIC_KEY }).trust).toBe('UNTRUSTED');
  });

  it('reports an unsigned local pack honestly rather than refusing it', () => {
    const local = { ...raw('eo-14412'), packId: 'acme-internal', signature: null };
    const loaded = parsePack(local, { publisherKeyPem: PUBLIC_KEY });
    expect(loaded.trust).toBe('UNSIGNED');
    expect(loaded.trustReason).toContain('attributable to nobody');
  });

  it('will not silently accept a signed pack when no key is available to check it', () => {
    expect(parsePack(raw('eo-14412'), { publisherKeyPem: null }).trust).toBe('UNTRUSTED');
  });

  it('can refuse anything unsigned outright, for a regulated deployment', () => {
    const local = { ...raw('eo-14412'), signature: null };
    expect(() => parsePack(local, { publisherKeyPem: PUBLIC_KEY, requireSigned: true })).toThrow(
      /UNSIGNED/,
    );
  });

  it('rejects a signature from a different publisher', () => {
    const other = generatePackKeypair();
    const forged = {
      ...raw('eo-14412'),
      signature: signPack(PolicyPackSchema.parse(raw('eo-14412')), other.privateKeyPem),
    };
    expect(parsePack(forged, { publisherKeyPem: PUBLIC_KEY }).trust).toBe('UNTRUSTED');
  });

  it('rejects a mangled signature rather than coercing it', () => {
    const pack = PolicyPackSchema.parse(raw('eo-14412'));
    expect(verifyPack({ ...pack, signature: 'zzzz' }, PUBLIC_KEY).trust).toBe('UNTRUSTED');
  });
});

describe('an unattributable horizon is visible in every finding it produces', () => {
  const args = {
    purpose: 'KEY_ESTABLISHMENT' as const,
    controlClass: 'SELF' as const,
    secrecyLifetimeYears: 5,
    currentYear: 2026.66,
  };

  it('marks Z and D as POLICY under a signed pack', () => {
    const m = scoreMosca({ ...args, policy: loadPack('eo-14412') });
    const s = JSON.stringify(m.factor);
    expect(s).toContain('"kind":"POLICY"');
    expect(s).not.toContain('horizon not attributable');
  });

  it('demotes them to ASSUMPTION under an unsigned one, without refusing to rank', () => {
    // Enforcement is disclosure, not prohibition: forbidding local packs just
    // makes an organization with a real disagreement fork the tool.
    const local = parsePack({ ...raw('eo-14412'), signature: null }, { publisherKeyPem: PUBLIC_KEY });
    const m = scoreMosca({ ...args, policy: local });
    const s = JSON.stringify(m.factor);
    expect(s).toContain('ASSUMPTION');
    expect(s).toContain('horizon not attributable');
    expect(typeof m.slackYears).toBe('number');
  });

  it('does not change the arithmetic, only its attribution', () => {
    const signed = scoreMosca({ ...args, policy: loadPack('eo-14412') });
    const unsigned = scoreMosca({
      ...args,
      policy: parsePack({ ...raw('eo-14412'), signature: null }, { publisherKeyPem: PUBLIC_KEY }),
    });
    expect(unsigned.slackYears).toBe(signed.slackYears);
  });
});

describe('loading from disk', () => {
  it('names the available packs when asked for one that does not exist', () => {
    expect(() => loadPack('definitely-not-a-pack')).toThrow(/unknown policy pack/);
  });

  it('validates the schema before anything else', () => {
    expect(PolicyPackSchema.safeParse({ packId: 'x' }).success).toBe(false);
  });
});
