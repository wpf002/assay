import { describe, expect, it } from 'vitest';
import { canonicalize, sha256Hex, assetId, makeAsset } from '../src/index.js';

describe('sha256', () => {
  it('matches published vectors', () => {
    expect(sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    );
  });

  it('handles multibyte input and block boundaries', () => {
    expect(sha256Hex('a'.repeat(55))).toHaveLength(64);
    expect(sha256Hex('a'.repeat(56))).toHaveLength(64);
    expect(sha256Hex('a'.repeat(64))).toHaveLength(64);
    expect(sha256Hex('é中🔐')).toHaveLength(64);
  });
});

describe('canonical json', () => {
  it('is insensitive to key order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
  });
  it('is sensitive to array order', () => {
    expect(canonicalize([1, 2])).not.toBe(canonicalize([2, 1]));
  });
});

describe('asset identity', () => {
  it('is stable across parameter key order', () => {
    expect(assetId('RSA', { modulusLength: 2048, padding: 'pss' }, 'KEY_ESTABLISHMENT')).toBe(
      assetId('RSA', { padding: 'pss', modulusLength: 2048 }, 'KEY_ESTABLISHMENT'),
    );
  });

  it('separates the same primitive used for different purposes', () => {
    expect(assetId('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT')).not.toBe(
      assetId('RSA', { modulusLength: 2048 }, 'DIGITAL_SIGNATURE'),
    );
  });
});

describe('vulnerability classification', () => {
  it('flags Shor-broken asymmetric regardless of size', () => {
    expect(makeAsset('RSA', { modulusLength: 16384 }, 'KEY_ESTABLISHMENT').quantumVulnerable).toBe(true);
    expect(makeAsset('X25519', {}, 'KEY_ESTABLISHMENT').quantumVulnerable).toBe(true);
  });

  it('clears standardized PQ primitives', () => {
    expect(makeAsset('ML-KEM', { parameterSet: '768' }, 'KEY_ESTABLISHMENT').quantumVulnerable).toBe(
      false,
    );
  });

  it('applies Grover to symmetric keys below 256 bits', () => {
    expect(makeAsset('AES', { keySize: 128 }, 'DATA_ENCRYPTION').quantumVulnerable).toBe(true);
    expect(makeAsset('AES', { keySize: 256 }, 'DATA_ENCRYPTION').quantumVulnerable).toBe(false);
  });

  it('does not report an already-broken primitive as quantum-safe', () => {
    expect(makeAsset('3DES', {}, 'DATA_ENCRYPTION').quantumVulnerable).toBe(true);
    expect(makeAsset('MD5', {}, 'INTEGRITY').quantumVulnerable).toBe(true);
  });

  it('derives classical strength from NIST SP 800-57 equivalences', () => {
    expect(makeAsset('RSA', { modulusLength: 2048 }, 'KEY_ESTABLISHMENT').classicalSecurityBits).toBe(112);
    expect(makeAsset('RSA', { modulusLength: 3072 }, 'KEY_ESTABLISHMENT').classicalSecurityBits).toBe(128);
    expect(makeAsset('ECDSA', { curve: 'P-384' }, 'DIGITAL_SIGNATURE').classicalSecurityBits).toBe(192);
  });
});
