import { describe, expect, it } from 'vitest';
import {
  cipherFromName,
  joseAlgorithm,
  normalizeCurve,
  signatureFromName,
  sshAlgorithm,
  tlsCipherSuite,
} from '../src/index.js';

describe('one algorithm, many spellings', () => {
  it('recognizes 3DES however the ecosystem writes it', () => {
    for (const name of ['des-ede3-cbc', 'DES-CBC3-SHA', '3des-cbc', 'DESede', 'des3']) {
      expect(cipherFromName(name)?.primitive).toBe('3DES');
    }
  });

  it('finds the bulk cipher in a legacy TLS suite name', () => {
    const specs = tlsCipherSuite('ECDHE-RSA-DES-CBC3-SHA');
    expect(specs.map((s) => s.primitive)).toContain('3DES');
    expect(specs.map((s) => s.primitive)).toContain('ECDH');
  });

  it('normalizes a curve to one name across config, wire and certificate', () => {
    for (const name of ['prime256v1', 'secp256r1', 'P-256', 'nistp256']) {
      expect(normalizeCurve(name)).toBe('P-256');
    }
    // The SSH wire name and the nginx directive must agree, or the two
    // modalities mint different assets and never corroborate.
    expect(sshAlgorithm('ecdh-sha2-nistp256')?.parameters['curve']).toBe('P-256');
  });

  it('splits a TLS 1.2 suite across both urgency tracks', () => {
    const specs = tlsCipherSuite('ECDHE-ECDSA-AES128-GCM-SHA256');
    const purposes = new Set(specs.map((s) => s.purpose));
    expect(purposes.has('KEY_ESTABLISHMENT')).toBe(true);
    expect(purposes.has('CERTIFICATE_AUTH')).toBe(true);
    expect(purposes.has('DATA_ENCRYPTION')).toBe(true);
  });

  it('treats RSA key transport as key establishment, not as a certificate', () => {
    const specs = tlsCipherSuite('AES128-SHA');
    const kex = specs.find((s) => s.purpose === 'KEY_ESTABLISHMENT');
    expect(kex?.primitive).toBe('RSA');
    expect(kex?.parameters['mode']).toBe('KEY_TRANSPORT');
  });

  it('expands a JOSE alg into a signature primitive and a digest', () => {
    expect(joseAlgorithm('PS384').map((s) => s.primitive)).toEqual(['RSA', 'SHA2']);
    expect(joseAlgorithm('PS384')[0]?.parameters['padding']).toBe('PSS');
  });

  it('resolves an SSH group number to a prime length', () => {
    expect(sshAlgorithm('diffie-hellman-group14-sha1')?.parameters['primeLength']).toBe(2048);
    expect(sshAlgorithm('diffie-hellman-group1-sha1')?.parameters['primeLength']).toBe(768);
  });

  it('recognizes a post-quantum SSH KEX as safe', () => {
    expect(sshAlgorithm('mlkem768x25519-sha256@openssh.com')?.primitive).toBe('ML-KEM');
  });
});

describe('post-quantum SSH names name only what they are', () => {
  it('does not claim sntrup761 is the NIST standard', () => {
    // Streamlined NTRU Prime carries no FIPS 203 OID and must not corroborate
    // a vendor roadmap that promises ML-KEM.
    const spec = sshAlgorithm('sntrup761x25519-sha512@openssh.com');
    expect(spec?.primitive).toBe('UNKNOWN');
    expect(spec?.parameters['name']).toBe('sntrup761x25519');
  });

  it('gives both spellings of one KEM the same parameters', () => {
    // OpenSSH ships the vendor-suffixed and bare names side by side.
    expect(sshAlgorithm('sntrup761x25519-sha512')?.parameters).toEqual(
      sshAlgorithm('sntrup761x25519-sha512@openssh.com')?.parameters,
    );
    expect(sshAlgorithm('mlkem768x25519-sha256')?.parameters).toEqual({});
  });
});

describe('digests and ciphers the union does not name', () => {
  it('reads the digest out of an RFC 6668 SSH MAC name', () => {
    expect(sshAlgorithm('hmac-sha2-256')?.parameters['hash']).toBe('SHA2');
    expect(sshAlgorithm('hmac-sha2-512-etm@openssh.com')?.parameters['hash']).toBe('SHA2');
  });

  it('recognizes pyca and Java spellings of 3DES', () => {
    expect(cipherFromName('TripleDES')?.primitive).toBe('3DES');
    expect(cipherFromName('des-ede-cbc')?.primitive).toBe('3DES');
  });

  it('does not report single DES as 3DES', () => {
    // 3DES claims 112 classical bits; single DES has 56.
    for (const name of ['DES', 'des-cbc', 'des']) {
      const spec = cipherFromName(name);
      expect(spec?.primitive).toBe('UNKNOWN');
      expect(spec?.parameters['name']).toBe('DES');
    }
    expect(cipherFromName('des-cbc')?.parameters['mode']).toBe('CBC');
  });

  it('names the ciphers that have no primitive of their own rather than dropping them', () => {
    for (const [name, expected] of [['RC2', 'RC2'], ['Blowfish', 'Blowfish'], ['CAST5', 'CAST5'], ['IDEA', 'IDEA']]) {
      expect(cipherFromName(name as string)?.parameters['name']).toBe(expected);
    }
  });
});

describe('JOSE key management algorithms stay on the confidentiality track', () => {
  it('reads RSA-OAEP as OAEP key establishment, not as a PKCS1v15 signature', () => {
    const specs = joseAlgorithm('RSA-OAEP-256');
    expect(specs[0]?.purpose).toBe('KEY_ESTABLISHMENT');
    expect(specs[0]?.parameters['padding']).toBe('OAEP');
  });

  it('keeps RSA1_5 key transport off the authenticity track', () => {
    expect(joseAlgorithm('RSA1_5')[0]?.purpose).toBe('KEY_ESTABLISHMENT');
  });

  it('still reads RS256 as a signature', () => {
    expect(joseAlgorithm('RS256')[0]?.purpose).toBe('DIGITAL_SIGNATURE');
    expect(joseAlgorithm('RS256')[0]?.parameters['padding']).toBe('PKCS1v15');
  });
});

describe('OpenSSL suite names without a key-exchange prefix', () => {
  it('reads AES128-SHA as static RSA key transport, the worst HNDL case', () => {
    const specs = tlsCipherSuite('AES128-SHA');
    const kex = specs.find((s) => s.purpose === 'KEY_ESTABLISHMENT');
    expect(kex?.primitive).toBe('RSA');
    expect(kex?.parameters['mode']).toBe('KEY_TRANSPORT');
  });

  it('does not invent a key exchange for anonymous or PSK suites', () => {
    for (const name of ['ADH-AES128-SHA', 'PSK-AES128-CBC-SHA']) {
      expect(tlsCipherSuite(name).some((s) => s.purpose === 'KEY_ESTABLISHMENT')).toBe(false);
    }
  });

  it('distinguishes ephemeral from static key agreement', () => {
    expect(tlsCipherSuite('ECDHE-RSA-AES128-GCM-SHA256').find((s) => s.primitive === 'ECDH')?.parameters['ephemeral']).toBe('true');
    expect(tlsCipherSuite('ECDH-RSA-AES128-GCM-SHA256').find((s) => s.primitive === 'ECDH')?.parameters['ephemeral']).toBe('false');
  });

  it('leaves a TLS 1.3 suite as the AEAD alone, since the group is negotiated separately', () => {
    const specs = tlsCipherSuite('TLS_AES_256_GCM_SHA384');
    expect(specs).toHaveLength(1);
    expect(specs[0]?.primitive).toBe('AES');
  });
});

describe('OID long names', () => {
  it('reads the key algorithm out of a glued certificate signature name', () => {
    // sha256WithRSAEncryption is what an X.509 signatureAlgorithm field says,
    // and it is what OpenSSL accepts for one-shot signing.
    for (const name of ['sha256WithRSAEncryption', 'RSA-SHA256', 'sha256WithRSA']) {
      const specs = signatureFromName(name);
      expect(specs.map((s) => s.primitive)).toContain('RSA');
      expect(specs.map((s) => s.primitive)).toContain('SHA2');
    }
  });

  it('reads ECDSA and DSA long forms', () => {
    expect(signatureFromName('ecdsa-with-SHA384').map((s) => s.primitive)).toContain('ECDSA');
    expect(signatureFromName('dsaWithSHA1').map((s) => s.primitive)).toContain('DSA');
  });

  it('does not turn the joining word into a digest', () => {
    expect(signatureFromName('sha256WithRSAEncryption').filter((s) => s.primitive === 'MD5')).toHaveLength(0);
  });
});
