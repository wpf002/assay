import type { Primitive, Purpose } from '@assay/core';

/**
 * Algorithm-name normalization, shared by AST rules and config parsers.
 *
 * Every table here is a place a false positive can be born, so each entry maps
 * a name a developer actually writes to a primitive plus the parameters that
 * determine its strength. Names that cannot be resolved return null; the caller
 * must not guess.
 */

export interface AlgoSpec {
  readonly primitive: Primitive;
  readonly parameters: Readonly<Record<string, string | number>>;
  readonly purpose?: Purpose;
}

const HASHES: Readonly<Record<string, AlgoSpec>> = {
  md5: { primitive: 'MD5', parameters: { outputLength: 128 } },
  'md5-sha1': { primitive: 'MD5', parameters: { outputLength: 128 } },
  sha1: { primitive: 'SHA1', parameters: { outputLength: 160 } },
  sha: { primitive: 'SHA1', parameters: { outputLength: 160 } },
  sha224: { primitive: 'SHA2', parameters: { outputLength: 224 } },
  sha256: { primitive: 'SHA2', parameters: { outputLength: 256 } },
  sha384: { primitive: 'SHA2', parameters: { outputLength: 384 } },
  sha512: { primitive: 'SHA2', parameters: { outputLength: 512 } },
  'sha512-224': { primitive: 'SHA2', parameters: { outputLength: 224 } },
  'sha512-256': { primitive: 'SHA2', parameters: { outputLength: 256 } },
  'sha3-224': { primitive: 'SHA3', parameters: { outputLength: 224 } },
  'sha3-256': { primitive: 'SHA3', parameters: { outputLength: 256 } },
  'sha3-384': { primitive: 'SHA3', parameters: { outputLength: 384 } },
  'sha3-512': { primitive: 'SHA3', parameters: { outputLength: 512 } },
  blake2b512: { primitive: 'UNKNOWN', parameters: { name: 'BLAKE2b', outputLength: 512 } },
  blake2s256: { primitive: 'UNKNOWN', parameters: { name: 'BLAKE2s', outputLength: 256 } },
};

/** Accepts node ('sha256'), WebCrypto ('SHA-256') and python ('SHA256') spellings. */
export function hashFromName(name: string): AlgoSpec | null {
  const k = name.trim().toLowerCase().replace(/^-+|-+$/g, '');
  const direct = HASHES[k];
  if (direct) return direct;
  const dashless = k.replace(/-/g, '');
  for (const [key, spec] of Object.entries(HASHES)) {
    if (key.replace(/-/g, '') === dashless) return spec;
  }
  return null;
}

/**
 * OpenSSL-style cipher spec: aes-256-gcm, aes128-cbc, des-ede3-cbc, rc4.
 * The mode matters as much as the key size - AES-128-ECB is a finding in a way
 * AES-256-GCM is not - so it is preserved as a parameter.
 */
export function cipherFromName(name: string): AlgoSpec | null {
  const n = name.trim().toLowerCase();
  if (/^(des-ede3|3des|desede|des3)/.test(n)) {
    return { primitive: '3DES', parameters: { ...modeOf(n) }, purpose: 'DATA_ENCRYPTION' };
  }
  if (/^(rc4|arcfour|arc4)/.test(n)) {
    return { primitive: 'RC4', parameters: {}, purpose: 'DATA_ENCRYPTION' };
  }
  if (/^chacha20/.test(n)) {
    return {
      primitive: 'ChaCha20',
      parameters: { keySize: 256, ...(n.includes('poly1305') ? { mode: 'POLY1305' } : {}) },
      purpose: 'DATA_ENCRYPTION',
    };
  }
  const aes = /^aes[-_]?(128|192|256)?(?:[-_](\w+))?/.exec(n);
  if (aes) {
    const keySize = aes[1] ? Number(aes[1]) : undefined;
    const mode = aes[2] ? aes[2].toUpperCase() : undefined;
    return {
      primitive: 'AES',
      parameters: {
        ...(keySize === undefined ? {} : { keySize }),
        ...(mode === undefined ? {} : { mode }),
      },
      purpose: 'DATA_ENCRYPTION',
    };
  }
  return null;
}

function modeOf(n: string): Record<string, string> {
  const m = /(cbc|ecb|gcm|ctr|ofb|cfb|ccm|xts|siv)/.exec(n);
  return m ? { mode: (m[1] as string).toUpperCase() } : {};
}

const CURVES: Readonly<Record<string, string>> = {
  'p-256': 'P-256', prime256v1: 'P-256', secp256r1: 'P-256', 'nistp256': 'P-256',
  'p-384': 'P-384', secp384r1: 'P-384', 'nistp384': 'P-384',
  'p-521': 'P-521', secp521r1: 'P-521', 'nistp521': 'P-521',
  secp256k1: 'secp256k1',
  'p-224': 'P-224', secp224r1: 'P-224',
  x25519: 'X25519', curve25519: 'X25519', ed25519: 'Ed25519', x448: 'X448', ed448: 'Ed448',
};

export function normalizeCurve(name: string): string | null {
  return CURVES[name.trim().toLowerCase()] ?? null;
}

/**
 * JOSE algorithm identifiers. `alg` in a JWT is the whole security story, and
 * it resolves to a signature primitive plus its digest, which are two assets.
 */
export function joseAlgorithm(alg: string): readonly AlgoSpec[] {
  const a = alg.trim().toUpperCase();
  const digestBits = Number(a.slice(-3));
  const hash: AlgoSpec | null =
    Number.isFinite(digestBits) && digestBits > 0
      ? { primitive: 'SHA2', parameters: { outputLength: digestBits }, purpose: 'INTEGRITY' }
      : null;

  if (a === 'NONE') return [{ primitive: 'UNKNOWN', parameters: { alg: 'none' } }];
  if (a.startsWith('HS')) {
    return [
      { primitive: 'HMAC', parameters: { alg: a }, purpose: 'DIGITAL_SIGNATURE' },
      ...(hash ? [hash] : []),
    ];
  }
  if (a.startsWith('RS') || a.startsWith('PS')) {
    return [
      {
        primitive: 'RSA',
        parameters: { alg: a, padding: a.startsWith('PS') ? 'PSS' : 'PKCS1v15' },
        purpose: 'DIGITAL_SIGNATURE',
      },
      ...(hash ? [hash] : []),
    ];
  }
  if (a.startsWith('ES')) {
    const curve = a === 'ES256' ? 'P-256' : a === 'ES384' ? 'P-384' : a === 'ES512' ? 'P-521' : 'secp256k1';
    return [
      { primitive: 'ECDSA', parameters: { alg: a, curve }, purpose: 'DIGITAL_SIGNATURE' },
      ...(hash ? [hash] : []),
    ];
  }
  if (a === 'EDDSA') {
    return [{ primitive: 'EdDSA', parameters: { alg: a }, purpose: 'DIGITAL_SIGNATURE' }];
  }
  if (a.startsWith('RSA-OAEP') || a === 'RSA1_5') {
    return [
      {
        primitive: 'RSA',
        parameters: { alg: a, padding: a === 'RSA1_5' ? 'PKCS1v15' : 'OAEP' },
        purpose: 'KEY_ESTABLISHMENT',
      },
    ];
  }
  if (a.startsWith('ECDH-ES')) {
    return [{ primitive: 'ECDH', parameters: { alg: a }, purpose: 'KEY_ESTABLISHMENT' }];
  }
  if (a.startsWith('A') && a.includes('GCM')) {
    const bits = Number(a.replace(/\D/g, '').slice(0, 3));
    return [
      {
        primitive: 'AES',
        parameters: { mode: 'GCM', ...(Number.isFinite(bits) ? { keySize: bits } : {}) },
        purpose: 'DATA_ENCRYPTION',
      },
    ];
  }
  return [];
}

/**
 * OpenSSL signature spec as used by createSign('RSA-SHA256') and by
 * certificate signature algorithm fields.
 */
export function signatureFromName(name: string): readonly AlgoSpec[] {
  const n = name.trim().toLowerCase().replace(/with/g, '-');
  const parts = n.split(/[-_]/).filter(Boolean);
  const out: AlgoSpec[] = [];
  const hasRsaPss = n.includes('pss');

  for (const p of parts) {
    if (p === 'rsa' || p === 'rsassa') {
      out.push({
        primitive: 'RSA',
        parameters: { padding: hasRsaPss ? 'PSS' : 'PKCS1v15' },
        purpose: 'DIGITAL_SIGNATURE',
      });
    } else if (p === 'ecdsa' || p === 'ec') {
      out.push({ primitive: 'ECDSA', parameters: {}, purpose: 'DIGITAL_SIGNATURE' });
    } else if (p === 'dsa') {
      out.push({ primitive: 'DSA', parameters: {}, purpose: 'DIGITAL_SIGNATURE' });
    } else if (p === 'ed25519' || p === 'ed448') {
      out.push({ primitive: 'EdDSA', parameters: { curve: p === 'ed25519' ? 'Ed25519' : 'Ed448' }, purpose: 'DIGITAL_SIGNATURE' });
    } else {
      const h = hashFromName(p);
      if (h) out.push({ ...h, purpose: 'INTEGRITY' });
    }
  }
  return out;
}

/**
 * SSH KEX / host-key / cipher / MAC algorithm names, for sshd_config and for
 * Phase 2 handshake enumeration. Both callers need the same table or the
 * modalities will disagree about what they saw.
 */
export function sshAlgorithm(name: string): AlgoSpec | null {
  const n = name.trim().toLowerCase();
  if (n.startsWith('curve25519-sha256')) {
    return { primitive: 'X25519', parameters: {}, purpose: 'KEY_ESTABLISHMENT' };
  }
  if (n.startsWith('ecdh-sha2-nistp')) {
    const curve = normalizeCurve(n.replace('ecdh-sha2-', ''));
    return {
      primitive: 'ECDH',
      parameters: curve ? { curve } : {},
      purpose: 'KEY_ESTABLISHMENT',
    };
  }
  if (n.startsWith('diffie-hellman-group')) {
    const g = /group(\d+)/.exec(n);
    const groupSizes: Readonly<Record<string, number>> = {
      '1': 768, '5': 1536, '14': 2048, '15': 3072, '16': 4096, '17': 6144, '18': 8192,
    };
    const bits = g?.[1] ? groupSizes[g[1]] : undefined;
    return {
      primitive: 'DH',
      parameters: bits === undefined ? {} : { primeLength: bits },
      purpose: 'KEY_ESTABLISHMENT',
    };
  }
  if (n.startsWith('sntrup') || n.startsWith('mlkem') || n.includes('ml-kem')) {
    return { primitive: 'ML-KEM', parameters: { name: n }, purpose: 'KEY_ESTABLISHMENT' };
  }
  if (n.startsWith('ssh-rsa') || n.startsWith('rsa-sha2')) {
    return { primitive: 'RSA', parameters: {}, purpose: 'DIGITAL_SIGNATURE' };
  }
  if (n.startsWith('ssh-ed25519')) {
    return { primitive: 'EdDSA', parameters: { curve: 'Ed25519' }, purpose: 'DIGITAL_SIGNATURE' };
  }
  if (n.startsWith('ecdsa-sha2-nistp')) {
    const curve = normalizeCurve(n.replace('ecdsa-sha2-', ''));
    return {
      primitive: 'ECDSA',
      parameters: curve ? { curve } : {},
      purpose: 'DIGITAL_SIGNATURE',
    };
  }
  if (n.startsWith('ssh-dss')) {
    return { primitive: 'DSA', parameters: {}, purpose: 'DIGITAL_SIGNATURE' };
  }
  if (n.startsWith('hmac-')) {
    const h = hashFromName(n.replace('hmac-', '').replace(/-etm@.*/, ''));
    return { primitive: 'HMAC', parameters: h ? { hash: h.primitive } : {}, purpose: 'INTEGRITY' };
  }
  const c = cipherFromName(n.replace(/@openssh\.com$/, ''));
  return c;
}

/**
 * IANA / OpenSSL TLS cipher-suite names. One suite is several assets: a key
 * exchange, a bulk cipher and a MAC, on different urgency tracks. Returning
 * them as one blob is how tools end up ranking a VPN concentrator next to a
 * code-signing cert.
 */
export function tlsCipherSuite(name: string): readonly AlgoSpec[] {
  const n = name.trim().toUpperCase();
  const out: AlgoSpec[] = [];

  if (n.startsWith('TLS_AES_') || n.startsWith('TLS_CHACHA20')) {
    // TLS 1.3 suites name only the AEAD; the group is negotiated separately.
    const c = cipherFromName(n.replace(/^TLS_/, '').replace(/_/g, '-').toLowerCase());
    if (c) out.push(c);
    return out;
  }
  if (/ECDHE/.test(n)) out.push({ primitive: 'ECDH', parameters: { ephemeral: 'true' }, purpose: 'KEY_ESTABLISHMENT' });
  else if (/DHE/.test(n)) out.push({ primitive: 'DH', parameters: { ephemeral: 'true' }, purpose: 'KEY_ESTABLISHMENT' });
  else if (/^(TLS_)?RSA/.test(n)) out.push({ primitive: 'RSA', parameters: { mode: 'KEY_TRANSPORT' }, purpose: 'KEY_ESTABLISHMENT' });

  if (/ECDSA/.test(n)) out.push({ primitive: 'ECDSA', parameters: {}, purpose: 'CERTIFICATE_AUTH' });
  else if (/RSA/.test(n)) out.push({ primitive: 'RSA', parameters: {}, purpose: 'CERTIFICATE_AUTH' });

  const bulk = /(AES[-_]?(?:128|256)[-_]?(?:GCM|CBC|CCM)|CHACHA20[-_]POLY1305|3DES|DES[-_]CBC3|RC4)/.exec(n);
  if (bulk?.[1]) {
    const c = cipherFromName(bulk[1].replace(/_/g, '-').toLowerCase());
    if (c) out.push(c);
  }
  const mac = /(SHA384|SHA256|SHA1|SHA|MD5)$/.exec(n);
  if (mac?.[1]) {
    const h = hashFromName(mac[1]);
    if (h) out.push({ ...h, purpose: 'INTEGRITY' });
  }
  return out;
}
