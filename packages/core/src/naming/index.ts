import type { Primitive, Purpose } from '../types/crypto-asset.js';

/**
 * Algorithm-name normalization.
 *
 * Lives in core because three modalities read the same names and must agree.
 * `sshd_config` says `ecdh-sha2-nistp256`; an SSH handshake says the same
 * string on the wire; a certificate says `P-256`. If the config parser and the
 * network prober normalized those differently they would produce two assets
 * with different content hashes, and the noisy-OR across independent modality
 * groups - the entire point of I1 - would silently never fire.
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
  // RFC 6668 spells the SSH SHA-2 MACs `hmac-sha2-256`, where the `2` is the
  // family and not part of the output length. Without folding it away, every
  // modern `MACs` line resolves to null and its HMACs lose their digest.
  const k = name.trim().toLowerCase().replace(/^-+|-+$/g, '').replace(/^sha2-(?=\d)/, 'sha');
  const direct = HASHES[k];
  if (direct) return direct;
  const dashless = k.replace(/-/g, '');
  for (const [key, spec] of Object.entries(HASHES)) {
    if (key.replace(/-/g, '') === dashless) return spec;
  }
  return null;
}

/**
 * Block ciphers with no member in the Primitive union.
 *
 * Mapping them onto a neighbouring primitive is worse than admitting the gap:
 * single DES reported as 3DES asserts 112-bit strength for a 56-bit cipher, and
 * RC2 has no relationship to 3DES at all. They are carried the way BLAKE2 is
 * above - the real name in `name`, so the asset stays distinguishable and no
 * false strength claim reaches the CBOM.
 */
const UNNAMED_CIPHERS: Readonly<Record<string, Readonly<Record<string, string | number>>>> = {
  des: { name: 'DES', keySize: 56 },
  rc2: { name: 'RC2' },
  blowfish: { name: 'Blowfish' },
  cast5: { name: 'CAST5' },
  idea: { name: 'IDEA' },
};

/**
 * OpenSSL-style cipher spec: aes-256-gcm, aes128-cbc, des-ede3-cbc, rc4.
 * The mode matters as much as the key size - AES-128-ECB is a finding in a way
 * AES-256-GCM is not - so it is preserved as a parameter.
 */
export function cipherFromName(name: string): AlgoSpec | null {
  const n = name.trim().toLowerCase();
  // OpenSSL spells 3DES five different ways depending on where it appears:
  // `DES-EDE3-CBC` in a cipher spec, `DES-CBC3-SHA` in a TLS suite name,
  // `3des-cbc` on the SSH wire, `DESede` in Java, `TripleDES` in pyca. Missing
  // one of them means a 3DES endpoint silently reports as having no bulk
  // cipher at all.
  if (/^(des-ede|des-cbc3|3des|desede|des3|tripledes)/.test(n)) {
    return { primitive: '3DES', parameters: { ...modeOf(n) }, purpose: 'DATA_ENCRYPTION' };
  }
  const unnamed = /^(des|rc2|blowfish|cast5|idea)(?:[-_]|$)/.exec(n);
  if (unnamed?.[1]) {
    return {
      primitive: 'UNKNOWN',
      parameters: { ...UNNAMED_CIPHERS[unnamed[1]], ...modeOf(n) },
      purpose: 'DATA_ENCRYPTION',
    };
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
  // Before the RS/PS signature branch: `RSA-OAEP`, `RSA-OAEP-256` and `RSA1_5`
  // all start with `RS`, so testing that prefix first filed every JWE key
  // management algorithm on the authenticity track with PKCS1v15 padding -
  // losing the harvest-now-decrypt-later term for a key transport algorithm.
  if (a.startsWith('RSA-OAEP') || a === 'RSA1_5') {
    return [
      {
        primitive: 'RSA',
        parameters: { alg: a, padding: a === 'RSA1_5' ? 'PKCS1v15' : 'OAEP' },
        purpose: 'KEY_ESTABLISHMENT',
      },
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

  for (const raw of parts) {
    // OID long names glue the algorithm to a suffix: sha256WithRSAEncryption,
    // ecdsa-with-SHA256, dsaWithSHA1. Strip the suffix before matching, or the
    // key algorithm in every certificate signature field goes unrecognized.
    const p = raw.replace(/(encryption|signature)$/, '');
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
    } else if (p !== '' && p !== 'with' && p !== 'md') {
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
  if (n.startsWith('mlkem') || n.includes('ml-kem')) {
    // The wire name is provenance. In parameters it splits one key agreement
    // into a row per spelling - OpenSSH ships both `...-sha256` and
    // `...-sha256@openssh.com` - and stops the SSH and TLS modalities from
    // agreeing on a content hash for the same KEM.
    return { primitive: 'ML-KEM', parameters: {}, purpose: 'KEY_ESTABLISHMENT' };
  }
  if (n.startsWith('sntrup')) {
    // Streamlined NTRU Prime is not FIPS 203. Calling it ML-KEM stamps the NIST
    // ML-KEM OID on an asset that is not it, and lets a vendor roadmap claiming
    // ML-KEM be corroborated by an endpoint that never negotiates it - the one
    // contradiction attest exists to catch. It is still not Shor-broken, so the
    // quantum verdict is unchanged; only the standardized label is withheld.
    const kem = /^sntrup\d+(?:x25519)?/.exec(n)?.[0] ?? 'sntrup';
    return { primitive: 'UNKNOWN', parameters: { name: kem }, purpose: 'KEY_ESTABLISHMENT' };
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
  const bare = n.replace(/^TLS[-_]/, '');

  if (/ECDHE|EECDH/.test(bare)) {
    out.push({ primitive: 'ECDH', parameters: { ephemeral: 'true' }, purpose: 'KEY_ESTABLISHMENT' });
  } else if (/DHE|EDH/.test(bare)) {
    out.push({ primitive: 'DH', parameters: { ephemeral: 'true' }, purpose: 'KEY_ESTABLISHMENT' });
  } else if (/^ECDH[-_]/.test(bare)) {
    out.push({ primitive: 'ECDH', parameters: { ephemeral: 'false' }, purpose: 'KEY_ESTABLISHMENT' });
  } else if (/^DH[-_]/.test(bare)) {
    out.push({ primitive: 'DH', parameters: { ephemeral: 'false' }, purpose: 'KEY_ESTABLISHMENT' });
  } else if (!/^(ADH|AECDH|PSK|SRP|KRB5|GOST|NULL|AECDHE)/.test(bare)) {
    // OpenSSL names the RSA key-transport suites with no key-exchange prefix
    // at all: AES128-SHA, AES256-GCM-SHA384, DES-CBC3-SHA. Requiring an "RSA"
    // token misses every one of them - and static RSA key transport is the
    // single worst case for harvest-now-decrypt-later, because one leaked
    // private key retroactively opens every recorded session.
    out.push({ primitive: 'RSA', parameters: { mode: 'KEY_TRANSPORT' }, purpose: 'KEY_ESTABLISHMENT' });
  }

  if (/ECDSA/.test(bare)) out.push({ primitive: 'ECDSA', parameters: {}, purpose: 'CERTIFICATE_AUTH' });
  else if (/DSS/.test(bare)) out.push({ primitive: 'DSA', parameters: {}, purpose: 'CERTIFICATE_AUTH' });
  else if (!/^(ADH|AECDH|PSK|SRP|NULL)/.test(bare)) {
    out.push({ primitive: 'RSA', parameters: {}, purpose: 'CERTIFICATE_AUTH' });
  }

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
