import { normalizeCurve, type Primitive, type Purpose } from '@assay/core';

/**
 * Imported symbol -> asset.
 *
 * The strongest signal available in a stripped binary. `ECDSA_do_sign` is not
 * a string that happens to say ECDSA - it is a relocation the loader must
 * resolve, which means the code path exists and was linked. That is why
 * BINARY_SYMBOL sits at 0.85 while BINARY_STRING sits at 0.30.
 *
 * What it still cannot tell you is whether the path is ever taken. A binary
 * that links all of libcrypto imports symbols for algorithms it never calls,
 * which is a reachability question and is why 0.85 is not 0.98.
 */

export interface SymbolMatch {
  readonly symbol: string;
  readonly primitive: Primitive;
  readonly parameters: Readonly<Record<string, string | number>>;
  readonly purpose: Purpose;
  readonly rationale: string;
}

interface Rule {
  readonly pattern: RegExp;
  readonly primitive: Primitive;
  readonly purpose: Purpose;
  readonly rationale: string;
  readonly parameters?: (symbol: string) => Readonly<Record<string, string | number>>;
}

const curveFrom = (symbol: string): Readonly<Record<string, string | number>> => {
  const m = /(?:NID_)?(?:X9_62_)?(prime256v1|secp\d{3}[kr]1|nistp\d{3}|P-?\d{3})/i.exec(symbol);
  const curve = m?.[1] === undefined ? null : normalizeCurve(m[1]);
  return curve === null ? {} : { curve };
};

const sizeFrom = (symbol: string): Readonly<Record<string, string | number>> => {
  const m = /(\d{3,4})/.exec(symbol);
  return m?.[1] === undefined ? {} : { modulusLength: Number(m[1]) };
};

/** Key size and mode as an EVP cipher accessor states them: EVP_aes_256_gcm. */
const evpCipherFrom = (symbol: string): Readonly<Record<string, string | number>> => {
  const bits = /_(128|192|256)_/.exec(symbol)?.[1];
  const mode = /_(gcm|ccm|cbc|ctr|ecb|ofb|cfb\d*|xts|ocb|wrap)(?:$|_)/.exec(symbol)?.[1];
  return {
    ...(bits === undefined ? {} : { keySize: Number(bits) }),
    ...(mode === undefined ? {} : { mode: mode.toUpperCase() }),
  };
};

/** Digest length from the trailing figure: EVP_sha384, EVP_sha512_224. */
const evpDigestFrom = (symbol: string): Readonly<Record<string, string | number>> => {
  const m = /(\d{3})$/.exec(symbol);
  return m?.[1] === undefined ? {} : { outputLength: Number(m[1]) };
};

/**
 * Order matters: the first matching rule wins, so specific patterns precede
 * generic ones. `EVP_` wrappers are deliberately last, because they name a
 * family rather than an algorithm.
 */
const RULES: readonly Rule[] = [
  {
    pattern: /^(RSA_(sign|verify|public_encrypt|private_decrypt|generate_key|generate_multi_prime_key)|RSA_padding_add)/,
    primitive: 'RSA',
    purpose: 'DIGITAL_SIGNATURE',
    rationale: 'OpenSSL low-level RSA entry point',
    parameters: sizeFrom,
  },
  {
    pattern: /^(ECDSA_(do_sign|do_verify|sign|verify)|ECDSA_SIG_)/,
    primitive: 'ECDSA',
    purpose: 'DIGITAL_SIGNATURE',
    rationale: 'OpenSSL ECDSA entry point',
    parameters: curveFrom,
  },
  {
    pattern: /^(ECDH_compute_key|EC_POINT_mul|EC_KEY_(new|generate_key|set_group))/,
    primitive: 'ECDH',
    purpose: 'KEY_ESTABLISHMENT',
    rationale: 'OpenSSL elliptic-curve key agreement',
    parameters: curveFrom,
  },
  {
    pattern: /^(DH_(compute_key|generate_key|new)|DH_check)/,
    primitive: 'DH',
    purpose: 'KEY_ESTABLISHMENT',
    rationale: 'OpenSSL finite-field Diffie-Hellman',
  },
  {
    pattern: /^(DSA_(do_sign|do_verify|sign|verify|generate_key))/,
    primitive: 'DSA',
    purpose: 'DIGITAL_SIGNATURE',
    rationale: 'OpenSSL DSA entry point',
  },
  {
    pattern: /^(X25519|x25519_|curve25519_)/,
    primitive: 'X25519',
    purpose: 'KEY_ESTABLISHMENT',
    rationale: 'X25519 key agreement',
  },
  {
    pattern: /^(ED25519_(sign|verify|keypair)|ed25519_)/,
    primitive: 'EdDSA',
    purpose: 'DIGITAL_SIGNATURE',
    rationale: 'Ed25519 signature',
  },
  {
    pattern: /^(AES_(encrypt|decrypt|set_encrypt_key|set_decrypt_key|cbc_encrypt)|aes_v8_|aesni_)/,
    primitive: 'AES',
    purpose: 'DATA_ENCRYPTION',
    rationale: 'AES block cipher entry point, including hardware-accelerated variants',
  },
  {
    pattern: /^(DES_(ecb3_encrypt|ede3_cbc_encrypt|set_key)|des_ede3)/,
    primitive: '3DES',
    purpose: 'DATA_ENCRYPTION',
    rationale: 'Triple DES entry point',
  },
  {
    pattern: /^(RC4|rc4_)/,
    primitive: 'RC4',
    purpose: 'DATA_ENCRYPTION',
    rationale: 'RC4 stream cipher',
  },
  {
    pattern: /^(ChaCha20|chacha20_|CRYPTO_chacha)/,
    primitive: 'ChaCha20',
    purpose: 'DATA_ENCRYPTION',
    rationale: 'ChaCha20 stream cipher',
  },
  {
    pattern: /^(MD5_(Init|Update|Final)|md5_block)/,
    primitive: 'MD5',
    purpose: 'INTEGRITY',
    rationale: 'MD5 digest',
  },
  {
    pattern: /^(SHA1_(Init|Update|Final)|sha1_block)/,
    primitive: 'SHA1',
    purpose: 'INTEGRITY',
    rationale: 'SHA-1 digest',
  },
  {
    pattern: /^(SHA(224|256|384|512)_(Init|Update|Final)|sha(256|512)_block)/,
    primitive: 'SHA2',
    purpose: 'INTEGRITY',
    rationale: 'SHA-2 digest',
    parameters: (s) => {
      const m = /(224|256|384|512)/.exec(s);
      return m?.[1] === undefined ? {} : { outputLength: Number(m[1]) };
    },
  },
  {
    pattern: /^(SHA3_|KeccakF)/,
    primitive: 'SHA3',
    purpose: 'INTEGRITY',
    rationale: 'SHA-3 / Keccak permutation',
  },
  {
    pattern: /^(HMAC_(Init|Update|Final|CTX)|hmac_)/,
    primitive: 'HMAC',
    purpose: 'INTEGRITY',
    rationale: 'HMAC construction',
  },
  {
    pattern: /^(PKCS5_PBKDF2_HMAC|pbkdf2)/i,
    primitive: 'PBKDF2',
    purpose: 'KEY_DERIVATION',
    rationale: 'PBKDF2 key derivation',
  },
  {
    pattern: /^(EVP_PBE_scrypt|scrypt_)/,
    primitive: 'scrypt',
    purpose: 'KEY_DERIVATION',
    rationale: 'scrypt key derivation',
  },
  {
    pattern: /^(argon2)/i,
    primitive: 'Argon2',
    purpose: 'KEY_DERIVATION',
    rationale: 'Argon2 key derivation',
  },
  {
    pattern: /^(ML_KEM|mlkem|kyber)/i,
    primitive: 'ML-KEM',
    purpose: 'KEY_ESTABLISHMENT',
    rationale: 'ML-KEM / Kyber key encapsulation - a post-quantum positive, worth reporting as one',
  },
  {
    pattern: /^(ML_DSA|mldsa|dilithium)/i,
    primitive: 'ML-DSA',
    purpose: 'DIGITAL_SIGNATURE',
    rationale: 'ML-DSA / Dilithium signature',
  },
  {
    pattern: /^(SLH_DSA|slhdsa|sphincs)/i,
    primitive: 'SLH-DSA',
    purpose: 'DIGITAL_SIGNATURE',
    rationale: 'SLH-DSA / SPHINCS+ signature',
  },
  // EVP_ accessors last, and only the ones that name an algorithm outright.
  // OpenSSL 3 deprecated the low-level RSA_/AES_/SHA*_ entry points above, so a
  // current libcrypto consumer imports these and nothing else - which left the
  // 0.85 modality dead for the commonest case in modern software. The family
  // wrappers (EVP_DigestSignInit, EVP_PKEY_CTX_new_id) stay unmatched on
  // purpose: they name an algorithm in an argument, and a symbol table has no
  // arguments to read.
  {
    pattern: /^EVP_aes_(128|192|256)_/,
    primitive: 'AES',
    purpose: 'DATA_ENCRYPTION',
    rationale: 'OpenSSL EVP cipher accessor naming AES and its key size',
    parameters: evpCipherFrom,
  },
  {
    pattern: /^EVP_des_ede3/,
    primitive: '3DES',
    purpose: 'DATA_ENCRYPTION',
    rationale: 'OpenSSL EVP cipher accessor naming Triple DES',
    parameters: evpCipherFrom,
  },
  {
    pattern: /^EVP_rc4/,
    primitive: 'RC4',
    purpose: 'DATA_ENCRYPTION',
    rationale: 'OpenSSL EVP cipher accessor naming RC4',
  },
  {
    pattern: /^EVP_chacha20/,
    primitive: 'ChaCha20',
    purpose: 'DATA_ENCRYPTION',
    rationale: 'OpenSSL EVP cipher accessor naming ChaCha20',
    parameters: () => ({ keySize: 256 }),
  },
  {
    pattern: /^EVP_md5(_sha1)?$/,
    primitive: 'MD5',
    purpose: 'INTEGRITY',
    rationale: 'OpenSSL EVP digest accessor naming MD5',
    parameters: () => ({ outputLength: 128 }),
  },
  {
    pattern: /^EVP_sha1$/,
    primitive: 'SHA1',
    purpose: 'INTEGRITY',
    rationale: 'OpenSSL EVP digest accessor naming SHA-1',
    parameters: () => ({ outputLength: 160 }),
  },
  {
    pattern: /^EVP_sha(224|256|384|512)(_(224|256))?$/,
    primitive: 'SHA2',
    purpose: 'INTEGRITY',
    rationale: 'OpenSSL EVP digest accessor naming SHA-2 and its output length',
    parameters: evpDigestFrom,
  },
  {
    pattern: /^EVP_(sha3_(224|256|384|512)|shake(128|256))$/,
    primitive: 'SHA3',
    purpose: 'INTEGRITY',
    rationale: 'OpenSSL EVP digest accessor naming SHA-3 / SHAKE',
  },
];

export function matchSymbol(symbol: string): SymbolMatch | null {
  const bare = symbol.replace(/^_+/, '').replace(/@.*$/, '');
  for (const rule of RULES) {
    if (!rule.pattern.test(bare)) continue;
    return {
      symbol,
      primitive: rule.primitive,
      parameters: rule.parameters === undefined ? {} : rule.parameters(bare),
      purpose: rule.purpose,
      rationale: rule.rationale,
    };
  }
  return null;
}

export function matchSymbols(symbols: readonly string[]): SymbolMatch[] {
  return symbols
    .map(matchSymbol)
    .filter((m): m is SymbolMatch => m !== null)
    .sort((a, b) => a.symbol.localeCompare(b.symbol));
}

/**
 * Library and version fingerprints.
 *
 * A version string is the difference between "this ships OpenSSL" and "this
 * ships OpenSSL 1.0.2, which has no post-quantum path and is a procurement
 * problem rather than an upgrade".
 */
export interface LibraryFingerprint {
  readonly library: string;
  readonly version: string | null;
  readonly evidence: string;
}

const FINGERPRINTS: readonly { name: string; pattern: RegExp }[] = [
  { name: 'OpenSSL', pattern: /OpenSSL\s+(\d+\.\d+\.\d+[a-z]?(?:-[\w.]+)?)/ },
  { name: 'BoringSSL', pattern: /BoringSSL(?:\s+([\w.]+))?/ },
  { name: 'LibreSSL', pattern: /LibreSSL\s+([\d.]+)/ },
  { name: 'mbedTLS', pattern: /mbed\s?TLS\s+([\d.]+)/ },
  { name: 'wolfSSL', pattern: /wolfSSL\s+([\d.]+)/ },
  { name: 'GnuTLS', pattern: /GnuTLS\s+([\d.]+)/ },
  // Anchored: without the boundary a GNSS receiver banner - ubiquitous in the
  // firmware images this detector targets - is reported as the NSS library
  // carrying a version number, which reads as strong evidence.
  { name: 'NSS', pattern: /\bNSS\s+([\d.]+)/ },
  { name: 'libsodium', pattern: /libsodium\s+([\d.]+)/ },
  { name: 'Bouncy Castle', pattern: /BouncyCastle(?:\s+v?([\d.]+))?/ },
];

export function fingerprintLibraries(strings: readonly string[]): LibraryFingerprint[] {
  const out = new Map<string, LibraryFingerprint>();
  for (const s of strings) {
    for (const fp of FINGERPRINTS) {
      const m = fp.pattern.exec(s);
      if (m === null) continue;
      const key = `${fp.name}@${m[1] ?? 'unknown'}`;
      if (!out.has(key)) {
        out.set(key, { library: fp.name, version: m[1] ?? null, evidence: s.slice(0, 160) });
      }
    }
  }
  return [...out.values()].sort((a, b) => a.library.localeCompare(b.library));
}
