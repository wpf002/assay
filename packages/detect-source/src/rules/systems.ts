import { cipherFromName, hashFromName, normalizeCurve, signatureFromName } from '@assay/core';
import type { Detection, Rule } from '../types.js';
import { DUAL_USE_NOTE, arg, boundTo, detection, num, str } from './helpers.js';

/**
 * Go, Java, C/C++, Rust and C#.
 *
 * These are where the estate actually lives. A TypeScript-only scanner reports
 * on the layer a company rewrote last year and says nothing about the payments
 * core, the appliance firmware, or the twelve-year-old Java service that signs
 * everything.
 *
 * The libraries differ in where they put the algorithm: Go names it in the
 * package path, Java in a string passed to a factory, OpenSSL in the function
 * name, .NET in the class. Each gets rules shaped to its own idiom rather than
 * one generic pattern that half-works everywhere.
 */

/* ------------------------------------------------------------------- Go */

const goStdlib: Rule = {
  id: 'go/crypto',
  languages: ['go'],
  methods: ['GenerateKey', 'GenerateMultiPrimeKey', 'New', 'NewCipher', 'NewTripleDESCipher', 'Sum', 'Sign', 'Verify', 'EncryptOAEP', 'DecryptOAEP', 'EncryptPKCS1v15', 'DecryptPKCS1v15', 'SignPKCS1v15', 'VerifyPKCS1v15', 'SignPSS'],
  rationale:
    'Go names the algorithm in the package path (crypto/rsa, crypto/des) and the strength in the call, so the receiver identifies the primitive without any string to resolve.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['crypto', 'golang.org/x/crypto']) && !/^(rsa|ecdsa|ed25519|ecdh|dsa|des|aes|rc4|md5|sha1|sha256|sha512|hmac|elliptic|chacha20poly1305|curve25519)\./.test(call.callee)) {
      return [];
    }
    // `import cryptorsa "crypto/rsa"` names the package something else at the
    // call site, so the switch runs on the last segment of the imported path
    // rather than on the identifier the file happens to use.
    const root = call.calleeParts[0] ?? '';
    const imported = ctx.aliases.get(root);
    const pkg = (imported === undefined ? root : (imported.split('/').pop() ?? root)).toLowerCase();
    const id = goStdlib.id;

    switch (pkg) {
      case 'rsa': {
        // rsa.GenerateKey(rand.Reader, 2048)
        const bits = num(call.args[1]) ?? num(call.args[0]);
        if (/OAEP|PKCS1v15$/.test(call.method) && !/Sign|Verify/.test(call.method)) {
          return [detection(id, 'RSA', { mode: 'KEY_TRANSPORT' }, 'KEY_ESTABLISHMENT')];
        }
        if (/Sign|Verify/.test(call.method)) {
          return [
            detection(id, 'RSA', { padding: call.method.includes('PSS') ? 'PSS' : 'PKCS1v15' }, 'DIGITAL_SIGNATURE'),
          ];
        }
        return [
          detection(
            id,
            'RSA',
            bits === null ? {} : { modulusLength: bits },
            'KEY_ESTABLISHMENT',
            'RULE_DEFAULT',
            DUAL_USE_NOTE,
          ),
        ];
      }
      case 'ecdsa':
        return [detection(id, 'ECDSA', curveOf(call.args[0]?.text ?? ''), 'DIGITAL_SIGNATURE')];
      case 'ed25519':
        return [detection(id, 'EdDSA', { curve: 'Ed25519' }, 'DIGITAL_SIGNATURE')];
      case 'ecdh':
        return [detection(id, 'ECDH', curveOf(call.callee), 'KEY_ESTABLISHMENT')];
      case 'curve25519':
        return [detection(id, 'X25519', {}, 'KEY_ESTABLISHMENT')];
      case 'dsa':
        return [detection(id, 'DSA', {}, 'DIGITAL_SIGNATURE')];
      case 'des':
        // crypto/des exposes both ciphers. Reporting des.NewCipher as 3DES
        // claims 112 classical bits for a 56-bit cipher and merges it into the
        // same asset as real 3DES; the Primitive union has no DES member, so it
        // is carried as a named UNKNOWN.
        return call.method === 'NewTripleDESCipher'
          ? [detection(id, '3DES', {}, 'DATA_ENCRYPTION')]
          : [
              detection(
                id,
                'UNKNOWN',
                { name: 'DES', keySize: 56 },
                'DATA_ENCRYPTION',
                'RESOLVED',
                'single DES: 56-bit, broken without reference to quantum',
              ),
            ];
      case 'aes':
        return [detection(id, 'AES', {}, 'DATA_ENCRYPTION')];
      case 'rc4':
        return [detection(id, 'RC4', {}, 'DATA_ENCRYPTION')];
      case 'chacha20poly1305':
        return [detection(id, 'ChaCha20', { keySize: 256, mode: 'POLY1305' }, 'DATA_ENCRYPTION')];
      case 'md5':
        return [detection(id, 'MD5', { outputLength: 128 }, 'INTEGRITY')];
      case 'sha1':
        return [detection(id, 'SHA1', { outputLength: 160 }, 'INTEGRITY')];
      case 'sha256':
        return [detection(id, 'SHA2', { outputLength: call.method === 'Sum224' ? 224 : 256 }, 'INTEGRITY')];
      case 'sha512':
        return [detection(id, 'SHA2', { outputLength: 512 }, 'INTEGRITY')];
      case 'hmac':
        return [detection(id, 'HMAC', {}, 'INTEGRITY')];
      default:
        return [];
    }
  },
};

function curveOf(text: string): Readonly<Record<string, string>> {
  const m = /P(224|256|384|521)/.exec(text);
  const curve = m?.[1] === undefined ? null : normalizeCurve(`P-${m[1]}`);
  return curve === null ? {} : { curve };
}

/* ----------------------------------------------------------------- Java */

const javaJca: Rule = {
  id: 'java/jca',
  languages: ['java'],
  methods: ['getInstance', 'initialize', 'init', 'generateKeyPair'],
  rationale:
    'JCA puts the entire algorithm specification in a string passed to a factory: Cipher.getInstance("AES/CBC/PKCS5Padding"), Signature.getInstance("SHA1withRSA"). The transformation string is the finding.',
  detect(call, ctx) {
    const receiver = call.calleeParts[call.calleeParts.length - 2] ?? '';
    const known = ['Cipher', 'Signature', 'MessageDigest', 'KeyPairGenerator', 'KeyGenerator', 'Mac', 'KeyAgreement', 'SecretKeyFactory'];
    if (!known.includes(receiver)) return [];
    // A local class named Cipher is not javax.crypto.Cipher.
    if (
      ctx.imports.size > 0 &&
      ![...ctx.imports].some((i) => /^(javax\.crypto|java\.security|org\.bouncycastle)/.test(i))
    ) {
      return [];
    }

    const spec = str(call.args[0]);
    const id = javaJca.id;
    if (spec === null) {
      const bits = num(call.args[0]);
      if (receiver === 'KeyPairGenerator' && bits !== null) {
        return [
          detection(id, 'RSA', { modulusLength: bits }, 'KEY_ESTABLISHMENT', 'RULE_DEFAULT', DUAL_USE_NOTE),
        ];
      }
      return [];
    }

    const out: Detection[] = [];
    // "AES/CBC/PKCS5Padding" - the mode and padding are half the security story.
    // A JCA transformation string is case-insensitive, so both halves are
    // upper-cased: `pkcs5padding` and `PKCS5Padding` are one configuration and
    // must not hash to two assets.
    const [algorithm, modeRaw, paddingRaw] = spec.split('/');
    const mode = modeRaw?.toUpperCase();
    const padding = paddingRaw?.toUpperCase();
    const name = (algorithm ?? spec).trim();

    if (receiver === 'Signature') {
      for (const s of signatureFromName(name)) {
        out.push(detection(id, s.primitive, s.parameters, s.purpose ?? 'DIGITAL_SIGNATURE'));
      }
      return out;
    }
    if (receiver === 'MessageDigest') {
      const h = hashFromName(name);
      return h === null ? [] : [detection(id, h.primitive, h.parameters, 'INTEGRITY')];
    }
    if (receiver === 'Mac') {
      const h = hashFromName(name.replace(/^Hmac/i, ''));
      out.push(detection(id, 'HMAC', h === null ? {} : { hash: h.primitive }, 'INTEGRITY'));
      return out;
    }
    if (receiver === 'KeyAgreement') {
      const upper = name.toUpperCase();
      if (upper.startsWith('ECDH')) return [detection(id, 'ECDH', {}, 'KEY_ESTABLISHMENT')];
      if (upper.startsWith('DH')) return [detection(id, 'DH', {}, 'KEY_ESTABLISHMENT')];
      if (upper.startsWith('X25519')) return [detection(id, 'X25519', {}, 'KEY_ESTABLISHMENT')];
      return [];
    }
    if (receiver === 'SecretKeyFactory') {
      if (/PBKDF2/i.test(name)) {
        const h = hashFromName(name.replace(/.*With/i, '').replace(/^Hmac/i, ''));
        return [detection(id, 'PBKDF2', h === null ? {} : { hash: h.primitive }, 'KEY_DERIVATION')];
      }
      return [];
    }
    if (receiver === 'KeyPairGenerator' || receiver === 'KeyGenerator') {
      const upper = name.toUpperCase();
      if (upper === 'RSA') {
        return [detection(id, 'RSA', {}, 'KEY_ESTABLISHMENT', 'RULE_DEFAULT', DUAL_USE_NOTE)];
      }
      if (upper === 'EC' || upper === 'ECDSA') {
        return [detection(id, 'ECDSA', {}, 'DIGITAL_SIGNATURE', 'RULE_DEFAULT', DUAL_USE_NOTE)];
      }
      if (upper === 'DSA') return [detection(id, 'DSA', {}, 'DIGITAL_SIGNATURE')];
      if (upper === 'DH' || upper === 'DIFFIEHELLMAN') {
        return [detection(id, 'DH', {}, 'KEY_ESTABLISHMENT')];
      }
      if (upper === 'ED25519') return [detection(id, 'EdDSA', { curve: 'Ed25519' }, 'DIGITAL_SIGNATURE')];
      const c = cipherFromName(name);
      return c === null ? [] : [detection(id, c.primitive, c.parameters, 'DATA_ENCRYPTION')];
    }

    // Cipher
    const c = cipherFromName(name);
    if (c === null) {
      if (/^RSA$/i.test(name)) {
        return [
          detection(
            id,
            'RSA',
            { mode: 'KEY_TRANSPORT', ...(padding === undefined ? {} : { padding }) },
            'KEY_ESTABLISHMENT',
          ),
        ];
      }
      return [];
    }
    return [
      detection(
        id,
        c.primitive,
        {
          ...c.parameters,
          ...(mode === undefined ? {} : { mode }),
          ...(padding === undefined ? {} : { padding }),
        },
        'DATA_ENCRYPTION',
      ),
    ];
  },
};

/* --------------------------------------------------------------- C / C++ */

const opensslC: Rule = {
  id: 'c/openssl',
  languages: ['c', 'cpp'],
  methods: [
    'RSA_generate_key_ex', 'RSA_new', 'RSA_sign', 'RSA_verify', 'RSA_public_encrypt', 'RSA_private_decrypt',
    'EVP_PKEY_CTX_new_id', 'EVP_PKEY_keygen', 'EVP_DigestInit_ex', 'EVP_EncryptInit_ex', 'EVP_DecryptInit_ex',
    'ECDSA_do_sign', 'ECDSA_sign', 'EC_KEY_new_by_curve_name', 'ECDH_compute_key',
    'DH_generate_key', 'DH_compute_key', 'DSA_generate_key',
    'MD5_Init', 'SHA1_Init', 'SHA256_Init', 'SHA512_Init', 'HMAC', 'HMAC_Init_ex',
    'DES_ede3_cbc_encrypt', 'AES_set_encrypt_key', 'RC4_set_key',
    'PKCS5_PBKDF2_HMAC', 'EVP_PBE_scrypt',
  ],
  rationale:
    'OpenSSL puts the algorithm in the function name. EVP_* wrappers name a family instead, so the algorithm comes from the NID or the EVP_md/EVP_cipher argument.',
  detect(call, ctx) {
    // Header gating: a project that includes no OpenSSL header is not calling it.
    if (ctx.imports.size > 0 && ![...ctx.imports].some((i) => /openssl\/|mbedtls\/|sodium/.test(i))) {
      if (!/^(RSA_|ECDSA_|EVP_|DH_|DSA_|SHA|MD5|HMAC|DES_|AES_|RC4_|PKCS5_)/.test(call.method)) return [];
    }
    const id = opensslC.id;
    const m = call.method;

    if (m.startsWith('RSA_')) {
      // Only RSA_generate_key_ex(rsa, bits, e, cb) carries a modulus. Argument 0
      // of RSA_public_encrypt / RSA_private_decrypt is the plaintext length, and
      // a positional fallback across the whole RSA_ prefix reported
      // `RSA_public_encrypt(16, ...)` as a 16-bit key.
      const bits = m === 'RSA_generate_key_ex' ? num(call.args[1]) : null;
      const isSig = /sign|verify/i.test(m);
      return [
        detection(
          id,
          'RSA',
          bits === null ? {} : { modulusLength: bits },
          isSig ? 'DIGITAL_SIGNATURE' : 'KEY_ESTABLISHMENT',
          isSig ? 'RESOLVED' : 'RULE_DEFAULT',
          isSig ? undefined : DUAL_USE_NOTE,
        ),
      ];
    }
    if (m.startsWith('ECDSA_')) return [detection(id, 'ECDSA', {}, 'DIGITAL_SIGNATURE')];
    if (m === 'EC_KEY_new_by_curve_name') {
      const nid = call.args[0]?.text ?? '';
      const curve = normalizeCurve(nid.replace(/^NID_(X9_62_)?/, ''));
      return [
        detection(id, 'ECDSA', curve === null ? {} : { curve }, 'DIGITAL_SIGNATURE', 'RULE_DEFAULT', DUAL_USE_NOTE),
      ];
    }
    if (m === 'ECDH_compute_key') return [detection(id, 'ECDH', {}, 'KEY_ESTABLISHMENT')];
    if (m.startsWith('DH_')) return [detection(id, 'DH', {}, 'KEY_ESTABLISHMENT')];
    if (m.startsWith('DSA_')) return [detection(id, 'DSA', {}, 'DIGITAL_SIGNATURE')];
    if (m === 'DES_ede3_cbc_encrypt') return [detection(id, '3DES', { mode: 'CBC' }, 'DATA_ENCRYPTION')];
    if (m === 'AES_set_encrypt_key') {
      const bits = num(call.args[1]);
      return [detection(id, 'AES', bits === null ? {} : { keySize: bits }, 'DATA_ENCRYPTION')];
    }
    if (m === 'RC4_set_key') return [detection(id, 'RC4', {}, 'DATA_ENCRYPTION')];
    if (m === 'PKCS5_PBKDF2_HMAC') {
      const iterations = num(call.args[4]);
      return [
        detection(id, 'PBKDF2', iterations === null ? {} : { iterations }, 'KEY_DERIVATION'),
      ];
    }
    if (m === 'EVP_PBE_scrypt') return [detection(id, 'scrypt', {}, 'KEY_DERIVATION')];
    if (/^(MD5|SHA1|SHA256|SHA512)_Init$/.test(m)) {
      const h = hashFromName(m.replace('_Init', ''));
      return h === null ? [] : [detection(id, h.primitive, h.parameters, 'INTEGRITY')];
    }
    if (m.startsWith('HMAC')) return [detection(id, 'HMAC', {}, 'INTEGRITY')];

    if (m === 'EVP_PKEY_CTX_new_id') {
      const nid = call.args[0]?.text ?? '';
      const spec = evpKeyType(nid);
      return spec === null ? [] : [spec(id)];
    }
    if (m === 'EVP_DigestInit_ex' || m === 'EVP_EncryptInit_ex' || m === 'EVP_DecryptInit_ex') {
      // The algorithm is the EVP_sha256() / EVP_aes_128_cbc() argument.
      const argText = call.args[1]?.callee ?? call.args[1]?.text ?? '';
      const name = /EVP_([a-z0-9_]+)/.exec(argText)?.[1];
      if (name === undefined) return [];
      const h = hashFromName(name.replace(/_/g, '-'));
      if (h !== null) return [detection(id, h.primitive, h.parameters, 'INTEGRITY')];
      const c = cipherFromName(name.replace(/_/g, '-'));
      return c === null ? [] : [detection(id, c.primitive, c.parameters, 'DATA_ENCRYPTION')];
    }
    return [];
  },
};

function evpKeyType(nid: string): ((id: string) => Detection) | null {
  if (/EVP_PKEY_RSA/.test(nid)) {
    return (id) => detection(id, 'RSA', {}, 'KEY_ESTABLISHMENT', 'RULE_DEFAULT', DUAL_USE_NOTE);
  }
  if (/EVP_PKEY_EC\b/.test(nid)) {
    return (id) => detection(id, 'ECDSA', {}, 'DIGITAL_SIGNATURE', 'RULE_DEFAULT', DUAL_USE_NOTE);
  }
  if (/EVP_PKEY_ED25519/.test(nid)) {
    return (id) => detection(id, 'EdDSA', { curve: 'Ed25519' }, 'DIGITAL_SIGNATURE');
  }
  if (/EVP_PKEY_X25519/.test(nid)) return (id) => detection(id, 'X25519', {}, 'KEY_ESTABLISHMENT');
  if (/EVP_PKEY_DH/.test(nid)) return (id) => detection(id, 'DH', {}, 'KEY_ESTABLISHMENT');
  return null;
}

/* ----------------------------------------------------------------- Rust */

const rustCrypto: Rule = {
  id: 'rust/crypto',
  languages: ['rust'],
  methods: ['generate', 'new', 'from_pkcs8', 'sign', 'verify', 'digest', 'derive', 'encrypt', 'decrypt', 'new_from_slice'],
  rationale:
    'Rust crypto crates put the algorithm in the type path: RsaPrivateKey::new, ring::signature::ECDSA_P256_SHA256, aes_gcm::Aes256Gcm::new.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['rsa', 'ring', 'openssl', 'aes', 'aes_gcm', 'chacha20poly1305', 'ed25519_dalek', 'x25519_dalek', 'p256', 'p384', 'sha2', 'sha1', 'md5', 'hmac', 'pbkdf2', 'argon2'])) {
      // Fall back to the path itself: `use` is often glob-imported.
      if (!/^(Rsa|Ecdsa|Ed25519|X25519|Aes|ChaCha|Sha|Md5|Hmac|Pbkdf2|Argon2|SigningKey|StaticSecret)/.test(call.callee)) {
        return [];
      }
    }
    // The crate path the symbol was imported from is matched alongside the
    // spelling at the call site. A renamed import (`use rsa::RsaPrivateKey as
    // PrivKey`) otherwise hides the type name this whole rule dispatches on,
    // and a bare `SigningKey` is Ed25519 in ed25519_dalek but ECDSA in p256.
    const path = `${call.callee}::${ctx.aliases.get(call.calleeParts[0] ?? '') ?? ''}`;
    const id = rustCrypto.id;

    if (/Rsa/.test(path)) {
      const bits = num(call.args[1]) ?? num(call.args[0]);
      return [
        detection(id, 'RSA', bits === null ? {} : { modulusLength: bits }, 'KEY_ESTABLISHMENT', 'RULE_DEFAULT', DUAL_USE_NOTE),
      ];
    }
    // Before the digest branches: the `hmac` crate's idiomatic alias is
    // `type HmacSha256 = Hmac<Sha256>`, which matches the SHA-2 test too, so
    // testing the hashes first classified the entire Rust MAC surface as a
    // bare digest and never emitted an HMAC at all.
    if (/Hmac/.test(path)) {
      const digest = /Hmac[_:]*((?:Sha|Md)\d+)/i.exec(path)?.[1];
      const h = digest === undefined ? null : hashFromName(digest);
      const out: Detection[] = [
        detection(id, 'HMAC', h === null ? {} : { hash: h.primitive }, 'INTEGRITY'),
      ];
      if (h) out.push(detection(id, h.primitive, h.parameters, 'INTEGRITY'));
      return out;
    }
    if (/Ed25519/i.test(path)) {
      return [detection(id, 'EdDSA', { curve: 'Ed25519' }, 'DIGITAL_SIGNATURE')];
    }
    if (/X25519|StaticSecret|EphemeralSecret/.test(path)) {
      return [detection(id, 'X25519', {}, 'KEY_ESTABLISHMENT')];
    }
    if (/\bp256\b|\bp384\b|Ecdsa/i.test(path)) {
      const curve = /p384/i.test(path) ? 'P-384' : 'P-256';
      return [detection(id, 'ECDSA', { curve }, 'DIGITAL_SIGNATURE')];
    }
    if (/ChaCha20/i.test(path)) {
      return [detection(id, 'ChaCha20', { keySize: 256, mode: 'POLY1305' }, 'DATA_ENCRYPTION')];
    }
    if (/Aes(128|192|256)?/.test(path)) {
      const bits = /Aes(128|192|256)/.exec(path)?.[1];
      const mode = /Gcm|Cbc|Ctr|Ecb/.exec(path)?.[0]?.toUpperCase();
      return [
        detection(
          id,
          'AES',
          { ...(bits === undefined ? {} : { keySize: Number(bits) }), ...(mode === undefined ? {} : { mode }) },
          'DATA_ENCRYPTION',
        ),
      ];
    }
    if (/Sha1\b/.test(path)) return [detection(id, 'SHA1', { outputLength: 160 }, 'INTEGRITY')];
    if (/Sha(224|256|384|512)/.test(path)) {
      const bits = Number(/Sha(224|256|384|512)/.exec(path)?.[1] ?? 256);
      return [detection(id, 'SHA2', { outputLength: bits }, 'INTEGRITY')];
    }
    if (/Md5/i.test(path)) return [detection(id, 'MD5', { outputLength: 128 }, 'INTEGRITY')];
    if (/Pbkdf2/i.test(path)) return [detection(id, 'PBKDF2', {}, 'KEY_DERIVATION')];
    if (/Argon2/i.test(path)) return [detection(id, 'Argon2', {}, 'KEY_DERIVATION')];
    return [];
  },
};

/* ------------------------------------------------------------------- C# */

const dotnet: Rule = {
  id: 'csharp/system-security',
  languages: ['csharp'],
  methods: ['Create', 'CreateFromName', 'ComputeHash', 'SignData', 'VerifyData', 'Encrypt', 'Decrypt', 'DeriveKeyMaterial'],
  rationale:
    '.NET names the algorithm in the class: RSA.Create(2048), SHA1.Create(), Aes.Create(). The class is the finding and the argument is the strength.',
  detect(call, ctx) {
    if (
      ctx.imports.size > 0 &&
      ![...ctx.imports].some((i) => /System\.Security\.Cryptography|BouncyCastle/.test(i))
    ) {
      return [];
    }
    const cls = call.calleeParts[call.calleeParts.length - 2] ?? '';
    const id = dotnet.id;
    const bits = num(arg(call, 0));

    switch (cls) {
      case 'RSA':
      case 'RSACryptoServiceProvider':
      case 'RSACng':
        return [
          detection(
            id,
            'RSA',
            bits === null ? {} : { modulusLength: bits },
            'KEY_ESTABLISHMENT',
            'RULE_DEFAULT',
            DUAL_USE_NOTE,
          ),
        ];
      case 'ECDsa':
      case 'ECDsaCng':
        return [detection(id, 'ECDSA', {}, 'DIGITAL_SIGNATURE')];
      case 'ECDiffieHellman':
      case 'ECDiffieHellmanCng':
        return [detection(id, 'ECDH', {}, 'KEY_ESTABLISHMENT')];
      case 'DSA':
        return [detection(id, 'DSA', {}, 'DIGITAL_SIGNATURE')];
      case 'Aes':
      case 'AesCng':
      case 'AesManaged':
        return [detection(id, 'AES', {}, 'DATA_ENCRYPTION')];
      case 'TripleDES':
      case 'TripleDESCng':
        return [detection(id, '3DES', {}, 'DATA_ENCRYPTION')];
      // Neither has a member in the Primitive union, and 3DES is the wrong one
      // to borrow: it asserts 112 classical bits for a 56-bit cipher and for a
      // 40-128-bit Feistel cipher that is not related to DES at all.
      case 'DES':
        return [
          detection(
            id,
            'UNKNOWN',
            { name: 'DES', keySize: 56 },
            'DATA_ENCRYPTION',
            'RESOLVED',
            'single DES: 56-bit, broken without reference to quantum',
          ),
        ];
      case 'RC2':
        return [
          detection(
            id,
            'UNKNOWN',
            { name: 'RC2' },
            'DATA_ENCRYPTION',
            'RESOLVED',
            'RC2: broken without reference to quantum',
          ),
        ];
      case 'MD5':
      case 'MD5CryptoServiceProvider':
        return [detection(id, 'MD5', { outputLength: 128 }, 'INTEGRITY')];
      case 'SHA1':
      case 'SHA1CryptoServiceProvider':
      case 'SHA1Managed':
        return [detection(id, 'SHA1', { outputLength: 160 }, 'INTEGRITY')];
      case 'SHA256':
      case 'SHA384':
      case 'SHA512': {
        return [detection(id, 'SHA2', { outputLength: Number(cls.replace('SHA', '')) }, 'INTEGRITY')];
      }
      case 'HMACSHA1':
        return [
          detection(id, 'HMAC', { hash: 'SHA1' }, 'INTEGRITY'),
          detection(id, 'SHA1', { outputLength: 160 }, 'INTEGRITY'),
        ];
      case 'HMACSHA256':
        return [
          detection(id, 'HMAC', { hash: 'SHA2' }, 'INTEGRITY'),
          detection(id, 'SHA2', { outputLength: 256 }, 'INTEGRITY'),
        ];
      case 'Rfc2898DeriveBytes':
        return [detection(id, 'PBKDF2', {}, 'KEY_DERIVATION')];
      default:
        return [];
    }
  },
};

export const SYSTEMS_RULES: readonly Rule[] = [goStdlib, javaJca, opensslC, rustCrypto, dotnet];
