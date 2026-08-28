import type { Detection, Rule } from '../types.js';
import {
  cipherFromName,
  hashFromName,
  joseAlgorithm,
  normalizeCurve,
  signatureFromName,
} from '../algorithms.js';
import { DUAL_USE_NOTE, arg, boundTo, detection, num, prop, str } from './helpers.js';

const NODE_CRYPTO = ['node:crypto', 'crypto'] as const;

/**
 * TypeScript / JavaScript rules.
 *
 * Each rule resolves parameters from the call site, not from the file. The
 * target is `RSA/2048/KEY_ESTABLISHMENT at src/keys.ts:41`, never "RSA is
 * somewhere in this file" - the second is what makes a 40,000-row CBOM.
 */

const generateKeyPair: Rule = {
  id: 'ts/node-crypto/generateKeyPair',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['generateKeyPairSync', 'generateKeyPair'],
  rationale:
    'node:crypto keypair generation names the algorithm in argument 0 and its strength in the options object. Both are usually literals.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, NODE_CRYPTO) && call.calleeParts[0] !== 'crypto') return [];
    const type = str(call.args[0]);
    if (type === null) return [];
    const opts = call.args[1];
    const modulusLength = num(prop(opts, 'modulusLength'));
    const namedCurve = str(prop(opts, 'namedCurve'));
    const divisorLength = num(prop(opts, 'divisorLength'));
    const id = generateKeyPair.id;

    switch (type.toLowerCase()) {
      case 'rsa':
        return [
          detection(
            id,
            'RSA',
            modulusLength === null ? {} : { modulusLength },
            'KEY_ESTABLISHMENT',
            'RULE_DEFAULT',
            DUAL_USE_NOTE,
          ),
        ];
      case 'rsa-pss':
        // PSS is signature-only; no ambiguity to defer.
        return [
          detection(
            id,
            'RSA',
            { padding: 'PSS', ...(modulusLength === null ? {} : { modulusLength }) },
            'DIGITAL_SIGNATURE',
          ),
        ];
      case 'ec': {
        const curve = namedCurve === null ? null : normalizeCurve(namedCurve);
        return [
          detection(
            id,
            'ECDSA',
            curve === null ? {} : { curve },
            'DIGITAL_SIGNATURE',
            'RULE_DEFAULT',
            `${DUAL_USE_NOTE} (node 'ec' covers both ECDSA and ECDH)`,
          ),
        ];
      }
      case 'ed25519':
      case 'ed448':
        return [
          detection(id, 'EdDSA', { curve: type === 'ed25519' ? 'Ed25519' : 'Ed448' }, 'DIGITAL_SIGNATURE'),
        ];
      case 'x25519':
        return [detection(id, 'X25519', {}, 'KEY_ESTABLISHMENT')];
      case 'x448':
        return [detection(id, 'X448', {}, 'KEY_ESTABLISHMENT')];
      case 'dsa':
        return [
          detection(
            id,
            'DSA',
            {
              ...(modulusLength === null ? {} : { modulusLength }),
              ...(divisorLength === null ? {} : { divisorLength }),
            },
            'DIGITAL_SIGNATURE',
          ),
        ];
      case 'dh':
        return [
          detection(id, 'DH', modulusLength === null ? {} : { primeLength: modulusLength }, 'KEY_ESTABLISHMENT'),
        ];
      default:
        return [];
    }
  },
};

const createHash: Rule = {
  id: 'ts/node-crypto/createHash',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['createHash'],
  rationale: 'Digest name is argument 0 and is a literal in almost all real code.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, NODE_CRYPTO) && call.calleeParts[0] !== 'crypto') return [];
    const name = str(call.args[0]);
    const spec = name === null ? null : hashFromName(name);
    return spec === null
      ? []
      : [detection(createHash.id, spec.primitive, spec.parameters, 'INTEGRITY')];
  },
};

const createHmac: Rule = {
  id: 'ts/node-crypto/createHmac',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['createHmac'],
  rationale: 'HMAC plus its underlying digest are two assets on the integrity track.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, NODE_CRYPTO) && call.calleeParts[0] !== 'crypto') return [];
    const name = str(call.args[0]);
    const spec = name === null ? null : hashFromName(name);
    const out: Detection[] = [
      detection(createHmac.id, 'HMAC', spec === null ? {} : { hash: spec.primitive }, 'INTEGRITY'),
    ];
    if (spec) out.push(detection(createHmac.id, spec.primitive, spec.parameters, 'INTEGRITY'));
    return out;
  },
};

const createCipher: Rule = {
  id: 'ts/node-crypto/createCipheriv',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['createCipheriv', 'createDecipheriv', 'createCipher', 'createDecipher'],
  rationale:
    'The OpenSSL cipher spec carries key size and mode. AES-128-ECB and AES-256-GCM are different findings and must not collapse.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, NODE_CRYPTO) && call.calleeParts[0] !== 'crypto') return [];
    const name = str(call.args[0]);
    const spec = name === null ? null : cipherFromName(name);
    return spec === null
      ? []
      : [detection(createCipher.id, spec.primitive, spec.parameters, 'DATA_ENCRYPTION')];
  },
};

const kdf: Rule = {
  id: 'ts/node-crypto/kdf',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['pbkdf2', 'pbkdf2Sync', 'scrypt', 'scryptSync', 'hkdf', 'hkdfSync'],
  rationale: 'Iteration count and digest are the whole security argument for PBKDF2.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, NODE_CRYPTO) && call.calleeParts[0] !== 'crypto') return [];
    if (call.method.startsWith('scrypt')) {
      return [detection(kdf.id, 'scrypt', {}, 'KEY_DERIVATION')];
    }
    if (call.method.startsWith('hkdf')) {
      const digest = str(call.args[0]);
      const spec = digest === null ? null : hashFromName(digest);
      return [
        detection(kdf.id, 'PBKDF2', { kdf: 'HKDF', ...(spec ? { hash: spec.primitive } : {}) }, 'KEY_DERIVATION'),
      ];
    }
    const iterations = num(call.args[2]);
    const digest = str(call.args[4]);
    const spec = digest === null ? null : hashFromName(digest);
    return [
      detection(
        kdf.id,
        'PBKDF2',
        {
          ...(iterations === null ? {} : { iterations }),
          ...(spec === null ? {} : { hash: spec.primitive }),
        },
        'KEY_DERIVATION',
      ),
    ];
  },
};

const keyAgreement: Rule = {
  id: 'ts/node-crypto/keyAgreement',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['createECDH', 'createDiffieHellman', 'createDiffieHellmanGroup', 'diffieHellman'],
  rationale: 'Unambiguously key establishment - the confidentiality track, where HNDL applies.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, NODE_CRYPTO) && call.calleeParts[0] !== 'crypto') return [];
    if (call.method === 'createECDH') {
      const curve = str(call.args[0]);
      const norm = curve === null ? null : normalizeCurve(curve);
      return [detection(keyAgreement.id, 'ECDH', norm === null ? {} : { curve: norm }, 'KEY_ESTABLISHMENT')];
    }
    const primeLength = num(call.args[0]);
    return [
      detection(
        keyAgreement.id,
        'DH',
        primeLength === null ? {} : { primeLength },
        'KEY_ESTABLISHMENT',
      ),
    ];
  },
};

const rsaTransport: Rule = {
  id: 'ts/node-crypto/rsaTransport',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['publicEncrypt', 'privateDecrypt', 'publicDecrypt', 'privateEncrypt'],
  rationale: 'RSA used to move a key. Confidentiality track; recorded traffic is already exposed.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, NODE_CRYPTO) && call.calleeParts[0] !== 'crypto') return [];
    const padding = str(prop(call.args[0], 'padding'));
    const oaepHash = str(prop(call.args[0], 'oaepHash'));
    return [
      detection(
        rsaTransport.id,
        'RSA',
        {
          mode: 'KEY_TRANSPORT',
          ...(padding === null ? {} : { padding }),
          ...(oaepHash === null ? {} : { oaepHash }),
        },
        'KEY_ESTABLISHMENT',
      ),
    ];
  },
};

const signing: Rule = {
  id: 'ts/node-crypto/sign',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['createSign', 'createVerify'],
  rationale:
    "createSign('RSA-SHA256') names both the signature primitive and its digest; a bare digest name does not identify the key algorithm and is not reported as one.",
  detect(call, ctx) {
    if (!boundTo(call, ctx, NODE_CRYPTO) && call.calleeParts[0] !== 'crypto') return [];
    const name = str(call.args[0]);
    if (name === null) return [];
    return signatureFromName(name).map((s) =>
      detection(signing.id, s.primitive, s.parameters, s.purpose ?? 'DIGITAL_SIGNATURE'),
    );
  },
};

const webcrypto: Rule = {
  id: 'ts/webcrypto/subtle',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['generateKey', 'importKey', 'deriveKey', 'deriveBits', 'sign', 'verify', 'encrypt', 'decrypt', 'digest', 'wrapKey', 'unwrapKey'],
  rationale:
    'WebCrypto is global, so the gate is the `subtle` receiver rather than an import. The algorithm object carries name plus modulusLength / namedCurve / length.',
  detect(call) {
    if (!call.calleeParts.includes('subtle')) return [];
    // The algorithm is not always argument 0: importKey puts it third and
    // wrapKey fourth. Reading position 0 unconditionally silently misses every
    // key-wrapping site, which is the confidentiality-track half of WebCrypto.
    const ALGORITHM_POSITION: Readonly<Record<string, number>> = {
      importKey: 2,
      wrapKey: 3,
      unwrapKey: 3,
    };
    const first = call.args[ALGORITHM_POSITION[call.method] ?? 0];
    const name = str(first) ?? str(prop(first, 'name'));
    if (name === null) return [];
    const n = name.toUpperCase();
    const id = webcrypto.id;
    const modulusLength = num(prop(first, 'modulusLength'));
    const namedCurveRaw = str(prop(first, 'namedCurve'));
    const namedCurve = namedCurveRaw === null ? null : normalizeCurve(namedCurveRaw);
    const length = num(prop(first, 'length'));
    const hashRaw = str(prop(first, 'hash')) ?? str(prop(prop(first, 'hash'), 'name'));
    const hash = hashRaw === null ? null : hashFromName(hashRaw);
    const out: Detection[] = [];

    if (n === 'RSASSA-PKCS1-V1_5' || n === 'RSA-PSS') {
      out.push(
        detection(
          id,
          'RSA',
          {
            padding: n === 'RSA-PSS' ? 'PSS' : 'PKCS1v15',
            ...(modulusLength === null ? {} : { modulusLength }),
          },
          'DIGITAL_SIGNATURE',
        ),
      );
    } else if (n === 'RSA-OAEP') {
      out.push(
        detection(
          id,
          'RSA',
          { padding: 'OAEP', ...(modulusLength === null ? {} : { modulusLength }) },
          'KEY_ESTABLISHMENT',
        ),
      );
    } else if (n === 'ECDSA') {
      out.push(detection(id, 'ECDSA', namedCurve === null ? {} : { curve: namedCurve }, 'DIGITAL_SIGNATURE'));
    } else if (n === 'ECDH') {
      out.push(detection(id, 'ECDH', namedCurve === null ? {} : { curve: namedCurve }, 'KEY_ESTABLISHMENT'));
    } else if (n === 'X25519') {
      out.push(detection(id, 'X25519', {}, 'KEY_ESTABLISHMENT'));
    } else if (n === 'ED25519') {
      out.push(detection(id, 'EdDSA', { curve: 'Ed25519' }, 'DIGITAL_SIGNATURE'));
    } else if (n.startsWith('AES-')) {
      out.push(
        detection(
          id,
          'AES',
          { mode: n.slice(4), ...(length === null ? {} : { keySize: length }) },
          call.method === 'wrapKey' || call.method === 'unwrapKey' ? 'KEY_ESTABLISHMENT' : 'DATA_ENCRYPTION',
        ),
      );
    } else if (n === 'HMAC') {
      out.push(detection(id, 'HMAC', hash === null ? {} : { hash: hash.primitive }, 'INTEGRITY'));
    } else if (n === 'PBKDF2') {
      const iterations = num(prop(first, 'iterations'));
      out.push(
        detection(
          id,
          'PBKDF2',
          {
            ...(iterations === null ? {} : { iterations }),
            ...(hash === null ? {} : { hash: hash.primitive }),
          },
          'KEY_DERIVATION',
        ),
      );
    } else {
      const direct = hashFromName(name);
      if (direct && call.method === 'digest') {
        out.push(detection(id, direct.primitive, direct.parameters, 'INTEGRITY'));
      }
    }

    if (hash && out.length > 0 && !out.some((d) => d.primitive === hash.primitive)) {
      out.push(detection(id, hash.primitive, hash.parameters, 'INTEGRITY'));
    }
    return out;
  },
};

const jwt: Rule = {
  id: 'ts/jsonwebtoken/sign',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['sign', 'verify', 'SignJWT', 'jwtVerify'],
  requiresImport: ['jsonwebtoken', 'jose'],
  rationale:
    "A JWT's `alg` is its entire security story and resolves to a signature primitive plus a digest.",
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['jsonwebtoken', 'jose'])) return [];
    const opts = arg(call, 2) ?? arg(call, 1);
    const alg = str(prop(opts, 'algorithm')) ?? str(prop(opts, 'alg'));
    const list = prop(opts, 'algorithms');
    const names: string[] = [];
    if (alg !== null) names.push(alg);
    if (list?.kind === 'array') {
      for (const item of list.array ?? []) {
        const s = str(item);
        if (s !== null) names.push(s);
      }
    }
    return names.flatMap((a) =>
      joseAlgorithm(a).map((s) =>
        detection(jwt.id, s.primitive, s.parameters, s.purpose ?? 'DIGITAL_SIGNATURE'),
      ),
    );
  },
};

const forge: Rule = {
  id: 'ts/node-forge/generateKeyPair',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['generateKeyPair', 'generateKeyPairSync', 'setPublicKey'],
  requiresImport: ['node-forge'],
  rationale: 'node-forge names RSA strength as `bits` rather than `modulusLength`.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['node-forge'])) return [];
    if (!call.callee.includes('rsa')) return [];
    const bits = num(prop(call.args[0], 'bits')) ?? num(call.args[0]);
    return [
      detection(
        forge.id,
        'RSA',
        bits === null ? {} : { modulusLength: bits },
        'KEY_ESTABLISHMENT',
        'RULE_DEFAULT',
        DUAL_USE_NOTE,
      ),
    ];
  },
};

const cryptoJs: Rule = {
  id: 'ts/crypto-js',
  languages: ['typescript', 'tsx', 'javascript'],
  methods: ['encrypt', 'decrypt', 'MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3', 'HmacSHA1', 'HmacSHA256'],
  requiresImport: ['crypto-js'],
  rationale:
    'crypto-js puts the algorithm in the member path (CryptoJS.AES.encrypt, CryptoJS.MD5) rather than in an argument.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['crypto-js'])) return [];
    const path = call.callee.toLowerCase();
    const id = cryptoJs.id;
    if (path.includes('tripledes') || path.includes('des3')) {
      return [detection(id, '3DES', {}, 'DATA_ENCRYPTION')];
    }
    if (path.includes('rc4')) return [detection(id, 'RC4', {}, 'DATA_ENCRYPTION')];
    if (path.includes('rabbit')) return [];
    if (path.includes('.aes.')) {
      return [detection(id, 'AES', { mode: 'CBC' }, 'DATA_ENCRYPTION', 'RULE_DEFAULT', 'crypto-js defaults to CBC with PKCS7 when no mode is given')];
    }
    const spec = hashFromName(call.method.replace(/^Hmac/, ''));
    if (spec === null) return [];
    const out: Detection[] = [];
    if (call.method.startsWith('Hmac')) {
      out.push(detection(id, 'HMAC', { hash: spec.primitive }, 'INTEGRITY'));
    }
    out.push(detection(id, spec.primitive, spec.parameters, 'INTEGRITY'));
    return out;
  },
};

export const TYPESCRIPT_RULES: readonly Rule[] = [
  generateKeyPair,
  createHash,
  createHmac,
  createCipher,
  kdf,
  keyAgreement,
  rsaTransport,
  signing,
  webcrypto,
  jwt,
  forge,
  cryptoJs,
];
