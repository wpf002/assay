import type { Detection, Rule } from '../types.js';
import { cipherFromName, hashFromName, joseAlgorithm, normalizeCurve } from '@assay/core';
import { DUAL_USE_NOTE, arg, boundTo, detection, num, str } from './helpers.js';

const HAZMAT = ['cryptography.hazmat.primitives', 'cryptography'] as const;
const PYCRYPTO = ['Crypto', 'Cryptodome'] as const;

/**
 * Python rules.
 *
 * pyca/cryptography and pycryptodome disagree about almost everything -
 * argument names, where the mode lives, whether the curve is a class or a
 * string - so the two library families get separate rules rather than one
 * rule with branches.
 */

const pycaAsymmetric: Rule = {
  id: 'py/pyca/generate_private_key',
  languages: ['python'],
  methods: ['generate_private_key', 'generate_parameters', 'generate'],
  rationale:
    'pyca names strength as key_size and the curve as a class instance, both readable at the call site.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, HAZMAT)) return [];
    const path = call.callee.toLowerCase();
    const id = pycaAsymmetric.id;
    const keySize = num(arg(call, 1, 'key_size')) ?? num(call.kwargs['key_size']);

    if (path.includes('rsa')) {
      const exp = num(call.kwargs['public_exponent']);
      return [
        detection(
          id,
          'RSA',
          {
            ...(keySize === null ? {} : { modulusLength: keySize }),
            ...(exp === null ? {} : { publicExponent: exp }),
          },
          'KEY_ESTABLISHMENT',
          'RULE_DEFAULT',
          DUAL_USE_NOTE,
        ),
      ];
    }
    if (path.includes('x25519')) return [detection(id, 'X25519', {}, 'KEY_ESTABLISHMENT')];
    if (path.includes('x448')) return [detection(id, 'X448', {}, 'KEY_ESTABLISHMENT')];
    if (path.includes('ed25519')) {
      return [detection(id, 'EdDSA', { curve: 'Ed25519' }, 'DIGITAL_SIGNATURE')];
    }
    if (path.includes('ed448')) return [detection(id, 'EdDSA', { curve: 'Ed448' }, 'DIGITAL_SIGNATURE')];
    if (path.includes('.dh.') || path.startsWith('dh.')) {
      return [
        detection(
          id,
          'DH',
          keySize === null ? {} : { primeLength: keySize },
          'KEY_ESTABLISHMENT',
        ),
      ];
    }
    if (path.includes('dsa')) {
      // pyca's DSA functions are generate_private_key(key_size, backend) and
      // generate_parameters(key_size, backend): key_size is positional 0, not
      // 1 as it is for RSA and DH. Reading index 1 collapsed DSA-1024 and
      // DSA-3072 into one parameterless asset.
      const dsaKeySize = num(arg(call, 0, 'key_size'));
      return [
        detection(id, 'DSA', dsaKeySize === null ? {} : { modulusLength: dsaKeySize }, 'DIGITAL_SIGNATURE'),
      ];
    }
    if (path.includes('.ec.') || path.startsWith('ec.')) {
      const curveArg = arg(call, 0, 'curve');
      const curveName = curveArg?.callee?.split('.').pop() ?? curveArg?.text.replace(/\(\)$/, '');
      const curve = curveName === undefined ? null : normalizeCurve(curveName);
      return [
        detection(
          id,
          'ECDSA',
          curve === null ? {} : { curve },
          'DIGITAL_SIGNATURE',
          'RULE_DEFAULT',
          `${DUAL_USE_NOTE} (a pyca EC key serves both ECDSA and ECDH)`,
        ),
      ];
    }
    return [];
  },
};

const pycaHash: Rule = {
  id: 'py/pyca/hashes',
  languages: ['python'],
  methods: ['SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'SHA3_256', 'SHA3_512', 'Hash'],
  rationale: 'pyca digest classes are named for the algorithm, so the class name is the parameter.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, HAZMAT)) return [];
    const spec = hashFromName(call.method.replace(/_/g, '-'));
    return spec === null ? [] : [detection(pycaHash.id, spec.primitive, spec.parameters, 'INTEGRITY')];
  },
};

const pycaCipher: Rule = {
  id: 'py/pyca/Cipher',
  languages: ['python'],
  methods: ['Cipher', 'AES', 'AES128', 'AES256', 'TripleDES', 'ARC4', 'ChaCha20', 'Blowfish', 'CAST5', 'IDEA'],
  rationale:
    'Cipher(algorithms.AES(key), modes.CBC(iv)) puts the algorithm and the mode in nested calls; both are read from the argument list.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, HAZMAT)) return [];
    const id = pycaCipher.id;

    if (call.method === 'Cipher') {
      const algo = call.args[0]?.callee?.split('.').pop() ?? null;
      const mode = call.args[1]?.callee?.split('.').pop() ?? null;
      if (algo === null) return [];
      const spec = cipherFromName(algo);
      if (spec === null) return [];
      return [
        detection(
          id,
          spec.primitive,
          { ...spec.parameters, ...(mode === null ? {} : { mode: mode.toUpperCase() }) },
          'DATA_ENCRYPTION',
        ),
      ];
    }

    const spec = cipherFromName(call.method);
    if (spec === null) return [];
    // algorithms.AES(key) on its own: the primitive is certain, the mode is not.
    return [detection(id, spec.primitive, spec.parameters, 'DATA_ENCRYPTION')];
  },
};

const pycaPadding: Rule = {
  id: 'py/pyca/padding',
  languages: ['python'],
  methods: ['OAEP', 'PKCS1v15', 'PSS'],
  rationale:
    'RSA padding choice is a finding in its own right: PKCS1v15 for encryption is a decryption-oracle risk independent of quantum.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, HAZMAT)) return [];
    const isSignature = call.method === 'PSS';
    return [
      detection(
        pycaPadding.id,
        'RSA',
        { padding: call.method },
        isSignature ? 'DIGITAL_SIGNATURE' : 'KEY_ESTABLISHMENT',
        'RULE_DEFAULT',
        'padding class observed; the key it wraps is resolved by correlation',
      ),
    ];
  },
};

const hashlib: Rule = {
  id: 'py/hashlib',
  languages: ['python'],
  methods: ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'new', 'pbkdf2_hmac', 'scrypt'],
  requiresImport: ['hashlib'],
  rationale: 'hashlib names the digest as the function or as a literal to new().',
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['hashlib'])) return [];
    const id = hashlib.id;
    if (call.method === 'pbkdf2_hmac') {
      const digest = str(arg(call, 0, 'hash_name'));
      const iterations = num(arg(call, 3, 'iterations'));
      const spec = digest === null ? null : hashFromName(digest);
      return [
        detection(
          id,
          'PBKDF2',
          {
            ...(iterations === null ? {} : { iterations }),
            ...(spec === null ? {} : { hash: spec.primitive }),
          },
          'KEY_DERIVATION',
        ),
      ];
    }
    if (call.method === 'scrypt') return [detection(id, 'scrypt', {}, 'KEY_DERIVATION')];
    const name = call.method === 'new' ? str(arg(call, 0, 'name')) : call.method;
    const spec = name === null ? null : hashFromName(name);
    if (spec === null) return [];

    // Python 3.9's usedforsecurity=False is the developer asserting this digest
    // is a cache key or an ETag, not a security control. Nothing in the source
    // can verify that, so it enters as an ASSUMPTION: the asset stays in the
    // inventory at OBSERVED and cannot reach the worklist as CONFIRMED work.
    // Django alone carries ten of these; ranking them as integrity findings is
    // exactly the noise the ceilings exist to prevent.
    const declaredNonSecurity = call.kwargs['usedforsecurity']?.boolean === false;
    return [
      detection(
        id,
        spec.primitive,
        spec.parameters,
        'INTEGRITY',
        declaredNonSecurity ? 'RULE_DEFAULT' : 'RESOLVED',
        declaredNonSecurity ? 'call declares usedforsecurity=False' : undefined,
        declaredNonSecurity
          ? ['developer asserts usedforsecurity=False; not verifiable from source']
          : undefined,
      ),
    ];
  },
};

const pycryptodome: Rule = {
  id: 'py/pycryptodome',
  languages: ['python'],
  methods: ['generate', 'new', 'construct', 'import_key'],
  rationale:
    'pycryptodome selects the algorithm by module (Crypto.Cipher.AES, Crypto.PublicKey.RSA) and the mode by an AES.MODE_* constant.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, PYCRYPTO)) return [];
    const path = call.callee;
    const id = pycryptodome.id;
    const lower = path.toLowerCase();

    if (/(^|\.)rsa\./.test(lower)) {
      const bits = num(arg(call, 0, 'bits'));
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
    if (/(^|\.)dsa\./.test(lower)) {
      const bits = num(arg(call, 0, 'bits'));
      return [
        detection(id, 'DSA', bits === null ? {} : { modulusLength: bits }, 'DIGITAL_SIGNATURE'),
      ];
    }
    if (/(^|\.)ecc\./.test(lower)) {
      const curveRaw = str(call.kwargs['curve']);
      const curve = curveRaw === null ? null : normalizeCurve(curveRaw);
      return [
        detection(
          id,
          'ECDSA',
          curve === null ? {} : { curve },
          'DIGITAL_SIGNATURE',
          'RULE_DEFAULT',
          DUAL_USE_NOTE,
        ),
      ];
    }

    const cipherModule = /(?:^|\.)(AES|DES3|DES|ARC4|ChaCha20|Blowfish|Salsa20)\./.exec(path);
    if (cipherModule?.[1]) {
      const spec = cipherFromName(cipherModule[1]);
      if (spec === null) return [];
      const modeArg = call.args[1] ?? call.kwargs['mode'];
      const mode = modeArg?.text.split('.').pop()?.replace(/^MODE_/, '');
      return [
        detection(
          id,
          spec.primitive,
          { ...spec.parameters, ...(mode === undefined ? {} : { mode }) },
          'DATA_ENCRYPTION',
        ),
      ];
    }

    const hashModule = /(?:^|\.)(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_256|SHA3_512)\./.exec(path);
    if (hashModule?.[1]) {
      const spec = hashFromName(hashModule[1].replace(/_/g, '-'));
      return spec === null ? [] : [detection(id, spec.primitive, spec.parameters, 'INTEGRITY')];
    }
    return [];
  },
};

const pyjwt: Rule = {
  id: 'py/pyjwt',
  languages: ['python'],
  methods: ['encode', 'decode'],
  requiresImport: ['jwt'],
  rationale:
    "PyJWT names the algorithm in `algorithm=` / `algorithms=`, or positionally: encode(payload, key, algorithm) and decode(jwt, key, algorithms) both put it in argument 2.",
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['jwt'])) return [];
    const names: string[] = [];
    // Argument 2 is the algorithm on both encode and decode, so the same slot
    // serves the single name and the allowlist; str() and the array check
    // decide which of the two it is.
    const third = call.args[2];
    const single = str(call.kwargs['algorithm'] ?? third);
    if (single !== null) names.push(single);
    const list = call.kwargs['algorithms'] ?? third;
    if (list?.kind === 'array') {
      for (const item of list.array ?? []) {
        const s = str(item);
        if (s !== null) names.push(s);
      }
    }
    return names.flatMap((a) =>
      joseAlgorithm(a).map((s) =>
        detection(pyjwt.id, s.primitive, s.parameters, s.purpose ?? 'DIGITAL_SIGNATURE'),
      ),
    );
  },
};

const paramiko: Rule = {
  id: 'py/paramiko/keys',
  languages: ['python'],
  methods: ['generate', 'from_private_key_file', 'from_private_key'],
  requiresImport: ['paramiko'],
  rationale: 'paramiko key classes are named for their algorithm.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['paramiko'])) return [];
    const id = paramiko.id;
    const bits = num(arg(call, 0, 'bits'));
    if (call.callee.includes('RSAKey')) {
      return [
        detection(id, 'RSA', bits === null ? {} : { modulusLength: bits }, 'DIGITAL_SIGNATURE'),
      ];
    }
    if (call.callee.includes('ECDSAKey')) return [detection(id, 'ECDSA', {}, 'DIGITAL_SIGNATURE')];
    if (call.callee.includes('Ed25519Key')) {
      return [detection(id, 'EdDSA', { curve: 'Ed25519' }, 'DIGITAL_SIGNATURE')];
    }
    if (call.callee.includes('DSSKey')) return [detection(id, 'DSA', {}, 'DIGITAL_SIGNATURE')];
    return [];
  },
};

const pyhmac: Rule = {
  id: 'py/hmac',
  languages: ['python'],
  methods: ['new', 'digest'],
  requiresImport: ['hmac'],
  rationale:
    'hmac.new(key, msg, hashlib.sha256) names its digest in argument 2 or the digestmod keyword. Django and most Python webhook verification live here, and a rule set without it misses the integrity surface entirely.',
  detect(call, ctx) {
    if (!boundTo(call, ctx, ['hmac'])) return [];
    const digestArg = arg(call, 2, 'digestmod');
    const raw = str(digestArg) ?? digestArg?.callee?.split('.').pop() ?? digestArg?.text.split('.').pop();
    const spec = raw === undefined || raw === null ? null : hashFromName(raw);
    const out: Detection[] = [
      detection(pyhmac.id, 'HMAC', spec === null ? {} : { hash: spec.primitive }, 'INTEGRITY'),
    ];
    if (spec) out.push(detection(pyhmac.id, spec.primitive, spec.parameters, 'INTEGRITY'));
    return out;
  },
};

export const PYTHON_RULES: readonly Rule[] = [
  pyhmac,
  pycaAsymmetric,
  pycaHash,
  pycaCipher,
  pycaPadding,
  hashlib,
  pycryptodome,
  pyjwt,
  paramiko,
];

export const ALL_RULE_DETECTIONS: readonly Detection[] = [];
