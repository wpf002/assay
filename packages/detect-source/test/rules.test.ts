import { describe, expect, it } from 'vitest';
import { languageFor, parseSource } from '../src/parsers/index.js';
import { ruleIndex } from '../src/rules/index.js';
import type { Detection, Lang } from '../src/types.js';

function detect(source: string, lang: Lang = 'typescript', file = 'a.ts'): Detection[] {
  const parsed = parseSource(file, source, lang);
  const index = ruleIndex(lang);
  const out: Detection[] = [];
  for (const call of parsed.calls) {
    for (const rule of index.get(call.method) ?? []) {
      if (rule.requiresImport && !rule.requiresImport.some((m) => parsed.context.imports.has(m))) continue;
      out.push(...rule.detect(call, parsed.context));
    }
  }
  return out;
}

const py = (s: string): Detection[] => detect(s, 'python', 'a.py');

describe('language dispatch', () => {
  it('maps extensions', () => {
    expect(languageFor('a.ts')).toBe('typescript');
    expect(languageFor('a.tsx')).toBe('tsx');
    expect(languageFor('a.mjs')).toBe('javascript');
    expect(languageFor('a.py')).toBe('python');
    expect(languageFor('a.rs')).toBe('rust');
    expect(languageFor('a.txt')).toBeNull();
  });
});

describe('node:crypto - resolved parameters, not "RSA somewhere"', () => {
  it('resolves the modulus from the options object', () => {
    const d = detect(`
      import crypto from 'node:crypto';
      crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    `);
    expect(d).toHaveLength(1);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.parameters['modulusLength']).toBe(2048);
    expect(d[0]?.purpose).toBe('KEY_ESTABLISHMENT');
  });

  it('marks dual-use key generation as a rule default rather than asserting a purpose', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
    `);
    expect(d[0]?.purposeSource).toBe('RULE_DEFAULT');
    expect(d[0]?.note).toContain('dual-use');
  });

  it('resolves rsa-pss to the authenticity track with no ambiguity', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.generateKeyPairSync('rsa-pss', { modulusLength: 3072 });
    `);
    expect(d[0]?.purpose).toBe('DIGITAL_SIGNATURE');
    expect(d[0]?.purposeSource).toBe('RESOLVED');
    expect(d[0]?.parameters['padding']).toBe('PSS');
  });

  it('normalizes openssl curve names', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.createECDH('secp384r1');
    `);
    expect(d[0]?.primitive).toBe('ECDH');
    expect(d[0]?.parameters['curve']).toBe('P-384');
  });

  it('separates key size from mode in a cipher spec', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.createCipheriv('aes-128-cbc', k, iv);
    `);
    expect(d[0]?.parameters).toEqual({ keySize: 128, mode: 'CBC' });
  });

  it('emits HMAC and its digest as two integrity assets', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.createHmac('sha1', key);
    `);
    expect(d.map((x) => x.primitive).sort()).toEqual(['HMAC', 'SHA1']);
  });

  it('captures the PBKDF2 iteration count, which is the whole security argument', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.pbkdf2Sync(pw, salt, 1000, 32, 'sha1');
    `);
    expect(d[0]?.parameters['iterations']).toBe(1000);
    expect(d[0]?.parameters['hash']).toBe('SHA1');
  });

  it('omits a parameter it cannot see rather than inventing one', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.generateKeyPairSync('rsa', { modulusLength: bits });
    `);
    expect(d).toHaveLength(1);
    expect(d[0]?.parameters['modulusLength']).toBeUndefined();
  });

  it('does not fire on an unrelated local object named crypto-ish', () => {
    expect(detect(`const wallet = { createHash: (x) => x }; wallet.createHash('sha1');`)).toHaveLength(0);
  });

  it('requires the import - a bare method call is not a finding', () => {
    expect(detect(`generateKeyPairSync('rsa', { modulusLength: 2048 });`)).toHaveLength(0);
  });

  it('handles require() as well as import', () => {
    const d = detect(`
      const crypto = require('node:crypto');
      crypto.createHash('md5');
    `);
    expect(d[0]?.primitive).toBe('MD5');
  });
});

describe('WebCrypto', () => {
  it('reads the algorithm object without needing an import', () => {
    const d = detect(`
      await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
    `);
    expect(d[0]?.primitive).toBe('ECDSA');
    expect(d[0]?.parameters['curve']).toBe('P-384');
  });

  it('puts AES-KW on the confidentiality track when it wraps a key', () => {
    const d = detect(`await crypto.subtle.wrapKey('raw', k, wk, { name: 'AES-KW', length: 256 });`);
    expect(d[0]?.purpose).toBe('KEY_ESTABLISHMENT');
  });
});

describe('JWT', () => {
  it('expands an alg into its signature primitive and its digest', () => {
    const d = detect(`
      import jwt from 'jsonwebtoken';
      jwt.sign(payload, key, { algorithm: 'RS256' });
    `);
    expect(d.map((x) => x.primitive).sort()).toEqual(['RSA', 'SHA2']);
    expect(d.find((x) => x.primitive === 'RSA')?.purpose).toBe('DIGITAL_SIGNATURE');
  });

  it('reads an algorithms allowlist on verify', () => {
    const d = detect(`
      import jwt from 'jsonwebtoken';
      jwt.verify(token, key, { algorithms: ['RS256', 'ES256'] });
    `);
    expect(d.some((x) => x.primitive === 'ECDSA')).toBe(true);
    expect(d.some((x) => x.primitive === 'RSA')).toBe(true);
  });
});

describe('python: pyca/cryptography', () => {
  it('reads key_size from a keyword argument', () => {
    const d = py(`
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(public_exponent=65537, key_size=2048)
`);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.parameters['modulusLength']).toBe(2048);
    expect(d[0]?.parameters['publicExponent']).toBe(65537);
  });

  it('reads the curve from a class instance passed as an argument', () => {
    const d = py(`
from cryptography.hazmat.primitives.asymmetric import ec
ec.generate_private_key(ec.SECP256R1())
`);
    expect(d[0]?.primitive).toBe('ECDSA');
    expect(d[0]?.parameters['curve']).toBe('P-256');
  });

  it('reads algorithm and mode out of nested Cipher() calls', () => {
    const d = py(`
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
Cipher(algorithms.AES(key), modes.CBC(iv))
`);
    const aes = d.find((x) => x.primitive === 'AES');
    expect(aes?.parameters['mode']).toBe('CBC');
  });

  it('puts X25519 generation on the confidentiality track', () => {
    const d = py(`
from cryptography.hazmat.primitives.asymmetric import x25519
x25519.X25519PrivateKey.generate()
`);
    expect(d[0]?.primitive).toBe('X25519');
    expect(d[0]?.purpose).toBe('KEY_ESTABLISHMENT');
  });

  it('does not fire on a local class called AES with no crypto import', () => {
    expect(py(`AES.new(key, AES.MODE_GCM)`)).toHaveLength(0);
  });
});

describe('python: hashlib and pycryptodome', () => {
  it('resolves hashlib.md5', () => {
    const d = py(`import hashlib\nhashlib.md5(data)`);
    expect(d[0]?.primitive).toBe('MD5');
  });

  it('resolves hashlib.new with a literal', () => {
    const d = py(`import hashlib\nhashlib.new('sha1')`);
    expect(d[0]?.primitive).toBe('SHA1');
  });

  it('captures pbkdf2 iterations', () => {
    const d = py(`import hashlib\nhashlib.pbkdf2_hmac('sha256', pw, salt, 600000)`);
    expect(d[0]?.parameters['iterations']).toBe(600000);
  });

  it('reads the pycryptodome mode constant', () => {
    const d = py(`
from Crypto.Cipher import AES
AES.new(key, AES.MODE_GCM)
`);
    expect(d[0]?.primitive).toBe('AES');
    expect(d[0]?.parameters['mode']).toBe('GCM');
  });

  it('reads PyJWT algorithm keyword', () => {
    const d = py(`import jwt\njwt.encode(payload, key, algorithm='ES256')`);
    expect(d.some((x) => x.primitive === 'ECDSA')).toBe(true);
  });
});

describe('unverifiable developer claims taint provenance (I6)', () => {
  it('marks hashlib usedforsecurity=False as an assumption', () => {
    const d = py(`import hashlib\nhashlib.md5(data, usedforsecurity=False)`);
    expect(d[0]?.primitive).toBe('MD5');
    // Still inventory - the call is really there - but not confirmable work.
    expect(d[0]?.assumptions?.[0]).toContain('usedforsecurity=False');
  });

  it('leaves an ordinary digest call untainted', () => {
    const d = py(`import hashlib\nhashlib.md5(data)`);
    expect(d[0]?.assumptions).toBeUndefined();
  });
});

describe('python hmac module', () => {
  it('reads the digest from the third positional argument', () => {
    const d = py(`
import hmac
import hashlib
hmac.new(key, msg, hashlib.sha256)
`);
    expect(d.map((x) => x.primitive).sort()).toEqual(['HMAC', 'SHA2']);
  });

  it('reads the digestmod keyword', () => {
    const d = py(`import hmac\nhmac.new(key, msg=data, digestmod='sha1')`);
    expect(d.find((x) => x.primitive === 'HMAC')?.parameters['hash']).toBe('SHA1');
  });

  it('does not fire without the import', () => {
    expect(py(`hmac.new(key, msg, hashlib.sha256)`)).toHaveLength(0);
  });
});

describe('the one-shot signing API', () => {
  it('resolves crypto.sign with a named algorithm', () => {
    const d = detect(`
      import crypto from 'node:crypto';
      crypto.sign('RSA-SHA256', data, key);
    `);
    expect(d.map((x) => x.primitive).sort()).toEqual(['RSA', 'SHA2']);
    expect(d.find((x) => x.primitive === 'RSA')?.purpose).toBe('DIGITAL_SIGNATURE');
  });

  it('resolves crypto.verify the same way', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.verify('sha256WithRSAEncryption', data, key, sig);
    `);
    expect(d.some((x) => x.primitive === 'RSA')).toBe(true);
  });

  it('emits nothing when the algorithm is null, which is legal and names no key type', () => {
    const d = detect(`
      import crypto from 'crypto';
      crypto.sign(null, data, key);
    `);
    expect(d).toHaveLength(0);
  });

  it('does not collide with a jsonwebtoken sign in the same file', () => {
    const d = detect(`
      import jwt from 'jsonwebtoken';
      jwt.sign(payload, key, { algorithm: 'ES256' });
    `);
    // Only the JWT rule fires: `jwt` is not bound to node:crypto.
    expect(d.every((x) => x.parameters['alg'] === 'ES256' || x.primitive === 'SHA2')).toBe(true);
  });
});
