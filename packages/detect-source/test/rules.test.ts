import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanSource, type SourceScanResult } from '../src/index.js';
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

  it('walks a JS constructor call, which is how jose and its peers are invoked', () => {
    const parsed = parseSource('a.ts', "import { SignJWT } from 'jose';\nnew SignJWT({});\n", 'typescript');
    expect(parsed.calls.some((c) => c.method === 'SignJWT')).toBe(true);
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

  it('finds the algorithm where each method actually puts it', () => {
    // importKey takes it third and unwrapKey fourth; reading position 0
    // everywhere misses the key-wrapping half of WebCrypto entirely.
    const imported = detect(
      `await crypto.subtle.importKey('raw', bytes, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);`,
    );
    expect(imported[0]?.primitive).toBe('ECDH');
    expect(imported[0]?.parameters['curve']).toBe('P-256');

    const unwrapped = detect(
      `await crypto.subtle.unwrapKey('raw', wrapped, kek, { name: 'AES-KW' }, { name: 'AES-GCM' }, true, ['decrypt']);`,
    );
    expect(unwrapped[0]?.primitive).toBe('AES');
    expect(unwrapped[0]?.parameters['mode']).toBe('KW');
    expect(unwrapped[0]?.purpose).toBe('KEY_ESTABLISHMENT');
  });

  it('does not read the AES-CTR counter width as a key size', () => {
    // On AesCtrParams `length` is the number of bits in the counter block, not
    // the key length, so this site must not claim a 64-bit AES key - and must
    // hash to the same asset as the generateKey site that made the key.
    const ctr = detect(
      `await crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 64 }, key, data);`,
    );
    expect(ctr[0]?.primitive).toBe('AES');
    expect(ctr[0]?.parameters['keySize']).toBeUndefined();

    const generated = detect(`await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);`);
    expect(generated[0]?.parameters['keySize']).toBe(256);
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

  it("reads jose's constructor-based signing API", () => {
    // jose puts the alg on setProtectedHeader, and the whole chain hangs off a
    // `new` expression the walker did not visit at all.
    const d = detect(`
      import { SignJWT } from 'jose';
      const t = await new SignJWT({}).setProtectedHeader({ alg: 'RS256' }).sign(key);
    `);
    expect(d.map((x) => x.primitive).sort()).toEqual(['RSA', 'SHA2']);
  });
});

describe('crypto-js', () => {
  it('does not report single DES as 3DES, and finds it at all', () => {
    const d = detect(`
      const CryptoJS = require('crypto-js');
      CryptoJS.DES.encrypt(msg, key);
    `);
    expect(d).toHaveLength(1);
    expect(d[0]?.primitive).not.toBe('3DES');
    expect(d[0]?.parameters['name']).toBe('DES');
  });

  it('still separates 3DES from DES', () => {
    const d = detect(`
      const CryptoJS = require('crypto-js');
      CryptoJS.TripleDES.encrypt(msg, key);
    `);
    expect(d[0]?.primitive).toBe('3DES');
  });

  it('reaches every Hmac digest variant the library ships', () => {
    // Dispatch is by method name, so a variant missing from `methods` never
    // reaches the rule and is indistinguishable from a clean scan.
    const d = detect(`
      const CryptoJS = require('crypto-js');
      CryptoJS.HmacSHA512(msg, key);
    `);
    expect(d.map((x) => x.primitive).sort()).toEqual(['HMAC', 'SHA2']);
    expect(d.find((x) => x.primitive === 'SHA2')?.parameters['outputLength']).toBe(512);
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

  it('reads the DSA key size from the argument pyca actually puts it in', () => {
    // dsa.generate_private_key(key_size, backend) - positional 0, unlike RSA
    // and DH, which put it at 1. Reading 1 collapsed every DSA size into one
    // parameterless asset.
    const d = py(`
from cryptography.hazmat.primitives.asymmetric import dsa
dsa.generate_private_key(2048)
`);
    expect(d[0]?.primitive).toBe('DSA');
    expect(d[0]?.parameters['modulusLength']).toBe(2048);
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

  it('reads the PyJWT algorithm passed positionally', () => {
    // encode(payload, key, algorithm) and decode(jwt, key, algorithms) both
    // put it in argument 2, and the positional form is legal and common.
    expect(py(`import jwt\njwt.encode(payload, key, "HS256")`).map((x) => x.primitive).sort()).toEqual([
      'HMAC',
      'SHA2',
    ]);
    expect(py(`import jwt\njwt.decode(tok, key, ["RS256"])`).some((x) => x.primitive === 'RSA')).toBe(true);
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

describe('the whole pipeline, from a file on disk to a Finding', () => {
  async function scan(files: Record<string, string>): Promise<SourceScanResult> {
    const dir = await mkdtemp(join(tmpdir(), 'assay-source-'));
    for (const [name, content] of Object.entries(files)) {
      await writeFile(join(dir, name), content, 'utf8');
    }
    return scanSource({ root: dir, systemId: 'svc', collectedAt: '2026-08-28T00:00:00.000Z' });
  }

  it('carries an unverifiable developer claim onto the finding (I6)', async () => {
    // The taint has to survive the join between the rule and the Finding, or
    // correlate never sees it and the assertion silently confirms.
    const { findings } = await scan({ 'a.py': 'import hashlib\nhashlib.md5(data, usedforsecurity=False)\n' });
    const md5 = findings.find((f) => f.asset.primitive === 'MD5');
    expect(md5?.assumptions?.[0]).toContain('usedforsecurity=False');
    expect(md5?.evidence.raw).toContain('purpose=INTEGRITY(RULE_DEFAULT)');
  });

  it('leaves an ordinary digest call with nothing to downgrade', async () => {
    const { findings } = await scan({ 'a.py': 'import hashlib\nhashlib.md5(data)\n' });
    const md5 = findings.find((f) => f.asset.primitive === 'MD5');
    expect(md5?.assumptions).toBeUndefined();
    expect(md5?.evidence.raw).toContain('purpose=INTEGRITY(RESOLVED)');
  });

  it('resolves a submodule import to the package that gates the rule', async () => {
    const { findings } = await scan({
      'a.ts': "import AES from 'crypto-js/aes';\nAES.encrypt(msg, key);\n",
    });
    expect(findings.map((f) => f.asset.primitive)).toEqual(['AES']);
  });
});
