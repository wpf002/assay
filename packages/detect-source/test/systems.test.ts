import { describe, expect, it } from 'vitest';
import { languageFor, parseSource } from '../src/parsers/index.js';
import { ruleIndex } from '../src/rules/index.js';
import type { Detection, Lang } from '../src/types.js';

function detect(source: string, lang: Lang, file: string): Detection[] {
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

const go = (s: string) => detect(s, 'go', 'main.go');
const java = (s: string) => detect(s, 'java', 'A.java');
const c = (s: string) => detect(s, 'c', 'a.c');
const rust = (s: string) => detect(s, 'rust', 'main.rs');
const cs = (s: string) => detect(s, 'csharp', 'A.cs');

describe('language dispatch', () => {
  it('maps the new extensions', () => {
    expect(languageFor('a.go')).toBe('go');
    expect(languageFor('A.java')).toBe('java');
    expect(languageFor('a.c')).toBe('c');
    expect(languageFor('a.cpp')).toBe('cpp');
    expect(languageFor('a.rs')).toBe('rust');
    expect(languageFor('A.cs')).toBe('csharp');
  });
});

describe('Go', () => {
  it('reads the modulus from rsa.GenerateKey', () => {
    const d = go(`
package main
import "crypto/rsa"
func main() { rsa.GenerateKey(rand.Reader, 2048) }
`);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.parameters['modulusLength']).toBe(2048);
  });

  it('reads the curve out of the elliptic argument', () => {
    const d = go(`
package main
import "crypto/ecdsa"
func main() { ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }
`);
    expect(d[0]?.primitive).toBe('ECDSA');
    expect(d[0]?.parameters['curve']).toBe('P-384');
  });

  it('puts RSA-OAEP on the confidentiality track and RSA-PSS on authenticity', () => {
    expect(go(`import "crypto/rsa"
func f() { rsa.EncryptOAEP(h, r, k, m, nil) }`)[0]?.purpose).toBe('KEY_ESTABLISHMENT');
    expect(go(`import "crypto/rsa"
func f() { rsa.SignPSS(r, k, h, d, nil) }`)[0]?.purpose).toBe('DIGITAL_SIGNATURE');
  });

  it('finds legacy primitives in the standard library', () => {
    const d = go(`
import ("crypto/des"
"crypto/rc4"
"crypto/md5")
func f() { des.NewTripleDESCipher(k); rc4.NewCipher(k); md5.New() }
`);
    const prims = d.map((x) => x.primitive);
    expect(prims).toContain('3DES');
    expect(prims).toContain('RC4');
    expect(prims).toContain('MD5');
  });

  it('does not report single DES at the strength of 3DES', () => {
    const single = go(`
import "crypto/des"
func f() { des.NewCipher(k) }
`);
    expect(single[0]?.primitive).not.toBe('3DES');
    expect(single[0]?.parameters['name']).toBe('DES');
    expect(single[0]?.parameters['keySize']).toBe(56);
    const triple = go(`
import "crypto/des"
func f() { des.NewTripleDESCipher(k) }
`);
    expect(triple[0]?.primitive).toBe('3DES');
  });

  it('records the import path an aliased spec names, not the raw spec text', () => {
    const parsed = parseSource('main.go', 'package main\nimport cryptorsa "crypto/rsa"\n', 'go');
    expect([...parsed.context.imports]).toContain('crypto/rsa');
    expect([...parsed.context.imports].every((i) => !i.includes('"'))).toBe(true);
  });

  it('resolves an aliased import to the package it names', () => {
    const d = go(`
package main
import cryptorsa "crypto/rsa"
func main() { cryptorsa.GenerateKey(rand.Reader, 2048) }
`);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.parameters['modulusLength']).toBe(2048);
  });
});

describe('Java JCA', () => {
  it('gives one transformation string one asset however it is capitalized', () => {
    // JCA transformation strings are case-insensitive; the parameters feed the
    // asset id, so a lower-case spelling would split the work item.
    const lower = java(`
import javax.crypto.Cipher;
class A { void f() throws Exception { Cipher.getInstance("aes/cbc/pkcs5padding"); } }
`);
    const upper = java(`
import javax.crypto.Cipher;
class A { void f() throws Exception { Cipher.getInstance("AES/CBC/PKCS5Padding"); } }
`);
    expect(lower[0]?.parameters).toEqual(upper[0]?.parameters);
  });

  it('splits a transformation string into algorithm, mode and padding', () => {
    const d = java(`
import javax.crypto.Cipher;
class A { void f() throws Exception { Cipher.getInstance("AES/CBC/PKCS5Padding"); } }
`);
    expect(d[0]?.primitive).toBe('AES');
    expect(d[0]?.parameters['mode']).toBe('CBC');
    expect(d[0]?.parameters['padding']).toBe('PKCS5PADDING');
  });

  it('resolves a fully-qualified receiver', () => {
    // `javax.crypto.Cipher` parses as a field_access, and without a case for it
    // the receiver came back empty and the rule bailed before its import gate.
    const d = java(`
import javax.crypto.Cipher;
class A { void f() throws Exception { javax.crypto.Cipher.getInstance("AES/GCM/NoPadding"); } }
`);
    expect(d[0]?.primitive).toBe('AES');
    expect(d[0]?.parameters['mode']).toBe('GCM');
  });

  it('reads a signature algorithm as its primitive plus its digest', () => {
    const d = java(`
import java.security.Signature;
class A { void f() throws Exception { Signature.getInstance("SHA1withRSA"); } }
`);
    expect(d.map((x) => x.primitive).sort()).toEqual(['RSA', 'SHA1']);
  });

  it('treats RSA in a Cipher as key transport, on the confidentiality track', () => {
    const d = java(`
import javax.crypto.Cipher;
class A { void f() throws Exception { Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); } }
`);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.purpose).toBe('KEY_ESTABLISHMENT');
  });

  it('reads PBKDF2 out of a SecretKeyFactory name', () => {
    const d = java(`
import javax.crypto.SecretKeyFactory;
class A { void f() throws Exception { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); } }
`);
    expect(d[0]?.primitive).toBe('PBKDF2');
    expect(d[0]?.parameters['hash']).toBe('SHA1');
  });

  it('does not fire on a local class called Cipher with no javax.crypto import', () => {
    expect(
      java(`import com.acme.Cipher;
class A { void f() { Cipher.getInstance("AES"); } }`),
    ).toHaveLength(0);
  });
});

describe('C and C++ with OpenSSL', () => {
  it('reads the modulus from RSA_generate_key_ex', () => {
    const d = c(`
#include <openssl/rsa.h>
int main() { RSA_generate_key_ex(rsa, 2048, e, NULL); }
`);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.parameters['modulusLength']).toBe(2048);
  });

  it('does not read a plaintext length as a modulus', () => {
    // Argument 0 of RSA_public_encrypt is the input length, not a key size.
    const d = c(`
#include <openssl/rsa.h>
int main() { RSA_public_encrypt(16, pt, out, rsa, RSA_PKCS1_OAEP_PADDING); }
`);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.parameters['modulusLength']).toBeUndefined();
  });

  it('reads the curve from a NID constant', () => {
    const d = c(`
#include <openssl/ec.h>
int main() { EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); }
`);
    expect(d[0]?.parameters['curve']).toBe('P-256');
  });

  it('resolves the algorithm behind an EVP wrapper from its argument', () => {
    const d = c(`
#include <openssl/evp.h>
int main() { EVP_DigestInit_ex(ctx, EVP_sha1(), NULL); }
`);
    expect(d[0]?.primitive).toBe('SHA1');
  });

  it('captures the PBKDF2 iteration count', () => {
    const d = c(`
#include <openssl/evp.h>
int main() { PKCS5_PBKDF2_HMAC(p, pl, s, sl, 1000, md, kl, out); }
`);
    expect(d[0]?.parameters['iterations']).toBe(1000);
  });

  it('works in C++ too', () => {
    const d = detect(
      `#include <openssl/evp.h>
int main() { EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr); }`,
      'cpp',
      'a.cpp',
    );
    expect(d[0]?.primitive).toBe('EdDSA');
  });
});

describe('Rust', () => {
  it('reads RSA strength from the constructor', () => {
    const d = rust(`
use rsa::RsaPrivateKey;
fn main() { let k = RsaPrivateKey::new(&mut rng, 2048); }
`);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.parameters['modulusLength']).toBe(2048);
  });

  it('reads the AES variant and mode out of the type name', () => {
    const d = rust(`
use aes_gcm::Aes256Gcm;
fn main() { let c = Aes256Gcm::new(key); }
`);
    expect(d[0]?.parameters['keySize']).toBe(256);
    expect(d[0]?.parameters['mode']).toBe('GCM');
  });

  it('puts x25519 on the confidentiality track and ed25519 on authenticity', () => {
    expect(rust(`use x25519_dalek::StaticSecret;
fn main(){ StaticSecret::new(rng); }`)[0]?.purpose).toBe('KEY_ESTABLISHMENT');
    expect(rust(`use ed25519_dalek::SigningKey;
fn main(){ SigningKey::generate(&mut rng); }`)[0]?.purpose).toBe('DIGITAL_SIGNATURE');
  });

  it('reads the hmac crate alias as a MAC, not as its inner digest', () => {
    // `type HmacSha256 = Hmac<Sha256>` is the crate README's own idiom, so this
    // is the whole Rust integrity surface rather than an edge case.
    const d = rust(`
use hmac::Hmac;
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
fn main() { let m = HmacSha256::new_from_slice(b"key").unwrap(); }
`);
    expect(d.map((x) => x.primitive).sort()).toEqual(['HMAC', 'SHA2']);
    expect(d.find((x) => x.primitive === 'HMAC')?.parameters['hash']).toBe('SHA2');
  });

  it('tells an ECDSA SigningKey apart from an Ed25519 one by the crate it came from', () => {
    const d = rust(`
use p256::ecdsa::SigningKey;
fn main() { let k = SigningKey::generate(&mut rng); }
`);
    expect(d[0]?.primitive).toBe('ECDSA');
    expect(d[0]?.parameters['curve']).toBe('P-256');
  });

  it('resolves a renamed import to the crate it names', () => {
    const d = rust(`
use rsa::RsaPrivateKey as PrivKey;
fn main() { let k = PrivKey::new(&mut rng, 2048); }
`);
    expect(d[0]?.primitive).toBe('RSA');
  });
});

describe('C#', () => {
  it('reads the class as the algorithm and the argument as the strength', () => {
    const d = cs(`
using System.Security.Cryptography;
class A { void F() { RSA.Create(3072); } }
`);
    expect(d[0]?.primitive).toBe('RSA');
    expect(d[0]?.parameters['modulusLength']).toBe(3072);
  });

  it('finds legacy .NET primitives', () => {
    const d = cs(`
using System.Security.Cryptography;
class A { void F() { TripleDES.Create(); SHA1.Create(); MD5.Create(); } }
`);
    const prims = d.map((x) => x.primitive);
    expect(prims).toContain('3DES');
    expect(prims).toContain('SHA1');
    expect(prims).toContain('MD5');
  });

  it('does not file RC2 and single DES under the 3DES primitive', () => {
    // Both would otherwise claim 112 classical bits, and RC2 is not related to
    // DES at all.
    const d = cs(`
using System.Security.Cryptography;
class A { void F() { RC2.Create(); DES.Create(); } }
`);
    expect(d.every((x) => x.primitive !== '3DES')).toBe(true);
    expect(d.map((x) => x.parameters['name']).sort()).toEqual(['DES', 'RC2']);
  });

  it('emits HMAC and its digest as two assets', () => {
    const d = cs(`
using System.Security.Cryptography;
class A { void F() { HMACSHA1.Create(); } }
`);
    expect(d.map((x) => x.primitive).sort()).toEqual(['HMAC', 'SHA1']);
  });

  it('does not fire without the namespace', () => {
    expect(cs(`using Acme.Utils;
class A { void F() { RSA.Create(2048); } }`)).toHaveLength(0);
  });
});

describe('entry points in compiled languages', () => {
  const entryOf = (source: string, lang: Lang, file: string) =>
    parseSource(file, source, lang) && require('../src/graph.js');

  it('recognizes a main function in each language', async () => {
    const { buildModuleNode } = await import('../src/graph.js');
    const cases: [Lang, string, string][] = [
      ['go', 'main.go', 'package main\nfunc main() {}\n'],
      ['rust', 'main.rs', 'fn main() {}\n'],
      ['c', 'main.c', 'int main(void) { return 0; }\n'],
      ['java', 'A.java', 'class A { public static void main(String[] a) {} }\n'],
      ['csharp', 'A.cs', 'class A { static void Main(string[] a) {} }\n'],
    ];
    for (const [lang, file, source] of cases) {
      const parsed = parseSource(file, source, lang);
      const node = buildModuleNode({ file, lang, root: parsed.root, source });
      expect(node.entryKind).toBe('package-main');
    }
    expect(entryOf).toBeDefined();
  });

  it('recognizes a Go http server as a framework route', async () => {
    const { buildModuleNode } = await import('../src/graph.js');
    const source = 'package main\nfunc main() { http.ListenAndServe(":8080", nil) }\n';
    const parsed = parseSource('main.go', source, 'go');
    expect(buildModuleNode({ file: 'main.go', lang: 'go', root: parsed.root, source }).entryKind).toBe(
      'framework-route',
    );
  });
});
