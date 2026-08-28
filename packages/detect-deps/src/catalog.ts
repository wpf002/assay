import type { Primitive, Purpose } from '@assay/core';

/**
 * Library -> cryptographic capability surface.
 *
 * READ THE CEILING FIRST. A manifest entry says a library IMPLEMENTS an
 * algorithm. It says nothing about whether the application USES it, which is
 * why DEPENDENCY sits at 0.35 and cannot confirm anything on its own (D1).
 *
 * The purpose of this table is not to produce findings. It is to tell the AST
 * scanner where to look and to make the gap visible: a repo that depends on
 * node-forge but shows no forge call sites either does not use it, or uses it
 * somewhere the rules do not yet reach. Both are worth knowing.
 */
export interface Capability {
  readonly primitive: Primitive;
  readonly purpose: Purpose;
  readonly parameters?: Readonly<Record<string, string | number>>;
}

export interface LibraryEntry {
  readonly ecosystem: 'npm' | 'pypi';
  readonly capabilities: readonly Capability[];
  readonly note?: string;
}

const kex = (primitive: Primitive, parameters?: Capability['parameters']): Capability => ({
  primitive,
  purpose: 'KEY_ESTABLISHMENT',
  ...(parameters ? { parameters } : {}),
});
const sig = (primitive: Primitive, parameters?: Capability['parameters']): Capability => ({
  primitive,
  purpose: 'DIGITAL_SIGNATURE',
  ...(parameters ? { parameters } : {}),
});
const enc = (primitive: Primitive, parameters?: Capability['parameters']): Capability => ({
  primitive,
  purpose: 'DATA_ENCRYPTION',
  ...(parameters ? { parameters } : {}),
});
const dig = (primitive: Primitive, parameters?: Capability['parameters']): Capability => ({
  primitive,
  purpose: 'INTEGRITY',
  ...(parameters ? { parameters } : {}),
});

export const CATALOG: Readonly<Record<string, LibraryEntry>> = {
  /* ------------------------------------------------------------------- npm */
  'node-forge': {
    ecosystem: 'npm',
    capabilities: [kex('RSA'), sig('RSA'), sig('ECDSA'), enc('AES'), enc('3DES'), enc('RC4'), dig('SHA1'), dig('MD5'), dig('SHA2')],
    note: 'pure-JS TLS/PKI stack; implements a wide legacy surface including 3DES and RC4',
  },
  'crypto-js': {
    ecosystem: 'npm',
    capabilities: [enc('AES'), enc('3DES'), enc('RC4'), dig('MD5'), dig('SHA1'), dig('SHA2'), dig('SHA3')],
  },
  jsonwebtoken: {
    ecosystem: 'npm',
    capabilities: [sig('RSA'), sig('ECDSA'), sig('HMAC'), sig('EdDSA')],
  },
  jose: {
    ecosystem: 'npm',
    capabilities: [sig('RSA'), sig('ECDSA'), sig('EdDSA'), sig('HMAC'), kex('ECDH'), kex('RSA'), enc('AES')],
  },
  jsrsasign: { ecosystem: 'npm', capabilities: [sig('RSA'), sig('ECDSA'), sig('DSA'), dig('SHA1'), dig('SHA2')] },
  elliptic: { ecosystem: 'npm', capabilities: [sig('ECDSA'), kex('ECDH'), sig('EdDSA')] },
  tweetnacl: { ecosystem: 'npm', capabilities: [sig('EdDSA', { curve: 'Ed25519' }), kex('X25519'), enc('ChaCha20')] },
  libsodium: { ecosystem: 'npm', capabilities: [sig('EdDSA'), kex('X25519'), enc('ChaCha20')] },
  'libsodium-wrappers': { ecosystem: 'npm', capabilities: [sig('EdDSA'), kex('X25519'), enc('ChaCha20')] },
  bcrypt: { ecosystem: 'npm', capabilities: [{ primitive: 'UNKNOWN', purpose: 'KEY_DERIVATION', parameters: { name: 'bcrypt' } }] },
  bcryptjs: { ecosystem: 'npm', capabilities: [{ primitive: 'UNKNOWN', purpose: 'KEY_DERIVATION', parameters: { name: 'bcrypt' } }] },
  argon2: { ecosystem: 'npm', capabilities: [{ primitive: 'Argon2', purpose: 'KEY_DERIVATION' }] },
  sshpk: { ecosystem: 'npm', capabilities: [sig('RSA'), sig('ECDSA'), sig('EdDSA'), sig('DSA')] },
  'ssh2': { ecosystem: 'npm', capabilities: [kex('ECDH'), kex('DH'), kex('X25519'), sig('RSA'), sig('ECDSA'), sig('EdDSA'), enc('AES'), enc('3DES')] },
  'node-rsa': { ecosystem: 'npm', capabilities: [kex('RSA'), sig('RSA')] },
  '@peculiar/x509': { ecosystem: 'npm', capabilities: [sig('RSA'), sig('ECDSA'), sig('EdDSA')] },
  'pkijs': { ecosystem: 'npm', capabilities: [sig('RSA'), sig('ECDSA'), kex('ECDH')] },
  'openpgp': { ecosystem: 'npm', capabilities: [sig('RSA'), sig('ECDSA'), sig('EdDSA'), kex('ECDH'), kex('RSA'), enc('AES'), enc('3DES')] },
  'md5': { ecosystem: 'npm', capabilities: [dig('MD5')] },
  'sha.js': { ecosystem: 'npm', capabilities: [dig('SHA1'), dig('SHA2')] },
  'hash.js': { ecosystem: 'npm', capabilities: [dig('SHA1'), dig('SHA2'), dig('SHA3')] },

  /* ------------------------------------------------------------------ pypi */
  cryptography: {
    ecosystem: 'pypi',
    capabilities: [kex('RSA'), sig('RSA'), sig('ECDSA'), kex('ECDH'), sig('EdDSA'), kex('X25519'), kex('DH'), sig('DSA'), enc('AES'), enc('3DES'), enc('ChaCha20'), enc('RC4'), dig('SHA1'), dig('SHA2'), dig('SHA3'), dig('MD5')],
    note: 'pyca/cryptography exposes both a modern API and a hazmat layer with deprecated primitives',
  },
  pycryptodome: {
    ecosystem: 'pypi',
    capabilities: [kex('RSA'), sig('RSA'), sig('DSA'), sig('ECDSA'), enc('AES'), enc('3DES'), enc('RC4'), enc('ChaCha20'), dig('MD5'), dig('SHA1'), dig('SHA2'), dig('SHA3')],
  },
  pycryptodomex: {
    ecosystem: 'pypi',
    capabilities: [kex('RSA'), sig('RSA'), sig('DSA'), sig('ECDSA'), enc('AES'), enc('3DES'), enc('RC4'), dig('MD5'), dig('SHA1'), dig('SHA2')],
  },
  pycrypto: {
    ecosystem: 'pypi',
    capabilities: [kex('RSA'), sig('RSA'), sig('DSA'), enc('AES'), enc('3DES'), enc('RC4'), dig('MD5'), dig('SHA1')],
    note: 'unmaintained since 2013 - a VENDOR_LOCKED candidate rather than VENDOR_UPGRADEABLE',
  },
  pyopenssl: { ecosystem: 'pypi', capabilities: [kex('RSA'), sig('RSA'), sig('ECDSA'), kex('ECDH'), kex('DH')] },
  paramiko: { ecosystem: 'pypi', capabilities: [kex('ECDH'), kex('DH'), kex('X25519'), sig('RSA'), sig('ECDSA'), sig('EdDSA'), sig('DSA'), enc('AES'), enc('3DES')] },
  pyjwt: { ecosystem: 'pypi', capabilities: [sig('RSA'), sig('ECDSA'), sig('HMAC'), sig('EdDSA')] },
  'python-jose': { ecosystem: 'pypi', capabilities: [sig('RSA'), sig('ECDSA'), sig('HMAC'), kex('ECDH'), enc('AES')] },
  ecdsa: { ecosystem: 'pypi', capabilities: [sig('ECDSA'), kex('ECDH')] },
  rsa: { ecosystem: 'pypi', capabilities: [kex('RSA'), sig('RSA')] },
  passlib: { ecosystem: 'pypi', capabilities: [{ primitive: 'PBKDF2', purpose: 'KEY_DERIVATION' }, { primitive: 'Argon2', purpose: 'KEY_DERIVATION' }, { primitive: 'scrypt', purpose: 'KEY_DERIVATION' }] },
  'argon2-cffi': { ecosystem: 'pypi', capabilities: [{ primitive: 'Argon2', purpose: 'KEY_DERIVATION' }] },
  bcrypt_py: { ecosystem: 'pypi', capabilities: [{ primitive: 'UNKNOWN', purpose: 'KEY_DERIVATION', parameters: { name: 'bcrypt' } }] },
  pynacl: { ecosystem: 'pypi', capabilities: [sig('EdDSA', { curve: 'Ed25519' }), kex('X25519'), enc('ChaCha20')] },
  oscrypto: { ecosystem: 'pypi', capabilities: [kex('RSA'), sig('RSA'), sig('ECDSA'), enc('AES'), enc('3DES')] },
  'M2Crypto': { ecosystem: 'pypi', capabilities: [kex('RSA'), sig('RSA'), sig('DSA'), kex('DH'), enc('AES'), enc('3DES')] },
};

/** Normalized lookup: npm scopes and PyPI's case/underscore rules differ. */
export function lookup(name: string, ecosystem: 'npm' | 'pypi'): LibraryEntry | null {
  const direct = CATALOG[name];
  if (direct && direct.ecosystem === ecosystem) return direct;
  const normalized = ecosystem === 'pypi' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name.toLowerCase();
  for (const [key, entry] of Object.entries(CATALOG)) {
    if (entry.ecosystem !== ecosystem) continue;
    const k = ecosystem === 'pypi' ? key.toLowerCase().replace(/[-_.]+/g, '-') : key.toLowerCase();
    if (k === normalized) return entry;
  }
  return null;
}
