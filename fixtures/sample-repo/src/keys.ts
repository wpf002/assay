import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

export function issueKeyPair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

export function signingKeyPair() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

export function modern() {
  return crypto.generateKeyPairSync('x25519');
}

export function legacyDigest(data: string) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

export function fingerprint(data: string) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function weakCipher(key: Buffer, iv: Buffer) {
  return crypto.createCipheriv('aes-128-cbc', key, iv);
}

export function stretch(pw: string, salt: Buffer) {
  return crypto.pbkdf2Sync(pw, salt, 1000, 32, 'sha1');
}

export function agree() {
  return crypto.createECDH('secp384r1');
}

export function token(payload: object, key: string) {
  return jwt.sign(payload, key, { algorithm: 'RS256' });
}

export async function webcryptoKey() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
}
