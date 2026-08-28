import crypto from 'node:crypto';

// Nothing imports this module. It is inventory, not work.
export function abandonedCipher(key: Buffer, iv: Buffer) {
  return crypto.createCipheriv('des-ede3-cbc', key, iv);
}
