import crypto from 'node:crypto';
import { issueKeyPair } from '../src/keys.js';

// Test-only crypto. Real findings, and not work items.
it('generates a keypair', () => {
  const rc4 = crypto.createCipheriv('rc4', Buffer.alloc(16), Buffer.alloc(0));
  const md5 = crypto.createHash('md5').update('x').digest('hex');
  expect(issueKeyPair()).toBeTruthy();
  expect([rc4, md5]).toBeTruthy();
});
