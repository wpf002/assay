import crypto from 'node:crypto';

// Imported from a reachable module, but this helper is never exported and
// never called from anything exported. Dead inside a live file.
function neverCalled(data: string) {
  return crypto.createHash('md5').update(data).digest('hex');
}

export function used(data: string) {
  return crypto.createHash('sha512').update(data).digest('hex');
}
