import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { generateGrantKeypair, signGrant, verifyGrant, type GrantPayload } from '@assay/scope';

/**
 * Grant lifecycle. Deliberately three separate verbs: whoever holds the
 * signing key is authorizing the scan, and that should be a person doing a
 * distinct, auditable thing - not a flag on the scanner.
 */

export async function keygen(outDir: string): Promise<void> {
  const { publicKeyPem, privateKeyPem } = generateGrantKeypair();
  const pub = resolve(outDir, 'assay-scope.pub.pem');
  const priv = resolve(outDir, 'assay-scope.key.pem');
  await writeFile(pub, publicKeyPem, 'utf8');
  await writeFile(priv, privateKeyPem, { encoding: 'utf8', mode: 0o600 });
  process.stdout.write(
    `wrote ${pub}\nwrote ${priv} (mode 0600)\n\n` +
      'The private key authorizes scanning. Keep it with whoever is allowed to\n' +
      'say yes; distribute only the public key to the machines that run scans.\n',
  );
}

export interface SignOptions {
  readonly key: string;
  readonly issuedBy: string;
  readonly targets: string;
  readonly ports?: string;
  readonly notBefore?: string;
  readonly notAfter: string;
  readonly purpose?: string;
  readonly grantId?: string;
  readonly out: string;
}

export async function sign(opts: SignOptions): Promise<void> {
  const privateKeyPem = await readFile(resolve(opts.key), 'utf8');
  const payload: GrantPayload = {
    grantId: opts.grantId ?? `grant-${Date.now().toString(36)}`,
    issuedBy: opts.issuedBy,
    targets: opts.targets.split(',').map((t) => t.trim()).filter(Boolean),
    ports: (opts.ports ?? '')
      .split(',')
      .map((p) => Number(p.trim()))
      .filter((p) => Number.isInteger(p) && p > 0),
    notBefore: new Date(opts.notBefore ?? Date.now()).toISOString(),
    notAfter: new Date(opts.notAfter).toISOString(),
    purpose: opts.purpose ?? '',
  };
  if (payload.targets.length === 0) throw new Error('--targets must name at least one target');
  if (!Number.isFinite(Date.parse(payload.notAfter))) throw new Error('--not-after is not a date');

  const grant = signGrant(payload, privateKeyPem);
  await writeFile(resolve(opts.out), `${JSON.stringify(grant, null, 2)}\n`, 'utf8');
  process.stdout.write(
    `wrote ${resolve(opts.out)}\n` +
      `  targets ${grant.targets.join(', ')}\n` +
      `  ports   ${grant.ports.length === 0 ? 'any' : grant.ports.join(', ')}\n` +
      `  window  ${grant.notBefore} .. ${grant.notAfter}\n`,
  );
}

export async function verify(grantPath: string, pubkeyPath: string): Promise<void> {
  const grant: unknown = JSON.parse(await readFile(resolve(grantPath), 'utf8'));
  const pub = await readFile(resolve(pubkeyPath), 'utf8');
  const verified = verifyGrant(grant, pub);
  process.stdout.write(
    `signature OK: grant ${verified.grantId} issued by ${verified.issuedBy}\n` +
      `  targets ${verified.targets.join(', ')}\n` +
      `  ports   ${verified.ports.length === 0 ? 'any' : verified.ports.join(', ')}\n` +
      `  window  ${verified.notBefore} .. ${verified.notAfter}\n` +
      `  purpose ${verified.purpose || '(none given)'}\n\n` +
      'A valid signature is not permission to probe right now - the window and\n' +
      'the target are checked again at probe time.\n',
  );
}
