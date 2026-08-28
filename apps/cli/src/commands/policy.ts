import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { PolicyPackSchema, generatePackKeypair, signPack, verifyPack } from '@assay/policy';

/**
 * Pack publishing (decision D3).
 *
 * The signature covers the horizon and the regulatory deadlines. It does NOT
 * cover migrationYearsByControl, so an organization can set its own migration
 * times - which it alone knows - without breaking attribution of the deadline,
 * which it alone should not be setting.
 */

export async function packKeygen(outDir: string): Promise<void> {
  const { publicKeyPem, privateKeyPem } = generatePackKeypair();
  const pub = resolve(outDir, 'assay-packs.pub.pem');
  const priv = resolve(outDir, 'assay-packs.key.pem');
  await writeFile(pub, publicKeyPem, 'utf8');
  await writeFile(priv, privateKeyPem, { encoding: 'utf8', mode: 0o600 });
  process.stdout.write(
    `wrote ${pub}\nwrote ${priv} (mode 0600)\n\n` +
      'Whoever holds the private key publishes horizons. Distribute the public\n' +
      'key with the packs; a ranking under an unsigned pack still works, it is\n' +
      'just not comparable with anyone else’s.\n',
  );
}

export async function packSign(packPath: string, keyPath: string): Promise<void> {
  const path = resolve(packPath);
  const pack = PolicyPackSchema.parse(JSON.parse(await readFile(path, 'utf8')));
  const privateKeyPem = await readFile(resolve(keyPath), 'utf8');
  const signed = { ...pack, signature: signPack(pack, privateKeyPem) };
  await writeFile(path, `${JSON.stringify(signed, null, 2)}\n`, 'utf8');
  process.stdout.write(
    `signed ${path}\n` +
      `  packId ${signed.packId}@${signed.packVersion}\n` +
      `  crqcYear ${signed.crqcYear}, deadlines ` +
      `${signed.regulatoryDeadlines.CONFIDENTIALITY ?? 'none'} / ` +
      `${signed.regulatoryDeadlines.AUTHENTICITY ?? 'none'}\n` +
      '  migrationYearsByControl is NOT covered: edit it locally without breaking this.\n',
  );
}

export { verifyPack };
