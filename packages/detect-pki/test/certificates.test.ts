import { webcrypto } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';
import { beforeAll, describe, expect, it } from 'vitest';
import { lifetimeBreaches, parseCertificates, scanCertificates } from '../src/index.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

interface MadeCert {
  pem: string;
}

async function makeCert(
  algorithm: Parameters<typeof webcrypto.subtle.generateKey>[0],
  signingAlgorithm: string,
  hash: string,
  opts: { notAfter?: Date; ca?: boolean; name?: string } = {},
): Promise<MadeCert> {
  const keys = (await webcrypto.subtle.generateKey(algorithm, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned(
    {
      serialNumber: '01',
      name: `CN=${opts.name ?? 'test.example.com'}`,
      notBefore: new Date('2026-01-01T00:00:00Z'),
      notAfter: opts.notAfter ?? new Date('2027-01-01T00:00:00Z'),
      signingAlgorithm: { name: signingAlgorithm, hash },
      keys,
      extensions: [new x509.BasicConstraintsExtension(opts.ca ?? false, undefined, true)],
    },
    webcrypto as unknown as Crypto,
  );
  return { pem: cert.toString('pem') };
}

let rsa2048Sha256: MadeCert;
let rsa1024Sha1: MadeCert;
let ecdsaP256: MadeCert;
let longLivedCa: MadeCert;

beforeAll(async () => {
  rsa2048Sha256 = await makeCert(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    'RSASSA-PKCS1-v1_5',
    'SHA-256',
  );
  rsa1024Sha1 = await makeCert(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    'RSASSA-PKCS1-v1_5',
    'SHA-1',
    { name: 'legacy.example.com' },
  );
  ecdsaP256 = await makeCert({ name: 'ECDSA', namedCurve: 'P-256' }, 'ECDSA', 'SHA-256', {
    name: 'ec.example.com',
  });
  longLivedCa = await makeCert(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    'RSASSA-PKCS1-v1_5',
    'SHA-256',
    { notAfter: new Date('2036-06-01T00:00:00Z'), ca: true, name: 'Example Root CA' },
  );
}, 60_000);

describe('parsing', () => {
  it('reads the subject key algorithm and size from the structure, not a guess', () => {
    const [c] = parseCertificates(Buffer.from(rsa2048Sha256.pem), 'a.pem');
    expect(c?.publicKey.primitive).toBe('RSA');
    expect(c?.publicKey.parameters['modulusLength']).toBe(2048);
    expect(c?.publicKey.classicalSecurityBits).toBe(112);
  });

  it('separates the subject key from the issuer signature and its digest', () => {
    const [c] = parseCertificates(Buffer.from(rsa1024Sha1.pem), 'legacy.pem');
    expect(c?.publicKey.parameters['modulusLength']).toBe(1024);
    expect(c?.signature.primitive).toBe('RSA');
    expect(c?.signatureDigest?.primitive).toBe('SHA1');
  });

  it('reads a named curve', () => {
    const [c] = parseCertificates(Buffer.from(ecdsaP256.pem), 'ec.pem');
    expect(c?.publicKey.primitive).toBe('ECDSA');
    expect(String(c?.publicKey.parameters['curve'])).toContain('256');
  });

  it('records validity, CA status and self-signing', () => {
    const [leaf] = parseCertificates(Buffer.from(rsa2048Sha256.pem), 'a.pem');
    const [ca] = parseCertificates(Buffer.from(longLivedCa.pem), 'ca.pem');
    expect(leaf?.isCA).toBe(false);
    expect(ca?.isCA).toBe(true);
    expect(ca?.selfSigned).toBe(true);
    expect(ca?.notAfter.startsWith('2036')).toBe(true);
  });

  it('reads every certificate in a bundle', () => {
    const bundle = `${rsa2048Sha256.pem}\n${ecdsaP256.pem}\n${longLivedCa.pem}`;
    expect(parseCertificates(Buffer.from(bundle), 'chain.pem')).toHaveLength(3);
  });

  it('returns nothing for a file that is not a certificate', () => {
    expect(parseCertificates(Buffer.from('hello world'), 'x.pem')).toHaveLength(0);
    expect(
      parseCertificates(Buffer.from('-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----'), 'x.pem'),
    ).toHaveLength(0);
  });
});

describe('scanning a directory', () => {
  it('emits PKI_CERTIFICATE evidence at its own ceiling', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-pki-'));
    await writeFile(join(dir, 'server.pem'), rsa2048Sha256.pem);
    const r = await scanCertificates({
      root: dir,
      systemId: 'edge',
      collectedAt: '2026-08-28T00:00:00.000Z',
    });
    expect(r.certificates).toHaveLength(1);
    expect(r.findings.every((f) => f.evidence.modality === 'PKI_CERTIFICATE')).toBe(true);
    // subject key + issuer signature + digest
    expect(r.findings).toHaveLength(3);
  });

  it('treats a CA certificate as bilateral, because reissuing one moves every relying party', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-pki-ca-'));
    await writeFile(join(dir, 'root.crt'), longLivedCa.pem);
    const r = await scanCertificates({
      root: dir,
      systemId: 'pki',
      collectedAt: '2026-08-28T00:00:00.000Z',
    });
    expect(r.findings.every((f) => f.controlClass === 'PROTOCOL_BILATERAL')).toBe(true);
  });

  it('treats a leaf certificate as SELF', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'assay-pki-leaf-'));
    await writeFile(join(dir, 'leaf.crt'), rsa2048Sha256.pem);
    const r = await scanCertificates({
      root: dir,
      systemId: 'edge',
      collectedAt: '2026-08-28T00:00:00.000Z',
    });
    expect(r.findings.every((f) => f.controlClass === 'SELF')).toBe(true);
  });
});

describe('lifetime against the migration deadline', () => {
  const certs = () => parseCertificates(Buffer.from(longLivedCa.pem), 'ca.pem');

  it('flags a quantum-vulnerable certificate that outlives the deadline', () => {
    const [breach] = lifetimeBreaches(certs(), 2032.0, 'eo-14412@1.0.0');
    expect(breach?.overhangYears).toBeGreaterThan(4);
    expect(breach?.certificate.isCA).toBe(true);
  });

  it('does not flag one that expires before the deadline', () => {
    const short = parseCertificates(Buffer.from(rsa2048Sha256.pem), 'a.pem');
    expect(lifetimeBreaches(short, 2032.0, 'p')).toHaveLength(0);
  });

  it('does not flag a quantum-safe key however long it lives', () => {
    const safe = certs().map((c) => ({
      ...c,
      publicKey: { ...c.publicKey, quantumVulnerable: false },
    }));
    expect(lifetimeBreaches(safe, 2032.0, 'p')).toHaveLength(0);
  });

  it('reports nothing when the pack asserts no deadline', () => {
    expect(lifetimeBreaches(certs(), null, 'nist-ir-8547-draft@0.2.0')).toHaveLength(0);
  });

  it('carries a derivation citing the notAfter and the pack', () => {
    const [breach] = lifetimeBreaches(certs(), 2032.0, 'eo-14412@1.0.0');
    const s = JSON.stringify(breach?.factor);
    expect(s).toContain('2036');
    expect(s).toContain('eo-14412@1.0.0');
    expect(s).toContain('POLICY');
  });
});
