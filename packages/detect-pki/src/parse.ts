import * as x509 from '@peculiar/x509';
import { makeAsset, type CryptoAsset } from '@assay/core';

/**
 * Certificate parsing.
 *
 * A certificate is the strongest evidence Assay can hold (PKI_CERTIFICATE,
 * ceiling 0.99): the algorithm and the key size are not inferred from a call
 * site, they are stated in a structure someone signed. It is also the only
 * modality that carries a hard date of its own - a certificate that is valid
 * past the migration deadline is a dated finding today, before any handshake
 * is ever observed.
 *
 * I9: this reads public keys and metadata. It never touches private keys, and
 * there is no code path here that could.
 */

export interface CertificateFacts {
  readonly fingerprintSha256: string;
  readonly subject: string;
  readonly issuer: string;
  readonly serialNumber: string;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly isCA: boolean;
  readonly selfSigned: boolean;
  readonly subjectAltNames: readonly string[];
  /** The public key in the certificate. */
  readonly publicKey: CryptoAsset;
  /** The algorithm the ISSUER used to sign it. A separate asset on a separate key. */
  readonly signature: CryptoAsset;
  /** The digest inside that signature, where one is named. */
  readonly signatureDigest: CryptoAsset | null;
  readonly source: string;
}

const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** Every certificate in a PEM bundle, or a single DER blob. */
export function parseCertificates(data: Buffer, source: string): CertificateFacts[] {
  const text = data.toString('binary');
  const blocks = text.match(PEM_BLOCK);
  const out: CertificateFacts[] = [];

  if (blocks !== null) {
    for (const block of blocks) {
      const cert = tryParse(() => new x509.X509Certificate(block));
      if (cert) out.push(factsOf(cert, source));
    }
    return out;
  }
  const cert = tryParse(() => new x509.X509Certificate(new Uint8Array(data)));
  if (cert) out.push(factsOf(cert, source));
  return out;
}

function tryParse(f: () => x509.X509Certificate): x509.X509Certificate | null {
  try {
    return f();
  } catch {
    return null;
  }
}

function factsOf(cert: x509.X509Certificate, source: string): CertificateFacts {
  const spki = cert.publicKey;
  const alg = spki.algorithm as unknown as Record<string, unknown>;
  const publicKey = publicKeyAsset(alg, spki.rawData.byteLength);
  const { signature, digest } = signatureAssets(
    cert.signatureAlgorithm as unknown as Record<string, unknown>,
  );

  let isCA = false;
  const bc = cert.getExtension('2.5.29.19');
  if (bc instanceof x509.BasicConstraintsExtension) isCA = bc.ca;

  const sans: string[] = [];
  const san = cert.getExtension('2.5.29.17');
  if (san instanceof x509.SubjectAlternativeNameExtension) {
    for (const name of san.names.items) sans.push(String(name.value));
  }

  return {
    fingerprintSha256: hex(cert.publicKey.rawData),
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    notBefore: cert.notBefore.toISOString(),
    notAfter: cert.notAfter.toISOString(),
    isCA,
    selfSigned: cert.subject === cert.issuer,
    subjectAltNames: sans.sort(),
    publicKey,
    signature,
    signatureDigest: digest,
    source,
  };
}

function publicKeyAsset(alg: Record<string, unknown>, spkiBytes: number): CryptoAsset {
  const name = String(alg['name'] ?? '').toUpperCase();
  const namedCurve = String(
    (alg['namedCurve'] as string | undefined) ??
      ((alg['publicKeyAlgorithm'] as Record<string, unknown> | undefined)?.['namedCurve'] as
        | string
        | undefined) ??
      '',
  );

  if (name.startsWith('RSA')) {
    const modulusLength = Number(alg['modulusLength'] ?? 0);
    return makeAsset(
      'RSA',
      modulusLength > 0 ? { modulusLength } : {},
      // A certificate's key authenticates the holder. Even when the same key
      // is later used for RSA key transport, what the certificate attests is
      // identity, so it lands on the authenticity track. A negotiated
      // handshake is what moves it to confidentiality, and that is Phase 2's
      // network modality, recorded separately.
      'CERTIFICATE_AUTH',
    );
  }
  if (name === 'ECDSA' || name === 'EC') {
    return makeAsset('ECDSA', namedCurve ? { curve: normalizeCurve(namedCurve) } : {}, 'CERTIFICATE_AUTH');
  }
  if (name === 'ED25519') return makeAsset('EdDSA', { curve: 'Ed25519' }, 'CERTIFICATE_AUTH');
  if (name === 'ED448') return makeAsset('EdDSA', { curve: 'Ed448' }, 'CERTIFICATE_AUTH');
  if (name === 'X25519') return makeAsset('X25519', {}, 'KEY_ESTABLISHMENT');
  return makeAsset('UNKNOWN', { algorithm: name || 'unrecognized', spkiBytes }, 'CERTIFICATE_AUTH');
}

function signatureAssets(alg: Record<string, unknown>): {
  signature: CryptoAsset;
  digest: CryptoAsset | null;
} {
  const name = String(alg['name'] ?? '').toUpperCase();
  const hashName = String(
    ((alg['hash'] as Record<string, unknown> | undefined)?.['name'] as string | undefined) ?? '',
  ).toUpperCase();

  const digest =
    hashName === ''
      ? null
      : makeAsset(
          hashName.startsWith('SHA-3') ? 'SHA3' : hashName === 'SHA-1' ? 'SHA1' : hashName === 'MD5' ? 'MD5' : 'SHA2',
          { outputLength: Number(hashName.replace(/\D/g, '')) || 160 },
          'INTEGRITY',
        );

  if (name.startsWith('RSASSA-PSS')) {
    return { signature: makeAsset('RSA', { padding: 'PSS' }, 'CERTIFICATE_AUTH'), digest };
  }
  if (name.startsWith('RSASSA')) {
    return { signature: makeAsset('RSA', { padding: 'PKCS1v15' }, 'CERTIFICATE_AUTH'), digest };
  }
  if (name === 'ECDSA') return { signature: makeAsset('ECDSA', {}, 'CERTIFICATE_AUTH'), digest };
  if (name.startsWith('ED')) {
    return { signature: makeAsset('EdDSA', {}, 'CERTIFICATE_AUTH'), digest: null };
  }
  return { signature: makeAsset('UNKNOWN', { algorithm: name || 'unrecognized' }, 'CERTIFICATE_AUTH'), digest };
}

function normalizeCurve(c: string): string {
  const n = c.toUpperCase().replace('SECP', 'P-').replace('R1', '');
  return /^P-(256|384|521)$/.test(n) ? n : c;
}

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 64);
}
