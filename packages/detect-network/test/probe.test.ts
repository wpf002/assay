import { webcrypto } from 'node:crypto';
import { createServer as createTlsServer, type Server as TlsServer } from 'node:tls';
import { createServer as createTcpServer, type Server as TcpServer } from 'node:net';
import * as x509 from '@peculiar/x509';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authorize, generateGrantKeypair, signGrant, verifyGrant } from '@assay/scope';
import {
  SSH_MSG_KEXINIT,
  parseKexInit,
  probeSsh,
  probeTarget,
  probeTls,
  sshFindings,
  tlsFindings,
} from '../src/index.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const keys = generateGrantKeypair();
const NOW = new Date('2026-08-28T12:00:00.000Z');
const clock = (): Date => NOW;

function grantFor(port: number) {
  return verifyGrant(
    signGrant(
      {
        grantId: 'test-grant',
        issuedBy: 'test',
        targets: ['127.0.0.1'],
        ports: [port],
        notBefore: '2026-08-01T00:00:00.000Z',
        notAfter: '2026-09-01T00:00:00.000Z',
        purpose: 'unit test',
      },
      keys.privateKeyPem,
    ),
    keys.publicKeyPem,
  );
}

const OPTS = { systemId: 'edge', collectedAt: '2026-08-28T00:00:00.000Z' };

/* ---------------------------------------------------------------- TLS server */

let tlsServer: TlsServer;
let tlsPort = 0;

beforeAll(async () => {
  const pair = (await webcrypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned(
    {
      serialNumber: '01',
      name: 'CN=localhost',
      notBefore: new Date('2026-01-01T00:00:00Z'),
      notAfter: new Date('2030-01-01T00:00:00Z'),
      signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      keys: pair,
    },
    webcrypto as unknown as Crypto,
  );
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', pair.privateKey);
  const keyPem = `-----BEGIN PRIVATE KEY-----\n${(Buffer.from(pkcs8)
    .toString('base64')
    .match(/.{1,64}/g) ?? []).join('\n')}\n-----END PRIVATE KEY-----`;

  tlsServer = createTlsServer({ key: keyPem, cert: cert.toString('pem') }, (s) => {
    s.on('error', () => undefined);
    s.end();
  });
  tlsServer.on('tlsClientError', () => undefined);
  await new Promise<void>((r) => tlsServer.listen(0, '127.0.0.1', r));
  tlsPort = (tlsServer.address() as { port: number }).port;
}, 60_000);

afterAll(() => {
  tlsServer?.close();
});

describe('TLS probing', () => {
  it('records what was SELECTED and what was OFFERED as separate facts', async () => {
    const target = authorize(grantFor(tlsPort), '127.0.0.1', tlsPort, NOW);
    const r = await probeTls(target, { clock, timeoutMs: 4000 });

    expect(r.reachable).toBe(true);
    expect(r.selected?.protocol).toBeTruthy();
    expect(r.offered.length).toBeGreaterThan(5);
    // Both are recorded even when they agree; a scanner that keeps only the
    // negotiated suite cannot distinguish "still accepts TLS 1.0" from
    // "negotiates TLS 1.0".
    expect(r.selected?.requested).toBe('unconstrained');
    expect(r.offered.some((o) => o.requested.startsWith('version:'))).toBe(true);
    expect(r.offered.some((o) => o.requested.startsWith('group:'))).toBe(true);
  }, 60_000);

  it('captures the peer chain for the PKI parser rather than parsing it here', async () => {
    const target = authorize(grantFor(tlsPort), '127.0.0.1', tlsPort, NOW);
    const r = await probeTls(target, { clock, timeoutMs: 4000 });
    expect(r.peerChainPem.length).toBeGreaterThan(0);
    expect(r.peerChainPem[0]).toContain('BEGIN CERTIFICATE');
  }, 60_000);

  it('does not fail the whole probe when the local client cannot offer a group', async () => {
    const target = authorize(grantFor(tlsPort), '127.0.0.1', tlsPort, NOW);
    const r = await probeTls(target, { clock, timeoutMs: 4000, groups: ['not-a-real-group'] });
    const failed = r.offered.find((o) => o.requested === 'group:not-a-real-group');
    expect(failed?.ok).toBe(false);
    // Attributed to us, not to the endpoint.
    expect(failed?.error).toBeTruthy();
    expect(r.reachable).toBe(true);
  }, 60_000);

  it('reports an unreachable endpoint without throwing', async () => {
    const port = 1;
    const target = authorize(grantFor(port), '127.0.0.1', port, NOW);
    const r = await probeTls(target, { clock, timeoutMs: 1500 });
    expect(r.reachable).toBe(false);
    expect(r.offered).toHaveLength(0);
    expect(r.probeCount).toBe(1);
  }, 60_000);

  it('turns a handshake into NETWORK_ACTIVE evidence on the bilateral track', async () => {
    const target = authorize(grantFor(tlsPort), '127.0.0.1', tlsPort, NOW);
    const r = await probeTls(target, { clock, timeoutMs: 4000 });
    const findings = tlsFindings(r, OPTS);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.evidence.modality === 'NETWORK_ACTIVE')).toBe(true);
    expect(findings.every((f) => f.controlClass === 'PROTOCOL_BILATERAL')).toBe(true);
    expect(findings.some((f) => f.evidence.raw.startsWith('SELECTED'))).toBe(true);
    expect(findings.every((f) => f.evidence.raw.includes('grant=test-grant'))).toBe(true);
  }, 60_000);

  it('records the negotiated group as a key-establishment asset', async () => {
    const target = authorize(grantFor(tlsPort), '127.0.0.1', tlsPort, NOW);
    const findings = tlsFindings(await probeTls(target, { clock, timeoutMs: 4000 }), OPTS);
    const kex = findings.filter((f) => f.asset.purpose === 'KEY_ESTABLISHMENT');
    expect(kex.length).toBeGreaterThan(0);
  }, 60_000);
});

/* ---------------------------------------------------------------- SSH server */

function kexInitPacket(lists: string[]): Buffer {
  const payloadParts: Buffer[] = [Buffer.from([SSH_MSG_KEXINIT]), Buffer.alloc(16)];
  for (const list of lists) {
    const b = Buffer.from(list, 'ascii');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.byteLength);
    payloadParts.push(len, b);
  }
  payloadParts.push(Buffer.from([0]), Buffer.alloc(4));
  const payload = Buffer.concat(payloadParts);
  const paddingLength = 8 - ((payload.byteLength + 5) % 8);
  const padding = Buffer.alloc(paddingLength);
  const header = Buffer.alloc(5);
  header.writeUInt32BE(payload.byteLength + 1 + paddingLength, 0);
  header.writeUInt8(paddingLength, 4);
  return Buffer.concat([header, payload, padding]);
}

const LISTS = [
  'curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha1',
  'ssh-ed25519,rsa-sha2-512,ssh-rsa',
  'aes128-ctr,3des-cbc',
  'aes128-ctr,3des-cbc',
  'hmac-sha2-256,hmac-sha1',
  'hmac-sha2-256,hmac-sha1',
  'none',
  'none',
  '',
  '',
];

describe('SSH KEXINIT parsing', () => {
  it('reads every name-list from a well-formed packet', () => {
    const k = parseKexInit(kexInitPacket(LISTS));
    expect(k?.kexAlgorithms).toContain('curve25519-sha256');
    expect(k?.hostKeyAlgorithms).toContain('ssh-ed25519');
    expect(k?.encryptionServerToClient).toContain('3des-cbc');
    expect(k?.macServerToClient).toContain('hmac-sha1');
  });

  it('rejects a packet whose declared lengths run past the buffer', () => {
    const p = kexInitPacket(LISTS);
    p.writeUInt32BE(6, 22); // overstate a name-list length near the end
    const truncated = p.subarray(0, 40);
    expect(parseKexInit(truncated)).toBeNull();
  });

  it('rejects an absurd packet length rather than allocating on it', () => {
    const p = Buffer.alloc(64);
    p.writeUInt32BE(0xffffffff, 0);
    expect(parseKexInit(p)).toBeNull();
  });

  it('rejects a packet that is not KEXINIT', () => {
    const p = kexInitPacket(LISTS);
    p.writeUInt8(21, 5);
    expect(parseKexInit(p)).toBeNull();
  });

  it('rejects a runt', () => {
    expect(parseKexInit(Buffer.alloc(3))).toBeNull();
  });
});

describe('SSH probing against a server', () => {
  let sshServer: TcpServer;
  let sshPort = 0;

  beforeAll(async () => {
    sshServer = createTcpServer((socket) => {
      // The prober closes as soon as it has the KEXINIT, so the server sees a
      // half-written stream. Swallow it here rather than letting it surface as
      // an unhandled exception in the runner.
      socket.on('error', () => undefined);
      socket.write('SSH-2.0-OpenSSH_9.6\r\n');
      socket.write(kexInitPacket(LISTS));
    });
    await new Promise<void>((r) => sshServer.listen(0, '127.0.0.1', r));
    sshPort = (sshServer.address() as { port: number }).port;
  });

  afterAll(() => {
    sshServer?.close();
  });

  it('reads the banner and the full advertised algorithm set in one connection', async () => {
    const target = authorize(grantFor(sshPort), '127.0.0.1', sshPort, NOW);
    const r = await probeSsh(target, { clock, timeoutMs: 3000 });
    expect(r.reachable).toBe(true);
    expect(r.banner).toBe('SSH-2.0-OpenSSH_9.6');
    expect(r.kexInit?.kexAlgorithms).toContain('diffie-hellman-group14-sha1');
  }, 30_000);

  it('turns the advertised set into evidence on the right tracks', async () => {
    const target = authorize(grantFor(sshPort), '127.0.0.1', sshPort, NOW);
    const findings = sshFindings(await probeSsh(target, { clock, timeoutMs: 3000 }), OPTS);

    const kex = findings.filter((f) => f.asset.purpose === 'KEY_ESTABLISHMENT');
    const sig = findings.filter((f) => f.asset.purpose === 'DIGITAL_SIGNATURE');
    expect(kex.some((f) => f.asset.primitive === 'X25519')).toBe(true);
    expect(kex.some((f) => f.asset.primitive === 'DH')).toBe(true);
    expect(sig.some((f) => f.asset.primitive === 'EdDSA')).toBe(true);
    expect(findings.some((f) => f.asset.primitive === '3DES')).toBe(true);
    expect(findings.every((f) => f.evidence.modality === 'NETWORK_ACTIVE')).toBe(true);
  }, 30_000);

  it('routes port 22 to SSH and everything else to TLS', async () => {
    const target = authorize(grantFor(sshPort), '127.0.0.1', sshPort, NOW);
    const report = await probeTarget(target, { ...OPTS, timeoutMs: 3000, clock });
    // This fixture is not on 22, so it is probed as TLS and simply fails.
    expect(report.ssh).toBeNull();
    expect(report.tls?.reachable).toBe(false);
  }, 30_000);
});
