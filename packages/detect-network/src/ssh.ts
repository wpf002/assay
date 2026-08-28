import { connect, type Socket } from 'node:net';
import type { AuthorizedTarget } from '@assay/scope';

/**
 * SSH algorithm enumeration.
 *
 * SSH is easier to inventory than TLS and more often forgotten. The server
 * announces its entire supported set in one unencrypted KEXINIT packet before
 * any negotiation happens, so a single connection yields the complete
 * capability list - no repeated handshakes, no guessing.
 *
 * We send a version banner (the protocol requires it) and read the server's
 * KEXINIT. We never send our own KEXINIT and never begin key exchange, so no
 * session is established and nothing is authenticated.
 */

export interface SshKexInit {
  readonly kexAlgorithms: readonly string[];
  readonly hostKeyAlgorithms: readonly string[];
  readonly encryptionClientToServer: readonly string[];
  readonly encryptionServerToClient: readonly string[];
  readonly macClientToServer: readonly string[];
  readonly macServerToClient: readonly string[];
  readonly compressionClientToServer: readonly string[];
  readonly compressionServerToClient: readonly string[];
}

export interface SshProbeResult {
  readonly host: string;
  readonly port: number;
  readonly grantId: string;
  readonly reachable: boolean;
  readonly banner: string | null;
  readonly kexInit: SshKexInit | null;
  readonly error: string | null;
  readonly startedAt: string;
  readonly finishedAt: string;
}

export const SSH_MSG_KEXINIT = 20;

/**
 * Parse a binary SSH packet containing SSH_MSG_KEXINIT.
 *
 * Exported and pure so the wire format can be tested without a server. Every
 * length here comes off the wire, so each one is bounds-checked: a malformed
 * or hostile packet must return null, never read past the buffer.
 */
export function parseKexInit(packet: Buffer): SshKexInit | null {
  if (packet.byteLength < 6) return null;
  const packetLength = packet.readUInt32BE(0);
  const paddingLength = packet.readUInt8(4);
  if (packetLength < 2 || packetLength > 1_000_000) return null;
  const payloadEnd = 4 + packetLength - paddingLength;
  if (payloadEnd > packet.byteLength || payloadEnd <= 5) return null;

  let offset = 5;
  if (packet.readUInt8(offset) !== SSH_MSG_KEXINIT) return null;
  offset += 1 + 16; // message id + cookie
  if (offset > payloadEnd) return null;

  const lists: string[][] = [];
  for (let i = 0; i < 10; i++) {
    if (offset + 4 > payloadEnd) return null;
    const len = packet.readUInt32BE(offset);
    offset += 4;
    if (len > 100_000 || offset + len > payloadEnd) return null;
    const value = packet.toString('ascii', offset, offset + len);
    offset += len;
    lists.push(value === '' ? [] : value.split(','));
  }

  return {
    kexAlgorithms: lists[0] as string[],
    hostKeyAlgorithms: lists[1] as string[],
    encryptionClientToServer: lists[2] as string[],
    encryptionServerToClient: lists[3] as string[],
    macClientToServer: lists[4] as string[],
    macServerToClient: lists[5] as string[],
    compressionClientToServer: lists[6] as string[],
    compressionServerToClient: lists[7] as string[],
  };
}

export interface SshProbeOptions {
  readonly timeoutMs?: number;
  readonly clock?: () => Date;
  readonly clientBanner?: string;
}

export async function probeSsh(
  target: AuthorizedTarget,
  opts: SshProbeOptions = {},
): Promise<SshProbeResult> {
  const clock = opts.clock ?? (() => new Date());
  const startedAt = clock().toISOString();
  const timeoutMs = opts.timeoutMs ?? 5000;
  const clientBanner = opts.clientBanner ?? 'SSH-2.0-assay_0.1.0';

  const result = await new Promise<{
    banner: string | null;
    kexInit: SshKexInit | null;
    error: string | null;
  }>((resolve) => {
    let socket: Socket;
    let settled = false;
    let buffer = Buffer.alloc(0);
    let banner: string | null = null;
    let bannerSent = false;

    const done = (r: { banner: string | null; kexInit: SshKexInit | null; error: string | null }): void => {
      if (settled) return;
      settled = true;
      try {
        socket.end();
        socket.destroy();
      } catch {
        /* already gone */
      }
      resolve(r);
    };

    try {
      socket = connect({ host: target.host, port: target.port });
    } catch (e) {
      resolve({ banner: null, kexInit: null, error: e instanceof Error ? e.message : String(e) });
      return;
    }

    socket.setTimeout(timeoutMs, () => done({ banner, kexInit: null, error: 'timeout' }));
    socket.once('error', (e: Error) => done({ banner, kexInit: null, error: e.message }));
    socket.once('close', () => done({ banner, kexInit: null, error: banner === null ? 'closed before banner' : 'closed before KEXINIT' }));

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength > 512_000) {
        done({ banner, kexInit: null, error: 'server sent more than 512KB before KEXINIT' });
        return;
      }

      if (banner === null) {
        // The banner may be preceded by arbitrary lines; the SSH one starts
        // with SSH-. Scan for it rather than assuming it is first.
        const idx = buffer.indexOf('\r\n');
        if (idx < 0) return;
        const line = buffer.toString('ascii', 0, idx);
        if (!line.startsWith('SSH-')) {
          buffer = buffer.subarray(idx + 2);
          return;
        }
        banner = line;
        buffer = buffer.subarray(idx + 2);
        if (!bannerSent) {
          bannerSent = true;
          socket.write(`${clientBanner}\r\n`);
        }
      }

      if (buffer.byteLength < 4) return;
      const packetLength = buffer.readUInt32BE(0);
      if (buffer.byteLength < 4 + packetLength) return;
      done({ banner, kexInit: parseKexInit(buffer), error: null });
    });
  });

  return {
    host: target.host,
    port: target.port,
    grantId: target.grantId,
    reachable: result.kexInit !== null,
    banner: result.banner,
    kexInit: result.kexInit,
    error: result.error,
    startedAt,
    finishedAt: clock().toISOString(),
  };
}
