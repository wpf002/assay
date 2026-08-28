import { connect, type ConnectionOptions, type TLSSocket } from 'node:tls';
import type { AuthorizedTarget } from '@assay/scope';

/**
 * TLS capability enumeration by repeated handshake.
 *
 * Two facts, stored separately, because they answer different questions:
 *   OFFERED  - what the endpoint agreed to when we asked for it. Capability.
 *   SELECTED - what it chose when we offered everything. Deployment reality.
 *
 * A server that still accepts TLS 1.0 but negotiates 1.3 with a modern client
 * is not the same finding as one that negotiates 1.0, and a scanner that
 * records only the negotiated suite cannot tell them apart. Assay keeps both
 * and lets `correlate` decide which answers the question being asked.
 *
 * The target is an AuthorizedTarget: it cannot be constructed without a
 * verified, in-window scope grant, so an out-of-scope probe does not compile.
 */

export interface HandshakeOutcome {
  readonly requested: string;
  readonly ok: boolean;
  readonly protocol: string | null;
  readonly cipher: string | null;
  /** Negotiated group / ephemeral key info, e.g. { type: 'ECDH', name: 'X25519', size: 253 }. */
  readonly ephemeral: { type?: string; name?: string; size?: number } | null;
  readonly error: string | null;
}

export interface TlsProbeResult {
  readonly host: string;
  readonly port: number;
  readonly grantId: string;
  readonly reachable: boolean;
  /** The handshake with no constraints. What this endpoint actually deploys. */
  readonly selected: HandshakeOutcome | null;
  /** One entry per constrained handshake. What the endpoint is willing to do. */
  readonly offered: readonly HandshakeOutcome[];
  /** PEM chain as presented. Fed to @assay/detect-pki rather than parsed here. */
  readonly peerChainPem: readonly string[];
  readonly probeCount: number;
  readonly startedAt: string;
  readonly finishedAt: string;
}

export interface TlsProbeOptions {
  readonly timeoutMs?: number;
  /** ISO timestamps are supplied so a probe record is reproducible in tests. */
  readonly clock?: () => Date;
  readonly servername?: string;
  readonly versions?: readonly string[];
  readonly cipherGroups?: readonly { readonly label: string; readonly ciphers: string }[];
  readonly groups?: readonly string[];
}

/** TLS versions worth asking about. 1.0 and 1.1 are findings if accepted. */
export const DEFAULT_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const;

/**
 * One representative suite per key-exchange family. The point is not to
 * enumerate every suite - it is to learn which key establishment the endpoint
 * will accept, because that is what lands on the confidentiality track.
 */
export const DEFAULT_CIPHER_GROUPS = [
  { label: 'ECDHE+AESGCM', ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384' },
  { label: 'ECDHE+CHACHA20', ciphers: 'ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305' },
  { label: 'DHE', ciphers: 'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA' },
  { label: 'RSA-key-transport', ciphers: 'AES256-GCM-SHA384:AES128-SHA' },
  { label: 'CBC-SHA1', ciphers: 'ECDHE-RSA-AES128-SHA:AES128-SHA' },
  { label: '3DES', ciphers: 'DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA' },
] as const;

/**
 * Named groups, including the hybrid PQ ones. Detecting that an endpoint
 * already negotiates X25519MLKEM768 is the only positive finding in this whole
 * tool, and it is worth reporting for the same reason the negatives are.
 */
export const DEFAULT_GROUPS = [
  'X25519MLKEM768',
  'X25519',
  'P-256',
  'P-384',
  'P-521',
  'ffdhe2048',
] as const;

export async function probeTls(
  target: AuthorizedTarget,
  opts: TlsProbeOptions = {},
): Promise<TlsProbeResult> {
  const clock = opts.clock ?? (() => new Date());
  const startedAt = clock().toISOString();
  const timeoutMs = opts.timeoutMs ?? 5000;
  const servername = opts.servername ?? (isIpLiteral(target.host) ? undefined : target.host);

  const base: ConnectionOptions = {
    host: target.host,
    port: target.port,
    // Certificate validity is not what is being measured. The chain is
    // captured and handed to detect-pki; refusing to complete a handshake with
    // an expired certificate would hide the very inventory we came for.
    rejectUnauthorized: false,
    ...(servername === undefined ? {} : { servername }),
  };

  const selected = await handshake('unconstrained', base, timeoutMs);
  const offered: HandshakeOutcome[] = [];

  if (selected.ok) {
    for (const version of opts.versions ?? DEFAULT_VERSIONS) {
      offered.push(
        await handshake(`version:${version}`, {
          ...base,
          minVersion: version as ConnectionOptions['minVersion'],
          maxVersion: version as ConnectionOptions['maxVersion'],
          // OpenSSL refuses legacy versions at the default security level.
          // Lowering it here is what makes "would you still accept TLS 1.0"
          // an answerable question rather than a local policy artefact.
          ciphers: 'ALL:@SECLEVEL=0',
        }, timeoutMs),
      );
    }
    for (const group of opts.cipherGroups ?? DEFAULT_CIPHER_GROUPS) {
      offered.push(
        await handshake(`ciphers:${group.label}`, {
          ...base,
          maxVersion: 'TLSv1.2',
          ciphers: `${group.ciphers}:@SECLEVEL=0`,
        }, timeoutMs),
      );
    }
    for (const g of opts.groups ?? DEFAULT_GROUPS) {
      offered.push(await handshake(`group:${g}`, { ...base, ecdhCurve: g }, timeoutMs));
    }
  }

  return {
    host: target.host,
    port: target.port,
    grantId: target.grantId,
    reachable: selected.ok,
    selected: selected.ok ? selected : null,
    offered,
    peerChainPem: selected.ok ? selected.chainPem : [],
    probeCount: 1 + offered.length,
    startedAt,
    finishedAt: clock().toISOString(),
  };
}

interface InternalOutcome extends HandshakeOutcome {
  readonly chainPem: readonly string[];
}

function handshake(
  requested: string,
  options: ConnectionOptions,
  timeoutMs: number,
): Promise<InternalOutcome> {
  return new Promise((resolve) => {
    let socket: TLSSocket;
    let settled = false;
    const done = (o: InternalOutcome): void => {
      if (settled) return;
      settled = true;
      try {
        // Close cleanly rather than resetting. This tool runs inside someone
        // else's network under a grant, and a probe that fills their logs with
        // connection resets is a probe that gets the grant revoked.
        socket.end();
        socket.destroy();
      } catch {
        /* already gone */
      }
      resolve(o);
    };

    const fail = (error: string): void =>
      done({ requested, ok: false, protocol: null, cipher: null, ephemeral: null, error, chainPem: [] });

    try {
      socket = connect(options);
    } catch (e) {
      // An unsupported group or cipher string throws synchronously. That is a
      // fact about this client, not about the endpoint, and is recorded as such.
      fail(`local: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }

    socket.setTimeout(timeoutMs, () => fail('timeout'));
    socket.once('error', (e: Error) => fail(e.message));
    socket.once('secureConnect', () => {
      const cipher = socket.getCipher();
      done({
        requested,
        ok: true,
        protocol: socket.getProtocol(),
        cipher: cipher?.standardName ?? cipher?.name ?? null,
        ephemeral: socket.getEphemeralKeyInfo() ?? null,
        error: null,
        chainPem: chainOf(socket),
      });
    });
  });
}

function chainOf(socket: TLSSocket): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let cert = socket.getPeerCertificate(true) as
    | (ReturnType<TLSSocket['getPeerCertificate']> & { issuerCertificate?: unknown; raw?: Buffer })
    | null;

  while (cert && cert.raw && !seen.has(cert.raw.toString('base64'))) {
    const b64 = cert.raw.toString('base64');
    seen.add(b64);
    out.push(
      `-----BEGIN CERTIFICATE-----\n${(b64.match(/.{1,64}/g) ?? []).join('\n')}\n-----END CERTIFICATE-----`,
    );
    const next = cert.issuerCertificate as typeof cert;
    if (next === cert) break;
    cert = next;
  }
  return out;
}

function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}
