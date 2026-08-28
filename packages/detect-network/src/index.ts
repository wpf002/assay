import {
  makeAsset,
  sshAlgorithm,
  tlsCipherSuite,
  normalizeCurve,
  type ControlClass,
  type Evidence,
  type Finding,
} from '@assay/core';
import type { AuthorizedTarget } from '@assay/scope';
import { probeTls, type HandshakeOutcome, type TlsProbeResult } from './tls.js';
import { probeSsh, type SshProbeResult } from './ssh.js';

export * from './tls.js';
export * from './ssh.js';

export const COLLECTOR_VERSION = 'detect-network/0.1.0';

/**
 * Network evidence.
 *
 * NETWORK_ACTIVE sits at 0.98 - just under a parsed certificate - because a
 * completed handshake is not an inference. But it answers only "what is
 * deployed"; it is silent on "what is possible", which is why the capability
 * probes are recorded as separate evidence from the selected one, and why
 * `correlate` keeps source and network answers distinct rather than picking a
 * winner.
 *
 * Anything reachable over a protocol both ends must agree on is
 * PROTOCOL_BILATERAL. You do not get to migrate a TLS endpoint alone.
 */

export interface NetworkFindingOptions {
  readonly systemId: string;
  readonly collectedAt: string;
  readonly controlClass?: ControlClass;
}

export function tlsFindings(result: TlsProbeResult, opts: NetworkFindingOptions): Finding[] {
  const controlClass = opts.controlClass ?? 'PROTOCOL_BILATERAL';
  const out: Finding[] = [];
  const where = `${result.host}:${result.port}`;

  const push = (
    outcome: HandshakeOutcome,
    kind: 'SELECTED' | 'OFFERED',
    detail: string,
    assets: readonly Finding['asset'][],
  ): void => {
    for (const asset of assets) {
      out.push({
        asset,
        systemId: opts.systemId,
        controlClass,
        evidence: {
          modality: 'NETWORK_ACTIVE',
          locator: `${where}#${outcome.requested}`,
          raw:
            `${kind} ${detail} :: protocol=${outcome.protocol ?? '-'} ` +
            `cipher=${outcome.cipher ?? '-'} ` +
            `group=${outcome.ephemeral?.name ?? '-'}(${outcome.ephemeral?.size ?? '-'}) ` +
            `grant=${result.grantId}`,
          collectedAt: opts.collectedAt,
          collectorVersion: COLLECTOR_VERSION,
          occurrence: { location: where, symbol: outcome.requested },
        },
      } satisfies Finding);
    }
  };

  if (result.selected) push(result.selected, 'SELECTED', 'negotiated', assetsOf(result.selected));

  for (const outcome of result.offered) {
    // A refused handshake is a fact too, but it is the ABSENCE of a capability
    // and there is no asset to attach it to. It stays in the probe record.
    if (!outcome.ok) continue;
    push(outcome, 'OFFERED', `accepted when asked for ${outcome.requested}`, assetsOf(outcome));
  }
  return out;
}

function assetsOf(outcome: HandshakeOutcome): Finding['asset'][] {
  const out: Finding['asset'][] = [];
  if (outcome.cipher !== null) {
    for (const spec of tlsCipherSuite(outcome.cipher)) {
      out.push(makeAsset(spec.primitive, spec.parameters, spec.purpose ?? 'DATA_ENCRYPTION'));
    }
  }
  // The negotiated group is the single most decisive fact in a TLS handshake
  // for post-quantum purposes: it names the key establishment that a recorded
  // session would be decrypted through.
  const name = outcome.ephemeral?.name;
  if (name !== undefined && name !== '') {
    out.push(groupAsset(name, outcome.ephemeral?.size));
  }
  return dedupe(out);
}

function groupAsset(name: string, size?: number): Finding['asset'] {
  const n = name.toUpperCase();
  if (n.includes('MLKEM') || n.includes('ML-KEM')) {
    // A hybrid group is genuinely two key exchanges. Recording it as ML-KEM is
    // right for the migration question - this endpoint is already safe - and
    // the classical half is named in the parameters, not lost.
    return makeAsset('ML-KEM', { group: name, hybrid: 'true' }, 'KEY_ESTABLISHMENT');
  }
  if (n === 'X25519') return makeAsset('X25519', {}, 'KEY_ESTABLISHMENT');
  if (n === 'X448') return makeAsset('X448', {}, 'KEY_ESTABLISHMENT');
  if (n.startsWith('FFDHE') || n.startsWith('DH')) {
    return makeAsset(
      'DH',
      { group: name, ...(size === undefined ? {} : { primeLength: size }) },
      'KEY_ESTABLISHMENT',
    );
  }
  const curve = normalizeCurve(name);
  return makeAsset('ECDH', curve === null ? { group: name } : { curve }, 'KEY_ESTABLISHMENT');
}

export function sshFindings(result: SshProbeResult, opts: NetworkFindingOptions): Finding[] {
  const controlClass = opts.controlClass ?? 'PROTOCOL_BILATERAL';
  if (result.kexInit === null) return [];
  const where = `${result.host}:${result.port}`;
  const out: Finding[] = [];

  const lists: readonly [readonly string[], string][] = [
    [result.kexInit.kexAlgorithms, 'kex_algorithms'],
    [result.kexInit.hostKeyAlgorithms, 'server_host_key_algorithms'],
    [result.kexInit.encryptionServerToClient, 'encryption_algorithms_s2c'],
    [result.kexInit.macServerToClient, 'mac_algorithms_s2c'],
  ];

  for (const [names, field] of lists) {
    for (const name of names) {
      const spec = sshAlgorithm(name);
      if (spec === null) continue;
      out.push({
        asset: makeAsset(spec.primitive, spec.parameters, spec.purpose ?? 'KEY_ESTABLISHMENT'),
        systemId: opts.systemId,
        controlClass,
        evidence: {
          modality: 'NETWORK_ACTIVE',
          locator: `${where}#${field}`,
          raw: `OFFERED ${field} entry "${name}" :: banner=${result.banner ?? '-'} grant=${result.grantId}`,
          collectedAt: opts.collectedAt,
          collectorVersion: COLLECTOR_VERSION,
          occurrence: { location: where, symbol: name },
        },
      } satisfies Finding);
    }
  }
  return out;
}

/* ------------------------------------------------------------- orchestration */

export interface ProbeOptions extends NetworkFindingOptions {
  readonly timeoutMs?: number;
  readonly clock?: () => Date;
}

export interface ProbeReport {
  readonly findings: readonly Finding[];
  readonly tls: TlsProbeResult | null;
  readonly ssh: SshProbeResult | null;
  /** PEM chain for @assay/detect-pki, so certificate facts come from one parser. */
  readonly peerChainPem: readonly string[];
}

/**
 * Probe one authorized target. The protocol is chosen by port rather than
 * attempted blindly: speaking TLS at an SSH daemon is noise in someone's log
 * and tells us nothing.
 */
export async function probeTarget(
  target: AuthorizedTarget,
  opts: ProbeOptions,
): Promise<ProbeReport> {
  const common = {
    ...(opts.timeoutMs === undefined ? {} : { timeoutMs: opts.timeoutMs }),
    ...(opts.clock === undefined ? {} : { clock: opts.clock }),
  };

  if (target.port === 22) {
    const ssh = await probeSsh(target, common);
    return { findings: sshFindings(ssh, opts), tls: null, ssh, peerChainPem: [] };
  }
  const tls = await probeTls(target, common);
  return { findings: tlsFindings(tls, opts), tls, ssh: null, peerChainPem: tls.peerChainPem };
}

function dedupe(assets: readonly Finding['asset'][]): Finding['asset'][] {
  const seen = new Set<string>();
  const out: Finding['asset'][] = [];
  for (const a of assets) {
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    out.push(a);
  }
  return out;
}

export function evidenceLocators(findings: readonly Finding[]): readonly Evidence['locator'][] {
  return findings.map((f) => f.evidence.locator);
}
