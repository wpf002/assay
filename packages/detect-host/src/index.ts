import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  cipherFromName,
  hashFromName,
  makeAsset,
  normalizeCurve,
  signatureFromName,
  sshAlgorithm,
  tlsCipherSuite,
  type AlgoSpec,
  type ControlClass,
  type CryptoAsset,
  type Finding,
} from '@assay/core';
import {
  HostInventorySchema,
  type Host,
  type HostConfig,
  type HostInventory,
  type HostKeyFile,
} from './types.js';

export * from './types.js';
export * from './adapters.js';

export const COLLECTOR_VERSION = 'detect-host/0.1.0';

/**
 * What is actually running on the machine.
 *
 * Every other modality in this tool carries a caveat that reduces to "we were
 * not standing on the host". A config file in a repository may be a template.
 * A dependency shows what the code could do. A certificate in a tree is not
 * what the endpoint presents. This detector answers all three, which is why
 * HOST_AGENT sits at a 0.9 ceiling and in DEPLOYMENT_MODALITIES: it corroborates
 * a source finding rather than repeating it, so under I1 the two stack across
 * independent groups instead of collapsing into one.
 *
 * Assay ships no agent and this module collects nothing. It reads an export
 * from the tool the customer already runs. That is deliberate and permanent: an
 * agent would need root on every host in a regulated estate, and I8 forbids
 * ambient authority of that kind. The adapters translate three common shapes.
 */

/* ---------------------------------------------------------------- packages */

/**
 * A library being installed is not evidence that it is used, so this is
 * deliberately NOT emitted as a finding.
 *
 * Doing so would be the DEPENDENCY mistake with a better ceiling attached: an
 * OpenSSL package on a box says the box can do RSA, exactly as a lockfile entry
 * says a service can. The list is still worth keeping, because a version below
 * a known post-quantum release is a hard migration blocker no config change can
 * work around, so it comes back as a note rather than as a work item.
 */
export interface PackageNote {
  readonly host: string;
  readonly name: string;
  readonly version: string;
  readonly why: string;
}

/** Libraries whose version bounds what the host can negotiate at all. */
const BOUNDING: Readonly<Record<string, { minPq: string; note: string }>> = {
  openssl: { minPq: '3.5', note: 'ML-KEM and ML-DSA land in OpenSSL 3.5' },
  gnutls: { minPq: '3.8.4', note: 'no ML-KEM before 3.8.4' },
  libssh2: { minPq: '1.11.1', note: 'no hybrid key exchange before 1.11.1' },
  openssh: { minPq: '9.0', note: 'sntrup761x25519 hybrid KEX lands in 9.0' },
  nss: { minPq: '3.108', note: 'no ML-KEM before 3.108' },
};

/**
 * Numeric-segment comparison, which is all a package version needs here.
 *
 * A segment that will not parse counts as below the threshold: "3.5.0-beta" is
 * not 3.5, and guessing in the other direction would clear a blocker that is
 * still there.
 */
export function versionBelow(have: string, want: string): boolean {
  const a = have.split(/[.\-+_~]/);
  const b = want.split(/[.\-+_~]/);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = Number.parseInt(a[i] ?? '', 10);
    const y = Number.parseInt(b[i] ?? '', 10);
    if (Number.isNaN(y)) return false;
    if (Number.isNaN(x)) return true;
    if (x !== y) return x < y;
  }
  return false;
}

export function packageNotes(host: Host): PackageNote[] {
  const out: PackageNote[] = [];
  for (const p of [...host.packages].sort((a, b) => cmp(a.name, b.name))) {
    const bound = BOUNDING[p.name.toLowerCase()];
    if (bound === undefined || p.version === '') continue;
    if (!versionBelow(p.version, bound.minPq)) continue;
    out.push({
      host: host.hostId,
      name: p.name,
      version: p.version,
      why: `${p.name} ${p.version} cannot negotiate post-quantum: ${bound.note}`,
    });
  }
  return out;
}

/* ----------------------------------------------------------------- configs */

type Kind = 'tls-suites' | 'ssh-algorithms' | 'ciphers' | 'signatures' | 'macs' | 'groups';

/**
 * Directives worth reading, and how to read each one's values.
 *
 * Keyed on the directive rather than the file: the same directive appears in
 * several files, and the path is evidence rather than identity.
 */
const DIRECTIVES: Readonly<Record<string, Kind>> = {
  ciphers: 'ssh-algorithms',
  macs: 'macs',
  kexalgorithms: 'ssh-algorithms',
  hostkeyalgorithms: 'ssh-algorithms',
  pubkeyacceptedalgorithms: 'ssh-algorithms',
  pubkeyacceptedkeytypes: 'ssh-algorithms',
  casignaturealgorithms: 'ssh-algorithms',
  hostbasedacceptedalgorithms: 'ssh-algorithms',
  ssl_ciphers: 'tls-suites',
  ssl_cipher: 'tls-suites',
  sslciphersuite: 'tls-suites',
  ssl_protocols: 'tls-suites',
  ciphersuites: 'tls-suites',
  ssl_ecdh_curve: 'groups',
  curves: 'groups',
  groups: 'groups',
  signaturealgorithms: 'signatures',
  cipher: 'ciphers',
  auth: 'signatures',
};

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Split a directive's value into tokens.
 *
 * A leading `!` or `-` in an OpenSSL cipher string means "remove this", so the
 * token is a statement that the algorithm is NOT offered. Reporting it as a
 * finding would turn a hardening step into a work item, which is the fastest
 * way to lose a reader's trust in the whole list.
 */
export function splitList(value: string): string[] {
  return value
    .split(/[\s,:;]+/)
    .map((v) => v.trim())
    .filter((v) => v !== '' && !v.startsWith('!') && !v.startsWith('-'))
    .map((v) => v.replace(/^[+^]/, ''))
    .filter((v) => v !== '');
}

function specsFor(kind: Kind, token: string): readonly AlgoSpec[] {
  switch (kind) {
    case 'tls-suites':
      return tlsCipherSuite(token);
    case 'ssh-algorithms': {
      const s = sshAlgorithm(token);
      return s === null ? [] : [s];
    }
    case 'ciphers': {
      const c = cipherFromName(token);
      return c === null ? [] : [c];
    }
    case 'macs': {
      const h = hashFromName(token.replace(/^hmac-/i, '').replace(/-etm@.*$/, ''));
      return h === null ? [] : [{ ...h, purpose: 'INTEGRITY' as const }];
    }
    case 'signatures':
      return signatureFromName(token);
    case 'groups': {
      const curve = normalizeCurve(token);
      return curve === null
        ? []
        : [
            {
              primitive: 'ECDH' as const,
              parameters: { curve, ephemeral: 'true' },
              purpose: 'KEY_ESTABLISHMENT' as const,
            },
          ];
    }
  }
}

/* ------------------------------------------------------------------ assets */

function assetOf(spec: AlgoSpec): CryptoAsset {
  return makeAsset(spec.primitive, spec.parameters, spec.purpose ?? 'DATA_ENCRYPTION');
}

/**
 * Who has to change it.
 *
 * A host is somebody's server and the daemon config on it is ours to edit, but
 * only one end of a protocol. sshd offering 3DES is PROTOCOL_BILATERAL:
 * removing it breaks every client that has nothing else, which is the whole
 * reason the line is still there.
 */
function controlOfConfig(c: HostConfig): ControlClass {
  return /cipher|kex|mac|ciphersuite|group|curve|protocol/i.test(c.directive)
    ? 'PROTOCOL_BILATERAL'
    : 'SELF';
}

export interface HostFindingOptions {
  /** Fallback when a host does not name its own system. */
  readonly systemId: string;
  readonly collectedAt: string;
  /** Include directives whose owning service was not running at collection. */
  readonly includeInactive?: boolean;
}

export interface HostScanResult {
  readonly findings: Finding[];
  readonly notes: PackageNote[];
  /** Tokens no rule recognized, so a gap is visible rather than silent. */
  readonly unrecognized: { host: string; where: string; token: string }[];
  readonly hostsSeen: number;
}

export function hostFindings(inventory: HostInventory, opts: HostFindingOptions): HostScanResult {
  const findings: Finding[] = [];
  const notes: PackageNote[] = [];
  const unrecognized: { host: string; where: string; token: string }[] = [];

  // Sorted throughout: the engine is pure (I7) and two runs over one export
  // have to produce byte-identical output.
  const hosts = [...inventory.hosts].sort((a, b) => cmp(a.hostId, b.hostId));

  for (const host of hosts) {
    const systemId = host.systemId === '' ? opts.systemId : host.systemId;
    const where = host.hostname === '' ? host.hostId : host.hostname;
    notes.push(...packageNotes(host));

    for (const c of [...host.configs].sort((a, b) => cmp(a.path + a.directive, b.path + b.directive))) {
      if (!c.active && opts.includeInactive !== true) continue;
      const kind = DIRECTIVES[c.directive.trim().toLowerCase()];
      if (kind === undefined) continue;

      for (const token of splitList(c.value)) {
        const specs = specsFor(kind, token);
        if (specs.length === 0) {
          unrecognized.push({ host: host.hostId, where: `${c.path}:${c.directive}`, token });
          continue;
        }
        for (const spec of specs) {
          findings.push({
            asset: assetOf(spec),
            systemId,
            controlClass: controlOfConfig(c),
            evidence: {
              modality: 'HOST_AGENT',
              locator: `${where}:${c.path}`,
              raw:
                `${c.directive} ${token} :: read from the running host by ` +
                `${inventory.source === '' ? 'a host agent' : inventory.source}` +
                (c.active ? '' : ' (owning service not running at collection time)'),
              collectedAt: opts.collectedAt,
              collectorVersion: COLLECTOR_VERSION,
              occurrence: { location: c.path, symbol: c.directive },
            },
            // Reading a directive is reading the file the daemon loaded, not a
            // connection it made. A service can be configured to offer a suite
            // it never selects, so this stays short of the NETWORK_ACTIVE claim.
            ...(c.active
              ? {}
              : { caveats: ['the owning service was not running when the agent collected this'] }),
          });
        }
      }
    }

    for (const k of [...host.keyFiles].sort((a, b) => cmp(a.path, b.path))) {
      const spec = keySpec(k);
      if (spec === null) {
        unrecognized.push({ host: host.hostId, where: k.path, token: k.algorithm });
        continue;
      }
      findings.push({
        asset: assetOf(spec),
        systemId,
        // A key on our own disk is ours to rotate. An SSH host key is not:
        // replacing it invalidates every client's known_hosts entry.
        controlClass: k.kind === 'ssh-host-key' ? 'PROTOCOL_BILATERAL' : 'SELF',
        evidence: {
          modality: 'HOST_AGENT',
          locator: `${where}:${k.path}`,
          raw:
            `${k.kind} ${k.algorithm}${k.bits === null ? '' : `-${k.bits}`}` +
            `${k.curve === '' ? '' : ` ${k.curve}`}` +
            `${k.subject === '' ? '' : ` subject=${k.subject}`}` +
            `${k.notAfter === null ? '' : ` notAfter=${k.notAfter}`}` +
            ` :: present on the host per ${inventory.source === '' ? 'a host agent' : inventory.source}` +
            '; no key material was read (I9)',
          collectedAt: opts.collectedAt,
          collectorVersion: COLLECTOR_VERSION,
          occurrence: { location: k.path, symbol: k.algorithm },
        },
      });
    }

    for (const l of [...host.listeners].sort((a, b) => a.port - b.port)) {
      for (const token of l.offers) {
        const specs = tlsCipherSuite(token);
        if (specs.length === 0) {
          unrecognized.push({ host: host.hostId, where: `${where}:${l.port}`, token });
          continue;
        }
        for (const spec of specs) {
          findings.push({
            asset: assetOf(spec),
            systemId,
            controlClass: 'PROTOCOL_BILATERAL',
            evidence: {
              modality: 'HOST_AGENT',
              locator: `${where}:${l.port}`,
              raw:
                `${l.service === '' ? l.protocol || 'listener' : l.service} on port ${l.port} ` +
                `offers ${token} :: configured offer read from the host, not an observed handshake`,
              collectedAt: opts.collectedAt,
              collectorVersion: COLLECTOR_VERSION,
              occurrence: { location: `${where}:${l.port}`, symbol: token },
            },
          });
        }
      }
    }
  }

  return { findings, notes, unrecognized, hostsSeen: hosts.length };
}

/**
 * A key or certificate sitting on the machine.
 *
 * I9: the algorithm, the size and the path, never the bytes. HostKeyFile has no
 * field that could carry key material, so there is no path here that could leak
 * it even by accident.
 */
function keySpec(k: HostKeyFile): AlgoSpec | null {
  const curve = k.curve === '' ? null : normalizeCurve(k.curve);
  const purpose = k.kind === 'certificate' ? ('CERTIFICATE_AUTH' as const) : ('DIGITAL_SIGNATURE' as const);

  const sigs = signatureFromName(k.algorithm);
  const sig = sigs.find((s) => s.primitive !== 'UNKNOWN') ?? sigs[0];
  const base = sig ?? sshAlgorithm(k.algorithm);
  if (base === null || base === undefined) return null;

  return {
    primitive: base.primitive,
    parameters: {
      ...base.parameters,
      ...(k.bits === null ? {} : { modulusLength: k.bits }),
      ...(curve === null ? {} : { curve }),
    },
    purpose,
  };
}

/**
 * Read a normalized inventory from disk.
 *
 * The same shape as detect-kms, and for the same reason: in a regulated or
 * air-gapped estate the customer's own tool holds the credentials, exports what
 * it sees, and Assay classifies it.
 */
export async function importHosts(path: string): Promise<HostInventory> {
  const raw: unknown = JSON.parse(await readFile(resolve(path), 'utf8'));
  return HostInventorySchema.parse(raw);
}
