import { describe, expect, it } from 'vitest';
import {
  HostInventorySchema,
  fromAnsibleFacts,
  fromFlat,
  fromOsquery,
  hostFindings,
  packageNotes,
  splitList,
  versionBelow,
} from '../src/index.js';
import type { Host, HostInventory } from '../src/index.js';

const AT = '2026-08-30T00:00:00.000Z';

const host = (over: Partial<Host> = {}): Host =>
  HostInventorySchema.parse({
    collectedAt: AT,
    source: 'test-agent',
    hosts: [{ hostId: 'h1', hostname: 'web-01', systemId: 'payments', ...over }],
  }).hosts[0] as Host;

const inv = (h: Host): HostInventory => ({ collectedAt: AT, source: 'test-agent', hosts: [h] });
const run = (h: Host) => hostFindings(inv(h), { systemId: 'fallback', collectedAt: AT });

describe('the modality every other one defers to', () => {
  it('reads a running sshd config as HOST_AGENT, not as source config', () => {
    // The whole point: the same line in a repository is a proposal, and here it
    // is the running state. Different modality, different ceiling, and the two
    // are in different correlated groups so they stack under I1.
    const r = run(
      host({ configs: [{ path: '/etc/ssh/sshd_config', directive: 'Ciphers', value: '3des-cbc', active: true }] }),
    );
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]?.evidence.modality).toBe('HOST_AGENT');
    expect(r.findings[0]?.asset.primitive).toBe('3DES');
    expect(r.findings[0]?.evidence.raw).toContain('read from the running host');
  });

  it('attributes the finding to the host, not to a repository path', () => {
    const r = run(host({ configs: [{ path: '/etc/ssh/sshd_config', directive: 'Ciphers', value: 'aes128-cbc', active: true }] }));
    expect(r.findings[0]?.evidence.locator).toBe('web-01:/etc/ssh/sshd_config');
  });

  it('uses the host’s own system when it names one, and the fallback when it does not', () => {
    const named = run(host({ configs: [{ path: '/e', directive: 'Ciphers', value: 'aes128-cbc', active: true }] }));
    const bare = run(
      host({ systemId: '', configs: [{ path: '/e', directive: 'Ciphers', value: 'aes128-cbc', active: true }] }),
    );
    expect(named.findings[0]?.systemId).toBe('payments');
    expect(bare.findings[0]?.systemId).toBe('fallback');
  });
});

describe('what it refuses to claim', () => {
  it('drops a directive whose service was not running, unless asked', () => {
    const h = host({ configs: [{ path: '/etc/ssh/sshd_config', directive: 'Ciphers', value: '3des-cbc', active: false }] });
    expect(run(h).findings).toHaveLength(0);

    const forced = hostFindings(inv(h), { systemId: 'x', collectedAt: AT, includeInactive: true });
    expect(forced.findings).toHaveLength(1);
    // And it carries the reason it cannot be CONFIRMED, rather than passing as
    // though the agent had watched the daemon load it.
    expect(forced.findings[0]?.caveats?.[0]).toContain('not running');
  });

  it('never turns an installed package into a finding', () => {
    // A library on the box says the box CAN do RSA, exactly as a lockfile says
    // a service can. That is the DEPENDENCY mistake with a better ceiling.
    const r = run(host({ packages: [{ name: 'openssl', version: '1.1.1', source: 'rpm' }] }));
    expect(r.findings).toHaveLength(0);
    expect(r.notes).toHaveLength(1);
    expect(r.notes[0]?.why).toContain('cannot negotiate post-quantum');
  });

  it('does not treat a removed cipher as an offered one', () => {
    // `!3DES` and `-RC4` in an OpenSSL string are hardening. Reporting them as
    // findings would turn the fix into the bug.
    expect(splitList('HIGH:!aNULL:!3DES:-RC4:+AES128')).toEqual(['HIGH', 'AES128']);
  });

  it('says a listener offer is configured, not observed', () => {
    const r = run(host({ listeners: [{ port: 443, protocol: 'tcp', service: 'nginx', offers: ['ECDHE-RSA-AES128-GCM-SHA256'] }] }));
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.findings[0]?.evidence.raw).toContain('not an observed handshake');
  });
});

describe('key material is never read (I9)', () => {
  it('records a certificate by algorithm, size and path only', () => {
    const r = run(
      host({
        keyFiles: [
          { path: '/etc/pki/tls/certs/web.crt', kind: 'certificate', algorithm: 'rsa', bits: 2048, curve: '', subject: 'CN=web-01', notAfter: '2027-01-01' },
        ],
      }),
    );
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]?.asset.primitive).toBe('RSA');
    expect(r.findings[0]?.asset.parameters['modulusLength']).toBe(2048);
    expect(r.findings[0]?.evidence.raw).toContain('no key material was read');
  });

  it('has no schema field that could carry key bytes', () => {
    const parsed = HostInventorySchema.parse({
      collectedAt: AT,
      hosts: [
        {
          hostId: 'h1',
          keyFiles: [{ path: '/k', kind: 'private-key', algorithm: 'rsa', pem: '-----BEGIN PRIVATE KEY-----' }],
        },
      ],
    });
    expect(JSON.stringify(parsed)).not.toContain('BEGIN PRIVATE KEY');
  });

  it('makes an SSH host key bilateral, because rotating one breaks every client', () => {
    const r = run(host({ keyFiles: [{ path: '/etc/ssh/ssh_host_rsa_key.pub', kind: 'ssh-host-key', algorithm: 'ssh-rsa', bits: 2048, curve: '', subject: '', notAfter: null }] }));
    expect(r.findings[0]?.controlClass).toBe('PROTOCOL_BILATERAL');
  });

  it('makes our own certificate ours to rotate', () => {
    const r = run(host({ keyFiles: [{ path: '/etc/pki/web.crt', kind: 'certificate', algorithm: 'rsa', bits: 2048, curve: '', subject: '', notAfter: null }] }));
    expect(r.findings[0]?.controlClass).toBe('SELF');
  });
});

describe('version comparison', () => {
  it('compares numerically, not lexically', () => {
    expect(versionBelow('3.10', '3.5')).toBe(false);
    expect(versionBelow('3.4.9', '3.5')).toBe(true);
    expect(versionBelow('3.5.0', '3.5')).toBe(false);
  });

  it('treats an unparseable segment as below, so a blocker is not cleared by a guess', () => {
    expect(versionBelow('3.5-beta', '3.5.1')).toBe(true);
  });

  it('only flags libraries whose version actually bounds the negotiation', () => {
    expect(packageNotes(host({ packages: [{ name: 'openssl', version: '3.5.1', source: '' }] }))).toEqual([]);
    expect(packageNotes(host({ packages: [{ name: 'zlib', version: '1.0', source: '' }] }))).toEqual([]);
    expect(packageNotes(host({ packages: [{ name: 'openssh', version: '8.9', source: '' }] }))).toHaveLength(1);
  });
});

describe('output is deterministic (I7)', () => {
  it('does not depend on the order hosts or directives arrived in', () => {
    const a: HostInventory = {
      collectedAt: AT,
      source: 's',
      hosts: [
        host({ hostId: 'b', configs: [{ path: '/z', directive: 'Ciphers', value: 'aes128-cbc', active: true }] }),
        host({ hostId: 'a', configs: [{ path: '/a', directive: 'Ciphers', value: '3des-cbc', active: true }] }),
      ],
    };
    const b: HostInventory = { ...a, hosts: [...a.hosts].reverse() };
    const key = (r: ReturnType<typeof hostFindings>) => JSON.stringify(r.findings);
    expect(key(hostFindings(a, { systemId: 'x', collectedAt: AT }))).toBe(
      key(hostFindings(b, { systemId: 'x', collectedAt: AT })),
    );
  });
});

describe('unrecognized tokens are counted, not swallowed', () => {
  it('reports what no rule understood', () => {
    const r = run(host({ configs: [{ path: '/etc/ssh/sshd_config', directive: 'Ciphers', value: 'not-a-cipher', active: true }] }));
    expect(r.findings).toHaveLength(0);
    expect(r.unrecognized).toEqual([{ host: 'h1', where: '/etc/ssh/sshd_config:Ciphers', token: 'not-a-cipher' }]);
  });

  it('ignores a directive that is not about cryptography', () => {
    const r = run(host({ configs: [{ path: '/etc/ssh/sshd_config', directive: 'Port', value: '22', active: true }] }));
    expect(r.findings).toHaveLength(0);
    expect(r.unrecognized).toHaveLength(0);
  });
});

describe('adapters translate what a customer already has', () => {
  it('reads osquery rows', () => {
    const { inventory, skipped } = fromOsquery(
      [
        { name: 'crypto_packages', hostIdentifier: 'web-01', columns: { name: 'openssl', version: '1.1.1k' } },
        { name: 'crypto_config', hostIdentifier: 'web-01', columns: { path: '/etc/ssh/sshd_config', label: 'Ciphers', value: '3des-cbc', running: '1' } },
        { name: 'unrelated', hostIdentifier: 'web-01', columns: {} },
      ],
      { collectedAt: AT, systemId: 'payments' },
    );
    expect(skipped).toBe(1);
    const r = hostFindings(inventory, { systemId: 'payments', collectedAt: AT });
    expect(r.findings[0]?.asset.primitive).toBe('3DES');
    expect(r.notes[0]?.name).toBe('openssl');
  });

  it('defaults an osquery config row to inactive, because reading a file is not watching a daemon', () => {
    const { inventory } = fromOsquery(
      [{ name: 'crypto_config', hostIdentifier: 'h', columns: { path: '/e', label: 'Ciphers', value: '3des-cbc' } }],
      { collectedAt: AT },
    );
    expect(inventory.hosts[0]?.configs[0]?.active).toBe(false);
  });

  it('reads Ansible facts', () => {
    const { inventory } = fromAnsibleFacts(
      {
        'web-01': {
          ansible_fqdn: 'web-01.example.com',
          packages: { openssh: [{ version: '8.9p1' }] },
          assay_crypto_config: { '/etc/ssh/sshd_config': { Ciphers: 'aes128-cbc' } },
        },
      },
      { collectedAt: AT, systemId: 'payments' },
    );
    const r = hostFindings(inventory, { systemId: 'payments', collectedAt: AT });
    expect(r.findings[0]?.evidence.locator).toBe('web-01.example.com:/etc/ssh/sshd_config');
    expect(r.notes[0]?.why).toContain('sntrup761x25519');
  });

  it('reads a flat export, and counts a row it cannot place', () => {
    const { inventory, skipped } = fromFlat(
      [
        { host: 'h', kind: 'listener', where: 'not-a-port', what: 'ECDHE-RSA-AES128-GCM-SHA256' },
        { host: 'h', kind: 'listener', where: '443', what: 'ECDHE-RSA-AES128-GCM-SHA256' },
        { host: '', kind: 'config', where: '/e', what: 'Ciphers' },
      ],
      { collectedAt: AT },
    );
    expect(skipped).toBe(2);
    expect(hostFindings(inventory, { systemId: 'x', collectedAt: AT }).findings.length).toBeGreaterThan(0);
  });
});
