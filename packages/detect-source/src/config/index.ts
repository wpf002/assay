import { basename } from 'node:path';
import type { Detection } from '../types.js';
import {
  cipherFromName,
  hashFromName,
  normalizeCurve,
  sshAlgorithm,
  tlsCipherSuite,
} from '@assay/core';

/**
 * Configuration parsing.
 *
 * A TLS terminator's cipher list is the deployed cryptography of every service
 * behind it, and it never appears in application source. This is the modality
 * that catches the estate a source scan structurally cannot see - which is why
 * SOURCE_CONFIG sits at 0.90 rather than being folded into SOURCE_AST.
 */

export interface ConfigFinding {
  readonly line: number;
  readonly raw: string;
  readonly directive: string;
  readonly detections: readonly Detection[];
}

export type ConfigKind = 'nginx' | 'openssl' | 'java-security' | 'sshd' | 'ssh';

export function configKindFor(path: string): ConfigKind | null {
  const name = basename(path).toLowerCase();
  if (name === 'nginx.conf' || /\.nginx$/.test(name) || /nginx.*\.conf$/.test(name)) return 'nginx';
  if (name === 'openssl.cnf' || name === 'openssl.conf') return 'openssl';
  if (name === 'java.security') return 'java-security';
  if (name === 'sshd_config') return 'sshd';
  if (name === 'ssh_config') return 'ssh';
  return null;
}

export function parseConfig(kind: ConfigKind, source: string): readonly ConfigFinding[] {
  switch (kind) {
    case 'nginx':
      return parseNginx(source);
    case 'openssl':
      return parseOpenssl(source);
    case 'java-security':
      return parseJavaSecurity(source);
    case 'sshd':
    case 'ssh':
      return parseSshd(source);
  }
}

const det = (
  ruleId: string,
  spec: { primitive: Detection['primitive']; parameters: Detection['parameters']; purpose?: Detection['purpose'] },
  fallbackPurpose: Detection['purpose'],
): Detection => ({
  primitive: spec.primitive,
  parameters: spec.parameters,
  purpose: spec.purpose ?? fallbackPurpose,
  purposeSource: 'RESOLVED',
  ruleId,
});

/* -------------------------------------------------------------------- nginx */

function parseNginx(source: string): ConfigFinding[] {
  const out: ConfigFinding[] = [];
  source.split(/\r?\n/).forEach((line, i) => {
    const trimmed = line.trim().replace(/;$/, '');
    if (trimmed === '' || trimmed.startsWith('#')) return;

    const ciphers = /^ssl_ciphers\s+(.+)$/.exec(trimmed);
    if (ciphers?.[1]) {
      const suites = ciphers[1].replace(/^["']|["']$/g, '').split(':').filter((s) => !s.startsWith('!'));
      const detections = suites.flatMap((s) =>
        tlsCipherSuite(s).map((spec) => det('config/nginx/ssl_ciphers', spec, 'DATA_ENCRYPTION')),
      );
      if (detections.length > 0) {
        out.push({ line: i + 1, raw: trimmed, directive: 'ssl_ciphers', detections });
      }
      return;
    }

    const curve = /^ssl_ecdh_curve\s+(.+)$/.exec(trimmed);
    if (curve?.[1]) {
      const detections = curve[1]
        .split(':')
        .map((c) => normalizeCurve(c))
        .filter((c): c is string => c !== null)
        .map((c) => {
          // X25519 names its own curve. Emitting curve=X25519 alongside would
          // give the same primitive two content hashes and two worklist rows.
          const montgomery = c === 'X25519' || c === 'X448';
          return det(
            'config/nginx/ssl_ecdh_curve',
            {
              primitive: montgomery ? (c as 'X25519' | 'X448') : 'ECDH',
              parameters: montgomery ? {} : { curve: c },
              purpose: 'KEY_ESTABLISHMENT',
            },
            'KEY_ESTABLISHMENT',
          );
        });
      if (detections.length > 0) {
        out.push({ line: i + 1, raw: trimmed, directive: 'ssl_ecdh_curve', detections });
      }
      return;
    }

    // A protocol version is not itself an algorithm, but TLS 1.0/1.1 pin a
    // fixed and broken suite set, so it is recorded as an integrity finding.
    const protocols = /^ssl_protocols\s+(.+)$/.exec(trimmed);
    if (protocols?.[1]) {
      const legacy = protocols[1].split(/\s+/).filter((p) => /TLSv1(\.[01])?$/.test(p) || /SSLv/.test(p));
      if (legacy.length > 0) {
        out.push({
          line: i + 1,
          raw: trimmed,
          directive: 'ssl_protocols',
          detections: legacy.map((p) => ({
            primitive: 'SHA1' as const,
            parameters: { outputLength: 160 },
            purpose: 'INTEGRITY' as const,
            purposeSource: 'RESOLVED' as const,
            ruleId: 'config/nginx/ssl_protocols',
            note: `${p} mandates SHA-1 in its PRF and signature suites`,
          })),
        });
      }
    }
  });
  return out;
}

/* ------------------------------------------------------------------ openssl */

function parseOpenssl(source: string): ConfigFinding[] {
  const out: ConfigFinding[] = [];
  source.split(/\r?\n/).forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return;
    const kv = /^(\w+)\s*=\s*(.+?)\s*(?:#.*)?$/.exec(trimmed);
    if (!kv?.[1] || !kv[2]) return;
    const key = kv[1].toLowerCase();
    const value = kv[2];

    if (key === 'default_md') {
      const spec = hashFromName(value);
      if (spec) {
        out.push({
          line: i + 1,
          raw: trimmed,
          directive: 'default_md',
          detections: [det('config/openssl/default_md', spec, 'INTEGRITY')],
        });
      }
      return;
    }
    if (key === 'default_bits') {
      const bits = Number(value);
      if (Number.isFinite(bits)) {
        out.push({
          line: i + 1,
          raw: trimmed,
          directive: 'default_bits',
          detections: [
            {
              primitive: 'RSA',
              parameters: { modulusLength: bits },
              purpose: 'CERTIFICATE_AUTH',
              purposeSource: 'RULE_DEFAULT',
              ruleId: 'config/openssl/default_bits',
              note: 'default_bits governs RSA key generation for certificates issued by this configuration',
            },
          ],
        });
      }
      return;
    }
    if (key === 'default_crl_days' || key === 'default_days') return;
    if (key.includes('curve')) {
      const curve = normalizeCurve(value);
      if (curve) {
        out.push({
          line: i + 1,
          raw: trimmed,
          directive: key,
          detections: [
            det(
              'config/openssl/curve',
              { primitive: 'ECDSA', parameters: { curve }, purpose: 'CERTIFICATE_AUTH' },
              'CERTIFICATE_AUTH',
            ),
          ],
        });
      }
    }
  });
  return out;
}

/* ----------------------------------------------------------- java.security */

function parseJavaSecurity(source: string): ConfigFinding[] {
  const out: ConfigFinding[] = [];
  const lines = source.split(/\r?\n/);
  // java.security folds long values across backslash continuations.
  let buffer = '';
  let startLine = 0;

  const flush = (endIndex: number): void => {
    if (buffer === '') return;
    const kv = /^([\w.]+)\s*=\s*(.*)$/.exec(buffer.trim());
    buffer = '';
    if (!kv?.[1] || kv[2] === undefined) return;
    const key = kv[1];
    if (!/disabledAlgorithms|legacyAlgorithms|disabledMechanisms/i.test(key)) return;

    // A disabled-algorithm list is a policy statement about what this JVM will
    // refuse. It is recorded because its absence is the finding: an algorithm
    // NOT on this list is one the JVM still accepts.
    const entries = kv[2].split(',').map((e) => e.trim()).filter(Boolean);
    const detections: Detection[] = [];
    for (const entry of entries) {
      const name = (entry.split(/\s+/)[0] ?? '').replace(/,$/, '');
      const spec = hashFromName(name) ?? cipherFromName(name);
      if (spec) {
        detections.push({
          primitive: spec.primitive,
          parameters: spec.parameters,
          purpose: spec.purpose ?? 'INTEGRITY',
          purposeSource: 'RESOLVED',
          ruleId: 'config/java-security/disabledAlgorithms',
          note: `disabled by JVM policy (${entry}) - recorded so the inventory can distinguish "absent" from "still permitted"`,
        });
      }
    }
    if (detections.length > 0) {
      out.push({ line: startLine + 1, raw: `${key}=...`, directive: key, detections });
    }
  };

  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || trimmed === '') return;
    if (buffer === '') startLine = i;
    if (trimmed.endsWith('\\')) {
      buffer += trimmed.slice(0, -1);
      return;
    }
    buffer += trimmed;
    flush(i);
  });
  flush(lines.length);
  return out;
}

/* --------------------------------------------------------------- sshd_config */

const SSH_DIRECTIVES: Readonly<Record<string, Detection['purpose']>> = {
  kexalgorithms: 'KEY_ESTABLISHMENT',
  hostkeyalgorithms: 'DIGITAL_SIGNATURE',
  pubkeyacceptedalgorithms: 'DIGITAL_SIGNATURE',
  pubkeyacceptedkeytypes: 'DIGITAL_SIGNATURE',
  hostbasedacceptedalgorithms: 'DIGITAL_SIGNATURE',
  ciphers: 'DATA_ENCRYPTION',
  macs: 'INTEGRITY',
  casignaturealgorithms: 'CERTIFICATE_AUTH',
};

function parseSshd(source: string): ConfigFinding[] {
  const out: ConfigFinding[] = [];
  source.split(/\r?\n/).forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return;
    const kv = /^(\w+)[\s=]+(.+)$/.exec(trimmed);
    if (!kv?.[1] || !kv[2]) return;
    const directive = kv[1].toLowerCase();
    const purpose = SSH_DIRECTIVES[directive];
    if (purpose === undefined) return;

    // Leading +/-/^ modify the built-in default list rather than replacing it.
    const names = kv[2]
      .replace(/^[+\-^]/, '')
      .split(',')
      .map((n) => n.trim())
      .filter(Boolean);

    const detections = names
      .map((n) => ({ name: n, spec: sshAlgorithm(n) }))
      .filter((x): x is { name: string; spec: NonNullable<ReturnType<typeof sshAlgorithm>> } => x.spec !== null)
      .map(({ name, spec }) => ({
        primitive: spec.primitive,
        // The wire name (curve25519-sha256, ecdh-sha2-nistp256) is provenance,
        // not an asset parameter. Folding it into parameters would give the
        // same key agreement three different content hashes and split one work
        // item into three rows - the exact failure mode the ceilings exist to
        // prevent, arriving through the back door.
        parameters: spec.parameters,
        purpose: spec.purpose ?? purpose,
        purposeSource: 'RESOLVED' as const,
        ruleId: `config/sshd/${directive}`,
        note: `negotiated as ${name}`,
      }));

    if (detections.length > 0) {
      out.push({ line: i + 1, raw: trimmed, directive, detections });
    }
  });
  return out;
}
