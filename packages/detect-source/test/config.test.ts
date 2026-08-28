import { describe, expect, it } from 'vitest';
import { configKindFor, parseConfig } from '../src/config/index.js';

describe('config kind detection', () => {
  it('recognizes the files that carry deployed cryptography', () => {
    expect(configKindFor('/etc/nginx/nginx.conf')).toBe('nginx');
    expect(configKindFor('/etc/ssh/sshd_config')).toBe('sshd');
    expect(configKindFor('/etc/ssl/openssl.cnf')).toBe('openssl');
    expect(configKindFor('/jdk/conf/security/java.security')).toBe('java-security');
    expect(configKindFor('/src/index.ts')).toBeNull();
  });
});

describe('nginx', () => {
  const conf = `
server {
  ssl_protocols TLSv1 TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:!aNULL;
  ssl_ecdh_curve prime256v1:X25519;
}
`;
  const findings = parseConfig('nginx', conf);
  const all = findings.flatMap((f) => f.detections);

  it('splits a cipher suite into its key exchange, bulk cipher and MAC', () => {
    const suite = findings.find((f) => f.directive === 'ssl_ciphers');
    const primitives = suite?.detections.map((d) => d.primitive) ?? [];
    expect(primitives).toContain('ECDH');
    expect(primitives).toContain('AES');
    expect(primitives).toContain('SHA2');
  });

  it('keeps the key exchange and the certificate signature on different tracks', () => {
    const suite = findings.find((f) => f.directive === 'ssl_ciphers');
    const purposes = new Set(suite?.detections.map((d) => d.purpose));
    expect(purposes.has('KEY_ESTABLISHMENT')).toBe(true);
    expect(purposes.has('CERTIFICATE_AUTH')).toBe(true);
  });

  it('does not emit curve=X25519 for the X25519 primitive', () => {
    const x = all.find((d) => d.primitive === 'X25519');
    expect(x?.parameters).toEqual({});
  });

  it('flags legacy protocol versions but not modern ones', () => {
    const protocols = findings.find((f) => f.directive === 'ssl_protocols');
    expect(protocols?.detections).toHaveLength(1);
    expect(protocols?.detections[0]?.primitive).toBe('SHA1');
  });

  it('ignores negated suites', () => {
    expect(JSON.stringify(all)).not.toContain('aNULL');
  });

  it('records the line number', () => {
    expect(findings.every((f) => f.line > 0)).toBe(true);
  });
});

describe('an OpenSSL cipher list is not a list of suites', () => {
  const suites = (line: string): string[] =>
    parseConfig('nginx', line)
      .flatMap((f) => f.detections)
      .map((d) => `${d.primitive}/${d.purpose}`);

  it('does not read a cipher class keyword as a static-RSA suite', () => {
    // `ssl_ciphers HIGH:!aNULL:!MD5;` is one of the most common lines in
    // production and contains no suite this parser can expand.
    expect(suites('ssl_ciphers HIGH:!aNULL:!MD5;')).toEqual([]);
    expect(suites('ssl_ciphers DEFAULT;')).toEqual([]);
  });

  it('does not report a removed cipher as deployed', () => {
    expect(suites('ssl_ciphers ALL:-RC4:!aNULL;')).toEqual([]);
  });

  it('ignores a sort directive', () => {
    const withStrength = suites('ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:!aNULL:@STRENGTH;');
    expect(withStrength).toEqual(suites('ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;'));
  });

  it('still reads the suites around the keywords', () => {
    expect(suites('ssl_ciphers HIGH:ECDHE-RSA-AES128-GCM-SHA256:!aNULL;')).toContain(
      'ECDH/KEY_ESTABLISHMENT',
    );
  });
});

describe('an nginx directive ends at the semicolon, not at the newline', () => {
  const findings = parseConfig(
    'nginx',
    `
server {
  ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:
              ECDHE-RSA-CHACHA20-POLY1305:
              DHE-RSA-AES128-GCM-SHA256;
}
`,
  );
  const all = findings.flatMap((f) => f.detections);

  it('keeps every suite in a wrapped cipher list', () => {
    const prims = all.map((d) => d.primitive);
    expect(prims).toContain('ChaCha20');
    expect(prims).toContain('DH');
    expect(prims).toContain('ECDSA');
  });

  it('does not mint static RSA key transport out of the trailing separator', () => {
    expect(all.some((d) => d.parameters['mode'] === 'KEY_TRANSPORT')).toBe(false);
  });

  it('reports the line the directive starts on', () => {
    expect(findings[0]?.line).toBe(3);
  });
});

describe('sshd_config', () => {
  const findings = parseConfig(
    'sshd',
    `
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha1
HostKeyAlgorithms ssh-rsa,ssh-ed25519
Ciphers aes256-gcm@openssh.com,3des-cbc
MACs hmac-sha2-256,hmac-sha1
`,
  );
  const all = findings.flatMap((f) => f.detections);

  it('resolves group sizes for classical DH', () => {
    const dh = all.find((d) => d.primitive === 'DH');
    expect(dh?.parameters['primeLength']).toBe(2048);
  });

  it('keeps the wire name out of the asset parameters', () => {
    const x = all.find((d) => d.primitive === 'X25519');
    expect(x?.parameters).toEqual({});
    expect(x?.note).toContain('curve25519-sha256');
  });

  it('puts host keys on the authenticity track and KEX on confidentiality', () => {
    expect(all.find((d) => d.primitive === 'X25519')?.purpose).toBe('KEY_ESTABLISHMENT');
    expect(all.find((d) => d.primitive === 'EdDSA')?.purpose).toBe('DIGITAL_SIGNATURE');
  });

  it('finds 3DES in a cipher list', () => {
    expect(all.some((d) => d.primitive === '3DES')).toBe(true);
  });

  it('ignores directives that are not algorithm lists', () => {
    expect(parseConfig('sshd', 'Port 22\nPermitRootLogin no\n')).toHaveLength(0);
  });
});

describe('sshd list operators change the default list rather than replacing it', () => {
  const prims = (line: string): string[] =>
    parseConfig('sshd', line)
      .flatMap((f) => f.detections)
      .map((d) => d.primitive);

  it('does not report an algorithm the config removes', () => {
    // `Ciphers -3des-cbc,arcfour` is a hardening directive; reading it as a
    // replacement list reports the two worst ciphers on a host that just
    // turned them off.
    expect(prims('Ciphers -3des-cbc,arcfour\n')).toEqual([]);
    expect(prims('KexAlgorithms -diffie-hellman-group1-sha1\n')).toEqual([]);
  });

  it('records algorithms appended to the defaults', () => {
    expect(prims('Ciphers +aes128-cbc\n')).toContain('AES');
    expect(prims('KexAlgorithms ^curve25519-sha256\n')).toContain('X25519');
  });

  it('leaves a plain replacement list alone', () => {
    expect(prims('Ciphers aes256-gcm@openssh.com,3des-cbc\n')).toContain('3DES');
  });
});

describe('openssl.cnf', () => {
  const findings = parseConfig('openssl', 'default_md = sha1\ndefault_bits = 1024\ndefault_days = 365\n');
  it('reads the default digest and key size', () => {
    const prims = findings.flatMap((f) => f.detections).map((d) => d.primitive);
    expect(prims).toContain('SHA1');
    expect(prims).toContain('RSA');
  });
  it('does not mistake a day count for a key size', () => {
    expect(findings.every((f) => f.directive !== 'default_days')).toBe(true);
  });
});

describe('java.security', () => {
  it('records disabled algorithms across line continuations', () => {
    const findings = parseConfig(
      'java-security',
      'jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, \\\n    MD5withRSA, DH keySize < 1024\n',
    );
    const prims = findings.flatMap((f) => f.detections).map((d) => d.primitive);
    expect(prims).toContain('RC4');
    expect(findings[0]?.detections[0]?.note).toContain('disabled by JVM policy');
  });

  it('records the signature algorithms, which are most of what the lists name', () => {
    // A dropped MD5withRSA is indistinguishable in the inventory from a JVM
    // that still permits it, which is the distinction this parser exists for.
    const findings = parseConfig(
      'java-security',
      'jdk.certpath.disabledAlgorithms=MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024, MD5withRSA, SHA1withRSA\n',
    );
    const detections = findings.flatMap((f) => f.detections);
    expect(detections.some((d) => d.primitive === 'RSA' && d.note?.includes('MD5withRSA'))).toBe(true);
    expect(detections.some((d) => d.primitive === 'RSA' && d.note?.includes('SHA1withRSA'))).toBe(true);
    expect(detections.some((d) => d.primitive === 'RSA' && d.note?.includes('RSA keySize'))).toBe(true);
  });
});
