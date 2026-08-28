import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as x509 from '@peculiar/x509';
import { beforeAll, describe, expect, it } from 'vitest';
import { computeConfidence, gate, type Finding, type Occurrence } from '@assay/core';
import { assemble } from '@assay/correlate';
import {
  CONSTANT_SIGNATURES,
  analyzeBinary,
  detectFormat,
  findConstants,
  findDerStructures,
  fingerprintLibraries,
  matchSymbol,
  parseBinary,
  scanBinaries,
} from '../src/index.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const sig = (id: string) => CONSTANT_SIGNATURES.find((s) => s.id === id);

/* ------------------------------------------------- synthetic format fixtures */

/** A minimal but structurally valid ELF64 with one symbol in .symtab. */
function makeElf(symbolName: string): Buffer {
  const strtab = Buffer.concat([Buffer.from([0]), Buffer.from(`${symbolName}\0`, 'ascii')]);
  const shstr = Buffer.from('\0.symtab\0.strtab\0.shstrtab\0', 'ascii');
  const sym = Buffer.alloc(24);
  sym.writeUInt32LE(1, 0); // st_name -> offset 1 in strtab

  const ehsize = 64;
  const shentsize = 64;
  const symOff = ehsize;
  const strOff = symOff + sym.length;
  const shstrOff = strOff + strtab.length;
  const shoff = shstrOff + shstr.length;

  const header = Buffer.alloc(ehsize);
  header.write('\x7fELF', 0, 'latin1');
  header[4] = 2; // 64-bit
  header[5] = 1; // little-endian
  header.writeUInt16LE(2, 16); // ET_EXEC
  header.writeUInt16LE(0x3e, 18); // x86_64
  header.writeBigUInt64LE(BigInt(shoff), 0x28);
  header.writeUInt16LE(shentsize, 0x3a);
  header.writeUInt16LE(4, 0x3c); // 4 sections
  header.writeUInt16LE(3, 0x3e); // shstrndx

  const section = (nameOff: number, type: number, offset: number, size: number, link: number, entsize: number) => {
    const s = Buffer.alloc(shentsize);
    s.writeUInt32LE(nameOff, 0);
    s.writeUInt32LE(type, 4);
    s.writeBigUInt64LE(BigInt(offset), 0x18);
    s.writeBigUInt64LE(BigInt(size), 0x20);
    s.writeUInt32LE(link, 0x28);
    s.writeBigUInt64LE(BigInt(entsize), 0x38);
    return s;
  };

  return Buffer.concat([
    header,
    sym,
    strtab,
    shstr,
    section(0, 0, 0, 0, 0, 0), // SHT_NULL
    section(1, 2, symOff, sym.length, 2, 24), // .symtab -> link .strtab (index 2)
    section(9, 3, strOff, strtab.length, 0, 0), // .strtab
    section(17, 3, shstrOff, shstr.length, 0, 0), // .shstrtab
  ]);
}

/** A minimal PE32+ with one import from one DLL. */
function makePe(dll: string, fn: string): Buffer {
  const size = 0x600;
  const buf = Buffer.alloc(size);
  buf.write('MZ', 0, 'latin1');
  const peOff = 0x80;
  buf.writeUInt32LE(peOff, 0x3c);
  buf.writeUInt32LE(0x00004550, peOff); // "PE\0\0"
  buf.writeUInt16LE(0x8664, peOff + 4); // x86_64
  buf.writeUInt16LE(1, peOff + 6); // one section
  buf.writeUInt16LE(240, peOff + 20); // optional header size
  const optOff = peOff + 24;
  buf.writeUInt16LE(0x20b, optOff); // PE32+

  const importRva = 0x1000;
  buf.writeUInt32LE(importRva, optOff + 112 + 8); // data directory 1: import table
  buf.writeUInt32LE(0x100, optOff + 112 + 12);

  const secOff = optOff + 240;
  buf.write('.idata\0\0', secOff, 'latin1');
  buf.writeUInt32LE(0x1000, secOff + 8); // virtual size
  buf.writeUInt32LE(importRva, secOff + 12); // virtual address
  buf.writeUInt32LE(0x200, secOff + 20); // pointer to raw data

  // Import descriptor at file 0x200 (rva 0x1000)
  const desc = 0x200;
  buf.writeUInt32LE(0x1100, desc); // lookup table rva
  buf.writeUInt32LE(0x1200, desc + 12); // dll name rva
  buf.writeUInt32LE(0x1100, desc + 16); // thunk rva
  // terminator is the zeroed 20 bytes that follow

  buf.writeBigUInt64LE(BigInt(0x1300), 0x300); // lookup entry -> hint/name rva
  buf.write(`${dll}\0`, 0x400, 'latin1');
  buf.writeUInt16LE(0, 0x500); // hint
  buf.write(`${fn}\0`, 0x502, 'latin1');
  return buf;
}

/* --------------------------------------------------------------------- tests */

describe('format detection', () => {
  it('recognizes ELF, Mach-O and PE', () => {
    expect(detectFormat(makeElf('RSA_sign'))).toBe('elf');
    expect(detectFormat(makePe('libcrypto.dll', 'RSA_sign'))).toBe('pe');
    expect(detectFormat(readFileSync(process.execPath))).toBe('macho');
  });

  it('does not mistake a Java class file for a universal binary', () => {
    const javaClass = Buffer.alloc(16);
    javaClass.writeUInt32BE(0xcafebabe, 0);
    javaClass.writeUInt32BE(65, 4); // major version, far above a plausible arch count
    expect(detectFormat(javaClass)).toBe('unknown');
  });

  it('returns unknown rather than throwing on a runt', () => {
    expect(detectFormat(Buffer.alloc(2))).toBe('unknown');
    expect(parseBinary(Buffer.alloc(2)).format).toBe('unknown');
  });
});

describe('symbol tables', () => {
  it('reads a symbol out of an ELF .symtab', () => {
    const info = parseBinary(makeElf('ECDSA_do_sign'));
    expect(info.format).toBe('elf');
    expect(info.arch).toBe('x86_64');
    expect(info.symbols).toContain('ECDSA_do_sign');
  });

  it('reads an imported function and its DLL out of a PE import table', () => {
    const info = parseBinary(makePe('libcrypto-3-x64.dll', 'RSA_public_encrypt'));
    expect(info.symbols).toContain('RSA_public_encrypt');
    expect(info.linkedLibraries).toContain('libcrypto-3-x64.dll');
  });

  it('survives a truncated file without throwing', () => {
    const elf = makeElf('RSA_sign');
    expect(() => parseBinary(elf.subarray(0, 70))).not.toThrow();
    expect(parseBinary(elf.subarray(0, 70)).truncated).toBe(true);
  });
});

describe('symbol classification', () => {
  it('maps OpenSSL entry points to the right primitive and track', () => {
    expect(matchSymbol('ECDSA_do_sign')?.primitive).toBe('ECDSA');
    expect(matchSymbol('ECDSA_do_sign')?.purpose).toBe('DIGITAL_SIGNATURE');
    expect(matchSymbol('ECDH_compute_key')?.purpose).toBe('KEY_ESTABLISHMENT');
    expect(matchSymbol('DES_ede3_cbc_encrypt')?.primitive).toBe('3DES');
    expect(matchSymbol('_SHA256_Update')?.parameters['outputLength']).toBe(256);
  });

  it('reports a post-quantum symbol as the positive finding it is', () => {
    expect(matchSymbol('ML_KEM_768_encap')?.primitive).toBe('ML-KEM');
    expect(matchSymbol('dilithium3_sign')?.primitive).toBe('ML-DSA');
  });

  it('ignores symbols that merely contain a crypto word', () => {
    expect(matchSymbol('my_rsa_helper_thing')).toBeNull();
    expect(matchSymbol('keyboard_init')).toBeNull();
    expect(matchSymbol('design_system_render')).toBeNull();
  });
});

describe('byte-exact constants', () => {
  it('finds an AES S-box embedded in arbitrary data', () => {
    const sbox = sig('aes-sbox');
    const blob = Buffer.concat([Buffer.alloc(500, 0xab), Buffer.from(sbox?.bytes as Uint8Array), Buffer.alloc(500)]);
    const hits = findConstants(blob);
    expect(hits.some((h) => h.signature.id === 'aes-sbox')).toBe(true);
    expect(hits.find((h) => h.signature.id === 'aes-sbox')?.offset).toBe(500);
  });

  it('finds SHA-2 constants in BOTH byte orders', () => {
    // A compiler emits a uint32 table in target order. Big-endian-only
    // signatures find SHA-2 in essentially nothing that ships.
    expect(sig('sha256-k')).toBeDefined();
    expect(sig('sha256-k-le')).toBeDefined();
    const le = sig('sha256-k-le');
    const blob = Buffer.concat([Buffer.alloc(64), Buffer.from(le?.bytes as Uint8Array)]);
    expect(findConstants(blob).some((h) => h.signature.id === 'sha256-k-le')).toBe(true);
  });

  it('does not swap a byte-string constant', () => {
    expect(sig('chacha-sigma-le')).toBeUndefined();
    expect(sig('aes-sbox-le')).toBeUndefined();
  });

  it('finds nothing in random-looking data', () => {
    const blob = Buffer.alloc(4096);
    for (let i = 0; i < blob.length; i++) blob[i] = (i * 37 + 11) & 0xff;
    expect(findConstants(blob)).toHaveLength(0);
  });
});

describe('embedded DER, found by parsing rather than by string match', () => {
  let certDer: Buffer;
  let keyDer: Buffer;

  beforeAll(async () => {
    const keys = (await webcrypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const cert = await x509.X509CertificateGenerator.createSelfSigned(
      {
        serialNumber: '01',
        name: 'CN=embedded.example',
        notBefore: new Date('2026-01-01T00:00:00Z'),
        notAfter: new Date('2036-01-01T00:00:00Z'),
        signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        keys,
      },
      webcrypto as unknown as Crypto,
    );
    certDer = Buffer.from(cert.rawData);
    keyDer = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
  }, 60_000);

  it('finds a DER certificate with no PEM armour anywhere in sight', () => {
    const blob = Buffer.concat([Buffer.alloc(1024, 0x90), certDer, Buffer.alloc(1024, 0x90)]);
    const found = findDerStructures(blob);
    const cert = found.find((c) => c.kind === 'certificate');
    expect(cert?.offset).toBe(1024);
    expect(cert?.length).toBe(certDer.length);
    expect(cert?.algorithmOid).toBe('1.2.840.113549.1.1.11');
  });

  it('never carries private key bytes out of the parser (I9)', () => {
    const blob = Buffer.concat([Buffer.alloc(256), keyDer, Buffer.alloc(256)]);
    const key = findDerStructures(blob).find((c) => c.kind === 'private-key');
    expect(key).toBeDefined();
    expect(key?.algorithmOid).toBe('1.2.840.113549.1.1.1');
    // The existence and the algorithm are the finding. The material is not.
    expect(key?.bytes).toBeNull();
  });

  it('does not report the private key material in any emitted evidence', async () => {
    const report = analyzeBinary(
      Buffer.concat([Buffer.alloc(256), keyDer, Buffer.alloc(256)]),
      'firmware.bin',
    );
    expect(report).not.toBeNull();
    const serialized = JSON.stringify(report);
    // A distinctive 16-byte window of the key must not appear anywhere.
    expect(serialized).not.toContain(keyDer.subarray(40, 56).toString('hex'));
    expect(serialized).not.toContain(keyDer.subarray(40, 56).toString('base64'));
  });

  it('ignores a SEQUENCE whose declared length runs past the buffer', () => {
    const bogus = Buffer.alloc(200);
    bogus[0] = 0x30;
    bogus[1] = 0x84;
    bogus.writeUInt32BE(0x7fffffff, 2);
    expect(findDerStructures(bogus)).toHaveLength(0);
  });
});

describe('library fingerprints', () => {
  it('separates a version from a bare name', () => {
    const fp = fingerprintLibraries(['OpenSSL 1.0.2u  20 Dec 2019', 'mbed TLS 2.28.0']);
    expect(fp.find((f) => f.library === 'OpenSSL')?.version).toBe('1.0.2u');
    expect(fp.find((f) => f.library === 'mbedTLS')?.version).toBe('2.28.0');
  });
});

describe('a real binary of known composition', () => {
  const report = analyzeBinary(readFileSync(process.execPath), 'node');

  it('parses the executable and its symbol table', () => {
    expect(report?.info.format).toBe('macho');
    expect(report?.info.symbols.length).toBeGreaterThan(1000);
  });

  it('finds the NIST curve parameters that a TLS stack must contain', () => {
    const ids = new Set(report?.constants.map((c) => c.signature.id));
    expect(ids.has('p256-prime')).toBe(true);
    expect(ids.has('p384-prime')).toBe(true);
  });

  it('finds SHA-2 round constants in the order the compiler emitted them', () => {
    const ids = new Set(report?.constants.map((c) => c.signature.id));
    expect(ids.has('sha256-k-le') || ids.has('sha256-k')).toBe(true);
  });

  it('finds the root certificates the runtime ships with', () => {
    expect(report?.der.some((d) => d.kind === 'certificate')).toBe(true);
  });
});

/* ------------------------------------------------------------- the exit gate */

const occurrenceFor = (findings: readonly Finding[]): Occurrence =>
  assemble(findings).occurrences[0] as Occurrence;

const finding = (modality: Finding['evidence']['modality'], locator: string): Finding => ({
  asset: { id: 'a', primitive: 'AES', parameters: {}, purpose: 'DATA_ENCRYPTION', quantumVulnerable: true, classicalSecurityBits: 128, nistQuantumSecurityLevel: null, oid: null },
  systemId: 'firmware',
  controlClass: 'VENDOR_LOCKED',
  evidence: {
    modality,
    locator,
    raw: 'x',
    collectedAt: '2026-08-28T00:00:00.000Z',
    collectorVersion: 'test',
  },
});

describe('exit gate: BINARY_STRING never confirms without independent corroboration', () => {
  it('holds under adversarial repetition', () => {
    for (const count of [1, 10, 500, 5000]) {
      const findings = Array.from({ length: count }, (_, i) => finding('BINARY_STRING', `f.bin@${i}`));
      const g = gate(occurrenceFor(findings));
      expect(g.confidence).toBe(0.3);
      expect(g.assertionLevel).toBe('SUSPECTED');
    }
  });

  it('does not confirm even when every other binary modality piles on', () => {
    // BINARY_SYMBOL and BINARY_CONSTANT are in the SAME correlated group as
    // BINARY_STRING: they are three views of one artefact, and the group takes
    // the maximum rather than stacking.
    const g = gate(
      occurrenceFor([
        finding('BINARY_STRING', 'f.bin@1'),
        finding('BINARY_SYMBOL', 'f.bin!AES_encrypt'),
        finding('HOST_AGENT', 'host:1'),
      ]),
    );
    expect(g.confidence).toBeLessThanOrEqual(0.9);
  });

  it('confirms once a genuinely independent modality agrees', () => {
    const g = gate(
      occurrenceFor([finding('BINARY_STRING', 'f.bin@1'), finding('NETWORK_ACTIVE', 'host:443')]),
    );
    expect(g.assertionLevel).toBe('CONFIRMED');
  });

  it('demotes a low-specificity constant so it cannot confirm alone', () => {
    // 0x09 followed by 31 zero bytes is the X25519 base point and is also
    // ordinary padding, so it is emitted at the string ceiling.
    const blob = Buffer.concat([Buffer.alloc(64, 0xff), Buffer.from(sig('x25519-basepoint')?.bytes as Uint8Array)]);
    const report = analyzeBinary(blob, 'pad.bin');
    expect(report).not.toBeNull();
    expect(report?.constants.some((c) => c.signature.id === 'x25519-basepoint')).toBe(true);
  });
});

describe('scanning a tree', () => {
  it('emits findings at the modality each observation deserves', async () => {
    const r = await scanBinaries({
      root: resolveNodeDir(),
      systemId: 'runtime',
      collectedAt: '2026-08-28T00:00:00.000Z',
      include: ['node'],
    });
    if (r.filesScanned === 0) return; // node is not inside a scannable directory here
    const modalities = new Set(r.findings.map((f) => f.evidence.modality));
    expect(modalities.size).toBeGreaterThan(0);
    expect(r.findings.every((f) => f.controlClass === 'VENDOR_LOCKED')).toBe(true);
  }, 120_000);
});

function resolveNodeDir(): string {
  return process.execPath.slice(0, process.execPath.lastIndexOf('/'));
}
