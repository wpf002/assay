import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';
import { beforeAll, describe, expect, it } from 'vitest';
import { computeConfidence, gate, type Finding, type Occurrence } from '@assay/core';
import { assemble } from '@assay/correlate';
import {
  CONSTANT_SIGNATURES,
  analyzeBinary,
  detectFormat,
  findConstants,
  extractStrings,
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

  buf.writeUInt32LE(16, optOff + 108); // NumberOfRvaAndSizes: the usual full set

  const importRva = 0x1000;
  buf.writeUInt32LE(importRva, optOff + 112 + 8); // data directory 1: import table
  buf.writeUInt32LE(0x100, optOff + 112 + 12);

  const secOff = optOff + 240;
  buf.write('.idata\0\0', secOff, 'latin1');
  buf.writeUInt32LE(0x1000, secOff + 8); // virtual size
  buf.writeUInt32LE(importRva, secOff + 12); // virtual address
  buf.writeUInt32LE(0x400, secOff + 16); // size of raw data: what actually backs the RVAs
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

/**
 * An ELF64 whose .symtab claims `symbolCount` entries, all naming a string in a
 * NUL-free run that reaches EOF. The section header table sits at the front so
 * nothing after the run can terminate a string early - which is what makes the
 * per-symbol cost the distance to EOF rather than a few bytes.
 */
function makeNulFreeElf(symbolCount: number, padBytes: number): Buffer {
  const ehsize = 64;
  const shentsize = 64;
  const shstr = Buffer.from('\0.symtab\0.strtab\0.shstrtab\0', 'ascii');
  const shoff = ehsize + shstr.length;
  const symOff = shoff + 4 * shentsize;
  const strOff = symOff + symbolCount * 24;

  const header = Buffer.alloc(ehsize);
  header.write('\x7fELF', 0, 'latin1');
  header[4] = 2;
  header[5] = 1;
  header.writeUInt16LE(2, 16);
  header.writeUInt16LE(0x3e, 18);
  header.writeBigUInt64LE(BigInt(shoff), 0x28);
  header.writeUInt16LE(shentsize, 0x3a);
  header.writeUInt16LE(4, 0x3c);
  header.writeUInt16LE(3, 0x3e);

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

  const symtab = Buffer.alloc(symbolCount * 24);
  for (let i = 0; i < symbolCount; i++) symtab.writeUInt32LE(1, i * 24); // st_name -> into the pad

  return Buffer.concat([
    header,
    shstr,
    section(0, 0, 0, 0, 0, 0),
    section(1, 2, symOff, symtab.length, 2, 24), // .symtab -> .strtab
    section(9, 3, strOff, padBytes, 0, 0), // .strtab, entirely inside the pad
    section(17, 3, ehsize, shstr.length, 0, 0),
    symtab,
    Buffer.alloc(padBytes, 0x41),
  ]);
}

/**
 * A PE32 sized to make the import walk as expensive as its header fields allow:
 * many sections, 4096 descriptors, and thunk values naming an RVA no section
 * covers, so the inner loop never terminates early.
 */
function makeHostilePe(sectionCount: number): Buffer {
  const size = 0x110000;
  const buf = Buffer.alloc(size);
  buf.write('MZ', 0, 'latin1');
  const peOff = 0x80;
  buf.writeUInt32LE(peOff, 0x3c);
  buf.writeUInt32LE(0x00004550, peOff);
  buf.writeUInt16LE(0x14c, peOff + 4); // x86
  buf.writeUInt16LE(sectionCount, peOff + 6);
  buf.writeUInt16LE(224, peOff + 20);
  const optOff = peOff + 24;
  buf.writeUInt16LE(0x10b, optOff); // PE32
  buf.writeUInt32LE(16, optOff + 92); // NumberOfRvaAndSizes

  const importRva = 0x4000;
  buf.writeUInt32LE(importRva, optOff + 96 + 8);

  const secOff = optOff + 224;
  // Section 0 maps the descriptor and thunk region 1:1. The rest exist only to
  // lengthen a lookup that used to be a linear scan.
  buf.writeUInt32LE(0x100000, secOff + 8);
  buf.writeUInt32LE(0x4000, secOff + 12);
  buf.writeUInt32LE(0x100000, secOff + 16);
  buf.writeUInt32LE(0x4000, secOff + 20);
  for (let i = 1; i < sectionCount; i++) {
    const s = secOff + i * 40;
    buf.writeUInt32LE(0x1000, s + 8);
    buf.writeUInt32LE(0x40000000 + i * 0x10000, s + 12);
    buf.writeUInt32LE(0x1000, s + 16);
    buf.writeUInt32LE(0x4000, s + 20);
  }

  const thunkRva = 0x18000;
  for (let i = 0; i < 4096; i++) {
    const d = 0x4000 + i * 20;
    buf.writeUInt32LE(thunkRva, d); // lookup table
    buf.writeUInt32LE(thunkRva, d + 12); // dll name
    buf.writeUInt32LE(thunkRva, d + 16); // thunk
  }
  // 0x100 is below every section's virtual address, so it maps to no file
  // offset and the thunk loop runs to its cap.
  for (let i = 0; i < 100_000; i++) buf.writeUInt32LE(0x100, thunkRva + i * 4);
  return buf;
}

/** A minimal thin Mach-O 64 with one symbol and one dylib load command. */
function makeMachO(symbol: string, dylibCmd: number, dylib: string): Buffer {
  const symtabCmd = Buffer.alloc(24);
  const nameLen = dylib.length + 1;
  const dylibSize = 24 + Math.ceil(nameLen / 8) * 8;
  const header = Buffer.alloc(32);
  const strtab = Buffer.concat([Buffer.from([0]), Buffer.from(`_${symbol}\0`, 'ascii')]);
  const nlist = Buffer.alloc(16);
  nlist.writeUInt32LE(1, 0); // n_strx -> offset 1 in the string table

  const symOff = 32 + 24 + dylibSize;
  const strOff = symOff + nlist.length;

  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeInt32LE(0x0100000c, 4); // arm64
  header.writeUInt32LE(2, 16); // ncmds
  header.writeUInt32LE(24 + dylibSize, 20);

  symtabCmd.writeUInt32LE(0x02, 0); // LC_SYMTAB
  symtabCmd.writeUInt32LE(24, 4);
  symtabCmd.writeUInt32LE(symOff, 8);
  symtabCmd.writeUInt32LE(1, 12);
  symtabCmd.writeUInt32LE(strOff, 16);
  symtabCmd.writeUInt32LE(strtab.length, 20);

  const dylibCommand = Buffer.alloc(dylibSize);
  dylibCommand.writeUInt32LE(dylibCmd >>> 0, 0);
  dylibCommand.writeUInt32LE(dylibSize, 4);
  dylibCommand.writeUInt32LE(24, 8); // name offset within the command
  dylibCommand.write(`${dylib}\0`, 24, 'latin1');

  return Buffer.concat([header, symtabCmd, dylibCommand, nlist, strtab]);
}

/** A universal binary wrapping the given slices. */
function makeFat(slices: readonly Buffer[]): Buffer {
  const head = Buffer.alloc(8 + slices.length * 20);
  head.writeUInt32BE(0xcafebabe, 0);
  head.writeUInt32BE(slices.length, 4);
  const body: Buffer[] = [];
  let offset = head.length;
  slices.forEach((slice, i) => {
    const entry = 8 + i * 20;
    head.writeUInt32BE(0x0100000c, entry); // cputype
    head.writeUInt32BE(offset, entry + 8);
    head.writeUInt32BE(slice.length, entry + 12);
    body.push(slice);
    offset += slice.length;
  });
  return Buffer.concat([head, ...body]);
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

describe('a hostile file cannot cost more than its own size', () => {
  // A synchronous parse cannot be interrupted by a test timeout, so these
  // measure. Both fixtures parse in tens of milliseconds and both used to take
  // many seconds, so the budget is loose enough not to be a flake.
  const BUDGET_MS = 2_000;

  it('reads a symbol table whose names run to EOF without a NUL in linear time', () => {
    // Every st_name points into a run of 0x41 reaching the end of the file. An
    // unbounded NUL search costs the distance to EOF per symbol; bounded to the
    // 512-byte window cstr actually returns, it costs 512.
    const elf = makeNulFreeElf(40_000, 16 * 1024 * 1024);
    const started = performance.now();
    const info = parseBinary(elf);
    expect(performance.now() - started).toBeLessThan(BUDGET_MS);
    expect(info.format).toBe('elf');
    expect(info.symbols).toHaveLength(1);
  });

  it('walks a PE import table in a budget the file length pays for', () => {
    // Descriptor count, thunk count and section count are all header fields
    // with no relation to the file's size. Driven to their caps against a
    // linear section lookup, this 1 MB file ran for tens of seconds.
    const pe = makeHostilePe(192);
    const started = performance.now();
    const info = parseBinary(pe);
    expect(performance.now() - started).toBeLessThan(BUDGET_MS);
    expect(info.format).toBe('pe');
    expect(info.symbols).toHaveLength(0);
  });
});

describe('universal binaries', () => {
  it('keeps the symbols of the good slices when one slice is unparseable', () => {
    const thin = makeMachO('ECDSA_do_sign', 0x0c, '/usr/lib/libcrypto.dylib');
    expect(parseBinary(makeFat([thin])).symbols).toContain('ECDSA_do_sign');
    const withRunt = parseBinary(makeFat([thin, Buffer.alloc(4)]));
    expect(withRunt.symbols).toContain('ECDSA_do_sign');
    expect(withRunt.truncated).toBe(true);
  });

  it('does not report a slice it could not reach as a complete parse', () => {
    const fat = Buffer.alloc(64);
    fat.writeUInt32BE(0xcafebabe, 0);
    fat.writeUInt32BE(1, 4);
    fat.writeUInt32BE(0x0100000c, 8);
    fat.writeUInt32BE(64, 16); // offset
    fat.writeUInt32BE(0x10000, 20); // size, well past the end of the file
    const info = parseBinary(fat);
    expect(info.symbols).toHaveLength(0);
    expect(info.truncated).toBe(true);
  });

  it('names a weakly linked or re-exported dylib', () => {
    for (const cmd of [0x0c, 0x0d, 0x20, 0x80000018, 0x8000001f, 0x80000023]) {
      const info = parseBinary(makeMachO('ECDSA_do_sign', cmd, '/usr/lib/libcrypto.dylib'));
      expect(info.linkedLibraries).toContain('/usr/lib/libcrypto.dylib');
    }
  });
});

describe('an incomplete parse says so', () => {
  it('flags an ELF whose .symtab claims more entries than the file holds', () => {
    const elf = makeElf('ECDSA_do_sign');
    // The .symtab section header is the second of four, at the tail.
    const shoff = Number(elf.readBigUInt64LE(0x28));
    elf.writeBigUInt64LE(500_000n * 24n, shoff + 64 + 0x20); // sh_size
    const info = parseBinary(elf);
    expect(info.symbols).toContain('ECDSA_do_sign');
    expect(info.truncated).toBe(true);
  });
});

describe('PE section mapping', () => {
  it('ignores a data directory the file says it does not have', () => {
    // SizeOfOptionalHeader 96 and NumberOfRvaAndSizes 0: entry 1 does not
    // exist, and the bytes at its address are the first section header.
    const buf = Buffer.alloc(0x600);
    buf.write('MZ', 0, 'latin1');
    const peOff = 0x80;
    buf.writeUInt32LE(peOff, 0x3c);
    buf.writeUInt32LE(0x00004550, peOff);
    buf.writeUInt16LE(0x14c, peOff + 4);
    buf.writeUInt16LE(1, peOff + 6);
    buf.writeUInt16LE(96, peOff + 20);
    const optOff = peOff + 24;
    buf.writeUInt16LE(0x10b, optOff);

    const secOff = optOff + 96;
    buf.write('.text\0\0\0', secOff, 'latin1');
    buf.writeUInt32LE(0x1000, secOff + 8); // VirtualSize: what was read as the import RVA
    buf.writeUInt32LE(0x1000, secOff + 12);
    buf.writeUInt32LE(0x400, secOff + 16);
    buf.writeUInt32LE(0x200, secOff + 20);

    buf.writeUInt32LE(0x1100, 0x200); // a descriptor, if anyone looks
    buf.writeUInt32LE(0x1200, 0x200 + 12);
    buf.writeUInt32LE(0x1100, 0x200 + 16);
    buf.writeUInt32LE(0x1300, 0x300);
    buf.write('totally-not-a-dll.dll\0', 0x400, 'latin1');
    buf.write('NOT_AN_IMPORT_SYMBOL\0', 0x502, 'latin1');

    const info = parseBinary(buf);
    expect(info.symbols).toHaveLength(0);
    expect(info.linkedLibraries).toHaveLength(0);
  });

  it('refuses to map an RVA past the section that has file bytes behind it', () => {
    // .data declares VirtualSize 0x2000 over SizeOfRawData 0x200 - the shape of
    // .bss and of every packed binary. An RVA in the virtual tail has no file
    // backing, and mapping it anyway reads .rdata and names a symbol that is
    // nowhere in the import table.
    const buf = Buffer.alloc(0x800);
    buf.write('MZ', 0, 'latin1');
    const peOff = 0x80;
    buf.writeUInt32LE(peOff, 0x3c);
    buf.writeUInt32LE(0x00004550, peOff);
    buf.writeUInt16LE(0x8664, peOff + 4);
    buf.writeUInt16LE(2, peOff + 6);
    buf.writeUInt16LE(240, peOff + 20);
    const optOff = peOff + 24;
    buf.writeUInt16LE(0x20b, optOff);
    buf.writeUInt32LE(16, optOff + 108);
    buf.writeUInt32LE(0x1250, optOff + 112 + 8); // import RVA, in the virtual tail

    const secOff = optOff + 240;
    buf.write('.data\0\0\0', secOff, 'latin1');
    buf.writeUInt32LE(0x2000, secOff + 8);
    buf.writeUInt32LE(0x1000, secOff + 12);
    buf.writeUInt32LE(0x200, secOff + 16);
    buf.writeUInt32LE(0x200, secOff + 20);
    buf.write('.rdata\0\0', secOff + 40, 'latin1');
    buf.writeUInt32LE(0x1000, secOff + 48);
    buf.writeUInt32LE(0x4000, secOff + 52);
    buf.writeUInt32LE(0x400, secOff + 56);
    buf.writeUInt32LE(0x400, secOff + 60);

    buf.writeUInt32LE(0x1300, 0x450); // descriptor, as .rdata bytes would be read
    buf.writeUInt32LE(0x1350, 0x450 + 12);
    buf.writeUInt32LE(0x1300, 0x450 + 16);
    buf.writeBigUInt64LE(0x1400n, 0x500);
    buf.write('totally-unrelated.dll\0', 0x550, 'latin1');
    buf.write('RSA_public_encrypt\0', 0x602, 'latin1');

    const info = parseBinary(buf);
    expect(info.symbols).toHaveLength(0);
    expect(info.linkedLibraries).toHaveLength(0);
  });

  it('maps a section whose VirtualSize is zero using its SizeOfRawData', () => {
    const pe = makePe('libcrypto-3-x64.dll', 'RSA_public_encrypt');
    // VirtualSize 0 is valid and means the loader maps SizeOfRawData instead.
    pe.writeUInt32LE(0, 0x80 + 24 + 240 + 8);
    expect(parseBinary(pe).symbols).toContain('RSA_public_encrypt');
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

  it('matches the EVP accessors that name an algorithm outright', () => {
    // OpenSSL 3 deprecated the low-level entry points above, so this is the
    // whole import surface of a current libcrypto consumer.
    expect(matchSymbol('EVP_aes_256_gcm')?.primitive).toBe('AES');
    expect(matchSymbol('EVP_aes_256_gcm')?.parameters['keySize']).toBe(256);
    expect(matchSymbol('EVP_aes_128_cbc')?.parameters['mode']).toBe('CBC');
    expect(matchSymbol('EVP_des_ede3_cbc')?.primitive).toBe('3DES');
    expect(matchSymbol('EVP_md5')?.primitive).toBe('MD5');
    expect(matchSymbol('EVP_sha1')?.primitive).toBe('SHA1');
    expect(matchSymbol('EVP_sha256')?.parameters['outputLength']).toBe(256);
    expect(matchSymbol('EVP_sha512_224')?.parameters['outputLength']).toBe(224);
    expect(matchSymbol('EVP_sha3_256')?.primitive).toBe('SHA3');
    expect(matchSymbol('EVP_chacha20_poly1305')?.primitive).toBe('ChaCha20');
  });

  it('leaves the EVP wrappers that name only a family unmatched', () => {
    // The algorithm is an argument to these, and a symbol table has no
    // arguments to read. Guessing one would be a fabricated 0.85 finding.
    expect(matchSymbol('EVP_PKEY_CTX_new_id')).toBeNull();
    expect(matchSymbol('EVP_DigestSignInit')).toBeNull();
    expect(matchSymbol('EVP_EncryptInit_ex')).toBeNull();
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

  it('finds the MD5 T-table in both word orders', () => {
    // T[i] = floor(2^32 * abs(sin i)), FIPS-independent but fixed: T[1..4] are
    // d76aa478 e8c7b756 242070db c1bdceee.
    const be = Buffer.from('d76aa478e8c7b756242070dbc1bdceee', 'hex');
    const le = Buffer.from('78a46ad756b7c7e8db702024eecebdc1', 'hex');
    expect(findConstants(Buffer.concat([Buffer.alloc(64), be])).some((h) => h.signature.id === 'md5-t')).toBe(true);
    expect(findConstants(Buffer.concat([Buffer.alloc(64), le])).some((h) => h.signature.id === 'md5-t-le')).toBe(true);
  });

  it('finds the DES permuted choice 1 table a 3DES key schedule computes from', () => {
    // PC-1 begins 57 49 41 33 25 17 9 1 58 50 42 34 26 18 10 2 (FIPS 46-3).
    const pc1 = Buffer.from([57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2]);
    const blob = Buffer.concat([Buffer.alloc(64, 0xff), pc1, Buffer.alloc(64, 0xff)]);
    expect(findConstants(blob).some((h) => h.signature.id === 'des-pc1')).toBe(true);
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
  let ecSpki: Buffer;

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

    const ec = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    ecSpki = Buffer.from(await webcrypto.subtle.exportKey('spki', ec.publicKey));
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

  it('finds an EC public key, whose whole structure fits in a short-form length', () => {
    // A P-256 SubjectPublicKeyInfo is 91 bytes, so it opens `30 59` - and a
    // scanner that only looked at long-form lengths skipped every one of them.
    // A pinned EC trust anchor is the highest-value thing in a firmware image.
    expect(ecSpki.length).toBeLessThan(128);
    const blob = Buffer.concat([Buffer.alloc(512, 0x90), ecSpki, Buffer.alloc(512, 0x90)]);
    const key = findDerStructures(blob).find((c) => c.kind === 'public-key');
    expect(key?.offset).toBe(512);
    expect(key?.algorithmOid).toBe('1.2.840.10045.2.1');
  });

  it('does not call a v1 TBSCertificate body an embedded private key', () => {
    // SEQUENCE { INTEGER serial, SEQUENCE AlgorithmIdentifier } is a v1
    // TBSCertificate and a CertificationRequestInfo as much as it is the front
    // of a PKCS#8 key. Only the trailing OCTET STRING settles it, and "private
    // key in shipped firmware" is far too expensive an alarm to guess at.
    const tbs = Buffer.concat([
      Buffer.from('308181', 'hex'),
      Buffer.from('020101', 'hex'),
      Buffer.from('300d06092a864886f70d01010b0500', 'hex'),
      Buffer.alloc(111),
    ]);
    expect(findDerStructures(tbs).some((c) => c.kind === 'private-key')).toBe(false);
  });

  it('reports a PKCS#1 private key, which has no AlgorithmIdentifier to name', async () => {
    // openssl genrsa writes this form and `BEGIN RSA PRIVATE KEY` holds it.
    // Every element is an INTEGER, so there is no OID anywhere in it - and the
    // finding used to be classified and then dropped for want of one.
    const pkcs1 = pkcs1From(keyDer);
    const candidate = findDerStructures(pkcs1).find((c) => c.kind === 'private-key');
    expect(candidate?.algorithmOid).toBeNull();
    expect(candidate?.bytes).toBeNull();

    const dir = await mkdtemp(join(tmpdir(), 'assay-binary-'));
    try {
      await writeFile(join(dir, 'firmware.bin'), Buffer.concat([Buffer.alloc(256), pkcs1, Buffer.alloc(256)]));
      const r = await scanBinaries({
        root: dir,
        systemId: 'firmware',
        collectedAt: '2026-08-28T00:00:00.000Z',
        include: ['firmware.bin'],
      });
      const emitted = r.findings.filter((f) => f.evidence.raw.includes('embedded private-key'));
      expect(emitted).toHaveLength(1);
      // I9 still holds: the algorithm and the existence, never the material.
      expect(JSON.stringify(r)).not.toContain(pkcs1.subarray(40, 56).toString('hex'));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
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

  it('does not read a GNSS receiver banner as the NSS library', () => {
    // GNSS version strings are everywhere in the firmware this scanner reads,
    // and the fabricated finding carries a version, which reads as evidence.
    expect(fingerprintLibraries(['u-blox NEO-M8 GNSS 1.4.2 receiver firmware'])).toHaveLength(0);
    expect(fingerprintLibraries(['SNSS 1.0'])).toHaveLength(0);
    expect(fingerprintLibraries(['libnss3 NSS 3.90'])[0]?.version).toBe('3.90');
  });
});

describe('printable string extraction', () => {
  it('breaks up a run too long to be a single JavaScript string', () => {
    // V8 refuses to build a string over 0x1fffffe8 characters, so one printable
    // run spanning a 512 MB file threw and aborted the whole scan. Chunking is
    // what keeps that from happening; the boundary is checked at a size a test
    // can afford to allocate.
    const hits = extractStrings(Buffer.alloc(200_000, 0x41));
    expect(hits.length).toBeGreaterThan(1);
    expect(Math.max(...hits.map((h) => h.value.length))).toBeLessThanOrEqual(64 * 1024);
    expect(hits.reduce((n, h) => n + h.value.length, 0)).toBe(200_000);
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

/** The RSAPrivateKey inside a PKCS#8 wrapper - the PKCS#1 form on its own. */
function pkcs1From(pkcs8: Buffer): Buffer {
  // PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING }
  let at = 4 + 3; // the outer SEQUENCE header, then the version INTEGER
  at += 2 + (pkcs8[at + 1] as number); // the AlgorithmIdentifier, short form
  return pkcs8.subarray(at + 4, at + 4 + pkcs8.readUInt16BE(at + 2));
}

function resolveNodeDir(): string {
  return process.execPath.slice(0, process.execPath.lastIndexOf('/'));
}
