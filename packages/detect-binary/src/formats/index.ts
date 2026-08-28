/**
 * Executable format parsing: ELF, Mach-O (incl. universal), PE/COFF.
 *
 * The goal is the imported symbol table, which is the strong signal in a
 * stripped binary: `EVP_PKEY_CTX_new_id` and `ECDSA_do_sign` name the
 * operation and the library. Everything here is bounds-checked against a
 * length the file itself supplied, because a malformed or hostile binary is
 * exactly the input this code will be pointed at.
 */

export type BinaryFormat = 'elf' | 'macho' | 'pe' | 'unknown';

export interface BinaryInfo {
  readonly format: BinaryFormat;
  readonly arch: string;
  /** Imported and defined symbol names, deduplicated and sorted. */
  readonly symbols: readonly string[];
  /** Shared libraries this binary links against, where the format names them. */
  readonly linkedLibraries: readonly string[];
  readonly truncated: boolean;
}

const EMPTY: BinaryInfo = {
  format: 'unknown',
  arch: 'unknown',
  symbols: [],
  linkedLibraries: [],
  truncated: false,
};

export function detectFormat(data: Buffer): BinaryFormat {
  if (data.byteLength < 4) return 'unknown';
  if (data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) return 'elf';
  const magic = data.readUInt32LE(0);
  if (magic === 0xfeedface || magic === 0xfeedfacf) return 'macho';
  const be = data.readUInt32BE(0);
  if (be === 0xfeedface || be === 0xfeedfacf) return 'macho';
  // Universal ("fat") binary: 0xcafebabe. Java class files share the magic, so
  // the archive count is sanity-checked before committing to Mach-O.
  if (be === 0xcafebabe && data.byteLength >= 8 && data.readUInt32BE(4) < 32) return 'macho';
  if (be === 0xcafebabf) return 'macho';
  if (data[0] === 0x4d && data[1] === 0x5a) return 'pe';
  return 'unknown';
}

export function parseBinary(data: Buffer): BinaryInfo {
  try {
    switch (detectFormat(data)) {
      case 'elf':
        return parseElf(data);
      case 'macho':
        return parseMachO(data);
      case 'pe':
        return parsePe(data);
      default:
        return EMPTY;
    }
  } catch {
    // A parse failure is a fact about the file, not a reason to abort a scan
    // of ten thousand of them.
    return { ...EMPTY, format: detectFormat(data), truncated: true };
  }
}

/* ---------------------------------------------------------------------- ELF */

const ELF_ARCH: Readonly<Record<number, string>> = {
  0x03: 'x86',
  0x28: 'arm',
  0x3e: 'x86_64',
  0xb7: 'aarch64',
  0xf3: 'riscv',
};

function parseElf(data: Buffer): BinaryInfo {
  const is64 = data[4] === 2;
  const little = data[5] === 1;
  const u16 = (o: number): number => (little ? data.readUInt16LE(o) : data.readUInt16BE(o));
  const u32 = (o: number): number => (little ? data.readUInt32LE(o) : data.readUInt32BE(o));
  const uN = (o: number): number =>
    is64 ? Number(little ? data.readBigUInt64LE(o) : data.readBigUInt64BE(o)) : u32(o);

  const arch = ELF_ARCH[u16(18)] ?? `elf-machine-${u16(18)}`;
  const shoff = uN(is64 ? 0x28 : 0x20);
  const shentsize = u16(is64 ? 0x3a : 0x2e);
  const shnum = u16(is64 ? 0x3c : 0x30);
  const shstrndx = u16(is64 ? 0x3e : 0x32);

  if (shoff === 0 || shnum === 0 || shoff + shnum * shentsize > data.byteLength) {
    return { ...EMPTY, format: 'elf', arch, truncated: true };
  }

  interface Section {
    name: string;
    type: number;
    offset: number;
    size: number;
    link: number;
    entsize: number;
  }
  const raw: Omit<Section, 'name'>[] = [];
  for (let i = 0; i < shnum; i++) {
    const base = shoff + i * shentsize;
    raw.push({
      type: u32(base + 4),
      offset: uN(base + (is64 ? 0x18 : 0x10)),
      size: uN(base + (is64 ? 0x20 : 0x14)),
      link: u32(base + (is64 ? 0x28 : 0x18)),
      entsize: uN(base + (is64 ? 0x38 : 0x24)),
    });
  }
  const nameOffsets = Array.from({ length: shnum }, (_, i) => u32(shoff + i * shentsize));
  const shstr = raw[shstrndx];
  const sections: Section[] = raw.map((s, i) => ({
    ...s,
    name: shstr === undefined ? '' : cstr(data, shstr.offset + (nameOffsets[i] ?? 0)),
  }));

  const symbols = new Set<string>();
  const libraries = new Set<string>();

  // SHT_SYMTAB = 2, SHT_DYNSYM = 11.
  for (const section of sections) {
    if (section.type !== 2 && section.type !== 11) continue;
    const strtab = sections[section.link];
    if (strtab === undefined) continue;
    const entsize = section.entsize > 0 ? section.entsize : is64 ? 24 : 16;
    const count = Math.floor(section.size / entsize);
    for (let i = 0; i < count && i < 200_000; i++) {
      const off = section.offset + i * entsize;
      if (off + 4 > data.byteLength) break;
      const nameOff = u32(off);
      if (nameOff === 0) continue;
      const name = cstr(data, strtab.offset + nameOff);
      if (name !== '') symbols.add(name);
    }
  }

  // DT_NEEDED entries in .dynamic name the shared libraries.
  const dynamic = sections.find((s) => s.name === '.dynamic');
  const dynstr = sections.find((s) => s.name === '.dynstr');
  if (dynamic !== undefined && dynstr !== undefined) {
    const step = is64 ? 16 : 8;
    for (let off = dynamic.offset; off + step <= dynamic.offset + dynamic.size; off += step) {
      if (off + step > data.byteLength) break;
      const tag = uN(off);
      if (tag === 0) break;
      if (tag === 1) libraries.add(cstr(data, dynstr.offset + uN(off + step / 2)));
    }
  }

  return {
    format: 'elf',
    arch,
    symbols: [...symbols].sort(),
    linkedLibraries: [...libraries].filter(Boolean).sort(),
    truncated: false,
  };
}

/* ------------------------------------------------------------------- Mach-O */

const MACHO_ARCH: Readonly<Record<number, string>> = {
  7: 'x86',
  0x01000007: 'x86_64',
  12: 'arm',
  0x0100000c: 'arm64',
};

function parseMachO(data: Buffer): BinaryInfo {
  const be = data.readUInt32BE(0);
  if (be === 0xcafebabe || be === 0xcafebabf) {
    // Universal binary: parse every slice and union the results, because a
    // library can genuinely differ between architectures.
    const wide = be === 0xcafebabf;
    const count = data.readUInt32BE(4);
    const merged: BinaryInfo[] = [];
    for (let i = 0; i < count && i < 32; i++) {
      const entry = 8 + i * (wide ? 32 : 20);
      if (entry + (wide ? 32 : 20) > data.byteLength) break;
      const offset = wide ? Number(data.readBigUInt64BE(entry + 8)) : data.readUInt32BE(entry + 8);
      const size = wide ? Number(data.readBigUInt64BE(entry + 16)) : data.readUInt32BE(entry + 12);
      if (offset + size > data.byteLength) continue;
      merged.push(parseMachO(data.subarray(offset, offset + size)));
    }
    return {
      format: 'macho',
      arch: merged.map((m) => m.arch).join('+') || 'universal',
      symbols: [...new Set(merged.flatMap((m) => m.symbols))].sort(),
      linkedLibraries: [...new Set(merged.flatMap((m) => m.linkedLibraries))].sort(),
      truncated: merged.some((m) => m.truncated),
    };
  }

  const magic = data.readUInt32LE(0);
  const is64 = magic === 0xfeedfacf;
  const arch = MACHO_ARCH[data.readInt32LE(4)] ?? `cpu-${data.readInt32LE(4)}`;
  const ncmds = data.readUInt32LE(16);
  let offset = is64 ? 32 : 28;

  const symbols = new Set<string>();
  const libraries = new Set<string>();

  for (let i = 0; i < ncmds && offset + 8 <= data.byteLength; i++) {
    const cmd = data.readUInt32LE(offset);
    const cmdsize = data.readUInt32LE(offset + 4);
    if (cmdsize < 8 || offset + cmdsize > data.byteLength) break;

    if (cmd === 0x02) {
      // LC_SYMTAB
      const symoff = data.readUInt32LE(offset + 8);
      const nsyms = data.readUInt32LE(offset + 12);
      const stroff = data.readUInt32LE(offset + 16);
      const nlistSize = is64 ? 16 : 12;
      for (let s = 0; s < nsyms && s < 200_000; s++) {
        const n = symoff + s * nlistSize;
        if (n + nlistSize > data.byteLength) break;
        const strx = data.readUInt32LE(n);
        if (strx === 0) continue;
        const name = cstr(data, stroff + strx);
        if (name !== '') symbols.add(name.replace(/^_/, ''));
      }
    } else if (cmd === 0x0c || cmd === 0x0d || cmd === 0x1f || cmd === 0x20) {
      // LC_LOAD_DYLIB and friends: the name is at an offset within the command.
      const nameOff = data.readUInt32LE(offset + 8);
      if (nameOff < cmdsize) libraries.add(cstr(data, offset + nameOff));
    }
    offset += cmdsize;
  }

  return {
    format: 'macho',
    arch,
    symbols: [...symbols].sort(),
    linkedLibraries: [...libraries].filter(Boolean).sort(),
    truncated: false,
  };
}

/* -------------------------------------------------------------------- PE */

function parsePe(data: Buffer): BinaryInfo {
  const peOff = data.readUInt32LE(0x3c);
  if (peOff + 24 > data.byteLength || data.readUInt32LE(peOff) !== 0x00004550) {
    return { ...EMPTY, format: 'pe', truncated: true };
  }
  const machine = data.readUInt16LE(peOff + 4);
  const arch = machine === 0x8664 ? 'x86_64' : machine === 0x14c ? 'x86' : machine === 0xaa64 ? 'arm64' : `pe-${machine}`;
  const numberOfSections = data.readUInt16LE(peOff + 6);
  const sizeOfOptional = data.readUInt16LE(peOff + 20);
  const optOff = peOff + 24;
  const pe32Plus = data.readUInt16LE(optOff) === 0x20b;

  // Data directory entry 1 is the import table.
  const dirOff = optOff + (pe32Plus ? 112 : 96);
  if (dirOff + 16 > data.byteLength) return { ...EMPTY, format: 'pe', arch, truncated: true };
  const importRva = data.readUInt32LE(dirOff + 8);
  if (importRva === 0) return { format: 'pe', arch, symbols: [], linkedLibraries: [], truncated: false };

  interface Sec {
    va: number;
    vsize: number;
    raw: number;
  }
  const sections: Sec[] = [];
  const secOff = optOff + sizeOfOptional;
  for (let i = 0; i < numberOfSections; i++) {
    const s = secOff + i * 40;
    if (s + 40 > data.byteLength) break;
    sections.push({ va: data.readUInt32LE(s + 12), vsize: data.readUInt32LE(s + 8), raw: data.readUInt32LE(s + 20) });
  }
  const toFile = (rva: number): number => {
    for (const s of sections) {
      if (rva >= s.va && rva < s.va + Math.max(s.vsize, 1)) return s.raw + (rva - s.va);
    }
    return -1;
  };

  const symbols = new Set<string>();
  const libraries = new Set<string>();
  let entry = toFile(importRva);

  for (let i = 0; entry >= 0 && entry + 20 <= data.byteLength && i < 4096; i++, entry += 20) {
    const lookupRva = data.readUInt32LE(entry);
    const nameRva = data.readUInt32LE(entry + 12);
    const thunkRva = data.readUInt32LE(entry + 16);
    if (lookupRva === 0 && nameRva === 0 && thunkRva === 0) break;

    const nameOff = toFile(nameRva);
    if (nameOff >= 0) libraries.add(cstr(data, nameOff).toLowerCase());

    let thunk = toFile(lookupRva !== 0 ? lookupRva : thunkRva);
    const step = pe32Plus ? 8 : 4;
    for (let j = 0; thunk >= 0 && thunk + step <= data.byteLength && j < 100_000; j++, thunk += step) {
      const value = pe32Plus ? data.readBigUInt64LE(thunk) : BigInt(data.readUInt32LE(thunk));
      if (value === 0n) break;
      const ordinalFlag = pe32Plus ? 1n << 63n : 1n << 31n;
      if ((value & ordinalFlag) !== 0n) continue; // imported by ordinal; no name
      const hintOff = toFile(Number(value));
      if (hintOff >= 0) {
        const name = cstr(data, hintOff + 2);
        if (name !== '') symbols.add(name);
      }
    }
  }

  return {
    format: 'pe',
    arch,
    symbols: [...symbols].sort(),
    linkedLibraries: [...libraries].filter(Boolean).sort(),
    truncated: false,
  };
}

/* ------------------------------------------------------------------ helpers */

function cstr(data: Buffer, offset: number, max = 512): string {
  if (offset < 0 || offset >= data.byteLength) return '';
  const end = Math.min(offset + max, data.byteLength);
  const nul = data.indexOf(0, offset);
  return data.toString('utf8', offset, nul >= 0 && nul < end ? nul : end);
}
