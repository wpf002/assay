/**
 * Printable string extraction.
 *
 * The weakest modality in the tool (BINARY_STRING, ceiling 0.30) and the one
 * that produces the most output, which is exactly the combination that makes
 * other scanners unusable. It earns its place for two things it does well:
 * library version fingerprints, and directing attention. It is arithmetically
 * incapable of confirming anything on its own.
 */

export interface StringHit {
  readonly value: string;
  readonly offset: number;
  readonly encoding: 'ascii' | 'utf16le';
}

/**
 * Longest string this will build in one piece.
 *
 * A printable run can be as long as the file, and V8 refuses to construct a
 * string over 0x1fffffe8 characters - so a 512 MB blob of 0x41, a size the
 * default maxFileBytes admits, threw out of extractStrings and took the whole
 * scan down with it, every later file included. A long run is emitted in
 * chunks instead: nothing is dropped and no single string approaches the limit.
 */
const MAX_RUN_CHARS = 64 * 1024;

function pushRun(
  out: StringHit[],
  data: Buffer,
  start: number,
  end: number,
  encoding: 'ascii' | 'utf16le',
  limit: number,
): void {
  const chunk = MAX_RUN_CHARS * (encoding === 'utf16le' ? 2 : 1);
  for (let at = start; at < end && out.length < limit; at += chunk) {
    const stop = Math.min(at + chunk, end);
    out.push({
      value: data.toString(encoding === 'utf16le' ? 'utf16le' : 'latin1', at, stop),
      offset: at,
      encoding,
    });
  }
}

export function extractStrings(data: Buffer, minLength = 6, limit = 20_000): StringHit[] {
  const out: StringHit[] = [];

  let start = -1;
  for (let i = 0; i <= data.byteLength && out.length < limit; i++) {
    const b = i < data.byteLength ? (data[i] as number) : 0;
    const printable = b >= 0x20 && b <= 0x7e;
    if (printable) {
      if (start < 0) start = i;
      continue;
    }
    if (start >= 0 && i - start >= minLength) {
      pushRun(out, data, start, i, 'ascii', limit);
    }
    start = -1;
  }

  // UTF-16LE, which is where every Windows binary keeps its version strings.
  let wstart = -1;
  for (let i = 0; i + 1 < data.byteLength && out.length < limit; i += 2) {
    const lo = data[i] as number;
    const hi = data[i + 1] as number;
    const printable = hi === 0 && lo >= 0x20 && lo <= 0x7e;
    if (printable) {
      if (wstart < 0) wstart = i;
      continue;
    }
    if (wstart >= 0 && (i - wstart) / 2 >= minLength) {
      pushRun(out, data, wstart, i, 'utf16le', limit);
    }
    wstart = -1;
  }

  return out;
}

/**
 * Strings that suggest cryptography. Deliberately narrow: this modality is
 * capped at 0.30 anyway, and a loose pattern turns a scan into a wall of
 * matches on the word "key".
 */
const CRYPTO_STRING =
  /\b(AES-(?:128|192|256)-(?:GCM|CBC|CTR|ECB)|RSA-(?:1024|2048|3072|4096)|ECDSA|ECDHE?|X25519|Ed25519|ChaCha20-Poly1305|3DES|DES-EDE3|RC4|MD5|SHA-?1|SHA-?(?:224|256|384|512)|PBKDF2|scrypt|Argon2|TLS_[A-Z0-9_]{8,}|ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d{3}|diffie-hellman-group\d+)\b/;

export function cryptoStrings(hits: readonly StringHit[], limit = 400): StringHit[] {
  const seen = new Set<string>();
  const out: StringHit[] = [];
  for (const hit of hits) {
    if (!CRYPTO_STRING.test(hit.value)) continue;
    if (seen.has(hit.value)) continue;
    seen.add(hit.value);
    out.push(hit);
    if (out.length >= limit) break;
  }
  return out;
}
