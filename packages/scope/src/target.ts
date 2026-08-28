/**
 * Target matching. Every function here is a place an out-of-scope host could
 * slip through, so each rule is narrow and stated explicitly.
 */

export type TargetKind = 'cidr4' | 'cidr6' | 'hostname' | 'glob';

export function classify(target: string): TargetKind {
  if (target.includes('/')) return target.includes(':') ? 'cidr6' : 'cidr4';
  if (target.startsWith('*.')) return 'glob';
  return 'hostname';
}

export function matchesTarget(target: string, host: string): boolean {
  switch (classify(target)) {
    case 'cidr4':
      return matchCidr4(target, host);
    case 'cidr6':
      return matchCidr6(target, host);
    case 'glob':
      return matchGlob(target, host);
    case 'hostname':
      return normalizeHost(target) === normalizeHost(host);
  }
}

/** Lowercase, strip one trailing dot, strip brackets from an IPv6 literal. */
export function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
}

/**
 * `*.example.com` matches `api.example.com` but NOT `example.com` and NOT
 * `a.b.example.com`. A glob that crossed dots would turn one authorized
 * subdomain into an authorized subtree, which is the most likely way a grant
 * gets accidentally over-broad.
 */
function matchGlob(pattern: string, host: string): boolean {
  const suffix = normalizeHost(pattern.slice(2));
  const h = normalizeHost(host);
  if (!h.endsWith(`.${suffix}`)) return false;
  const label = h.slice(0, h.length - suffix.length - 1);
  return label.length > 0 && !label.includes('.');
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    // Reject non-canonical octets. `010.0.0.1` is decimal here but octal to
    // some resolvers, and a target string that reads as one address to a human
    // reviewer and another to a resolver is exactly how an allowlist gets
    // walked past. Canonical form or nothing.
    if (!/^(0|[1-9]\d{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out = (out << 8) | n;
  }
  return out >>> 0;
}

function matchCidr4(cidr: string, host: string): boolean {
  const [network, bitsRaw] = cidr.split('/');
  if (network === undefined || bitsRaw === undefined) return false;
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const net = ipv4ToInt(network);
  const addr = ipv4ToInt(normalizeHost(host));
  if (net === null || addr === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (net & mask) === (addr & mask);
}

/** Expands `::` and rejects anything that is not a full literal address. */
export function ipv6ToBytes(ip: string): Uint8Array | null {
  const addr = normalizeHost(ip).split('%')[0] as string;
  if (!/^[0-9a-f:.]+$/.test(addr)) return null;
  const doubleColons = addr.split('::').length - 1;
  if (doubleColons > 1) return null;

  let head: string[] = [];
  let tail: string[] = [];
  if (doubleColons === 1) {
    const [h, t] = addr.split('::');
    head = (h ?? '').split(':').filter(Boolean);
    tail = (t ?? '').split(':').filter(Boolean);
  } else {
    head = addr.split(':');
    if (head.length !== 8 && !addr.includes('.')) return null;
  }

  // Trailing IPv4 form: ::ffff:192.0.2.1
  const expandV4 = (groups: string[]): string[] | null => {
    const last = groups[groups.length - 1];
    if (last === undefined || !last.includes('.')) return groups;
    const v4 = ipv4ToInt(last);
    if (v4 === null) return null;
    return [
      ...groups.slice(0, -1),
      ((v4 >>> 16) & 0xffff).toString(16),
      (v4 & 0xffff).toString(16),
    ];
  };
  const h2 = expandV4(head);
  const t2 = expandV4(tail);
  if (h2 === null || t2 === null) return null;

  const fill = 8 - h2.length - t2.length;
  if (fill < 0 || (doubleColons === 0 && fill !== 0)) return null;
  const groups = [...h2, ...Array<string>(fill).fill('0'), ...t2];
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = groups[i] as string;
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    bytes[i * 2] = (v >> 8) & 0xff;
    bytes[i * 2 + 1] = v & 0xff;
  }
  return bytes;
}

function matchCidr6(cidr: string, host: string): boolean {
  const idx = cidr.lastIndexOf('/');
  if (idx < 0) return false;
  const bits = Number(cidr.slice(idx + 1));
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  const net = ipv6ToBytes(cidr.slice(0, idx));
  const addr = ipv6ToBytes(host);
  if (net === null || addr === null) return false;

  const fullBytes = bits >> 3;
  for (let i = 0; i < fullBytes; i++) {
    if (net[i] !== addr[i]) return false;
  }
  const remainder = bits & 7;
  if (remainder === 0) return true;
  const mask = (0xff << (8 - remainder)) & 0xff;
  return ((net[fullBytes] as number) & mask) === ((addr[fullBytes] as number) & mask);
}
