/**
 * Canonical JSON: object keys sorted, no insignificant whitespace.
 * Two structurally equal values serialize identically regardless of insertion
 * order. This is what makes the CBOM byte-identical for the same evidence set.
 */
export type Canonicalizable =
  | string
  | number
  | boolean
  | null
  | readonly Canonicalizable[]
  | { readonly [k: string]: Canonicalizable };

export function canonicalize(value: Canonicalizable): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const obj = value as { readonly [k: string]: Canonicalizable };
  return `{${Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k] as Canonicalizable)}`)
    .join(',')}}`;
}
