/**
 * Command-line option parsing that names the flag it rejects.
 *
 * commander hands every option through as a raw string, and `Number()` /
 * `new Date()` turn a typo into NaN or an Invalid Date rather than an error.
 * NaN then fails every comparison it takes part in, which is how a mistyped
 * --clock-skew-seconds silently switches off the grant window check in
 * `authorize()` and a mistyped --secrecy-years produces a worklist where
 * nothing is ever late. The operator is reading stderr and nothing else, so
 * the message has to name both the flag and the value they typed.
 */

export function numberOption(
  flag: string,
  raw: string,
  bounds: { readonly min?: number; readonly max?: number } = {},
): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) throw new Error(`${flag} is not a number: ${raw}`);
  if (bounds.min !== undefined && n < bounds.min) {
    throw new Error(`${flag} must be at least ${bounds.min}: ${raw}`);
  }
  if (bounds.max !== undefined && n > bounds.max) {
    throw new Error(`${flag} must be at most ${bounds.max}: ${raw}`);
  }
  return n;
}

export function dateOption(flag: string, raw: string): Date {
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) throw new Error(`${flag} is not a date: ${raw}`);
  return d;
}

/** The current time, or the operator's override for a reproducible run. */
export function nowOption(raw: string | undefined): Date {
  return raw === undefined || raw === '' ? new Date() : dateOption('--now', raw);
}
