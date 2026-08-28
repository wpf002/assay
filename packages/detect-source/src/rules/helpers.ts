import type { Arg, CallSite, Detection, FileContext, PurposeSource } from '../types.js';
import type { Primitive, Purpose } from '@assay/core';

export function str(a: Arg | undefined): string | null {
  return a?.kind === 'string' ? (a.string as string) : null;
}

export function num(a: Arg | undefined): number | null {
  return a?.kind === 'number' ? (a.number as number) : null;
}

export function prop(a: Arg | undefined, name: string): Arg | undefined {
  return a?.kind === 'object' ? a.object?.[name] : undefined;
}

/** Positional arg, or the python keyword of the same name. */
export function arg(call: CallSite, index: number, keyword?: string): Arg | undefined {
  if (keyword !== undefined && call.kwargs[keyword]) return call.kwargs[keyword];
  return call.args[index];
}

export function importedAny(ctx: FileContext, modules: readonly string[]): boolean {
  for (const m of modules) {
    if (ctx.imports.has(m)) return true;
    for (const seen of ctx.imports) {
      if (seen === m || seen.startsWith(`${m}.`)) return true;
    }
  }
  return false;
}

/** The receiver of a method call: `crypto` in `crypto.createHash`. */
export function receiver(call: CallSite): string | null {
  return call.calleeParts.length > 1 ? (call.calleeParts[call.calleeParts.length - 2] as string) : null;
}

/**
 * True when the receiver is bound to one of these modules, or when the call is
 * written with the module name directly. Import gating is the single largest
 * lever on precision: `AES.new(...)` is a finding only if `Crypto.Cipher.AES`
 * is in scope, and a local class called AES is not.
 */
export function boundTo(call: CallSite, ctx: FileContext, modules: readonly string[]): boolean {
  const root = call.calleeParts[0];
  if (root === undefined) return false;
  const mod = ctx.aliases.get(root);
  if (mod !== undefined) {
    for (const m of modules) {
      if (mod === m || mod.startsWith(`${m}.`) || m.startsWith(`${mod}.`)) return true;
    }
  }
  return false;
}

export function detection(
  ruleId: string,
  primitive: Primitive,
  parameters: Readonly<Record<string, string | number>>,
  purpose: Purpose,
  purposeSource: PurposeSource = 'RESOLVED',
  note?: string,
): Detection {
  return {
    primitive,
    parameters: pruneUndefined(parameters),
    purpose,
    purposeSource,
    ruleId,
    ...(note === undefined ? {} : { note }),
  };
}

function pruneUndefined(
  o: Readonly<Record<string, string | number | undefined>>,
): Readonly<Record<string, string | number>> {
  const out: Record<string, string | number> = {};
  for (const k of Object.keys(o).sort()) {
    const v = o[k];
    if (v !== undefined) out[k] = v;
  }
  return out;
}

/**
 * The rule-level default for dual-use key generation.
 *
 * A bare `generateKeyPairSync('rsa')` produces a key that may sign or may wrap.
 * The conservative choice is the confidentiality track, because that is the one
 * with the earlier deadline (EO 14412: 2030-12-31 vs 2031-12-31) and the one
 * where harvest-now-decrypt-later already applies. The choice is recorded as
 * RULE_DEFAULT so the UI can show it and Phase 3 can overwrite it from the use
 * site rather than inheriting a silent guess.
 */
export const DUAL_USE_NOTE =
  'key generation site is dual-use; purpose defaulted to the earlier-deadline track pending use-site correlation';
