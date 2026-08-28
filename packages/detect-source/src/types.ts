import type { Primitive, Purpose } from '@assay/core';

export type Lang =
  | 'typescript'
  | 'tsx'
  | 'javascript'
  | 'python'
  | 'go'
  | 'java'
  | 'c'
  | 'cpp'
  | 'rust'
  | 'csharp';

/** Languages whose call syntax and import forms are close enough to share a walker. */
export const ALL_LANGS: readonly Lang[] = [
  'typescript',
  'tsx',
  'javascript',
  'python',
  'go',
  'java',
  'c',
  'cpp',
  'rust',
  'csharp',
];

/** A literal argument the parser was able to resolve. `unresolved` is honest, not a failure. */
export interface Arg {
  readonly kind: 'string' | 'number' | 'boolean' | 'object' | 'array' | 'call' | 'unresolved';
  readonly string?: string;
  readonly number?: number;
  readonly boolean?: boolean;
  readonly object?: Readonly<Record<string, Arg>>;
  readonly array?: readonly Arg[];
  /** Dotted callee when this argument is itself a call, e.g. `ec.SECP256R1()`. */
  readonly callee?: string;
  readonly text: string;
  /** Python keyword-argument name, where the call used one. */
  readonly keyword?: string;
}

export interface CallSite {
  /** Dotted callee as written, e.g. "crypto.generateKeyPairSync". */
  readonly callee: string;
  readonly calleeParts: readonly string[];
  readonly method: string;
  readonly args: readonly Arg[];
  readonly kwargs: Readonly<Record<string, Arg>>;
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly text: string;
}

export interface FileContext {
  readonly file: string;
  readonly lang: Lang;
  /** Module specifiers this file imports, e.g. "node:crypto", "Crypto.Cipher". */
  readonly imports: ReadonlySet<string>;
  /** Local binding -> module it came from. Lets a rule tell forge.pki from pki. */
  readonly aliases: ReadonlyMap<string, string>;
}

/**
 * Whether the purpose was read off the API or supplied by the rule.
 *
 * Key generation is genuinely dual-use: `generateKeyPairSync('rsa')` produces a
 * key that may sign or may wrap. The rule picks the conservative track and says
 * so rather than silently asserting one. Phase 3 correlation refines it from the
 * use site; until then the distinction is visible in the evidence.
 */
export type PurposeSource = 'RESOLVED' | 'RULE_DEFAULT';

export interface Detection {
  readonly primitive: Primitive;
  readonly parameters: Readonly<Record<string, string | number>>;
  readonly purpose: Purpose;
  readonly purposeSource: PurposeSource;
  readonly ruleId: string;
  readonly note?: string;
  /** Unverifiable claims the rule relied on. Taint the provenance path (I6). */
  readonly assumptions?: readonly string[];
}

export interface Rule {
  readonly id: string;
  readonly languages: readonly Lang[];
  /** Method names this rule cares about. Indexed for dispatch. */
  readonly methods: readonly string[];
  /** If set, the rule fires only when the file imports one of these modules. */
  readonly requiresImport?: readonly string[];
  readonly detect: (call: CallSite, ctx: FileContext) => readonly Detection[];
  /** Why this rule is sound. Read by a human reviewing a false positive. */
  readonly rationale: string;
}

export const NO_DETECTIONS: readonly Detection[] = [];
