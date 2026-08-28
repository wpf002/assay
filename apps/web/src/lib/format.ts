import type { RankedFinding } from './api';

/**
 * Machine values are for the CBOM. People get words.
 *
 * KEY_ESTABLISHMENT, PROTOCOL_BILATERAL and RSA(modulusLength=2048) are what
 * the engine computes with and what the export carries. Putting them on screen
 * makes the reader translate before they can think, and most readers of this
 * page are not the engineer who wrote the rule.
 */

export function assetLabel(f: RankedFinding): string {
  const name = f.assetName;
  const open = name.indexOf('(');
  if (open < 0) return name;

  const primitive = name.slice(0, open);
  const params = Object.fromEntries(
    name
      .slice(open + 1, -1)
      .split(',')
      .map((p) => p.split('=') as [string, string]),
  );

  const size = params['modulusLength'] ?? params['keySize'] ?? params['primeLength'];
  const curve = params['curve'];
  const mode = params['mode'];
  const outputLength = params['outputLength'];
  const padding = params['padding'];

  if (primitive === 'DH' && params['ephemeral'] === 'true') return 'DHE';
  if (primitive === 'ECDH' && params['ephemeral'] === 'true') return 'ECDHE';
  if (mode === 'KEY_TRANSPORT') return `${primitive} key transport`;
  // Nobody writes "EdDSA-Ed25519"; the curve is the name people use.
  if (primitive === 'EdDSA' && curve !== undefined) return curve;

  // A curve is a separate word; a key size or mode is hyphenated onto the
  // primitive, the way every spec and every engineer writes it.
  const head = size ?? outputLength;
  const base =
    head === undefined
      ? primitive
      : `${primitive}-${head}`.replace('SHA2-', 'SHA-').replace('SHA1-160', 'SHA-1');
  const withMode = mode === undefined ? base : `${base}-${mode}`;
  const suffix = mode === undefined && padding !== undefined ? ` ${padding}` : '';
  return curve === undefined ? `${withMode}${suffix}` : `${withMode} ${curve}`;
}

export const PURPOSE: Readonly<Record<string, string>> = {
  KEY_ESTABLISHMENT: 'Key exchange',
  DATA_ENCRYPTION: 'Encryption',
  DIGITAL_SIGNATURE: 'Signing',
  CERTIFICATE_AUTH: 'Certificates',
  INTEGRITY: 'Hashing',
  KEY_DERIVATION: 'Key derivation',
  RANDOMNESS: 'Randomness',
};

export const CONTROL: Readonly<Record<string, string>> = {
  SELF: 'Our code',
  VENDOR_UPGRADEABLE: 'Vendor library',
  VENDOR_LOCKED: 'Vendor, no roadmap',
  HARDWARE: 'Hardware',
  PROTOCOL_BILATERAL: 'Both endpoints',
};

export const WHERE: Readonly<Record<string, string>> = {
  OBSERVED: 'Seen on the wire',
  ENTRY_POINT: 'In a live code path',
  DEPLOYED_CONFIG: 'In deployed config',
  LIBRARY_SURFACE: 'In published code',
  TRACE: 'Called by another service',
  UNANALYZED: '',
  NONE: '',
};

/**
 * What to actually do, derived from who controls the thing.
 *
 * Assay recommends and never edits, but a worklist that names no action is a
 * report, and the whole complaint about this category is that it produces
 * reports. The control class already encodes who has to act; this just says it
 * in words.
 */
const ACTIONS: Readonly<Record<string, { short: string; full: string }>> = {
  SELF: {
    short: 'Our code — change and ship',
    full: 'This is our code and our deployment. Change it and ship. Weeks, not years.',
  },
  VENDOR_UPGRADEABLE: {
    short: 'Vendor library — upgrade when released',
    full: 'A dependency we can upgrade. Track the vendor for a post-quantum release, then bump it.',
  },
  VENDOR_LOCKED: {
    short: 'Vendor with no roadmap — a procurement problem',
    full:
      'The vendor has no post-quantum path. No amount of engineering fixes this — it is a contract conversation, and it is the long pole in the plan.',
  },
  HARDWARE: {
    short: 'Hardware — bounded by the replacement cycle',
    full:
      'Bounded by how often the hardware is replaced, not by how fast anyone can code. Budget and order ahead of the deadline; you cannot compress this.',
  },
  PROTOCOL_BILATERAL: {
    short: 'Both endpoints — coordinate with the peer',
    full:
      'Both endpoints must support the replacement before either can use it. Agree the change with the peer first — editing the config alone changes nothing.',
  },
};

/**
 * What to actually do, derived from who controls the thing.
 *
 * Assay recommends and never edits, but a worklist that names no action is a
 * report, and the complaint about this whole category is that it produces
 * reports. The short form sits on the row; repeating a full sentence on ten
 * consecutive rows is noise, so the reasoning waits until the row is opened.
 */
export function action(f: RankedFinding): string {
  return ACTIONS[f.controlClass]?.short ?? '';
}

export function actionDetail(f: RankedFinding): string {
  return ACTIONS[f.controlClass]?.full ?? '';
}

/** When it is due, in words, not a signed float. */
export function due(f: RankedFinding): string {
  const years = Math.abs(f.slackYears);
  const rounded = years < 1 ? `${Math.round(years * 12)} months` : `${years.toFixed(1)} years`;
  return f.late ? `Overdue by ${rounded}` : `${rounded} of slack`;
}

/** Why that date, in one clause. */
export function driver(f: RankedFinding): string {
  if (f.bindingConstraint === 'REGULATORY') {
    const year = f.mosca.regulatory?.deadlineYear;
    return year === undefined ? 'Regulatory deadline' : `Deadline ${Math.floor(year) - 1}-12-31`;
  }
  return 'Quantum horizon';
}

export const ASSERTION: Readonly<Record<string, string>> = {
  CONFIRMED: 'Confirmed',
  OBSERVED: 'Observed',
  SUSPECTED: 'Suspected',
};

/* --------------------------------------------------------- plain explanations */

/**
 * Human names for the detection modalities, with what each is worth.
 *
 * The ceiling is the whole argument of this tool and it is meaningless as a
 * bare decimal. "A string in a binary, worth at most 30%" says why four
 * hundred of them still do not add up to a fact.
 */
export const MODALITY: Readonly<Record<string, string>> = {
  PKI_CERTIFICATE: 'A parsed certificate',
  NETWORK_ACTIVE: 'A completed handshake',
  RUNTIME_HOOK: 'A running process, instrumented',
  CLOUD_KMS_API: 'The key provider’s own answer',
  SOURCE_AST: 'A call in the source, with its arguments read',
  SOURCE_CONFIG: 'A configuration file',
  BINARY_CONSTANT: 'An exact algorithm constant in a binary',
  HOST_AGENT: 'An endpoint agent',
  BINARY_SYMBOL: 'An imported symbol in a binary',
  NETWORK_PASSIVE: 'Captured traffic',
  ASSERTED: 'A vendor questionnaire',
  DEPENDENCY: 'A dependency manifest',
  BINARY_STRING: 'A matching string in a binary',
};

export interface MoscaTerms {
  x: number;
  y: number;
  bindingConstraint: 'CRQC' | 'REGULATORY';
  crqc: { horizonYears: number; slackYears: number };
  regulatory: { deadlineYear: number; horizonYears: number; slackYears: number } | null;
  controlClass: string;
  track: string;
  policy: { packId: string; crqcYear: number; authority: string | null };
}

/** Why each control class takes as long as it does, in a clause that reads. */
const WHY_LONG: Readonly<Record<string, string>> = {
  SELF: 'it is our code and our deployment',
  VENDOR_UPGRADEABLE: 'we have to wait for a vendor release and then upgrade',
  VENDOR_LOCKED: 'the vendor controls it and has published no post-quantum path',
  HARDWARE: 'it is bound to a hardware replacement cycle, not to a code change',
  PROTOCOL_BILATERAL: 'both ends of the protocol have to move together',
};

const short = (years: number): string => `${years} year${years === 1 ? '' : 's'}`;

/** How much you are over or under, without a signed number in the prose. */
const margin = (slack: number): string =>
  slack < 0
    ? `leaves you ${Math.abs(slack)} years short — you are already late.`
    : `leaves ${slack} years to spare.`;

/** The date, as an argument rather than as arithmetic. */
export function whyThisDate(m: MoscaTerms): string[] {
  const lines: string[] = [];
  lines.push(
    `Replacing this takes about ${short(m.y)}: ${WHY_LONG[m.controlClass] ?? 'of who controls it'}.`,
  );

  if (m.bindingConstraint === 'REGULATORY' && m.regulatory !== null) {
    const deadline = `${Math.floor(m.regulatory.deadlineYear) - 1}-12-31`;
    lines.push(
      `The deadline is ${deadline}, ${m.regulatory.horizonYears} years away. Starting today ` +
        margin(m.regulatory.slackYears),
    );
    lines.push(
      m.crqc.slackYears > m.regulatory.slackYears
        ? `On the physics alone you would have had ${m.crqc.slackYears} years. The regulation is what binds here, not the quantum computer.`
        : 'The regulation and the physics point the same way here.',
    );
    return lines;
  }

  if (m.track === 'CONFIDENTIALITY') {
    lines.push(
      `Anything encrypted with it today has to stay secret for ${short(m.x)}, and this pack assumes a quantum computer by ${m.policy.crqcYear} — ${m.crqc.horizonYears} years away.`,
    );
    lines.push(
      `${short(m.x)} of secrecy plus ${short(m.y)} of work against a ${m.crqc.horizonYears}-year horizon ` +
        margin(m.crqc.slackYears),
    );
  } else {
    lines.push(
      `Signatures are not broken retroactively, so only the work counts: ${short(m.y)} against a ${m.crqc.horizonYears}-year horizon ` +
        margin(m.crqc.slackYears),
    );
  }
  return lines;
}

export interface ConfidenceGroup {
  contributing: string;
  ceiling: number;
  tallies: { modality: string; count: number; ceiling: number }[];
  suppressed: number;
}

/** How sure, and why more of the same evidence would not help. */
export function whyWeBelieve(value: number, groups: readonly ConfidenceGroup[]): string[] {
  if (groups.length === 0) return ['No evidence.'];
  const pct = Math.round(value * 100);
  const lines: string[] = [];

  if (groups.length === 1) {
    const g = groups[0] as ConfidenceGroup;
    const total = g.tallies.reduce((n, t) => n + t.count, 0);
    lines.push(
      `${MODALITY[g.contributing] ?? g.contributing} is the strongest thing we have, and that kind of evidence is worth at most ${Math.round(g.ceiling * 100)}%. So: ${pct}%.`,
    );
    if (total > 1) {
      lines.push(
        `We found it ${total} times. That does not raise the number — repeating one kind of observation is still one observation.`,
      );
    }
    return lines;
  }

  lines.push(
    `${groups.length} independent kinds of evidence agree, which is why this reaches ${pct}%: ` +
      groups.map((g) => (MODALITY[g.contributing] ?? g.contributing).toLowerCase()).join(', ') +
      '.',
  );
  const suppressed = groups.reduce((n, g) => n + g.suppressed, 0);
  if (suppressed > 0) {
    lines.push(
      `${suppressed} further observation${suppressed === 1 ? '' : 's'} of those same kinds were counted once each, not added up.`,
    );
  }
  return lines;
}
