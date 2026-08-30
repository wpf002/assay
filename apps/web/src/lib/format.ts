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
  // A curve outside the naming catalog is carried as `group`, verbatim from the
  // handshake. Dropping it renders two endpoints on two different curves as the
  // same bare primitive, which reads as one row duplicated.
  const curve = params['curve'] ?? params['group'];
  const mode = params['mode'];
  const outputLength = params['outputLength'];
  const padding = params['padding'];

  if (primitive === 'DH' && params['ephemeral'] === 'true') return 'DHE';
  if (primitive === 'ECDH' && params['ephemeral'] === 'true') return 'ECDHE';
  if (mode === 'KEY_TRANSPORT') {
    return padding === undefined ? `${primitive} Key Transport` : `${primitive} Key Transport ${padding}`;
  }
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
  KEY_ESTABLISHMENT: 'Key Exchange',
  DATA_ENCRYPTION: 'Encryption',
  DIGITAL_SIGNATURE: 'Signing',
  CERTIFICATE_AUTH: 'Certificates',
  INTEGRITY: 'Hashing',
  KEY_DERIVATION: 'Key Derivation',
  RANDOMNESS: 'Randomness',
};

/** Who has to make the change. Also the group name on the What To Do Next strip. */
export const CONTROL: Readonly<Record<string, string>> = {
  SELF: 'Our Code',
  VENDOR_UPGRADEABLE: 'Vendor Library',
  VENDOR_LOCKED: 'Vendor, No Roadmap',
  HARDWARE: 'Hardware',
  PROTOCOL_BILATERAL: 'Both Endpoints',
};

export const WHERE: Readonly<Record<string, string>> = {
  OBSERVED: 'Seen On The Wire',
  ENTRY_POINT: 'In A Live Code Path',
  DEPLOYED_CONFIG: 'In Deployed Config',
  LIBRARY_SURFACE: 'On A Public API Surface',
  TRACE: 'Called By Another Service',
  // Both of these were the empty string, so the row silently dropped the
  // fragment and a reader could not tell "nothing reached it" from "nobody
  // looked". Those are different claims and the second one is ours to own.
  UNANALYZED: 'Reachability Not Analyzed',
  NONE: 'No Call Site To Follow',
};

/**
 * What to actually do, derived from who controls the thing.
 *
 * Assay recommends and never edits, but a worklist that names no action is a
 * report, and the whole complaint about this category is that it produces
 * reports. The control class already encodes who has to act; this just says it
 * in words.
 */
const ACTIONS: Readonly<Record<string, { short: string; full: string; next: string }>> = {
  SELF: {
    short: 'Our code: change and ship',
    full: 'This is our code and our deployment. Change it and ship. Weeks, not years.',
    next: 'Change it and ship.',
  },
  VENDOR_UPGRADEABLE: {
    short: 'Vendor library: upgrade when released',
    full: 'A dependency we can upgrade. Watch the vendor for a post-quantum release, then bump the version.',
    next: 'Watch for a post-quantum release, then upgrade.',
  },
  VENDOR_LOCKED: {
    short: 'Vendor with no roadmap: a contract problem',
    full:
      'The vendor has published no post-quantum path. Engineering cannot fix this. It is a contract conversation, and it takes longer than anything else on this list.',
    next: 'Engineering cannot fix this. Open the contract conversation.',
  },
  HARDWARE: {
    short: 'Hardware: bound to the replacement cycle',
    full:
      'This moves at the speed of the hardware replacement cycle, not the speed of a code change. Budget and order well ahead of the deadline. There is no way to compress it.',
    next: 'Order it into the next refresh cycle.',
  },
  PROTOCOL_BILATERAL: {
    short: 'Both endpoints: coordinate with the peer',
    full:
      'Both endpoints must support the replacement before either can use it. Agree the change with the peer first. Editing our own config alone changes nothing.',
    next: 'Agree the change with the peer before touching config.',
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

/** The imperative form, for the What To Do Next strip. Same record, so the two cannot drift. */
export function actionNext(controlClass: string): string {
  return ACTIONS[controlClass]?.next ?? '';
}

/** When it is due, in words, not a signed float. */
export function due(f: RankedFinding): string {
  const years = Math.abs(f.slackYears);
  const months = Math.round(years * 12);
  const rounded =
    years >= 1
      ? `${years.toFixed(1)} years`
      : months === 0
        ? 'less than a month'
        : `${months} month${months === 1 ? '' : 's'}`;
  // The row already carries an Overdue chip, so repeating the word beside it
  // says it twice. "Of slack" is unglossed Mosca vocabulary on the busiest
  // column of the page.
  return f.late ? `${rounded} past due` : `${rounded} left`;
}

/**
 * Why that date, in one clause.
 *
 * The whole right column is dates, so a bare "Quantum horizon" is a category
 * sitting where a date should be. The year comes from the active pack; without
 * it the bare form is still correct, which is what the fallback is for.
 */
export function driver(f: RankedFinding, crqcYear?: number): string {
  if (f.bindingConstraint === 'REGULATORY') {
    const year = f.mosca.regulatory?.deadlineYear;
    return year === undefined ? 'Regulatory deadline' : `Due ${Math.floor(year) - 1}-12-31`;
  }
  return crqcYear === undefined ? 'Quantum horizon' : `Quantum horizon ${crqcYear}`;
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

/**
 * A span of work, in the unit a person would say it in.
 *
 * SELF is 0.5 years in both shipped packs, so "takes about 0.5 years" was the
 * most-rendered sentence in the panel and nobody says that out loud. Only used
 * for the Y term; slack figures keep the decimal, because there the precision
 * is the point.
 */
export function duration(years: number): string {
  if (years >= 1) return `${years} year${years === 1 ? '' : 's'}`;
  const months = Math.round(years * 12);
  return months === 0 ? 'less than a month' : `${months} month${months === 1 ? '' : 's'}`;
}

/**
 * The counterfactual, which is not always a positive quantity of time: once
 * X + Y passes the horizon the physics has run out too, and "you would have
 * had -1.66 years" says the opposite of what it means.
 */
const withoutTheDeadline = (slack: number): string =>
  slack < 0
    ? `you would already have been ${Math.abs(slack)} years late`
    : `you would have had ${short(slack)}`;

/** How much you are over or under, without a signed number in the prose. */
const margin = (slack: number): string =>
  slack < 0
    ? `leaves you ${Math.abs(slack)} years short, so you are already late.`
    : `leaves ${slack} years to spare.`;

/** The date, as an argument rather than as arithmetic. */
export function whyThisDate(m: MoscaTerms): string[] {
  const lines: string[] = [];
  lines.push(
    `Replacing this takes about ${duration(m.y)}: ${WHY_LONG[m.controlClass] ?? 'of who controls it'}.`,
  );

  if (m.bindingConstraint === 'REGULATORY' && m.regulatory !== null) {
    const deadline = `${Math.floor(m.regulatory.deadlineYear) - 1}-12-31`;
    lines.push(
      `The deadline is ${deadline}, ${m.regulatory.horizonYears} years away. Starting today ` +
        margin(m.regulatory.slackYears),
    );
    lines.push(
      m.crqc.slackYears > m.regulatory.slackYears
        ? `On the physics alone ${withoutTheDeadline(m.crqc.slackYears)}. The regulation is what binds here, not the quantum computer.`
        : 'The regulation and the physics point the same way here.',
    );
    return lines;
  }

  if (m.track === 'CONFIDENTIALITY') {
    lines.push(
      `Anything encrypted with it today has to stay secret for ${short(m.x)}, and this pack assumes a quantum computer by ${m.policy.crqcYear}, which is ${m.crqc.horizonYears} years away.`,
    );
    lines.push(
      `${short(m.x)} of secrecy plus ${duration(m.y)} of work against a ${m.crqc.horizonYears}-year horizon ` +
        margin(m.crqc.slackYears),
    );
  } else {
    lines.push(
      `Signatures are not broken retroactively, so only the work counts: ${duration(m.y)} against a ${m.crqc.horizonYears}-year horizon ` +
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
      `${MODALITY[g.contributing] ?? g.contributing} is the strongest evidence here, and that kind of evidence is worth at most ${Math.round(g.ceiling * 100)}%. That is where ${pct}% comes from.`,
    );
    if (total > 1) {
      lines.push(
        `We found it ${total} times. That does not raise the number, because repeating one kind of observation is still one observation.`,
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
