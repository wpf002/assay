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
