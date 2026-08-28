import { readFile } from 'node:fs/promises';
import { basename, relative, resolve } from 'node:path';
import fg from 'fast-glob';
import { makeAsset, type ControlClass, type Finding } from '@assay/core';
import { CATALOG, lookup, type LibraryEntry } from './catalog.js';

export * from './catalog.js';

export const COLLECTOR_VERSION = 'detect-deps/0.1.0';

/**
 * Manifest ingestion.
 *
 * Emits at the DEPENDENCY modality (ceiling 0.35), which cannot confirm
 * anything alone. These are search hints and coverage checks, not findings:
 * a repo depending on node-forge with no forge call sites either does not use
 * it or uses it somewhere the AST rules do not reach yet.
 */

export interface DepScanOptions {
  readonly root: string;
  readonly systemId: string;
  readonly collectedAt: string;
  readonly ignore?: readonly string[];
  /** Include devDependencies. Off by default: dev tooling is not the estate. */
  readonly includeDev?: boolean;
}

export interface DepScanResult {
  readonly findings: readonly Finding[];
  readonly manifests: readonly string[];
  /** Libraries seen in a manifest but absent from the catalog - the coverage gap. */
  readonly uncatalogued: readonly string[];
}

interface Declared {
  readonly name: string;
  readonly version: string | null;
  readonly ecosystem: 'npm' | 'pypi';
  readonly dev: boolean;
  readonly file: string;
  readonly line: number;
}

export async function scanDependencies(opts: DepScanOptions): Promise<DepScanResult> {
  const root = resolve(opts.root);
  const files = await fg(
    ['**/package.json', '**/pnpm-lock.yaml', '**/requirements*.txt', '**/poetry.lock', '**/Pipfile'],
    {
      cwd: root,
      ignore: [...(opts.ignore ?? ['**/node_modules/**', '**/.git/**', '**/dist/**', '**/.venv/**', '**/venv/**'])],
      absolute: true,
      suppressErrors: true,
    },
  );

  const declared: Declared[] = [];
  const manifests: string[] = [];

  for (const abs of files.sort()) {
    const rel = relative(root, abs);
    let text: string;
    try {
      text = await readFile(abs, 'utf8');
    } catch {
      continue;
    }
    manifests.push(rel);
    const name = basename(abs);
    if (name === 'package.json') declared.push(...parsePackageJson(text, rel));
    else if (name === 'pnpm-lock.yaml') declared.push(...parsePnpmLock(text, rel));
    else if (name === 'poetry.lock') declared.push(...parsePoetryLock(text, rel));
    else if (name === 'Pipfile') declared.push(...parsePipfile(text, rel));
    else declared.push(...parseRequirements(text, rel));
  }

  const findings: Finding[] = [];
  const uncatalogued = new Set<string>();
  const seen = new Set<string>();

  for (const d of declared.sort(byFileThenName)) {
    if (d.dev && opts.includeDev !== true) continue;
    const key = `${d.ecosystem}:${d.name}:${d.file}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const entry = lookup(d.name, d.ecosystem);
    if (entry === null) {
      if (looksCryptographic(d.name)) uncatalogued.add(`${d.ecosystem}:${d.name}`);
      continue;
    }
    findings.push(...toFindings(d, entry, opts));
  }

  return {
    findings,
    manifests,
    uncatalogued: [...uncatalogued].sort(),
  };
}

function toFindings(d: Declared, entry: LibraryEntry, opts: DepScanOptions): Finding[] {
  // A crypto library is upgradeable by definition unless it is abandoned; the
  // catalog note flags the ones that are really a procurement problem.
  const controlClass: ControlClass = entry.note?.includes('unmaintained')
    ? 'VENDOR_LOCKED'
    : 'VENDOR_UPGRADEABLE';

  return entry.capabilities.map((c) => ({
    asset: makeAsset(c.primitive, c.parameters ?? {}, c.purpose),
    systemId: opts.systemId,
    controlClass,
    evidence: {
      modality: 'DEPENDENCY' as const,
      locator: `${d.file}:${d.line}`,
      raw:
        `${d.ecosystem}:${d.name}${d.version ? `@${d.version}` : ''} implements ${c.primitive}` +
        ` (scope=${d.dev ? 'dev' : 'prod'})` +
        ' :: manifest evidence records that the library IMPLEMENTS this primitive, not that the application USES it' +
        (entry.note ? ` :: ${entry.note}` : ''),
      collectedAt: opts.collectedAt,
      collectorVersion: COLLECTOR_VERSION,
      occurrence: { location: d.file, line: d.line, symbol: d.name },
    },
  }));
}

/* ------------------------------------------------------------------ parsers */

function parsePackageJson(text: string, file: string): Declared[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  if (typeof json !== 'object' || json === null) return [];
  const obj = json as Record<string, unknown>;
  const out: Declared[] = [];
  for (const [field, dev] of [
    ['dependencies', false],
    ['optionalDependencies', false],
    ['peerDependencies', false],
    ['devDependencies', true],
  ] as const) {
    const section = obj[field];
    if (typeof section !== 'object' || section === null) continue;
    for (const [name, version] of Object.entries(section as Record<string, unknown>)) {
      out.push({
        name,
        version: typeof version === 'string' ? version : null,
        ecosystem: 'npm',
        dev,
        file,
        line: lineOf(text, `"${name}"`),
      });
    }
  }
  return out;
}

function parsePnpmLock(text: string, file: string): Declared[] {
  // Targeted extraction rather than a YAML parse: lockfile shape changes
  // between pnpm majors, and the package keys do not.
  const out: Declared[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    const m = /^\s{2}(\/?)(@?[^@\s/][^@\s]*(?:\/[^@\s]+)?)@([\d][^:\s(]*)/.exec(line);
    if (!m?.[2] || !m[3]) return;
    out.push({ name: m[2].replace(/^\//, ''), version: m[3], ecosystem: 'npm', dev: false, file, line: i + 1 });
  });
  return out;
}

/**
 * requirements.txt declares no scope of its own, so the filename is the only
 * signal there is. Testing the whole relative path marked every manifest under
 * a directory whose name merely contains "dev" or "test" - dev-portal,
 * attestation-service, latest-api - as dev tooling and silently dropped its
 * entire crypto surface.
 */
function isDevRequirements(name: string): boolean {
  return /^(dev|test)[-_.]requirements.*\.txt$/i.test(name) || /^requirements[-_.](dev|test)/i.test(name);
}

function parseRequirements(text: string, file: string): Declared[] {
  const out: Declared[] = [];
  text.split(/\r?\n/).forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith('-')) return;
    const m = /^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~]+\s*([^\s;#]+))?/.exec(trimmed);
    if (!m?.[1]) return;
    out.push({
      name: m[1],
      version: m[2] ?? null,
      ecosystem: 'pypi',
      dev: isDevRequirements(basename(file)),
      file,
      line: i + 1,
    });
  });
  return out;
}

function parsePoetryLock(text: string, file: string): Declared[] {
  const out: Declared[] = [];
  const lines = text.split(/\r?\n/);
  let name: string | null = null;
  let nameLine = 0;
  let category: string | null = null;

  const flush = (): void => {
    if (name !== null) {
      out.push({
        name,
        version: null,
        ecosystem: 'pypi',
        dev: category === 'dev',
        file,
        line: nameLine,
      });
    }
    name = null;
    category = null;
  };

  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed === '[[package]]') {
      flush();
      return;
    }
    const n = /^name\s*=\s*"([^"]+)"/.exec(trimmed);
    if (n?.[1] && name === null) {
      name = n[1];
      nameLine = i + 1;
      return;
    }
    const c = /^category\s*=\s*"([^"]+)"/.exec(trimmed);
    if (c?.[1]) category = c[1];
    const g = /^groups\s*=\s*\[(.*)\]/.exec(trimmed);
    if (g?.[1] && !g[1].includes('main')) category = 'dev';
  });
  flush();
  return out;
}

function parsePipfile(text: string, file: string): Declared[] {
  const out: Declared[] = [];
  // Only [packages] and [dev-packages] declare dependencies. Skipping other
  // table headers without leaving the current table read `verify_ssl = true`
  // under the stock [[source]] block as a pypi package - and it matches the
  // crypto-token pattern, so every Pipfile in the estate reported a
  // nonexistent `verify_ssl` as a coverage gap.
  let table: 'packages' | 'dev-packages' | null = null;
  text.split(/\r?\n/).forEach((line, i) => {
    const trimmed = line.trim();
    if (/^\[/.test(trimmed)) {
      table = /^\[dev-packages\]/.test(trimmed)
        ? 'dev-packages'
        : /^\[packages\]/.test(trimmed)
          ? 'packages'
          : null;
      return;
    }
    if (table === null) return;
    const m = /^([A-Za-z0-9._-]+)\s*=/.exec(trimmed);
    if (!m?.[1]) return;
    out.push({
      name: m[1],
      version: null,
      ecosystem: 'pypi',
      dev: table === 'dev-packages',
      file,
      line: i + 1,
    });
  });
  return out;
}

/* ------------------------------------------------------------------ helpers */

function lineOf(text: string, needle: string): number {
  const idx = text.indexOf(needle);
  if (idx < 0) return 1;
  return text.slice(0, idx).split('\n').length;
}

/**
 * Names that look cryptographic but are not in the catalog. Reported as a
 * coverage gap, so the pattern has to be tight: a loose one buries the real
 * gaps under `design-system` (sign), `ajv-keywords` (key) and `alien-signals`.
 * Matching is on token boundaries within the package name, not substrings.
 */
const CRYPTO_TOKENS =
  /(^|[^a-z])(crypto|crypt|cipher|tls|ssl|pki|x509|jwt|jose|jwk|jws|jwe|rsa|dsa|ecdsa|eddsa|ed25519|x25519|nacl|sodium|hmac|sha1|sha256|sha512|md5|aes|pgp|gpg|pbkdf2|bcrypt|scrypt|argon2|keystore|keyring|signature)([^a-z]|$)/i;

function looksCryptographic(name: string): boolean {
  const bare = name.replace(/^@[^/]+\//, '');
  return CRYPTO_TOKENS.test(bare);
}

export { CATALOG };
function byFileThenName(a: Declared, b: Declared): number {
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}
