import { HostInventorySchema, type Host, type HostInventory } from './types.js';

/**
 * Translations from what a customer already has into the shape above.
 *
 * Assay does not collect host data and will not. Every regulated estate this
 * product targets already runs something with an agent on every box - osquery,
 * Ansible, an EDR - and asking them to install a second one is asking for a
 * security review that takes longer than the migration. So the job here is
 * translation, and each adapter is deliberately small enough to read: an
 * operator has to be able to check that the thing reading their fleet inventory
 * only reads it.
 *
 * Every adapter is pure. Nothing here opens a socket or a file.
 */

/* ---------------------------------------------------------------- osquery */

/**
 * osquery scheduled-query results, in the format `--logger_plugin=filesystem`
 * writes: one object per row, tagged with the query name.
 *
 * Three query names are understood. Anything else is skipped rather than
 * guessed at, and the caller is told how many rows were dropped.
 */
export interface OsqueryRow {
  readonly name: string;
  readonly hostIdentifier?: string;
  readonly columns: Readonly<Record<string, string>>;
}

export interface OsqueryOptions {
  readonly collectedAt: string;
  /** Which system these hosts belong to, when the rows do not say. */
  readonly systemId?: string;
}

export interface AdapterResult {
  readonly inventory: HostInventory;
  /** Rows the adapter did not understand, counted rather than silently dropped. */
  readonly skipped: number;
}

export function fromOsquery(rows: readonly OsqueryRow[], opts: OsqueryOptions): AdapterResult {
  const hosts = new Map<string, Host>();
  let skipped = 0;

  const host = (id: string): Host => {
    const existing = hosts.get(id);
    if (existing !== undefined) return existing;
    const created: Host = {
      hostId: id,
      hostname: id,
      os: '',
      systemId: opts.systemId ?? '',
      packages: [],
      configs: [],
      keyFiles: [],
      listeners: [],
    };
    hosts.set(id, created);
    return created;
  };

  for (const row of rows) {
    const id = row.hostIdentifier ?? row.columns['hostname'] ?? '';
    if (id === '') {
      skipped++;
      continue;
    }
    const h = host(id) as {
      -readonly [K in keyof Host]: Host[K];
    } & { packages: Host['packages'][number][]; configs: Host['configs'][number][]; keyFiles: Host['keyFiles'][number][]; listeners: Host['listeners'][number][] };

    switch (row.name) {
      // `select name, version from deb_packages` / `rpm_packages` / `homebrew_packages`
      case 'crypto_packages': {
        const name = row.columns['name'];
        if (name === undefined) {
          skipped++;
          break;
        }
        h.packages = [
          ...h.packages,
          { name, version: row.columns['version'] ?? '', source: row.columns['source'] ?? 'osquery' },
        ];
        break;
      }
      // `select * from augeas where path like '/etc/ssh/sshd_config%'`
      case 'crypto_config': {
        const path = row.columns['path'];
        const directive = row.columns['label'] ?? row.columns['directive'];
        if (path === undefined || directive === undefined) {
          skipped++;
          break;
        }
        h.configs = [
          ...h.configs,
          {
            path,
            directive,
            value: row.columns['value'] ?? '',
            // osquery reads the file on disk, which is not proof the daemon
            // loaded it. The row says so only if the query joined against
            // `processes`; absent that, this is the honest default.
            active: row.columns['running'] === '1' || row.columns['running'] === 'true',
          },
        ];
        break;
      }
      // `select * from certificates`
      case 'crypto_certificates': {
        const path = row.columns['path'];
        const algorithm = row.columns['key_algorithm'] ?? row.columns['signing_algorithm'];
        if (path === undefined || algorithm === undefined) {
          skipped++;
          break;
        }
        const bits = Number.parseInt(row.columns['key_strength'] ?? '', 10);
        h.keyFiles = [
          ...h.keyFiles,
          {
            path,
            kind: 'certificate',
            algorithm,
            bits: Number.isNaN(bits) || bits <= 0 ? null : bits,
            curve: '',
            subject: row.columns['subject'] ?? '',
            notAfter: row.columns['not_valid_after'] ?? null,
          },
        ];
        break;
      }
      default:
        skipped++;
    }
    hosts.set(id, h);
  }

  return {
    inventory: HostInventorySchema.parse({
      collectedAt: opts.collectedAt,
      source: 'osquery',
      hosts: [...hosts.values()],
    }),
    skipped,
  };
}

/* ---------------------------------------------------------------- Ansible */

/**
 * Ansible fact cache: the JSON `setup` writes per host, keyed by inventory
 * hostname.
 *
 * Only the package list and a caller-supplied set of config facts are read.
 * Ansible facts also carry network addresses, mounted filesystems and
 * environment variables; none of that is touched, because a tool that reads a
 * fleet inventory has to be checkable at a glance for what it does not read.
 */
export interface AnsibleFacts {
  readonly ansible_distribution?: string;
  readonly ansible_distribution_version?: string;
  readonly ansible_fqdn?: string;
  /** From `package_facts`, keyed by package name. */
  readonly packages?: Readonly<Record<string, readonly { version?: string }[]>>;
  /** Directives a play collected deliberately, keyed by file path. */
  readonly assay_crypto_config?: Readonly<Record<string, Readonly<Record<string, string>>>>;
}

export function fromAnsibleFacts(
  byHost: Readonly<Record<string, AnsibleFacts>>,
  opts: OsqueryOptions,
): AdapterResult {
  const hosts: Host[] = [];
  let skipped = 0;

  for (const id of Object.keys(byHost).sort()) {
    const f = byHost[id];
    if (f === undefined) {
      skipped++;
      continue;
    }
    const packages = Object.entries(f.packages ?? {})
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([name, versions]) => ({
        name,
        version: versions[0]?.version ?? '',
        source: 'ansible',
      }));

    const configs = Object.entries(f.assay_crypto_config ?? {})
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .flatMap(([path, directives]) =>
        Object.entries(directives)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([directive, value]) => ({ path, directive, value, active: true })),
      );

    hosts.push({
      hostId: id,
      hostname: f.ansible_fqdn ?? id,
      os: [f.ansible_distribution, f.ansible_distribution_version].filter(Boolean).join(' '),
      systemId: opts.systemId ?? '',
      packages,
      configs,
      keyFiles: [],
      listeners: [],
    });
  }

  return {
    inventory: HostInventorySchema.parse({
      collectedAt: opts.collectedAt,
      source: 'ansible',
      hosts,
    }),
    skipped,
  };
}

/* ------------------------------------------------------------------ plain */

/**
 * The escape hatch: a flat list of observations, one per line.
 *
 * Every EDR exports something different and most of them export CSV. Rather
 * than write an adapter per vendor and get each of them subtly wrong, this
 * takes the four columns any of them can be reduced to with a spreadsheet, and
 * the customer does the reduction they can see.
 */
export interface FlatObservation {
  readonly host: string;
  readonly kind: 'package' | 'config' | 'key' | 'listener';
  readonly where: string;
  readonly what: string;
  readonly value?: string;
}

export function fromFlat(rows: readonly FlatObservation[], opts: OsqueryOptions): AdapterResult {
  const hosts = new Map<string, Host>();
  let skipped = 0;

  for (const r of rows) {
    if (r.host === '' || r.what === '') {
      skipped++;
      continue;
    }
    const h: Host = hosts.get(r.host) ?? {
      hostId: r.host,
      hostname: r.host,
      os: '',
      systemId: opts.systemId ?? '',
      packages: [],
      configs: [],
      keyFiles: [],
      listeners: [],
    };

    switch (r.kind) {
      case 'package':
        hosts.set(r.host, {
          ...h,
          packages: [...h.packages, { name: r.what, version: r.value ?? '', source: 'flat' }],
        });
        break;
      case 'config':
        hosts.set(r.host, {
          ...h,
          configs: [
            ...h.configs,
            { path: r.where, directive: r.what, value: r.value ?? '', active: true },
          ],
        });
        break;
      case 'key':
        hosts.set(r.host, {
          ...h,
          keyFiles: [
            ...h.keyFiles,
            {
              path: r.where,
              kind: 'certificate',
              algorithm: r.what,
              bits: toBits(r.value),
              curve: '',
              subject: '',
              notAfter: null,
            },
          ],
        });
        break;
      case 'listener': {
        const port = Number.parseInt(r.where, 10);
        if (Number.isNaN(port)) {
          skipped++;
          break;
        }
        hosts.set(r.host, {
          ...h,
          listeners: [...h.listeners, { port, protocol: '', service: '', offers: [r.what] }],
        });
        break;
      }
      default:
        skipped++;
    }
  }

  return {
    inventory: HostInventorySchema.parse({
      collectedAt: opts.collectedAt,
      source: 'flat export',
      hosts: [...hosts.values()].sort((a, b) => (a.hostId < b.hostId ? -1 : 1)),
    }),
    skipped,
  };
}

function toBits(value: string | undefined): number | null {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isNaN(n) || n <= 0 ? null : n;
}
