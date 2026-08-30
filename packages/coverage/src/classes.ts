import { MODALITIES, type Modality } from '@assay/core';

/**
 * What an estate is made of, from the point of view of "did we look".
 *
 * The buyer's question is not "how accurate is your scanner". It is "what
 * fraction of my estate does this cover, and can I sign a statement saying
 * so". A percentage cannot answer that: 80% of what, measured how, and does
 * the missing 20% contain the HSM. The answer has to be a list of the parts of
 * an estate, each marked examined or not, with the reason and the remedy.
 *
 * The classes are deliberately the ones an infrastructure owner would name,
 * not the ones the codebase is organized around. A detector is an
 * implementation detail; "the appliances" is a budget line.
 */
export const ESTATE_CLASSES = [
  'APPLICATION_SOURCE',
  'DEPLOYED_CONFIG',
  'DEPENDENCIES',
  'VENDOR_BINARIES',
  'CERTIFICATES',
  'MANAGED_KEYS',
  'NETWORK_ENDPOINTS',
  'HOSTS',
  'APPLIANCES',
  'THIRD_PARTY_SAAS',
] as const;
export type EstateClass = (typeof ESTATE_CLASSES)[number];

export interface ClassDefinition {
  readonly id: EstateClass;
  /** What an operator would call this part of their estate. */
  readonly label: string;
  /** Every modality that can produce evidence about this class. */
  readonly modalities: readonly Modality[];
  /**
   * What it would take to cover this class. Printed when nothing looked, so
   * "not examined" is actionable rather than an apology.
   */
  readonly remedy: string;
  /**
   * Whether Assay can cover this class today.
   *
   * The distinction matters more than the report first made it look. A list of
   * ten classes with six marked "not examined" reads as a list of things the
   * tool cannot do. In fact five of the six are a detector that shipped and was
   * simply not pointed at anything: the binary, KMS, network and PKI detectors
   * all exist, and vendor attestation is a command. Exactly one class - hosts -
   * has no implementation at all.
   *
   * READY means run the remedy and this class fills in.
   * UNBUILT means the remedy is a roadmap item, and saying otherwise would be a
   * promise the code does not keep.
   */
  readonly capability: 'READY' | 'UNBUILT';
  /**
   * The thing this class is never covered by, stated because operators assume
   * otherwise. Empty when there is no common confusion to head off.
   */
  readonly caveat: string;
}

export const CLASSES: readonly ClassDefinition[] = [
  {
    id: 'APPLICATION_SOURCE',
    capability: 'READY',
    label: 'Application source you build',
    modalities: ['SOURCE_AST', 'RUNTIME_HOOK'],
    remedy: 'point `assay scan` at the repository, or add it to the CI gate',
    caveat: 'covers only the repositories that were scanned; nothing here speaks for code you do not build',
  },
  {
    id: 'DEPLOYED_CONFIG',
    capability: 'READY',
    label: 'Deployed configuration',
    modalities: ['SOURCE_CONFIG', 'HOST_AGENT'],
    remedy: 'scan the trees that hold nginx.conf, sshd_config, openssl.cnf or java.security, or supply host-agent output',
    caveat:
      'a configuration file in a repository may be a template rather than the file a server is running; only host-agent evidence from the running machine settles that',
  },
  {
    id: 'DEPENDENCIES',
    capability: 'READY',
    label: 'Third-party libraries',
    modalities: ['DEPENDENCY'],
    remedy: 'scan a tree containing a lockfile or manifest',
    caveat:
      'a dependency shows what the code COULD do, never what it does; these are hints for directing a scan and are never a finding on their own',
  },
  {
    id: 'VENDOR_BINARIES',
    capability: 'READY',
    label: 'Vendor binaries and firmware',
    modalities: ['BINARY_SYMBOL', 'BINARY_CONSTANT', 'BINARY_STRING'],
    remedy: 'point a scan at the directories holding shipped binaries; binary analysis is on by default',
    caveat: 'a stripped or packed binary can defeat every one of these modalities without saying so',
  },
  {
    id: 'CERTIFICATES',
    capability: 'READY',
    label: 'Certificates and host keys',
    modalities: ['PKI_CERTIFICATE'],
    remedy: 'scan the trees holding PEM or DER material, or export the inventory from your CA',
    caveat: 'certificates found in a repository are not evidence of what a live endpoint presents',
  },
  {
    id: 'MANAGED_KEYS',
    capability: 'READY',
    label: 'Managed keys (KMS, HSM, KMIP)',
    modalities: ['CLOUD_KMS_API'],
    remedy: 'export the key inventory and re-run with `--key-inventory <file>`',
    caveat: 'Assay never reads key material (I9); the provider names the key spec and that is all that is recorded',
  },
  {
    id: 'NETWORK_ENDPOINTS',
    capability: 'READY',
    label: 'Live network endpoints',
    modalities: ['NETWORK_ACTIVE', 'NETWORK_PASSIVE'],
    remedy: 'run `assay probe` under a signed scope grant, or supply a pcap-derived inventory',
    caveat:
      'a handshake is ground truth for what was negotiated and silent about what else the endpoint would accept',
  },
  {
    id: 'HOSTS',
    capability: 'READY',
    label: 'Servers and endpoints',
    modalities: ['HOST_AGENT'],
    remedy: 'export from osquery, Ansible or your EDR and pass `--hosts <file>`',
    caveat:
      'a host agent reads the file the daemon loaded, which is stronger than a repository copy and still short of an observed handshake',
  },
  {
    id: 'APPLIANCES',
    capability: 'READY',
    label: 'Appliances and network devices',
    modalities: ['NETWORK_ACTIVE', 'ASSERTED'],
    remedy: 'run `assay probe` against the management endpoint under a signed grant, or record the vendor attestation',
    caveat: 'an appliance with no probe and no attestation is invisible to this tool, not absent from your estate',
  },
  {
    id: 'THIRD_PARTY_SAAS',
    capability: 'READY',
    label: 'Third-party and SaaS',
    modalities: ['ASSERTED'],
    remedy: 'record the vendor attestation with `assay attest`',
    caveat: 'a vendor questionnaire is an unverified claim and is ceilinged accordingly',
  },
];

const BY_ID = new Map(CLASSES.map((c) => [c.id, c]));

export function classOf(id: EstateClass): ClassDefinition {
  const c = BY_ID.get(id);
  /* c8 ignore next */
  if (c === undefined) throw new Error(`unknown estate class: ${id}`);
  return c;
}

/**
 * Which classes a modality speaks for.
 *
 * A modality can appear in more than one class - HOST_AGENT sees both deployed
 * configuration and the host it sits on - so this is a relation, not a
 * function. What it must not be is partial: a modality that speaks for no
 * class would silently vanish from every report, which is the exact failure
 * this whole file exists to prevent. A test enforces totality.
 */
export function classesFor(modality: Modality): readonly EstateClass[] {
  return CLASSES.filter((c) => c.modalities.includes(modality)).map((c) => c.id);
}

/** Every modality appears in at least one class. Asserted by test, not by hope. */
export const UNCLASSIFIED_MODALITIES: readonly Modality[] = MODALITIES.filter(
  (m) => classesFor(m).length === 0,
);
